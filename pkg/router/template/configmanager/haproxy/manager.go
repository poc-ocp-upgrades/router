package haproxy

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/router/pkg/router/routeapihelpers"
	templaterouter "github.com/openshift/router/pkg/router/template"
	templateutil "github.com/openshift/router/pkg/router/template/util"
)

const (
	haproxyManagerName				= "haproxy-manager"
	haproxyRunDir					= "run"
	haproxySocketFile				= "haproxy.sock"
	haproxyConnectionTimeout		= 30
	blueprintRoutePoolNamePrefix	= "_hapcm_blueprint_pool"
	dynamicServerPrefix				= "_dynamic"
	routePoolSizeAnnotation			= "router.openshift.io/pool-size"
	blueprintRoutePoolNamespace		= blueprintRoutePoolNamePrefix
	blueprintRoutePoolServiceName	= blueprintRoutePoolNamePrefix + ".svc"
)

type endpointToDynamicServerMap map[string]string
type configEntryMap map[string]string
type haproxyMapAssociation map[string]configEntryMap
type routeBackendEntry struct {
	id						string
	termination				routev1.TLSTerminationType
	wildcard				bool
	backendName				string
	mapAssociations			haproxyMapAssociation
	poolRouteBackendName	string
	dynamicServerMap		endpointToDynamicServerMap
}
type haproxyConfigManager struct {
	connectionInfo			string
	commitInterval			time.Duration
	blueprintRoutes			[]*routev1.Route
	blueprintRoutePoolSize	int
	maxDynamicServers		int
	wildcardRoutesAllowed	bool
	extendedValidation		bool
	router					templaterouter.RouterInterface
	defaultCertificate		string
	client					*Client
	reloadInProgress		bool
	backendEntries			map[string]*routeBackendEntry
	poolUsage				map[string]string
	lock					sync.Mutex
	commitTimer				*time.Timer
}

func NewHAProxyConfigManager(options templaterouter.ConfigManagerOptions) *haproxyConfigManager {
	_logClusterCodePath()
	defer _logClusterCodePath()
	client := NewClient(options.ConnectionInfo, haproxyConnectionTimeout)
	glog.V(4).Infof("%s: options = %+v\n", haproxyManagerName, options)
	return &haproxyConfigManager{connectionInfo: options.ConnectionInfo, commitInterval: options.CommitInterval, blueprintRoutes: buildBlueprintRoutes(options.BlueprintRoutes, options.ExtendedValidation), blueprintRoutePoolSize: options.BlueprintRoutePoolSize, maxDynamicServers: options.MaxDynamicServers, wildcardRoutesAllowed: options.WildcardRoutesAllowed, extendedValidation: options.ExtendedValidation, defaultCertificate: "", client: client, reloadInProgress: false, backendEntries: make(map[string]*routeBackendEntry), poolUsage: make(map[string]string)}
}
func (cm *haproxyConfigManager) Initialize(router templaterouter.RouterInterface, certPath string) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	certBytes := []byte{}
	if len(certPath) > 0 {
		if b, err := ioutil.ReadFile(certPath); err != nil {
			glog.Errorf("Loading router default certificate from %s: %v", certPath, err)
		} else {
			certBytes = b
		}
	}
	cm.lock.Lock()
	cm.router = router
	cm.defaultCertificate = string(certBytes)
	blueprints := cm.blueprintRoutes
	cm.lock.Unlock()
	for _, r := range blueprints {
		cm.provisionRoutePool(r)
	}
	glog.V(2).Infof("haproxy Config Manager router will flush out any dynamically configured changes within %s of each other", cm.commitInterval.String())
}
func (cm *haproxyConfigManager) AddBlueprint(route *routev1.Route) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	newRoute := route.DeepCopy()
	newRoute.Namespace = blueprintRoutePoolNamespace
	newRoute.Spec.Host = ""
	if cm.extendedValidation {
		if err := routeapihelpers.ExtendedValidateRoute(newRoute).ToAggregate(); err != nil {
			return err
		}
	}
	cm.lock.Lock()
	existingBlueprints := cm.blueprintRoutes
	cm.lock.Unlock()
	routeExists := false
	updated := false
	blueprints := make([]*routev1.Route, 0)
	for _, r := range existingBlueprints {
		if r.Namespace == newRoute.Namespace && r.Name == newRoute.Name {
			routeExists = true
			newRoute.Spec.Host = r.Spec.Host
			if !reflect.DeepEqual(r, newRoute) {
				updated = true
				blueprints = append(blueprints, newRoute)
				continue
			}
		}
		blueprints = append(blueprints, r)
	}
	if !routeExists {
		blueprints = append(blueprints, newRoute)
		updated = true
	}
	if !updated {
		return nil
	}
	cm.lock.Lock()
	cm.blueprintRoutes = blueprints
	cm.lock.Unlock()
	cm.provisionRoutePool(newRoute)
	return nil
}
func (cm *haproxyConfigManager) RemoveBlueprint(route *routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	deletedRoute := route.DeepCopy()
	deletedRoute.Namespace = blueprintRoutePoolNamespace
	cm.lock.Lock()
	existingBlueprints := cm.blueprintRoutes
	cm.lock.Unlock()
	updated := false
	blueprints := make([]*routev1.Route, 0)
	for _, r := range existingBlueprints {
		if r.Namespace == deletedRoute.Namespace && r.Name == deletedRoute.Name {
			updated = true
		} else {
			blueprints = append(blueprints, r)
		}
	}
	if !updated {
		return
	}
	cm.lock.Lock()
	cm.blueprintRoutes = blueprints
	cm.lock.Unlock()
	cm.removeRoutePool(deletedRoute)
}
func (cm *haproxyConfigManager) Register(id string, route *routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	wildcard := cm.wildcardRoutesAllowed && (route.Spec.WildcardPolicy == routev1.WildcardPolicySubdomain)
	entry := &routeBackendEntry{id: id, termination: routeTerminationType(route), wildcard: wildcard, backendName: routeBackendName(id, route), dynamicServerMap: make(endpointToDynamicServerMap)}
	cm.lock.Lock()
	defer cm.lock.Unlock()
	entry.BuildMapAssociations(route)
	cm.backendEntries[id] = entry
}
func (cm *haproxyConfigManager) AddRoute(id, routingKey string, route *routev1.Route) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if cm.isReloading() {
		return fmt.Errorf("Router reload in progress, cannot dynamically add route %s", id)
	}
	glog.V(4).Infof("Adding route id %s", id)
	if cm.isManagedPoolRoute(route) {
		return fmt.Errorf("managed pool blueprint route %s ignored", id)
	}
	matchedBlueprint := cm.findMatchingBlueprint(route)
	if matchedBlueprint == nil {
		return fmt.Errorf("no blueprint found that would match route %s/%s", route.Namespace, route.Name)
	}
	cm.Register(id, route)
	cm.lock.Lock()
	defer func() {
		cm.lock.Unlock()
		cm.scheduleRouterReload()
	}()
	slotName, err := cm.findFreeBackendPoolSlot(matchedBlueprint)
	if err != nil {
		return fmt.Errorf("finding free backend pool slot for route %s: %v", id, err)
	}
	glog.V(4).Infof("Adding route id %s using blueprint pool slot %s", id, slotName)
	entry, ok := cm.backendEntries[id]
	if !ok {
		return fmt.Errorf("route id %s was not registered", id)
	}
	cm.poolUsage[slotName] = id
	entry.poolRouteBackendName = slotName
	entry.BuildMapAssociations(route)
	if err := cm.addMapAssociations(entry.mapAssociations); err != nil {
		return fmt.Errorf("adding map associations for id %s: %v", id, err)
	}
	backendName := entry.BackendName()
	glog.V(4).Infof("Finding backend %s ...", backendName)
	backend, err := cm.client.FindBackend(backendName)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Setting routing key for backend %s ...", backendName)
	if err := backend.SetRoutingKey(routingKey); err != nil {
		return err
	}
	glog.V(4).Infof("Route %s added using blueprint pool slot %s", id, slotName)
	return nil
}
func (cm *haproxyConfigManager) RemoveRoute(id string, route *routev1.Route) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Removing route %s", id)
	if cm.isReloading() {
		return fmt.Errorf("Router reload in progress, cannot dynamically remove route id %s", id)
	}
	if cm.isManagedPoolRoute(route) {
		return fmt.Errorf("managed pool blueprint route %s ignored", id)
	}
	cm.lock.Lock()
	defer func() {
		cm.lock.Unlock()
		cm.scheduleRouterReload()
	}()
	entry, ok := cm.backendEntries[id]
	if !ok {
		return fmt.Errorf("route id %s was not registered", id)
	}
	backendName := entry.BackendName()
	glog.V(4).Infof("For route %s, removing backend %s", id, backendName)
	if err := cm.removeMapAssociations(entry.mapAssociations); err != nil {
		glog.Warningf("Continuing despite errors removing backend %s map associations: %v", backendName, err)
	}
	if len(entry.poolRouteBackendName) > 0 {
		delete(cm.poolUsage, entry.poolRouteBackendName)
	}
	delete(cm.backendEntries, id)
	glog.V(4).Infof("Finding backend %s ...", backendName)
	backend, err := cm.client.FindBackend(backendName)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Disabling all servers for backend %s", backendName)
	if err := backend.Disable(); err != nil {
		return err
	}
	glog.V(4).Infof("Committing changes made to backend %s", backendName)
	return backend.Commit()
}
func (cm *haproxyConfigManager) ReplaceRouteEndpoints(id string, oldEndpoints, newEndpoints []templaterouter.Endpoint, weight int32) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Replacing route endpoints for %s, weight=%v", id, weight)
	if cm.isReloading() {
		return fmt.Errorf("Router reload in progress, cannot dynamically add endpoints for %s", id)
	}
	configChanged := false
	cm.lock.Lock()
	defer func() {
		cm.lock.Unlock()
		if configChanged {
			cm.scheduleRouterReload()
		}
	}()
	entry, ok := cm.backendEntries[id]
	if !ok {
		return fmt.Errorf("route id %s was not registered", id)
	}
	weightIsRelative := false
	if entry.termination == routev1.TLSTerminationPassthrough {
		weightIsRelative = true
		weight = 100
	}
	backendName := entry.BackendName()
	glog.V(4).Infof("Finding backend %s ...", backendName)
	backend, err := cm.client.FindBackend(backendName)
	if err != nil {
		return err
	}
	modifiedEndpoints := make(map[string]templaterouter.Endpoint)
	for _, ep := range newEndpoints {
		modifiedEndpoints[ep.ID] = ep
	}
	deletedEndpoints := make(map[string]templaterouter.Endpoint)
	for _, ep := range oldEndpoints {
		if v2ep, ok := modifiedEndpoints[ep.ID]; ok {
			if reflect.DeepEqual(ep, v2ep) {
				delete(modifiedEndpoints, v2ep.ID)
			}
		} else {
			configChanged = true
			deletedEndpoints[ep.ID] = ep
		}
	}
	glog.V(4).Infof("Getting servers for backend %s", backendName)
	servers, err := backend.Servers()
	if err != nil {
		return err
	}
	glog.V(4).Infof("Processing endpoint changes, deleted=%+v, modified=%+v", deletedEndpoints, modifiedEndpoints)
	unusedServerNames := []string{}
	for _, s := range servers {
		relatedEndpointID := s.Name
		if isDynamicBackendServer(s) {
			if epid, ok := entry.dynamicServerMap[s.Name]; ok {
				relatedEndpointID = epid
			} else {
				unusedServerNames = append(unusedServerNames, s.Name)
				continue
			}
		}
		if _, ok := deletedEndpoints[relatedEndpointID]; ok {
			configChanged = true
			glog.V(4).Infof("For deleted endpoint %s, disabling server %s", relatedEndpointID, s.Name)
			backend.DisableServer(s.Name)
			if _, ok := entry.dynamicServerMap[s.Name]; ok {
				glog.V(4).Infof("Removing server %s from dynamic server map (backend=%s)", s.Name, backendName)
				delete(entry.dynamicServerMap, s.Name)
			}
			continue
		}
		if ep, ok := modifiedEndpoints[relatedEndpointID]; ok {
			configChanged = true
			glog.V(4).Infof("For modified endpoint %s, setting server %s info to %s:%s with weight %d and enabling", relatedEndpointID, s.Name, ep.IP, ep.Port, weight)
			backend.UpdateServerInfo(s.Name, ep.IP, ep.Port, weight, weightIsRelative)
			backend.EnableServer(s.Name)
			delete(modifiedEndpoints, relatedEndpointID)
		}
	}
	for _, name := range unusedServerNames {
		if len(modifiedEndpoints) == 0 {
			break
		}
		var ep templaterouter.Endpoint
		for _, v := range modifiedEndpoints {
			ep = v
			break
		}
		configChanged = true
		entry.dynamicServerMap[name] = ep.ID
		glog.V(4).Infof("For added endpoint %s, setting dynamic server %s info: (%s, %s, %d) and enabling", ep.ID, name, ep.IP, ep.Port, weight)
		backend.UpdateServerInfo(name, ep.IP, ep.Port, weight, weightIsRelative)
		backend.EnableServer(name)
		delete(modifiedEndpoints, ep.ID)
	}
	if len(modifiedEndpoints) > 0 {
		return fmt.Errorf("no free dynamic server slots for backend %s, %d endpoint(s) remaining", id, len(modifiedEndpoints))
	}
	glog.V(4).Infof("Committing backend %s", backendName)
	return backend.Commit()
}
func (cm *haproxyConfigManager) RemoveRouteEndpoints(id string, endpoints []templaterouter.Endpoint) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Removing endpoints for id %s", id)
	if cm.isReloading() {
		return fmt.Errorf("Router reload in progress, cannot dynamically delete endpoints for %s", id)
	}
	cm.lock.Lock()
	defer func() {
		cm.lock.Unlock()
		cm.scheduleRouterReload()
	}()
	entry, ok := cm.backendEntries[id]
	if !ok {
		return fmt.Errorf("route id %s was not registered", id)
	}
	backendName := entry.BackendName()
	glog.V(4).Infof("Finding backend %s ...", backendName)
	backend, err := cm.client.FindBackend(backendName)
	if err != nil {
		return err
	}
	endpointToDynServerMap := make(map[string]string)
	for serverName, endpointID := range entry.dynamicServerMap {
		endpointToDynServerMap[endpointID] = serverName
	}
	for _, ep := range endpoints {
		name := ep.ID
		if serverName, ok := endpointToDynServerMap[ep.ID]; ok {
			name = serverName
			delete(entry.dynamicServerMap, name)
		}
		glog.V(4).Infof("For endpoint %s, disabling server %s", ep.ID, name)
		backend.DisableServer(name)
	}
	glog.V(4).Infof("Committing backend %s", backendName)
	return backend.Commit()
}
func (cm *haproxyConfigManager) Notify(event templaterouter.RouterEventType) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Received a %s notification", string(event))
	cm.lock.Lock()
	defer cm.lock.Unlock()
	switch event {
	case templaterouter.RouterEventReloadStart:
		cm.reloadInProgress = true
	case templaterouter.RouterEventReloadError:
		cm.reloadInProgress = false
	case templaterouter.RouterEventReloadEnd:
		cm.reloadInProgress = false
		cm.reset()
	}
}
func (cm *haproxyConfigManager) Commit() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Committing dynamic config manager changes")
	cm.commitRouterConfig()
}
func (cm *haproxyConfigManager) ServerTemplateName(id string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if cm.maxDynamicServers > 0 {
		return fmt.Sprintf("%s-pod", dynamicServerPrefix)
	}
	return ""
}
func (cm *haproxyConfigManager) ServerTemplateSize(id string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if cm.maxDynamicServers < 1 {
		return ""
	}
	return fmt.Sprintf("%v", cm.maxDynamicServers)
}
func (cm *haproxyConfigManager) GenerateDynamicServerNames(id string) []string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if cm.maxDynamicServers > 0 {
		if prefix := cm.ServerTemplateName(id); len(prefix) > 0 {
			names := make([]string, cm.maxDynamicServers)
			for i := 0; i < cm.maxDynamicServers; i++ {
				names[i] = fmt.Sprintf("%s-%v", prefix, i+1)
			}
			return names
		}
	}
	return []string{}
}
func (cm *haproxyConfigManager) scheduleRouterReload() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cm.lock.Lock()
	defer cm.lock.Unlock()
	if cm.commitTimer == nil {
		cm.commitTimer = time.AfterFunc(cm.commitInterval, cm.commitRouterConfig)
	}
}
func (cm *haproxyConfigManager) commitRouterConfig() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cm.lock.Lock()
	cm.commitTimer = nil
	cm.lock.Unlock()
	route := createBlueprintRoute(routev1.TLSTerminationEdge)
	route.Name = fmt.Sprintf("%s-temp-%d", route.Name, time.Now().Unix())
	cm.router.AddRoute(route)
	cm.router.RemoveRoute(route)
	glog.V(4).Infof("Committing associated template router ... ")
	cm.router.Commit()
}
func (cm *haproxyConfigManager) isReloading() bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cm.lock.Lock()
	defer cm.lock.Unlock()
	return cm.reloadInProgress
}
func (cm *haproxyConfigManager) isManagedPoolRoute(route *routev1.Route) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return route.Namespace == blueprintRoutePoolNamespace
}
func (cm *haproxyConfigManager) provisionRoutePool(blueprint *routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	poolSize := getPoolSize(blueprint, cm.blueprintRoutePoolSize)
	glog.Infof("Provisioning blueprint route pool %s/%s-[1-%d]", blueprint.Namespace, blueprint.Name, poolSize)
	for i := 0; i < poolSize; i++ {
		route := blueprint.DeepCopy()
		route.Namespace = blueprintRoutePoolNamespace
		route.Name = fmt.Sprintf("%v-%v", route.Name, i+1)
		route.Spec.Host = ""
		cm.router.AddRoute(route)
	}
}
func (cm *haproxyConfigManager) removeRoutePool(blueprint *routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	poolSize := getPoolSize(blueprint, cm.blueprintRoutePoolSize)
	glog.Infof("Removing blueprint route pool %s/%s-[1-%d]", blueprint.Namespace, blueprint.Name, poolSize)
	for i := 0; i < poolSize; i++ {
		route := blueprint.DeepCopy()
		route.Namespace = blueprintRoutePoolNamespace
		route.Name = fmt.Sprintf("%v-%v", route.Name, i+1)
		route.Spec.Host = ""
		cm.router.RemoveRoute(route)
	}
}
func (cm *haproxyConfigManager) processMapAssociations(associations haproxyMapAssociation, add bool) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Associations = %+v", associations)
	haproxyMaps, err := cm.client.Maps()
	if err != nil {
		return err
	}
	for _, ham := range haproxyMaps {
		name := path.Base(ham.Name())
		if entries, ok := associations[name]; ok {
			glog.V(4).Infof("Applying to map %s, entries %+v ", name, entries)
			if err := applyMapAssociations(ham, entries, add); err != nil {
				return err
			}
		}
	}
	return nil
}
func (cm *haproxyConfigManager) findFreeBackendPoolSlot(blueprint *routev1.Route) (string, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	poolSize := getPoolSize(blueprint, cm.blueprintRoutePoolSize)
	idPrefix := fmt.Sprintf("%s:%s", blueprint.Namespace, blueprint.Name)
	for i := 0; i < poolSize; i++ {
		id := fmt.Sprintf("%s-%v", idPrefix, i+1)
		name := routeBackendName(id, blueprint)
		if _, ok := cm.poolUsage[name]; !ok {
			return name, nil
		}
	}
	return "", fmt.Errorf("no %s free pool slot available", idPrefix)
}
func (cm *haproxyConfigManager) addMapAssociations(m haproxyMapAssociation) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return cm.processMapAssociations(m, true)
}
func (cm *haproxyConfigManager) removeMapAssociations(m haproxyMapAssociation) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return cm.processMapAssociations(m, false)
}
func (cm *haproxyConfigManager) reset() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if cm.commitTimer != nil {
		commitTimer := cm.commitTimer
		defer func() {
			commitTimer.Stop()
		}()
		cm.commitTimer = nil
	}
	cm.poolUsage = make(map[string]string)
	for _, entry := range cm.backendEntries {
		entry.poolRouteBackendName = ""
		if len(entry.dynamicServerMap) > 0 {
			entry.dynamicServerMap = make(endpointToDynamicServerMap)
		}
	}
	cm.client.Reset()
}
func (cm *haproxyConfigManager) findMatchingBlueprint(route *routev1.Route) *routev1.Route {
	_logClusterCodePath()
	defer _logClusterCodePath()
	termination := routeTerminationType(route)
	routeModifiers := backendModAnnotations(route)
	for _, candidate := range cm.blueprintRoutes {
		t2 := routeTerminationType(candidate)
		if termination != t2 {
			continue
		}
		if len(routeModifiers) > 0 {
			if len(candidate.Annotations) == 0 {
				continue
			}
			candidateModifiers := backendModAnnotations(candidate)
			if !reflect.DeepEqual(routeModifiers, candidateModifiers) {
				continue
			}
		}
		if route.Spec.TLS == nil && candidate.Spec.TLS == nil {
			return candidate
		}
		tlsSpec := route.Spec.TLS
		if tlsSpec == nil {
			tlsSpec = &routev1.TLSConfig{Termination: routev1.TLSTerminationType("")}
		}
		if tlsSpec != nil && candidate.Spec.TLS != nil {
			candidateCopy := candidate.DeepCopy()
			candidateCopy.Spec.TLS.InsecureEdgeTerminationPolicy = tlsSpec.InsecureEdgeTerminationPolicy
			if reflect.DeepEqual(tlsSpec, candidateCopy.Spec.TLS) {
				return candidateCopy
			}
		}
	}
	return nil
}
func (entry *routeBackendEntry) BackendName() string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(entry.poolRouteBackendName) > 0 {
		return entry.poolRouteBackendName
	}
	return entry.backendName
}
func (entry *routeBackendEntry) BuildMapAssociations(route *routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	termination := routeTerminationType(route)
	policy := routev1.InsecureEdgeTerminationPolicyNone
	if route.Spec.TLS != nil {
		policy = route.Spec.TLS.InsecureEdgeTerminationPolicy
	}
	entry.mapAssociations = make(haproxyMapAssociation)
	associate := func(name, k, v string) {
		m, ok := entry.mapAssociations[name]
		if !ok {
			m = make(configEntryMap)
		}
		m[k] = v
		entry.mapAssociations[name] = m
	}
	hostspec := route.Spec.Host
	pathspec := route.Spec.Path
	if len(hostspec) == 0 {
		return
	}
	name := entry.BackendName()
	pathRE := templateutil.GenerateRouteRegexp(hostspec, pathspec, entry.wildcard)
	if policy == routev1.InsecureEdgeTerminationPolicyRedirect {
		associate("os_route_http_redirect.map", pathRE, name)
	}
	switch termination {
	case routev1.TLSTerminationType(""):
		associate("os_http_be.map", pathRE, name)
	case routev1.TLSTerminationEdge:
		associate("os_edge_reencrypt_be.map", pathRE, name)
		if policy == routev1.InsecureEdgeTerminationPolicyAllow {
			associate("os_http_be.map", pathRE, name)
		}
	case routev1.TLSTerminationReencrypt:
		associate("os_edge_reencrypt_be.map", pathRE, name)
		if policy == routev1.InsecureEdgeTerminationPolicyAllow {
			associate("os_http_be.map", pathRE, name)
		}
	}
	hostRE := templateutil.GenerateRouteRegexp(hostspec, "", entry.wildcard)
	if len(os.Getenv("ROUTER_ALLOW_WILDCARD_ROUTES")) > 0 && entry.wildcard {
		associate("os_wildcard_domain.map", hostRE, "1")
	}
	switch termination {
	case routev1.TLSTerminationReencrypt:
		associate("os_tcp_be.map", hostRE, name)
	case routev1.TLSTerminationPassthrough:
		associate("os_tcp_be.map", hostRE, name)
		associate("os_sni_passthrough.map", hostRE, "1")
	}
}
func buildBlueprintRoutes(customRoutes []*routev1.Route, validate bool) []*routev1.Route {
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes := make([]*routev1.Route, 0)
	terminationTypes := []routev1.TLSTerminationType{routev1.TLSTerminationType(""), routev1.TLSTerminationEdge, routev1.TLSTerminationPassthrough}
	for _, v := range terminationTypes {
		r := createBlueprintRoute(v)
		routes = append(routes, r)
	}
	for _, r := range customRoutes {
		dolly := r.DeepCopy()
		dolly.Namespace = blueprintRoutePoolNamespace
		if validate {
			if err := routeapihelpers.ExtendedValidateRoute(dolly).ToAggregate(); err != nil {
				glog.Errorf("Skipping blueprint route %s/%s due to invalid configuration: %v", r.Namespace, r.Name, err)
				continue
			}
		}
		routes = append(routes, dolly)
	}
	return routes
}
func generateRouteName(routeType routev1.TLSTerminationType) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	prefix := "http"
	switch routeType {
	case routev1.TLSTerminationEdge:
		prefix = "edge"
	case routev1.TLSTerminationPassthrough:
		prefix = "passthrough"
	case routev1.TLSTerminationReencrypt:
		prefix = "reencrypt"
	}
	return fmt.Sprintf("_blueprint-%v-route", prefix)
}
func createBlueprintRoute(routeType routev1.TLSTerminationType) *routev1.Route {
	_logClusterCodePath()
	defer _logClusterCodePath()
	name := generateRouteName(routeType)
	return &routev1.Route{ObjectMeta: metav1.ObjectMeta{Namespace: blueprintRoutePoolNamespace, Name: name}, Spec: routev1.RouteSpec{Host: "", TLS: &routev1.TLSConfig{Termination: routeType}, To: routev1.RouteTargetReference{Name: blueprintRoutePoolServiceName, Weight: new(int32)}}}
}
func routeBackendName(id string, route *routev1.Route) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	termination := routeTerminationType(route)
	prefix := templateutil.GenerateBackendNamePrefix(termination)
	return fmt.Sprintf("%s:%s", prefix, id)
}
func getPoolSize(r *routev1.Route, defaultSize int) int {
	_logClusterCodePath()
	defer _logClusterCodePath()
	v, ok := r.Annotations[routePoolSizeAnnotation]
	if ok {
		if poolSize, err := strconv.ParseInt(v, 10, 0); err != nil {
			return int(poolSize)
		} else {
			routeName := fmt.Sprintf("%s/%s", r.Namespace, r.Name)
			glog.Warningf("Blueprint route %s has an invalid pool size annotation %q, using default size %v, error: %v", routeName, v, defaultSize, err)
		}
	}
	return defaultSize
}
func routeTerminationType(route *routev1.Route) routev1.TLSTerminationType {
	_logClusterCodePath()
	defer _logClusterCodePath()
	termination := routev1.TLSTerminationType("")
	if route.Spec.TLS != nil {
		termination = route.Spec.TLS.Termination
	}
	return termination
}
func isDynamicBackendServer(server BackendServerInfo) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(dynamicServerPrefix) == 0 {
		return false
	}
	return strings.HasPrefix(server.Name, dynamicServerPrefix)
}
func applyMapAssociations(m *HAProxyMap, associations map[string]string, add bool) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	for k, v := range associations {
		glog.V(4).Infof("Applying to map %s(k=%v, v=%v), add=%+v", m.Name(), k, v, add)
		if add {
			if err := m.Add(k, v, true); err != nil {
				return err
			}
		} else {
			if err := m.Delete(k); err != nil {
				return err
			}
		}
		if err := m.Commit(); err != nil {
			return err
		}
	}
	return nil
}
func backendModAnnotations(route *routev1.Route) map[string]string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	termination := routeTerminationType(route)
	backendModifiers := modAnnotationsList(termination)
	annotations := make(map[string]string)
	for _, name := range backendModifiers {
		if v, ok := route.Annotations[name]; ok {
			annotations[name] = v
		}
	}
	return annotations
}
func modAnnotationsList(termination routev1.TLSTerminationType) []string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	annotations := []string{"haproxy.router.openshift.io/balance", "haproxy.router.openshift.io/ip_whitelist", "haproxy.router.openshift.io/timeout", "haproxy.router.openshift.io/rate-limit-connections", "haproxy.router.openshift.io/rate-limit-connections.concurrent-tcp", "haproxy.router.openshift.io/rate-limit-connections.rate-tcp", "haproxy.router.openshift.io/rate-limit-connections.rate-http", "haproxy.router.openshift.io/pod-concurrent-connections", "router.openshift.io/haproxy.health.check.interval"}
	if termination == routev1.TLSTerminationPassthrough {
		return annotations
	}
	annotations = append(annotations, "haproxy.router.openshift.io/disable_cookies")
	annotations = append(annotations, "router.openshift.io/cookie_name")
	annotations = append(annotations, "haproxy.router.openshift.io/hsts_header")
	return annotations
}
