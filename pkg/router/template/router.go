package templaterouter

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/util/sets"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/router/pkg/router/template/limiter"
)

const (
	ProtocolHTTP		= "http"
	ProtocolHTTPS		= "https"
	ProtocolTLS			= "tls"
	routeFile			= "routes.json"
	certDir				= "certs"
	caCertDir			= "cacerts"
	defaultCertName		= "default"
	caCertPostfix		= "_ca"
	destCertPostfix		= "_pod"
	routeKeySeparator	= ":"
)

type templateRouter struct {
	dir							string
	templates					map[string]*template.Template
	reloadScriptPath			string
	reloadInterval				time.Duration
	reloadCallbacks				[]func()
	state						map[string]ServiceAliasConfig
	serviceUnits				map[string]ServiceUnit
	certManager					certificateManager
	defaultCertificate			string
	defaultCertificatePath		string
	defaultCertificateDir		string
	defaultDestinationCAPath	string
	peerEndpointsKey			string
	peerEndpoints				[]Endpoint
	statsUser					string
	statsPassword				string
	statsPort					int
	allowWildcardRoutes			bool
	rateLimitedCommitFunction	*limiter.CoalescingSerializingRateLimiter
	lock						sync.Mutex
	bindPortsAfterSync			bool
	synced						bool
	stateChanged				bool
	metricReload				prometheus.Summary
	metricWriteConfig			prometheus.Summary
	dynamicConfigManager		ConfigManager
	dynamicallyConfigured		bool
}
type templateRouterCfg struct {
	dir							string
	templates					map[string]*template.Template
	reloadScriptPath			string
	reloadInterval				time.Duration
	reloadCallbacks				[]func()
	defaultCertificate			string
	defaultCertificatePath		string
	defaultCertificateDir		string
	defaultDestinationCAPath	string
	statsUser					string
	statsPassword				string
	statsPort					int
	allowWildcardRoutes			bool
	peerEndpointsKey			string
	includeUDP					bool
	bindPortsAfterSync			bool
	dynamicConfigManager		ConfigManager
}
type templateData struct {
	WorkingDir				string
	State					map[string](ServiceAliasConfig)
	ServiceUnits			map[string]ServiceUnit
	DefaultCertificate		string
	DefaultDestinationCA	string
	PeerEndpoints			[]Endpoint
	StatsUser				string
	StatsPassword			string
	StatsPort				int
	BindPorts				bool
	DynamicConfigManager	ConfigManager
}

func newTemplateRouter(cfg templateRouterCfg) (*templateRouter, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	dir := cfg.dir
	glog.V(2).Infof("Creating a new template router, writing to %s", dir)
	if len(cfg.peerEndpointsKey) > 0 {
		glog.V(2).Infof("Router will use %s service to identify peers", cfg.peerEndpointsKey)
	}
	certManagerConfig := &certificateManagerConfig{certKeyFunc: generateCertKey, caCertKeyFunc: generateCACertKey, destCertKeyFunc: generateDestCertKey, certDir: filepath.Join(dir, certDir), caCertDir: filepath.Join(dir, caCertDir)}
	certManager, err := newSimpleCertificateManager(certManagerConfig, newSimpleCertificateWriter())
	if err != nil {
		return nil, err
	}
	metricsReload := prometheus.NewSummary(prometheus.SummaryOpts{Namespace: "template_router", Name: "reload_seconds", Help: "Measures the time spent reloading the router in seconds."})
	prometheus.MustRegister(metricsReload)
	metricWriteConfig := prometheus.NewSummary(prometheus.SummaryOpts{Namespace: "template_router", Name: "write_config_seconds", Help: "Measures the time spent writing out the router configuration to disk in seconds."})
	prometheus.MustRegister(metricWriteConfig)
	router := &templateRouter{dir: dir, templates: cfg.templates, reloadScriptPath: cfg.reloadScriptPath, reloadInterval: cfg.reloadInterval, reloadCallbacks: cfg.reloadCallbacks, state: make(map[string]ServiceAliasConfig), serviceUnits: make(map[string]ServiceUnit), certManager: certManager, defaultCertificate: cfg.defaultCertificate, defaultCertificatePath: cfg.defaultCertificatePath, defaultCertificateDir: cfg.defaultCertificateDir, defaultDestinationCAPath: cfg.defaultDestinationCAPath, statsUser: cfg.statsUser, statsPassword: cfg.statsPassword, statsPort: cfg.statsPort, allowWildcardRoutes: cfg.allowWildcardRoutes, peerEndpointsKey: cfg.peerEndpointsKey, peerEndpoints: []Endpoint{}, bindPortsAfterSync: cfg.bindPortsAfterSync, dynamicConfigManager: cfg.dynamicConfigManager, metricReload: metricsReload, metricWriteConfig: metricWriteConfig, rateLimitedCommitFunction: nil}
	router.EnableRateLimiter(cfg.reloadInterval, router.commitAndReload)
	if err := router.writeDefaultCert(); err != nil {
		return nil, err
	}
	glog.V(4).Infof("Reading persisted state")
	if err := router.readState(); err != nil {
		return nil, err
	}
	if router.dynamicConfigManager != nil {
		glog.Infof("Initializing dynamic config manager ... ")
		router.dynamicConfigManager.Initialize(router, router.defaultCertificatePath)
	}
	glog.V(4).Infof("Committing state")
	router.commitAndReload()
	return router, nil
}
func (r *templateRouter) EnableRateLimiter(interval time.Duration, handlerFunc limiter.HandlerFunc) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.rateLimitedCommitFunction = limiter.NewCoalescingSerializingRateLimiter(interval, handlerFunc)
	glog.V(2).Infof("Template router will coalesce reloads within %s of each other", interval.String())
}
func secretToPem(secPath, outName string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var fileCrtName = filepath.Join(secPath, "tls.crt")
	var fileKeyName = filepath.Join(secPath, "tls.key")
	pemBlock, err := ioutil.ReadFile(fileCrtName)
	if err != nil {
		return err
	}
	keys, err := privateKeysFromPEM(pemBlock)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		keyBlock, err := ioutil.ReadFile(fileKeyName)
		if err != nil {
			return err
		}
		pemBlock = append(pemBlock, keyBlock...)
	}
	return ioutil.WriteFile(outName, pemBlock, 0444)
}
func (r *templateRouter) writeDefaultCert() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	dir := filepath.Join(r.dir, certDir)
	outPath := filepath.Join(dir, fmt.Sprintf("%s.pem", defaultCertName))
	if len(r.defaultCertificate) == 0 {
		if len(r.defaultCertificatePath) != 0 {
			return nil
		}
		err := secretToPem(r.defaultCertificateDir, outPath)
		if err != nil {
			glog.V(2).Infof("Router default cert from router container")
			return nil
		}
		r.defaultCertificatePath = outPath
		return nil
	}
	glog.V(2).Infof("Writing default certificate to %s", dir)
	if err := r.certManager.CertificateWriter().WriteCertificate(dir, defaultCertName, []byte(r.defaultCertificate)); err != nil {
		return err
	}
	r.defaultCertificatePath = outPath
	return nil
}
func (r *templateRouter) readState() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	data, err := ioutil.ReadFile(filepath.Join(r.dir, routeFile))
	if err != nil {
		r.state = make(map[string]ServiceAliasConfig)
		return nil
	}
	return json.Unmarshal(data, &r.state)
}
func (r *templateRouter) Commit() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.lock.Lock()
	if !r.synced {
		glog.V(4).Infof("Router state synchronized for the first time")
		r.synced = true
		r.stateChanged = true
		r.dynamicallyConfigured = false
	}
	needsCommit := r.stateChanged && !r.dynamicallyConfigured
	r.lock.Unlock()
	if needsCommit {
		r.rateLimitedCommitFunction.RegisterChange()
	}
}
func (r *templateRouter) commitAndReload() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if err := func() error {
		r.lock.Lock()
		defer r.lock.Unlock()
		glog.V(4).Infof("Writing the router state")
		if err := r.writeState(); err != nil {
			return err
		}
		r.stateChanged = false
		if r.dynamicConfigManager != nil {
			r.dynamicallyConfigured = true
			r.dynamicConfigManager.Notify(RouterEventReloadStart)
		}
		glog.V(4).Infof("Writing the router config")
		reloadStart := time.Now()
		err := r.writeConfig()
		r.metricWriteConfig.Observe(float64(time.Now().Sub(reloadStart)) / float64(time.Second))
		return err
	}(); err != nil {
		return err
	}
	for i, fn := range r.reloadCallbacks {
		glog.V(4).Infof("Calling reload function %d", i)
		fn()
	}
	glog.V(4).Infof("Reloading the router")
	reloadStart := time.Now()
	err := r.reloadRouter()
	r.metricReload.Observe(float64(time.Now().Sub(reloadStart)) / float64(time.Second))
	if err != nil {
		if r.dynamicConfigManager != nil {
			r.dynamicConfigManager.Notify(RouterEventReloadError)
		}
		return err
	}
	if r.dynamicConfigManager != nil {
		r.dynamicConfigManager.Notify(RouterEventReloadEnd)
	}
	return nil
}
func (r *templateRouter) writeState() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	data, err := json.MarshalIndent(r.state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal route table: %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(r.dir, routeFile), data, 0644); err != nil {
		return fmt.Errorf("failed to write route table: %v", err)
	}
	return nil
}
func (r *templateRouter) writeConfig() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	for k, cfg := range r.state {
		if err := r.writeCertificates(&cfg); err != nil {
			return fmt.Errorf("error writing certificates for %s: %v", k, err)
		}
		cfg.ServiceUnitNames = r.calculateServiceWeights(cfg.ServiceUnits)
		cfg.ActiveEndpoints = r.getActiveEndpoints(cfg.ServiceUnits)
		cfg.Status = ServiceAliasConfigStatusSaved
		r.state[k] = cfg
	}
	glog.V(4).Infof("Committing router certificate manager changes...")
	if err := r.certManager.Commit(); err != nil {
		return fmt.Errorf("error committing certificate changes: %v", err)
	}
	glog.V(4).Infof("Router certificate manager config committed")
	pathNames := make([]string, 0)
	for k := range r.templates {
		pathNames = append(pathNames, k)
	}
	sort.Strings(pathNames)
	for _, path := range pathNames {
		template := r.templates[path]
		file, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("error creating config file %s: %v", path, err)
		}
		data := templateData{WorkingDir: r.dir, State: r.state, ServiceUnits: r.serviceUnits, DefaultCertificate: r.defaultCertificatePath, DefaultDestinationCA: r.defaultDestinationCAPath, PeerEndpoints: r.peerEndpoints, StatsUser: r.statsUser, StatsPassword: r.statsPassword, StatsPort: r.statsPort, BindPorts: !r.bindPortsAfterSync || r.synced, DynamicConfigManager: r.dynamicConfigManager}
		if err := template.Execute(file, data); err != nil {
			file.Close()
			return fmt.Errorf("error executing template for file %s: %v", path, err)
		}
		file.Close()
	}
	return nil
}
func (r *templateRouter) writeCertificates(cfg *ServiceAliasConfig) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if r.shouldWriteCerts(cfg) {
		return r.certManager.WriteCertificatesForConfig(cfg)
	}
	return nil
}
func (r *templateRouter) reloadRouter() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cmd := exec.Command(r.reloadScriptPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error reloading router: %v\n%s", err, string(out))
	}
	glog.Infof("Router reloaded:\n%s", out)
	return nil
}
func (r *templateRouter) FilterNamespaces(namespaces sets.String) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.lock.Lock()
	defer r.lock.Unlock()
	if len(namespaces) == 0 {
		r.state = make(map[string]ServiceAliasConfig)
		r.serviceUnits = make(map[string]ServiceUnit)
		r.stateChanged = true
	}
	for k := range r.serviceUnits {
		ns, _ := getPartsFromEndpointsKey(k)
		if namespaces.Has(ns) {
			continue
		}
		delete(r.serviceUnits, k)
		r.stateChanged = true
	}
	for k := range r.state {
		ns, _ := getPartsFromRouteKey(k)
		if namespaces.Has(ns) {
			continue
		}
		delete(r.state, k)
		r.stateChanged = true
	}
	if r.stateChanged {
		r.dynamicallyConfigured = false
	}
}
func (r *templateRouter) CreateServiceUnit(id string) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.lock.Lock()
	defer r.lock.Unlock()
	r.createServiceUnitInternal(id)
}
func (r *templateRouter) createServiceUnitInternal(id string) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	namespace, name := getPartsFromEndpointsKey(id)
	service := ServiceUnit{Name: id, Hostname: fmt.Sprintf("%s.%s.svc", name, namespace), EndpointTable: []Endpoint{}, ServiceAliasAssociations: make(map[string]bool)}
	r.serviceUnits[id] = service
	r.stateChanged = true
}
func (r *templateRouter) findMatchingServiceUnit(id string) (ServiceUnit, bool) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	v, ok := r.serviceUnits[id]
	return v, ok
}
func (r *templateRouter) FindServiceUnit(id string) (ServiceUnit, bool) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.findMatchingServiceUnit(id)
}
func (r *templateRouter) DeleteServiceUnit(id string) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.lock.Lock()
	defer r.lock.Unlock()
	_, ok := r.findMatchingServiceUnit(id)
	if !ok {
		return
	}
	delete(r.serviceUnits, id)
	r.stateChanged = true
}
func (r *templateRouter) addServiceAliasAssociation(id, alias string) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if serviceUnit, ok := r.findMatchingServiceUnit(id); ok {
		glog.V(4).Infof("associated service unit %s -> service alias %s", id, alias)
		serviceUnit.ServiceAliasAssociations[alias] = true
	}
}
func (r *templateRouter) removeServiceAliasAssociation(id, alias string) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if serviceUnit, ok := r.findMatchingServiceUnit(id); ok {
		glog.V(4).Infof("removed association for service unit %s -> service alias %s", id, alias)
		delete(serviceUnit.ServiceAliasAssociations, alias)
	}
}
func (r *templateRouter) dynamicallyAddRoute(backendKey string, route *routev1.Route, backend *ServiceAliasConfig) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if r.dynamicConfigManager == nil {
		return false
	}
	glog.V(4).Infof("Dynamically adding route backend %s", backendKey)
	r.dynamicConfigManager.Register(backendKey, route)
	if !r.synced {
		return false
	}
	err := r.dynamicConfigManager.AddRoute(backendKey, backend.RoutingKeyName, route)
	if err != nil {
		glog.V(4).Infof("Router will reload as the ConfigManager could not dynamically add route for backend %s: %v", backendKey, err)
		return false
	}
	oldEndpoints := []Endpoint{}
	newWeights := r.calculateServiceWeights(backend.ServiceUnits)
	for key := range backend.ServiceUnits {
		if service, ok := r.findMatchingServiceUnit(key); ok {
			newEndpoints := service.EndpointTable
			glog.V(4).Infof("For new route backend %s, replacing endpoints for service %s: %+v", backendKey, key, service.EndpointTable)
			weight, ok := newWeights[key]
			if !ok {
				weight = 0
			}
			if err := r.dynamicConfigManager.ReplaceRouteEndpoints(backendKey, oldEndpoints, newEndpoints, weight); err != nil {
				glog.V(4).Infof("Router will reload as the ConfigManager could not dynamically replace endpoints for route backend %s, service %s: %v", backendKey, key, err)
				return false
			}
		}
	}
	glog.V(4).Infof("Dynamically added route backend %s", backendKey)
	return true
}
func (r *templateRouter) dynamicallyRemoveRoute(backendKey string, route *routev1.Route) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if r.dynamicConfigManager == nil || !r.synced {
		return false
	}
	glog.V(4).Infof("Dynamically removing route backend %s", backendKey)
	if err := r.dynamicConfigManager.RemoveRoute(backendKey, route); err != nil {
		glog.V(4).Infof("Router will reload as the ConfigManager could not dynamically remove route backend %s: %v", backendKey, err)
		return false
	}
	return true
}
func (r *templateRouter) dynamicallyReplaceEndpoints(id string, service ServiceUnit, oldEndpoints []Endpoint) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if r.dynamicConfigManager == nil || !r.synced {
		return false
	}
	glog.V(4).Infof("Replacing endpoints dynamically for service %s", id)
	newEndpoints := service.EndpointTable
	for backendKey := range service.ServiceAliasAssociations {
		cfg, ok := r.state[backendKey]
		if !ok {
			glog.V(4).Infof("Associated service alias %s not found in state, ignoring ...", backendKey)
			continue
		}
		newWeights := r.calculateServiceWeights(cfg.ServiceUnits)
		weight, ok := newWeights[id]
		if !ok {
			weight = 0
		}
		glog.V(4).Infof("Dynamically replacing endpoints for associated backend %s", backendKey)
		if err := r.dynamicConfigManager.ReplaceRouteEndpoints(backendKey, oldEndpoints, newEndpoints, weight); err != nil {
			glog.V(4).Infof("Router will reload as the ConfigManager could not dynamically replace endpoints for service id %s (backend=%s, weight=%v): %v", id, backendKey, weight, err)
			return false
		}
	}
	return true
}
func (r *templateRouter) dynamicallyRemoveEndpoints(service ServiceUnit, endpoints []Endpoint) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if r.dynamicConfigManager == nil || !r.synced {
		return false
	}
	glog.V(4).Infof("Dynamically removing endpoints for service unit %s", service.Name)
	for backendKey := range service.ServiceAliasAssociations {
		if _, ok := r.state[backendKey]; !ok {
			continue
		}
		glog.V(4).Infof("Dynamically removing endpoints for associated backend %s", backendKey)
		if err := r.dynamicConfigManager.RemoveRouteEndpoints(backendKey, endpoints); err != nil {
			glog.V(4).Infof("Router will reload as the ConfigManager could not dynamically remove endpoints for backend %s: %v", backendKey, err)
			return false
		}
	}
	return true
}
func (r *templateRouter) DeleteEndpoints(id string) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.lock.Lock()
	defer r.lock.Unlock()
	service, ok := r.findMatchingServiceUnit(id)
	if !ok {
		return
	}
	configChanged := r.dynamicallyRemoveEndpoints(service, service.EndpointTable)
	service.EndpointTable = []Endpoint{}
	r.serviceUnits[id] = service
	if id == r.peerEndpointsKey {
		r.peerEndpoints = []Endpoint{}
		glog.V(4).Infof("Peer endpoint table has been cleared")
	}
	r.stateChanged = true
	r.dynamicallyConfigured = r.dynamicallyConfigured && configChanged
}
func routeKey(route *routev1.Route) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return routeKeyFromParts(route.Namespace, route.Name)
}
func routeKeyFromParts(namespace, name string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return fmt.Sprintf("%s%s%s", namespace, routeKeySeparator, name)
}
func getPartsFromRouteKey(key string) (string, string) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	tokens := strings.SplitN(key, routeKeySeparator, 2)
	if len(tokens) != 2 {
		glog.Errorf("Expected separator %q not found in route key %q", routeKeySeparator, key)
	}
	namespace := tokens[0]
	name := tokens[1]
	return namespace, name
}
func (r *templateRouter) createServiceAliasConfig(route *routev1.Route, backendKey string) *ServiceAliasConfig {
	_logClusterCodePath()
	defer _logClusterCodePath()
	wantsWildcardSupport := (route.Spec.WildcardPolicy == routev1.WildcardPolicySubdomain)
	wildcard := r.allowWildcardRoutes && wantsWildcardSupport
	serviceUnits := getServiceUnits(route)
	activeServiceUnits := 0
	for _, weight := range serviceUnits {
		if weight > 0 {
			activeServiceUnits++
		}
	}
	config := ServiceAliasConfig{Name: route.Name, Namespace: route.Namespace, Host: route.Spec.Host, Path: route.Spec.Path, IsWildcard: wildcard, Annotations: route.Annotations, ServiceUnits: serviceUnits, ActiveServiceUnits: activeServiceUnits}
	if route.Spec.Port != nil {
		config.PreferPort = route.Spec.Port.TargetPort.String()
	}
	key := fmt.Sprintf("%s %s", config.TLSTermination, backendKey)
	config.RoutingKeyName = fmt.Sprintf("%x", md5.Sum([]byte(key)))
	tls := route.Spec.TLS
	if tls != nil && len(tls.Termination) > 0 {
		config.TLSTermination = tls.Termination
		config.InsecureEdgeTerminationPolicy = tls.InsecureEdgeTerminationPolicy
		if tls.Termination == routev1.TLSTerminationReencrypt && len(tls.DestinationCACertificate) == 0 && len(r.defaultDestinationCAPath) > 0 {
			config.VerifyServiceHostname = true
		}
		if tls.Termination != routev1.TLSTerminationPassthrough {
			config.Certificates = make(map[string]Certificate)
			if len(tls.Certificate) > 0 {
				certKey := generateCertKey(&config)
				cert := Certificate{ID: backendKey, Contents: tls.Certificate, PrivateKey: tls.Key}
				config.Certificates[certKey] = cert
			}
			if len(tls.CACertificate) > 0 {
				caCertKey := generateCACertKey(&config)
				caCert := Certificate{ID: backendKey, Contents: tls.CACertificate}
				config.Certificates[caCertKey] = caCert
			}
			if len(tls.DestinationCACertificate) > 0 {
				destCertKey := generateDestCertKey(&config)
				destCert := Certificate{ID: backendKey, Contents: tls.DestinationCACertificate}
				config.Certificates[destCertKey] = destCert
			}
		}
	}
	return &config
}
func (r *templateRouter) AddRoute(route *routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	backendKey := routeKey(route)
	newConfig := r.createServiceAliasConfig(route, backendKey)
	r.lock.Lock()
	defer r.lock.Unlock()
	if existingConfig, exists := r.state[backendKey]; exists {
		if configsAreEqual(newConfig, &existingConfig) {
			return
		}
		glog.V(4).Infof("Updating route %s/%s", route.Namespace, route.Name)
		r.removeRouteInternal(route)
	} else {
		glog.V(4).Infof("Adding route %s/%s", route.Namespace, route.Name)
	}
	for key := range newConfig.ServiceUnits {
		if _, ok := r.findMatchingServiceUnit(key); !ok {
			glog.V(4).Infof("Creating new frontend for key: %v", key)
			r.createServiceUnitInternal(key)
		}
		r.addServiceAliasAssociation(key, backendKey)
	}
	configChanged := r.dynamicallyAddRoute(backendKey, route, newConfig)
	r.state[backendKey] = *newConfig
	r.stateChanged = true
	r.dynamicallyConfigured = r.dynamicallyConfigured && configChanged
}
func (r *templateRouter) RemoveRoute(route *routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.lock.Lock()
	defer r.lock.Unlock()
	r.removeRouteInternal(route)
}
func (r *templateRouter) removeRouteInternal(route *routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	backendKey := routeKey(route)
	serviceAliasConfig, ok := r.state[backendKey]
	if !ok {
		return
	}
	configChanged := r.dynamicallyRemoveRoute(backendKey, route)
	for key := range serviceAliasConfig.ServiceUnits {
		r.removeServiceAliasAssociation(key, backendKey)
	}
	r.cleanUpServiceAliasConfig(&serviceAliasConfig)
	delete(r.state, backendKey)
	r.stateChanged = true
	r.dynamicallyConfigured = r.dynamicallyConfigured && configChanged
}
func (r *templateRouter) numberOfEndpoints(id string) int32 {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var eps = 0
	svc, ok := r.findMatchingServiceUnit(id)
	if ok && len(svc.EndpointTable) > eps {
		eps = len(svc.EndpointTable)
	}
	return int32(eps)
}
func (r *templateRouter) AddEndpoints(id string, endpoints []Endpoint) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.lock.Lock()
	defer r.lock.Unlock()
	frontend, _ := r.findMatchingServiceUnit(id)
	if reflect.DeepEqual(frontend.EndpointTable, endpoints) {
		glog.V(4).Infof("Ignoring change for %s, endpoints are the same", id)
		return
	}
	oldEndpoints := frontend.EndpointTable
	frontend.EndpointTable = endpoints
	r.serviceUnits[id] = frontend
	configChanged := r.dynamicallyReplaceEndpoints(id, frontend, oldEndpoints)
	if id == r.peerEndpointsKey {
		r.peerEndpoints = frontend.EndpointTable
		glog.V(4).Infof("Peer endpoints updated to: %#v", r.peerEndpoints)
	}
	r.stateChanged = true
	r.dynamicallyConfigured = r.dynamicallyConfigured && configChanged
}
func (r *templateRouter) cleanUpServiceAliasConfig(cfg *ServiceAliasConfig) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	err := r.certManager.DeleteCertificatesForConfig(cfg)
	if err != nil {
		glog.Errorf("Error deleting certificates for route %s, the route will still be deleted but files may remain in the container: %v", cfg.Host, err)
	}
}
func cmpStrSlices(first []string, second []string) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(first) != len(second) {
		return false
	}
	for _, fi := range first {
		found := false
		for _, si := range second {
			if fi == si {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func (r *templateRouter) shouldWriteCerts(cfg *ServiceAliasConfig) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if cfg.Status == ServiceAliasConfigStatusSaved {
		return false
	}
	if cfg.Certificates == nil {
		return false
	}
	if cfg.TLSTermination == routev1.TLSTerminationEdge || cfg.TLSTermination == routev1.TLSTerminationReencrypt {
		if hasRequiredEdgeCerts(cfg) {
			return true
		}
		if cfg.TLSTermination == routev1.TLSTerminationReencrypt {
			if hasReencryptDestinationCACert(cfg) {
				glog.V(4).Infof("a reencrypt route with host %s does not have an edge certificate, using default router certificate", cfg.Host)
				return true
			}
			if len(r.defaultDestinationCAPath) > 0 {
				glog.V(4).Infof("a reencrypt route with host %s does not have a destination CA, using default destination CA", cfg.Host)
				return true
			}
		}
		msg := fmt.Sprintf("a %s terminated route with host %s does not have the required certificates.  The route will still be created but no certificates will be written", cfg.TLSTermination, cfg.Host)
		if len(r.defaultCertificatePath) > 0 {
			glog.V(4).Info(msg)
		} else {
			glog.Warning(msg)
		}
		return false
	}
	return false
}
func (r *templateRouter) HasRoute(route *routev1.Route) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.lock.Lock()
	defer r.lock.Unlock()
	key := routeKey(route)
	_, ok := r.state[key]
	return ok
}
func (r *templateRouter) SyncedAtLeastOnce() bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.synced
}
func hasRequiredEdgeCerts(cfg *ServiceAliasConfig) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	hostCert, ok := cfg.Certificates[cfg.Host]
	return ok && len(hostCert.Contents) > 0 && len(hostCert.PrivateKey) > 0
}
func hasReencryptDestinationCACert(cfg *ServiceAliasConfig) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	destCertKey := generateDestCertKey(cfg)
	destCACert, ok := cfg.Certificates[destCertKey]
	return ok && len(destCACert.Contents) > 0
}
func generateCertKey(config *ServiceAliasConfig) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return config.Host
}
func generateCACertKey(config *ServiceAliasConfig) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return config.Host + caCertPostfix
}
func generateDestCertKey(config *ServiceAliasConfig) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return config.Host + destCertPostfix
}
func getServiceUnits(route *routev1.Route) map[string]int32 {
	_logClusterCodePath()
	defer _logClusterCodePath()
	serviceUnits := make(map[string]int32)
	key := endpointsKeyFromParts(route.Namespace, route.Spec.To.Name)
	serviceUnits[key] = getServiceUnitWeight(route.Spec.To.Weight)
	for _, svc := range route.Spec.AlternateBackends {
		key = endpointsKeyFromParts(route.Namespace, svc.Name)
		serviceUnits[key] = getServiceUnitWeight(svc.Weight)
	}
	return serviceUnits
}
func getServiceUnitWeight(weightRef *int32) int32 {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var weight int32 = 1
	if weightRef != nil {
		weight = *weightRef
	}
	if weight < 0 {
		weight = 0
	} else if weight > 256 {
		weight = 256
	}
	return weight
}
func (r *templateRouter) getActiveEndpoints(serviceUnits map[string]int32) int {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var activeEndpoints int32 = 0
	for key, weight := range serviceUnits {
		if weight > 0 {
			activeEndpoints += r.numberOfEndpoints(key)
		}
	}
	return int(activeEndpoints)
}
func (r *templateRouter) calculateServiceWeights(serviceUnits map[string]int32) map[string]int32 {
	_logClusterCodePath()
	defer _logClusterCodePath()
	serviceUnitNames := make(map[string]int32)
	epWeight := make(map[string]float32)
	var maxEpWeight float32 = 0.0
	for key, units := range serviceUnits {
		numEp := r.numberOfEndpoints(key)
		if numEp > 0 {
			epWeight[key] = float32(units) / float32(numEp)
		}
		if epWeight[key] > maxEpWeight {
			maxEpWeight = epWeight[key]
		}
	}
	var scaleWeight float32 = 0.0
	if maxEpWeight > 0.0 {
		scaleWeight = 256.0 / maxEpWeight
	}
	for key, weight := range epWeight {
		serviceUnitNames[key] = int32(weight * scaleWeight)
		if weight > 0.0 && serviceUnitNames[key] < 1 {
			serviceUnitNames[key] = 1
			numEp := r.numberOfEndpoints(key)
			glog.V(4).Infof("%s: WARNING: Too many endpoints to achieve desired weight for route. Service can have %d but has %d endpoints", key, int32(weight*float32(numEp)), numEp)
		}
		glog.V(6).Infof("%s: weight %d  %f  %d", key, serviceUnits[key], weight, serviceUnitNames[key])
	}
	return serviceUnitNames
}
func configsAreEqual(config1, config2 *ServiceAliasConfig) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return config1.Name == config2.Name && config1.Namespace == config2.Namespace && config1.Host == config2.Host && config1.Path == config2.Path && config1.TLSTermination == config2.TLSTermination && reflect.DeepEqual(config1.Certificates, config2.Certificates) && config1.PreferPort == config2.PreferPort && config1.InsecureEdgeTerminationPolicy == config2.InsecureEdgeTerminationPolicy && config1.RoutingKeyName == config2.RoutingKeyName && config1.IsWildcard == config2.IsWildcard && config1.VerifyServiceHostname == config2.VerifyServiceHostname && reflect.DeepEqual(config1.Annotations, config2.Annotations) && reflect.DeepEqual(config1.ServiceUnits, config2.ServiceUnits)
}
func privateKeysFromPEM(pemCerts []byte) ([]byte, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	buf := &bytes.Buffer{}
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if len(block.Headers) != 0 {
			continue
		}
		switch block.Type {
		case "RSA PRIVATE KEY", "PRIVATE KEY", "ANY PRIVATE KEY", "DSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "EC PRIVATE KEY":
			if err := pem.Encode(buf, block); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}
