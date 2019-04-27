package templaterouter

import (
	"crypto/md5"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
	"github.com/golang/glog"
	kapi "k8s.io/api/core/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	routev1 "github.com/openshift/api/route/v1"
	unidlingapi "github.com/openshift/router/pkg/router/unidling"
)

const (
	endpointsKeySeparator = "/"
)

type TemplatePlugin struct {
	Router		RouterInterface
	IncludeUDP	bool
	ServiceFetcher	ServiceLookup
}

func newDefaultTemplatePlugin(router RouterInterface, includeUDP bool, lookupSvc ServiceLookup) *TemplatePlugin {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &TemplatePlugin{Router: router, IncludeUDP: includeUDP, ServiceFetcher: lookupSvc}
}

type TemplatePluginConfig struct {
	WorkingDir			string
	TemplatePath			string
	ReloadScriptPath		string
	ReloadInterval			time.Duration
	ReloadCallbacks			[]func()
	DefaultCertificate		string
	DefaultCertificatePath		string
	DefaultCertificateDir		string
	DefaultDestinationCAPath	string
	StatsPort			int
	StatsUsername			string
	StatsPassword			string
	IncludeUDP			bool
	AllowWildcardRoutes		bool
	PeerService			*ktypes.NamespacedName
	BindPortsAfterSync		bool
	MaxConnections			string
	Ciphers				string
	StrictSNI			bool
	DynamicConfigManager		ConfigManager
}
type RouterInterface interface {
	SyncedAtLeastOnce() bool
	CreateServiceUnit(id string)
	FindServiceUnit(id string) (v ServiceUnit, ok bool)
	AddEndpoints(id string, endpoints []Endpoint)
	DeleteEndpoints(id string)
	AddRoute(route *routev1.Route)
	RemoveRoute(route *routev1.Route)
	HasRoute(route *routev1.Route) bool
	FilterNamespaces(namespaces sets.String)
	Commit()
}

func createTemplateWithHelper(t *template.Template) (*template.Template, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	funcMap := template.FuncMap{"generateHAProxyMap": func(data templateData) []string {
		return generateHAProxyMap(filepath.Base(t.Name()), data)
	}}
	clone, err := t.Clone()
	if err != nil {
		return nil, err
	}
	return clone.Funcs(funcMap), nil
}
func NewTemplatePlugin(cfg TemplatePluginConfig, lookupSvc ServiceLookup) (*TemplatePlugin, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	templateBaseName := filepath.Base(cfg.TemplatePath)
	masterTemplate, err := template.New("config").Funcs(helperFunctions).ParseFiles(cfg.TemplatePath)
	if err != nil {
		return nil, err
	}
	templates := map[string]*template.Template{}
	for _, template := range masterTemplate.Templates() {
		if template.Name() == templateBaseName {
			continue
		}
		templateWithHelper, err := createTemplateWithHelper(template)
		if err != nil {
			return nil, err
		}
		templates[template.Name()] = templateWithHelper
	}
	peerKey := ""
	if cfg.PeerService != nil {
		peerKey = peerEndpointsKey(*cfg.PeerService)
	}
	templateRouterCfg := templateRouterCfg{dir: cfg.WorkingDir, templates: templates, reloadScriptPath: cfg.ReloadScriptPath, reloadInterval: cfg.ReloadInterval, reloadCallbacks: cfg.ReloadCallbacks, defaultCertificate: cfg.DefaultCertificate, defaultCertificatePath: cfg.DefaultCertificatePath, defaultCertificateDir: cfg.DefaultCertificateDir, defaultDestinationCAPath: cfg.DefaultDestinationCAPath, statsUser: cfg.StatsUsername, statsPassword: cfg.StatsPassword, statsPort: cfg.StatsPort, allowWildcardRoutes: cfg.AllowWildcardRoutes, peerEndpointsKey: peerKey, bindPortsAfterSync: cfg.BindPortsAfterSync, dynamicConfigManager: cfg.DynamicConfigManager}
	router, err := newTemplateRouter(templateRouterCfg)
	return newDefaultTemplatePlugin(router, cfg.IncludeUDP, lookupSvc), err
}
func (p *TemplatePlugin) HandleEndpoints(eventType watch.EventType, endpoints *kapi.Endpoints) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	key := endpointsKey(endpoints)
	glog.V(4).Infof("Processing %d Endpoints for %s/%s (%v)", len(endpoints.Subsets), endpoints.Namespace, endpoints.Name, eventType)
	for i, s := range endpoints.Subsets {
		glog.V(4).Infof("  Subset %d : %#v", i, s)
	}
	if _, ok := p.Router.FindServiceUnit(key); !ok {
		p.Router.CreateServiceUnit(key)
	}
	switch eventType {
	case watch.Added, watch.Modified:
		glog.V(4).Infof("Modifying endpoints for %s", key)
		routerEndpoints := createRouterEndpoints(endpoints, !p.IncludeUDP, p.ServiceFetcher)
		key := endpointsKey(endpoints)
		p.Router.AddEndpoints(key, routerEndpoints)
	case watch.Deleted:
		glog.V(4).Infof("Deleting endpoints for %s", key)
		p.Router.DeleteEndpoints(key)
	}
	return nil
}
func (p *TemplatePlugin) HandleNode(eventType watch.EventType, node *kapi.Node) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return nil
}
func (p *TemplatePlugin) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	switch eventType {
	case watch.Added, watch.Modified:
		p.Router.AddRoute(route)
	case watch.Deleted:
		glog.V(4).Infof("Deleting route %s/%s", route.Namespace, route.Name)
		p.Router.RemoveRoute(route)
	}
	return nil
}
func (p *TemplatePlugin) HandleNamespaces(namespaces sets.String) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	p.Router.FilterNamespaces(namespaces)
	return nil
}
func (p *TemplatePlugin) Commit() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	p.Router.Commit()
	return nil
}
func endpointsKey(endpoints *kapi.Endpoints) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return endpointsKeyFromParts(endpoints.Namespace, endpoints.Name)
}
func endpointsKeyFromParts(namespace, name string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return fmt.Sprintf("%s%s%s", namespace, endpointsKeySeparator, name)
}
func getPartsFromEndpointsKey(key string) (string, string) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	tokens := strings.SplitN(key, endpointsKeySeparator, 2)
	if len(tokens) != 2 {
		glog.Errorf("Expected separator %q not found in endpoints key %q", endpointsKeySeparator, key)
	}
	namespace := tokens[0]
	name := tokens[1]
	return namespace, name
}
func peerEndpointsKey(namespacedName ktypes.NamespacedName) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return endpointsKeyFromParts(namespacedName.Namespace, namespacedName.Name)
}
func createRouterEndpoints(endpoints *kapi.Endpoints, excludeUDP bool, lookupSvc ServiceLookup) []Endpoint {
	_logClusterCodePath()
	defer _logClusterCodePath()
	wasIdled := false
	subsets := endpoints.Subsets
	if _, ok := endpoints.Annotations[unidlingapi.IdledAtAnnotation]; ok && len(endpoints.Subsets) == 0 {
		service, err := lookupSvc.LookupService(endpoints)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("unable to find idled service corresponding to idled endpoints %s/%s: %v", endpoints.Namespace, endpoints.Name, err))
			return []Endpoint{}
		}
		if !isServiceIPSet(service) {
			utilruntime.HandleError(fmt.Errorf("headless service %s/%s was marked as idled, but cannot setup unidling without a cluster IP", endpoints.Namespace, endpoints.Name))
			return []Endpoint{}
		}
		svcSubset := kapi.EndpointSubset{Addresses: []kapi.EndpointAddress{{IP: service.Spec.ClusterIP}}}
		for _, port := range service.Spec.Ports {
			endptPort := kapi.EndpointPort{Name: port.Name, Port: port.Port, Protocol: port.Protocol}
			svcSubset.Ports = append(svcSubset.Ports, endptPort)
		}
		subsets = []kapi.EndpointSubset{svcSubset}
		wasIdled = true
	}
	out := make([]Endpoint, 0, len(endpoints.Subsets)*4)
	for _, s := range subsets {
		for _, p := range s.Ports {
			if excludeUDP && p.Protocol == kapi.ProtocolUDP {
				continue
			}
			for _, a := range s.Addresses {
				ep := Endpoint{IP: a.IP, Port: strconv.Itoa(int(p.Port)), PortName: p.Name, NoHealthCheck: wasIdled}
				if a.TargetRef != nil {
					ep.TargetName = a.TargetRef.Name
					if a.TargetRef.Kind == "Pod" {
						ep.ID = fmt.Sprintf("pod:%s:%s:%s:%d", ep.TargetName, endpoints.Name, a.IP, p.Port)
					} else {
						ep.ID = fmt.Sprintf("ept:%s:%s:%d", endpoints.Name, a.IP, p.Port)
					}
				} else {
					ep.TargetName = ep.IP
					ep.ID = fmt.Sprintf("ept:%s:%s:%d", endpoints.Name, a.IP, p.Port)
				}
				s := ep.ID
				ep.IdHash = fmt.Sprintf("%x", md5.Sum([]byte(s)))
				out = append(out, ep)
			}
		}
	}
	return out
}
func isServiceIPSet(service *kapi.Service) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return service.Spec.ClusterIP != kapi.ClusterIPNone && service.Spec.ClusterIP != ""
}
