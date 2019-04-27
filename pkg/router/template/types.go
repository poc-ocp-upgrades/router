package templaterouter

import (
	"strings"
	"time"
	routev1 "github.com/openshift/api/route/v1"
)

type ServiceUnit struct {
	Name				string
	Hostname			string
	EndpointTable			[]Endpoint
	ServiceAliasAssociations	map[string]bool
}
type ServiceAliasConfig struct {
	Name				string
	Namespace			string
	Host				string
	Path				string
	TLSTermination			routev1.TLSTerminationType
	Certificates			map[string]Certificate
	VerifyServiceHostname		bool
	Status				ServiceAliasConfigStatus
	PreferPort			string
	InsecureEdgeTerminationPolicy	routev1.InsecureEdgeTerminationPolicyType
	RoutingKeyName			string
	IsWildcard			bool
	Annotations			map[string]string
	ServiceUnits			map[string]int32
	ServiceUnitNames		map[string]int32
	ActiveServiceUnits		int
	ActiveEndpoints			int
}
type ServiceAliasConfigStatus string

const (
	ServiceAliasConfigStatusSaved ServiceAliasConfigStatus = "saved"
)

type Certificate struct {
	ID		string
	Contents	string
	PrivateKey	string
}
type Endpoint struct {
	ID		string
	IP		string
	Port		string
	TargetName	string
	PortName	string
	IdHash		string
	NoHealthCheck	bool
}
type certificateManager interface {
	WriteCertificatesForConfig(config *ServiceAliasConfig) error
	DeleteCertificatesForConfig(config *ServiceAliasConfig) error
	Commit() error
	CertificateWriter() certificateWriter
}
type certificateManagerConfig struct {
	certKeyFunc	certificateKeyFunc
	caCertKeyFunc	certificateKeyFunc
	destCertKeyFunc	certificateKeyFunc
	certDir		string
	caCertDir	string
}
type certificateKeyFunc func(config *ServiceAliasConfig) string
type certificateWriter interface {
	WriteCertificate(directory string, id string, cert []byte) error
	DeleteCertificate(directory, id string) error
}
type ConfigManagerOptions struct {
	ConnectionInfo		string
	CommitInterval		time.Duration
	BlueprintRoutes		[]*routev1.Route
	BlueprintRoutePoolSize	int
	MaxDynamicServers	int
	WildcardRoutesAllowed	bool
	ExtendedValidation	bool
}
type ConfigManager interface {
	Initialize(router RouterInterface, certPath string)
	AddBlueprint(route *routev1.Route) error
	RemoveBlueprint(route *routev1.Route)
	Register(id string, route *routev1.Route)
	AddRoute(id, routingKey string, route *routev1.Route) error
	RemoveRoute(id string, route *routev1.Route) error
	ReplaceRouteEndpoints(id string, oldEndpoints, newEndpoints []Endpoint, weight int32) error
	RemoveRouteEndpoints(id string, endpoints []Endpoint) error
	Notify(event RouterEventType)
	ServerTemplateName(id string) string
	ServerTemplateSize(id string) string
	GenerateDynamicServerNames(id string) []string
}
type RouterEventType string

const (
	RouterEventReloadStart	= "reload-start"
	RouterEventReloadEnd	= "reload-end"
	RouterEventReloadError	= "reload-error"
)

func (s ServiceUnit) TemplateSafeName() string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return strings.Replace(s.Name, "/", "-", -1)
}
