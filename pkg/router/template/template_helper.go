package templaterouter

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"github.com/golang/glog"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/router/pkg/router/routeapihelpers"
	templateutil "github.com/openshift/router/pkg/router/template/util"
	haproxyutil "github.com/openshift/router/pkg/router/template/util/haproxy"
)

const (
	certConfigMap = "cert_config.map"
)

func isTrue(s string) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	v, _ := strconv.ParseBool(s)
	return v
}
func firstMatch(pattern string, values ...string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(7).Infof("firstMatch called with %s and %v", pattern, values)
	if re, err := regexp.Compile(`\A(?:` + pattern + `)\z`); err == nil {
		for _, value := range values {
			if re.MatchString(value) {
				glog.V(7).Infof("firstMatch returning string: %s", value)
				return value
			}
		}
		glog.V(7).Infof("firstMatch returning empty string")
	} else {
		glog.Errorf("Error with regex pattern in call to firstMatch: %v", err)
	}
	return ""
}
func env(name string, defaults ...string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if envValue := os.Getenv(name); envValue != "" {
		return envValue
	}
	for _, val := range defaults {
		if val != "" {
			return val
		}
	}
	return ""
}
func isInteger(s string) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_, err := strconv.Atoi(s)
	return (err == nil)
}
func matchValues(s string, allowedValues ...string) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(7).Infof("matchValues called with %s and %v", s, allowedValues)
	for _, value := range allowedValues {
		if value == s {
			glog.V(7).Infof("matchValues finds matching string: %s", s)
			return true
		}
	}
	glog.V(7).Infof("matchValues cannot match string: %s", s)
	return false
}
func matchPattern(pattern, s string) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(7).Infof("matchPattern called with %s and %s", pattern, s)
	status, err := regexp.MatchString(`\A(?:`+pattern+`)\z`, s)
	if err == nil {
		glog.V(7).Infof("matchPattern returning status: %v", status)
		return status
	}
	glog.Errorf("Error with regex pattern in call to matchPattern: %v", err)
	return false
}
func genSubdomainWildcardRegexp(hostname, path string, exactPath bool) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	subdomain := routeapihelpers.GetDomainForHost(hostname)
	if len(subdomain) == 0 {
		glog.Warningf("Generating subdomain wildcard regexp - invalid host name %s", hostname)
		return fmt.Sprintf("%s%s", hostname, path)
	}
	expr := regexp.QuoteMeta(fmt.Sprintf(".%s%s", subdomain, path))
	if exactPath {
		return fmt.Sprintf(`^[^\.]*%s$`, expr)
	}
	return fmt.Sprintf(`^[^\.]*%s(|/.*)$`, expr)
}
func generateRouteRegexp(hostname, path string, wildcard bool) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return templateutil.GenerateRouteRegexp(hostname, path, wildcard)
}
func genCertificateHostName(hostname string, wildcard bool) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return templateutil.GenCertificateHostName(hostname, wildcard)
}
func processEndpointsForAlias(alias ServiceAliasConfig, svc ServiceUnit, action string) []Endpoint {
	_logClusterCodePath()
	defer _logClusterCodePath()
	endpoints := endpointsForAlias(alias, svc)
	if strings.ToLower(action) == "shuffle" {
		for i := len(endpoints) - 1; i >= 0; i-- {
			rIndex := rand.Intn(i + 1)
			endpoints[i], endpoints[rIndex] = endpoints[rIndex], endpoints[i]
		}
	}
	return endpoints
}
func endpointsForAlias(alias ServiceAliasConfig, svc ServiceUnit) []Endpoint {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(alias.PreferPort) == 0 {
		return svc.EndpointTable
	}
	endpoints := make([]Endpoint, 0, len(svc.EndpointTable))
	for i := range svc.EndpointTable {
		endpoint := svc.EndpointTable[i]
		if endpoint.PortName == alias.PreferPort || endpoint.Port == alias.PreferPort {
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints
}
func backendConfig(name string, cfg ServiceAliasConfig, hascert bool) *haproxyutil.BackendConfig {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &haproxyutil.BackendConfig{Name: name, Host: cfg.Host, Path: cfg.Path, IsWildcard: cfg.IsWildcard, Termination: cfg.TLSTermination, InsecurePolicy: cfg.InsecureEdgeTerminationPolicy, HasCertificate: hascert}
}
func generateHAProxyCertConfigMap(td templateData) []string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	lines := make([]string, 0)
	for k, cfg := range td.State {
		hascert := false
		if len(cfg.Host) > 0 {
			cert, ok := cfg.Certificates[cfg.Host]
			hascert = ok && len(cert.Contents) > 0
		}
		backendConfig := backendConfig(k, cfg, hascert)
		if entry := haproxyutil.GenerateMapEntry(certConfigMap, backendConfig); entry != nil {
			fqCertPath := path.Join(td.WorkingDir, "certs", entry.Key)
			lines = append(lines, fmt.Sprintf("%s %s", fqCertPath, entry.Value))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(lines)))
	return lines
}
func validateHAProxyWhiteList(value string) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_, valid := haproxyutil.ValidateWhiteList(value)
	return valid
}
func generateHAProxyWhiteListFile(workingDir, id, value string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	name := path.Join(workingDir, "whitelists", fmt.Sprintf("%s.txt", id))
	cidrs, _ := haproxyutil.ValidateWhiteList(value)
	data := []byte(strings.Join(cidrs, "\n") + "\n")
	if err := ioutil.WriteFile(name, data, 0644); err != nil {
		glog.Errorf("Error writing haproxy whitelist contents: %v", err)
		return ""
	}
	return name
}
func getHTTPAliasesGroupedByHost(aliases map[string]ServiceAliasConfig) map[string]map[string]ServiceAliasConfig {
	_logClusterCodePath()
	defer _logClusterCodePath()
	result := make(map[string]map[string]ServiceAliasConfig)
	for k, a := range aliases {
		if a.TLSTermination == routev1.TLSTerminationPassthrough {
			continue
		}
		if _, exists := result[a.Host]; !exists {
			result[a.Host] = make(map[string]ServiceAliasConfig)
		}
		result[a.Host][k] = a
	}
	return result
}
func getPrimaryAliasKey(aliases map[string]ServiceAliasConfig) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(aliases) == 0 {
		return ""
	}
	if len(aliases) == 1 {
		for k := range aliases {
			return k
		}
	}
	keys := make([]string, len(aliases))
	for k := range aliases {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, k := range keys {
		if aliases[k].TLSTermination == routev1.TLSTerminationEdge || aliases[k].TLSTermination == routev1.TLSTerminationReencrypt {
			return k
		}
	}
	return keys[0]
}
func generateHAProxyMap(name string, td templateData) []string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if name == certConfigMap {
		return generateHAProxyCertConfigMap(td)
	}
	lines := make([]string, 0)
	for k, cfg := range td.State {
		backendConfig := backendConfig(k, cfg, false)
		if entry := haproxyutil.GenerateMapEntry(name, backendConfig); entry != nil {
			lines = append(lines, fmt.Sprintf("%s %s", entry.Key, entry.Value))
		}
	}
	return templateutil.SortMapPaths(lines, `^[^\.]*\.`)
}

var helperFunctions = template.FuncMap{"endpointsForAlias": endpointsForAlias, "processEndpointsForAlias": processEndpointsForAlias, "env": env, "matchPattern": matchPattern, "isInteger": isInteger, "matchValues": matchValues, "genSubdomainWildcardRegexp": genSubdomainWildcardRegexp, "generateRouteRegexp": generateRouteRegexp, "genCertificateHostName": genCertificateHostName, "genBackendNamePrefix": templateutil.GenerateBackendNamePrefix, "isTrue": isTrue, "firstMatch": firstMatch, "getHTTPAliasesGroupedByHost": getHTTPAliasesGroupedByHost, "getPrimaryAliasKey": getPrimaryAliasKey, "generateHAProxyMap": generateHAProxyMap, "validateHAProxyWhiteList": validateHAProxyWhiteList, "generateHAProxyWhiteListFile": generateHAProxyWhiteListFile}
