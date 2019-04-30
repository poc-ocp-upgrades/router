package util

import (
	"fmt"
	"regexp"
	"strings"
	"github.com/golang/glog"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/router/pkg/router/routeapihelpers"
)

func GenerateRouteRegexp(hostname, path string, wildcard bool) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	hostRE := regexp.QuoteMeta(hostname)
	if wildcard {
		subdomain := routeapihelpers.GetDomainForHost(hostname)
		if len(subdomain) == 0 {
			glog.Warningf("Generating subdomain wildcard regexp - invalid host name %s", hostname)
		} else {
			subdomainRE := regexp.QuoteMeta(fmt.Sprintf(".%s", subdomain))
			hostRE = fmt.Sprintf(`[^\.]*%s`, subdomainRE)
		}
	}
	portRE := "(:[0-9]+)?"
	var pathRE, subpathRE string
	switch {
	case len(strings.TrimRight(path, "/")) == 0:
		pathRE = ""
		subpathRE = "(/.*)?"
	case strings.HasSuffix(path, "/"):
		pathRE = regexp.QuoteMeta(path)
		subpathRE = "(.*)?"
	default:
		pathRE = regexp.QuoteMeta(path)
		subpathRE = "(/.*)?"
	}
	return "^" + hostRE + portRE + pathRE + subpathRE + "$"
}
func GenCertificateHostName(hostname string, wildcard bool) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if wildcard {
		if idx := strings.IndexRune(hostname, '.'); idx > 0 {
			return fmt.Sprintf("*.%s", hostname[idx+1:])
		}
	}
	return hostname
}
func GenerateBackendNamePrefix(termination routev1.TLSTerminationType) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	prefix := "be_http"
	switch termination {
	case routev1.TLSTerminationEdge:
		prefix = "be_edge_http"
	case routev1.TLSTerminationReencrypt:
		prefix = "be_secure"
	case routev1.TLSTerminationPassthrough:
		prefix = "be_tcp"
	}
	return prefix
}
