package controller

import (
	"fmt"
	"github.com/golang/glog"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/router/pkg/router"
	"github.com/openshift/router/pkg/router/routeapihelpers"
)

type RouteAdmissionFunc func(*routev1.Route) error
type RouteMap map[string][]*routev1.Route

func (srm RouteMap) RemoveRoute(key string, route *routev1.Route) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	k := 0
	removed := false
	m := srm[key]
	for i, v := range m {
		if m[i].Namespace == route.Namespace && m[i].Name == route.Name {
			removed = true
		} else {
			m[k] = v
			k++
		}
	}
	m = m[:k]
	if len(m) > 0 {
		srm[key] = m
	} else {
		delete(srm, key)
	}
	return removed
}
func (srm RouteMap) InsertRoute(key string, route *routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	srm.RemoveRoute(key, route)
	m := srm[key]
	for idx := range m {
		if routeapihelpers.RouteLessThan(route, m[idx]) {
			m = append(m, &routev1.Route{})
			copy(m[idx+1:], m[idx:])
			m[idx] = route
			srm[key] = m
			return
		}
	}
	srm[key] = append(m, route)
}

type HostAdmitter struct {
	plugin			router.Plugin
	admitter		RouteAdmissionFunc
	recorder		RejectionRecorder
	allowWildcardRoutes	bool
	disableNamespaceCheck	bool
	allowedNamespaces	sets.String
	claimedHosts		RouteMap
	claimedWildcards	RouteMap
	blockedWildcards	RouteMap
}

func NewHostAdmitter(plugin router.Plugin, fn RouteAdmissionFunc, allowWildcards, disableNamespaceCheck bool, recorder RejectionRecorder) *HostAdmitter {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &HostAdmitter{plugin: plugin, admitter: fn, recorder: recorder, allowWildcardRoutes: allowWildcards, disableNamespaceCheck: disableNamespaceCheck, claimedHosts: RouteMap{}, claimedWildcards: RouteMap{}, blockedWildcards: RouteMap{}}
}
func (p *HostAdmitter) HandleNode(eventType watch.EventType, node *kapi.Node) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return p.plugin.HandleNode(eventType, node)
}
func (p *HostAdmitter) HandleEndpoints(eventType watch.EventType, endpoints *kapi.Endpoints) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return p.plugin.HandleEndpoints(eventType, endpoints)
}
func (p *HostAdmitter) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if p.allowedNamespaces != nil && !p.allowedNamespaces.Has(route.Namespace) {
		return nil
	}
	if err := p.admitter(route); err != nil {
		glog.V(4).Infof("Route %s not admitted: %s", routeNameKey(route), err.Error())
		p.recorder.RecordRouteRejection(route, "RouteNotAdmitted", err.Error())
		p.plugin.HandleRoute(watch.Deleted, route)
		return err
	}
	if p.allowWildcardRoutes && len(route.Spec.Host) > 0 {
		switch eventType {
		case watch.Added, watch.Modified:
			if err := p.addRoute(route); err != nil {
				glog.Errorf("Route %s not admitted: %s", routeNameKey(route), err.Error())
				return err
			}
		case watch.Deleted:
			p.claimedHosts.RemoveRoute(route.Spec.Host, route)
			wildcardKey := routeapihelpers.GetDomainForHost(route.Spec.Host)
			p.claimedWildcards.RemoveRoute(wildcardKey, route)
			p.blockedWildcards.RemoveRoute(wildcardKey, route)
		}
	}
	return p.plugin.HandleRoute(eventType, route)
}
func (p *HostAdmitter) HandleNamespaces(namespaces sets.String) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	p.allowedNamespaces = namespaces
	return p.plugin.HandleNamespaces(namespaces)
}
func (p *HostAdmitter) Commit() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return p.plugin.Commit()
}
func (p *HostAdmitter) addRoute(route *routev1.Route) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	displacedRoutes, err, ownerNamespace := p.displacedRoutes(route)
	if err != nil {
		msg := fmt.Sprintf("a route in another namespace holds host %s", route.Spec.Host)
		if ownerNamespace == route.Namespace {
			msg = err.Error()
		}
		p.recorder.RecordRouteRejection(route, "HostAlreadyClaimed", msg)
		return err
	}
	for _, displacedRoute := range displacedRoutes {
		wildcardKey := routeapihelpers.GetDomainForHost(displacedRoute.Spec.Host)
		p.claimedHosts.RemoveRoute(displacedRoute.Spec.Host, displacedRoute)
		p.blockedWildcards.RemoveRoute(wildcardKey, displacedRoute)
		p.claimedWildcards.RemoveRoute(wildcardKey, displacedRoute)
		msg := ""
		if route.Namespace == displacedRoute.Namespace {
			if route.Spec.WildcardPolicy == routev1.WildcardPolicySubdomain {
				msg = fmt.Sprintf("wildcard route %s/%s has host *.%s blocking %s", route.Namespace, route.Name, wildcardKey, displacedRoute.Spec.Host)
			} else {
				msg = fmt.Sprintf("route %s/%s has host %s, blocking %s", route.Namespace, route.Name, route.Spec.Host, displacedRoute.Spec.Host)
			}
		} else {
			msg = fmt.Sprintf("a route in another namespace holds host %s", displacedRoute.Spec.Host)
		}
		p.recorder.RecordRouteRejection(displacedRoute, "HostAlreadyClaimed", msg)
		p.plugin.HandleRoute(watch.Deleted, displacedRoute)
	}
	if len(route.Spec.WildcardPolicy) == 0 {
		route.Spec.WildcardPolicy = routev1.WildcardPolicyNone
	}
	wildcardKey := routeapihelpers.GetDomainForHost(route.Spec.Host)
	switch route.Spec.WildcardPolicy {
	case routev1.WildcardPolicyNone:
		p.claimedHosts.InsertRoute(route.Spec.Host, route)
		p.blockedWildcards.InsertRoute(wildcardKey, route)
		p.claimedWildcards.RemoveRoute(wildcardKey, route)
	case routev1.WildcardPolicySubdomain:
		p.claimedWildcards.InsertRoute(wildcardKey, route)
		p.claimedHosts.RemoveRoute(route.Spec.Host, route)
		p.blockedWildcards.RemoveRoute(wildcardKey, route)
	default:
		p.claimedHosts.RemoveRoute(route.Spec.Host, route)
		p.claimedWildcards.RemoveRoute(wildcardKey, route)
		p.blockedWildcards.RemoveRoute(wildcardKey, route)
		err := fmt.Errorf("unsupported wildcard policy %s", route.Spec.WildcardPolicy)
		p.recorder.RecordRouteRejection(route, "RouteNotAdmitted", err.Error())
		return err
	}
	return nil
}
func (p *HostAdmitter) displacedRoutes(newRoute *routev1.Route) ([]*routev1.Route, error, string) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	displaced := []*routev1.Route{}
	for i, route := range p.claimedHosts[newRoute.Spec.Host] {
		if p.disableNamespaceCheck || route.Namespace == newRoute.Namespace {
			if route.UID == newRoute.UID {
				continue
			}
			if newRoute.Spec.WildcardPolicy == routev1.WildcardPolicySubdomain {
				continue
			}
			if route.Spec.Path != newRoute.Spec.Path {
				continue
			}
		}
		if routeapihelpers.RouteLessThan(route, newRoute) {
			return nil, fmt.Errorf("route %s/%s has host %s", route.Namespace, route.Name, route.Spec.Host), route.Namespace
		}
		displaced = append(displaced, p.claimedHosts[newRoute.Spec.Host][i])
	}
	wildcardKey := routeapihelpers.GetDomainForHost(newRoute.Spec.Host)
	for i, route := range p.claimedWildcards[wildcardKey] {
		if p.disableNamespaceCheck || route.Namespace == newRoute.Namespace {
			if route.UID == newRoute.UID {
				continue
			}
			if newRoute.Spec.WildcardPolicy != routev1.WildcardPolicySubdomain {
				continue
			}
			if route.Spec.Path != newRoute.Spec.Path {
				continue
			}
		}
		if routeapihelpers.RouteLessThan(route, newRoute) {
			return nil, fmt.Errorf("wildcard route %s/%s has host *.%s, blocking %s", route.Namespace, route.Name, wildcardKey, newRoute.Spec.Host), route.Namespace
		}
		displaced = append(displaced, p.claimedWildcards[wildcardKey][i])
	}
	if newRoute.Spec.WildcardPolicy == routev1.WildcardPolicySubdomain {
		for i, route := range p.blockedWildcards[wildcardKey] {
			if p.disableNamespaceCheck || route.Namespace == newRoute.Namespace {
				continue
			}
			if routeapihelpers.RouteLessThan(route, newRoute) {
				return nil, fmt.Errorf("route %s/%s has host %s, blocking *.%s", route.Namespace, route.Name, route.Spec.Host, wildcardKey), route.Namespace
			}
			displaced = append(displaced, p.blockedWildcards[wildcardKey][i])
		}
	}
	return displaced, nil, newRoute.Namespace
}
