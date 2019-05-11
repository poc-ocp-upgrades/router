package controller

import (
	"fmt"
	"strings"
	"github.com/golang/glog"
	kapi "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	kvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/watch"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/router/pkg/router"
	"github.com/openshift/router/pkg/router/controller/hostindex"
)

type RouteHostFunc func(*routev1.Route) string

func HostForRoute(route *routev1.Route) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return route.Spec.Host
}

type UniqueHost struct {
	plugin				router.Plugin
	recorder			RejectionRecorder
	allowedNamespaces	sets.String
	index				hostindex.Interface
}

func NewUniqueHost(plugin router.Plugin, disableOwnershipCheck bool, recorder RejectionRecorder) *UniqueHost {
	_logClusterCodePath()
	defer _logClusterCodePath()
	routeActivationFn := hostindex.SameNamespace
	if disableOwnershipCheck {
		routeActivationFn = hostindex.OldestFirst
	}
	return &UniqueHost{plugin: plugin, recorder: recorder, index: hostindex.New(routeActivationFn)}
}
func (p *UniqueHost) RoutesForHost(host string) ([]*routev1.Route, bool) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes, ok := p.index.RoutesForHost(host)
	return routes, ok
}
func (p *UniqueHost) HostLen() int {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return p.index.HostLen()
}
func (p *UniqueHost) HandleEndpoints(eventType watch.EventType, endpoints *kapi.Endpoints) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if p.allowedNamespaces != nil && !p.allowedNamespaces.Has(endpoints.Namespace) {
		return nil
	}
	return p.plugin.HandleEndpoints(eventType, endpoints)
}
func (p *UniqueHost) HandleNode(eventType watch.EventType, node *kapi.Node) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return p.plugin.HandleNode(eventType, node)
}
func (p *UniqueHost) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if p.allowedNamespaces != nil && !p.allowedNamespaces.Has(route.Namespace) {
		return nil
	}
	routeName := routeNameKey(route)
	host := route.Spec.Host
	if len(host) == 0 {
		glog.V(4).Infof("Route %s has no host value", routeName)
		p.recorder.RecordRouteRejection(route, "NoHostValue", "no host value was defined for the route")
		p.plugin.HandleRoute(watch.Deleted, route)
		return nil
	}
	if errs := ValidateHostName(route); len(errs) > 0 {
		glog.V(4).Infof("Route %s - invalid host name %s", routeName, host)
		errMessages := make([]string, len(errs))
		for i := 0; i < len(errs); i++ {
			errMessages[i] = errs[i].Error()
		}
		err := fmt.Errorf("host name validation errors: %s", strings.Join(errMessages, ", "))
		p.recorder.RecordRouteRejection(route, "InvalidHost", err.Error())
		p.plugin.HandleRoute(watch.Deleted, route)
		return err
	}
	switch eventType {
	case watch.Deleted:
		glog.V(4).Infof("Deleting route %s", routeName)
		changes := p.index.Remove(route)
		owner := "<unknown>"
		if old, ok := p.index.RoutesForHost(host); ok && len(old) > 0 {
			owner = old[0].Namespace
		}
		for _, other := range changes.GetActivated() {
			if err := p.plugin.HandleRoute(watch.Added, other); err != nil {
				utilruntime.HandleError(fmt.Errorf("unable to activate route %s/%s that was previously hidden by another route: %v", other.Namespace, other.Name, err))
			}
		}
		for _, other := range changes.GetDisplaced() {
			glog.V(4).Infof("route %s being deleted caused %s/%s to no longer be exposed", routeName, other.Namespace, other.Name)
			p.recorder.RecordRouteRejection(other, "HostAlreadyClaimed", fmt.Sprintf("namespace %s owns hostname %s", owner, host))
			if err := p.plugin.HandleRoute(watch.Deleted, other); err != nil {
				utilruntime.HandleError(fmt.Errorf("unable to clear route %s/%s that was previously exposed: %v", other.Namespace, other.Name, err))
			}
		}
		return p.plugin.HandleRoute(eventType, route)
	case watch.Added, watch.Modified:
		removed := false
		var nestedErr error
		changes, newRoute := p.index.Add(route)
		for _, other := range changes.GetActivated() {
			if other != route {
				if err := p.plugin.HandleRoute(watch.Added, other); err != nil {
					utilruntime.HandleError(fmt.Errorf("unable to activate route %s/%s that was previously hidden by another route: %v", other.Namespace, other.Name, err))
				}
				continue
			}
			nestedErr = p.plugin.HandleRoute(eventType, other)
		}
		for _, other := range changes.GetDisplaced() {
			if other != route {
				glog.V(4).Infof("route %s will replace path %s from %s because it is older", routeName, route.Spec.Path, other.Name)
				p.recorder.RecordRouteRejection(other, "HostAlreadyClaimed", fmt.Sprintf("replaced by older route %s", route.Name))
				if err := p.plugin.HandleRoute(watch.Deleted, other); err != nil {
					utilruntime.HandleError(fmt.Errorf("unable to clear route %s/%s that was previously exposed: %v", other.Namespace, other.Name, err))
				}
				continue
			}
			removed = true
			var owner *routev1.Route
			if old, ok := p.index.RoutesForHost(host); ok && len(old) > 0 {
				owner = old[0]
			} else {
				owner = &routev1.Route{}
				owner.Name = "<unknown>"
			}
			glog.V(4).Infof("Route %s cannot take %s from %s/%s", routeName, host, owner.Namespace, owner.Name)
			if owner.Namespace == route.Namespace {
				p.recorder.RecordRouteRejection(route, "HostAlreadyClaimed", fmt.Sprintf("route %s already exposes %s and is older", owner.Name, host))
			} else {
				p.recorder.RecordRouteRejection(route, "HostAlreadyClaimed", fmt.Sprintf("a route in another namespace holds %s and is older than %s", host, route.Name))
			}
			if !newRoute {
				if err := p.plugin.HandleRoute(watch.Deleted, route); err != nil {
					utilruntime.HandleError(fmt.Errorf("unable to clear route %s: %v", routeName, err))
				}
			}
		}
		if removed {
			return fmt.Errorf("another route has claimed this host")
		}
		return nestedErr
	default:
		return fmt.Errorf("unrecognized watch type: %v", eventType)
	}
}
func (p *UniqueHost) HandleNamespaces(namespaces sets.String) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	p.allowedNamespaces = namespaces
	p.index.Filter(func(route *routev1.Route) bool {
		return namespaces.Has(route.Namespace)
	})
	return p.plugin.HandleNamespaces(namespaces)
}
func (p *UniqueHost) Commit() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return p.plugin.Commit()
}
func routeNameKey(route *routev1.Route) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return fmt.Sprintf("%s/%s", route.Namespace, route.Name)
}
func ValidateHostName(route *routev1.Route) field.ErrorList {
	_logClusterCodePath()
	defer _logClusterCodePath()
	result := field.ErrorList{}
	if len(route.Spec.Host) < 1 {
		return result
	}
	specPath := field.NewPath("spec")
	hostPath := specPath.Child("host")
	if len(kvalidation.IsDNS1123Subdomain(route.Spec.Host)) != 0 {
		result = append(result, field.Invalid(hostPath, route.Spec.Host, "host must conform to DNS 952 subdomain conventions"))
	}
	segments := strings.Split(route.Spec.Host, ".")
	for _, s := range segments {
		errs := kvalidation.IsDNS1123Label(s)
		for _, e := range errs {
			result = append(result, field.Invalid(hostPath, route.Spec.Host, e))
		}
	}
	return result
}
