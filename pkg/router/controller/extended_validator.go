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

type ExtendedValidator struct {
	plugin		router.Plugin
	recorder	RejectionRecorder
}

func NewExtendedValidator(plugin router.Plugin, recorder RejectionRecorder) *ExtendedValidator {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &ExtendedValidator{plugin: plugin, recorder: recorder}
}
func (p *ExtendedValidator) HandleNode(eventType watch.EventType, node *kapi.Node) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return p.plugin.HandleNode(eventType, node)
}
func (p *ExtendedValidator) HandleEndpoints(eventType watch.EventType, endpoints *kapi.Endpoints) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return p.plugin.HandleEndpoints(eventType, endpoints)
}
func (p *ExtendedValidator) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	routeName := routeNameKey(route)
	if errs := routeapihelpers.ExtendedValidateRoute(route); len(errs) > 0 {
		errmsg := ""
		for i := 0; i < len(errs); i++ {
			errmsg = errmsg + "\n  - " + errs[i].Error()
		}
		glog.Errorf("Skipping route %s due to invalid configuration: %s", routeName, errmsg)
		p.recorder.RecordRouteRejection(route, "ExtendedValidationFailed", errmsg)
		p.plugin.HandleRoute(watch.Deleted, route)
		return fmt.Errorf("invalid route configuration")
	}
	return p.plugin.HandleRoute(eventType, route)
}
func (p *ExtendedValidator) HandleNamespaces(namespaces sets.String) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return p.plugin.HandleNamespaces(namespaces)
}
func (p *ExtendedValidator) Commit() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return p.plugin.Commit()
}
