package controller

import (
	"fmt"
	"sync"
	"time"
	"github.com/golang/glog"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	routev1 "github.com/openshift/api/route/v1"
	projectclient "github.com/openshift/client-go/project/clientset/versioned/typed/project/v1"
	"github.com/openshift/router/pkg/router"
)

type RouterController struct {
	lock			sync.Mutex
	Plugin			router.Plugin
	firstSyncDone		bool
	FilteredNamespaceNames	sets.String
	NamespaceLabels		labels.Selector
	NamespaceRoutes		map[string]map[string]*routev1.Route
	NamespaceEndpoints	map[string]map[string]*kapi.Endpoints
	ProjectClient		projectclient.ProjectInterface
	ProjectLabels		labels.Selector
	ProjectSyncInterval	time.Duration
	ProjectWaitInterval	time.Duration
	ProjectRetries		int
	WatchNodes		bool
}

func (c *RouterController) Run() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Info("Running router controller")
	if c.ProjectLabels != nil {
		c.HandleProjects()
		go utilwait.Forever(c.HandleProjects, c.ProjectSyncInterval)
	}
	c.handleFirstSync()
}
func (c *RouterController) HandleProjects() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	for i := 0; i < c.ProjectRetries; i++ {
		names, err := c.GetFilteredProjectNames()
		if err == nil {
			if names.Equal(c.FilteredNamespaceNames) {
				return
			}
			c.lock.Lock()
			defer c.lock.Unlock()
			c.FilteredNamespaceNames = names
			c.UpdateNamespaces()
			c.Commit()
			return
		}
		utilruntime.HandleError(fmt.Errorf("unable to get filtered projects for router: %v", err))
		time.Sleep(c.ProjectWaitInterval)
	}
	glog.V(4).Infof("Unable to update list of filtered projects")
}
func (c *RouterController) GetFilteredProjectNames() (sets.String, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	names := sets.String{}
	all, err := c.ProjectClient.List(v1.ListOptions{LabelSelector: c.ProjectLabels.String()})
	if err != nil {
		return nil, err
	}
	for _, item := range all.Items {
		names.Insert(item.Name)
	}
	return names, nil
}
func (c *RouterController) processNamespace(eventType watch.EventType, ns *kapi.Namespace) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	before := c.FilteredNamespaceNames.Has(ns.Name)
	switch eventType {
	case watch.Added, watch.Modified:
		if c.NamespaceLabels.Matches(labels.Set(ns.Labels)) {
			c.FilteredNamespaceNames.Insert(ns.Name)
		} else {
			c.FilteredNamespaceNames.Delete(ns.Name)
		}
	case watch.Deleted:
		c.FilteredNamespaceNames.Delete(ns.Name)
	}
	after := c.FilteredNamespaceNames.Has(ns.Name)
	if (!before && after) || (before && !after) {
		glog.V(5).Infof("Processing matched namespace: %s with labels: %v", ns.Name, ns.Labels)
		c.UpdateNamespaces()
		if !before && after {
			if epMap, ok := c.NamespaceEndpoints[ns.Name]; ok {
				for _, ep := range epMap {
					if err := c.Plugin.HandleEndpoints(watch.Modified, ep); err != nil {
						utilruntime.HandleError(err)
					}
				}
			}
			if routeMap, ok := c.NamespaceRoutes[ns.Name]; ok {
				for _, route := range routeMap {
					c.processRoute(watch.Modified, route)
				}
			}
		}
	}
}
func (c *RouterController) UpdateNamespaces() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	namespaces := sets.NewString(c.FilteredNamespaceNames.List()...)
	glog.V(4).Infof("Updating watched namespaces: %v", namespaces)
	if err := c.Plugin.HandleNamespaces(namespaces); err != nil {
		utilruntime.HandleError(err)
	}
}
func (c *RouterController) RecordNamespaceEndpoints(eventType watch.EventType, ep *kapi.Endpoints) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	switch eventType {
	case watch.Added, watch.Modified:
		if _, ok := c.NamespaceEndpoints[ep.Namespace]; !ok {
			c.NamespaceEndpoints[ep.Namespace] = make(map[string]*kapi.Endpoints)
		}
		c.NamespaceEndpoints[ep.Namespace][ep.Name] = ep
	case watch.Deleted:
		if _, ok := c.NamespaceEndpoints[ep.Namespace]; ok {
			delete(c.NamespaceEndpoints[ep.Namespace], ep.Name)
			if len(c.NamespaceEndpoints[ep.Namespace]) == 0 {
				delete(c.NamespaceEndpoints, ep.Namespace)
			}
		}
	}
}
func (c *RouterController) RecordNamespaceRoutes(eventType watch.EventType, rt *routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	switch eventType {
	case watch.Added, watch.Modified:
		if _, ok := c.NamespaceRoutes[rt.Namespace]; !ok {
			c.NamespaceRoutes[rt.Namespace] = make(map[string]*routev1.Route)
		}
		c.NamespaceRoutes[rt.Namespace][rt.Name] = rt
	case watch.Deleted:
		if _, ok := c.NamespaceRoutes[rt.Namespace]; ok {
			delete(c.NamespaceRoutes[rt.Namespace], rt.Name)
			if len(c.NamespaceRoutes[rt.Namespace]) == 0 {
				delete(c.NamespaceRoutes, rt.Namespace)
			}
		}
	}
}
func (c *RouterController) HandleNamespace(eventType watch.EventType, obj interface{}) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	ns := obj.(*kapi.Namespace)
	c.lock.Lock()
	defer c.lock.Unlock()
	glog.V(4).Infof("Processing Namespace: %s", ns.Name)
	glog.V(4).Infof("           Event: %s", eventType)
	c.processNamespace(eventType, ns)
	c.Commit()
}
func (c *RouterController) HandleNode(eventType watch.EventType, obj interface{}) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	node := obj.(*kapi.Node)
	c.lock.Lock()
	defer c.lock.Unlock()
	glog.V(4).Infof("Processing Node: %s", node.Name)
	glog.V(4).Infof("           Event: %s", eventType)
	if err := c.Plugin.HandleNode(eventType, node); err != nil {
		utilruntime.HandleError(err)
	}
}
func (c *RouterController) HandleRoute(eventType watch.EventType, obj interface{}) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	route := obj.(*routev1.Route)
	c.lock.Lock()
	defer c.lock.Unlock()
	c.processRoute(eventType, route)
	c.Commit()
}
func (c *RouterController) HandleEndpoints(eventType watch.EventType, obj interface{}) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	endpoints := obj.(*kapi.Endpoints)
	c.lock.Lock()
	defer c.lock.Unlock()
	c.RecordNamespaceEndpoints(eventType, endpoints)
	if err := c.Plugin.HandleEndpoints(eventType, endpoints); err != nil {
		utilruntime.HandleError(err)
	}
	c.Commit()
}
func (c *RouterController) Commit() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if c.firstSyncDone {
		if err := c.Plugin.Commit(); err != nil {
			utilruntime.HandleError(err)
		}
	}
}
func (c *RouterController) processRoute(eventType watch.EventType, route *routev1.Route) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Processing route: %s/%s -> %s %s", route.Namespace, route.Name, route.Spec.To.Name, route.UID)
	glog.V(4).Infof("           Alias: %s", route.Spec.Host)
	if len(route.Spec.Path) > 0 {
		glog.V(4).Infof("           Path: %s", route.Spec.Path)
	}
	glog.V(4).Infof("           Event: %s rv=%s", eventType, route.ResourceVersion)
	c.RecordNamespaceRoutes(eventType, route)
	if err := c.Plugin.HandleRoute(eventType, route); err != nil {
		utilruntime.HandleError(err)
	}
}
func (c *RouterController) handleFirstSync() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	c.lock.Lock()
	defer c.lock.Unlock()
	c.firstSyncDone = true
	glog.V(4).Infof("Router first sync complete")
	c.Commit()
}
