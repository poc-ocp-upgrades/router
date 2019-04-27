package haproxy

import (
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	routev1 "github.com/openshift/api/route/v1"
	templaterouter "github.com/openshift/router/pkg/router/template"
)

type BlueprintPlugin struct{ manager templaterouter.ConfigManager }

func NewBlueprintPlugin(cm templaterouter.ConfigManager) *BlueprintPlugin {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &BlueprintPlugin{manager: cm}
}
func (p *BlueprintPlugin) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	switch eventType {
	case watch.Added, watch.Modified:
		return p.manager.AddBlueprint(route)
	case watch.Deleted:
		p.manager.RemoveBlueprint(route)
	}
	return nil
}
func (p *BlueprintPlugin) HandleNode(eventType watch.EventType, node *kapi.Node) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return nil
}
func (p *BlueprintPlugin) HandleEndpoints(eventType watch.EventType, endpoints *kapi.Endpoints) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return nil
}
func (p *BlueprintPlugin) HandleNamespaces(namespaces sets.String) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return nil
}
func (p *BlueprintPlugin) Commit() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return nil
}
