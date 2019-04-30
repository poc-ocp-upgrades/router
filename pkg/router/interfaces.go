package router

import (
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	routev1 "github.com/openshift/api/route/v1"
)

type Plugin interface {
	HandleRoute(watch.EventType, *routev1.Route) error
	HandleEndpoints(watch.EventType, *kapi.Endpoints) error
	HandleNamespaces(namespaces sets.String) error
	HandleNode(watch.EventType, *kapi.Node) error
	Commit() error
}
