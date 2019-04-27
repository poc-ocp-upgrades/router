package factory

import (
	"fmt"
	"reflect"
	"sort"
	"time"
	"github.com/golang/glog"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	kclientset "k8s.io/client-go/kubernetes"
	kcache "k8s.io/client-go/tools/cache"
	routev1 "github.com/openshift/api/route/v1"
	projectclient "github.com/openshift/client-go/project/clientset/versioned/typed/project/v1"
	routeclientset "github.com/openshift/client-go/route/clientset/versioned"
	"github.com/openshift/router/pkg/router"
	routercontroller "github.com/openshift/router/pkg/router/controller"
	"github.com/openshift/router/pkg/router/routeapihelpers"
	informerfactory "k8s.io/client-go/informers"
)

const (
	DefaultResyncInterval = 30 * time.Minute
)

type RouterControllerFactory struct {
	KClient		kclientset.Interface
	RClient		routeclientset.Interface
	ProjectClient	projectclient.ProjectInterface
	ResyncInterval	time.Duration
	Namespace	string
	LabelSelector	string
	FieldSelector	string
	NamespaceLabels	labels.Selector
	ProjectLabels	labels.Selector
	RouteModifierFn	func(route *routev1.Route)
	informers	map[reflect.Type]kcache.SharedIndexInformer
}

func NewDefaultRouterControllerFactory(rc routeclientset.Interface, pc projectclient.ProjectInterface, kc kclientset.Interface) *RouterControllerFactory {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &RouterControllerFactory{KClient: kc, RClient: rc, ProjectClient: pc, ResyncInterval: DefaultResyncInterval, Namespace: v1.NamespaceAll, informers: map[reflect.Type]kcache.SharedIndexInformer{}}
}
func (f *RouterControllerFactory) Create(plugin router.Plugin, watchNodes bool) *routercontroller.RouterController {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	rc := &routercontroller.RouterController{Plugin: plugin, WatchNodes: watchNodes, NamespaceLabels: f.NamespaceLabels, FilteredNamespaceNames: make(sets.String), NamespaceRoutes: make(map[string]map[string]*routev1.Route), NamespaceEndpoints: make(map[string]map[string]*kapi.Endpoints), ProjectClient: f.ProjectClient, ProjectLabels: f.ProjectLabels, ProjectWaitInterval: 10 * time.Second, ProjectRetries: 5}
	if f.ResyncInterval > 10*time.Second {
		rc.ProjectSyncInterval = f.ResyncInterval - 10*time.Second
	} else {
		rc.ProjectSyncInterval = f.ResyncInterval
	}
	f.initInformers(rc)
	f.processExistingItems(rc)
	f.registerInformerEventHandlers(rc)
	return rc
}
func (f *RouterControllerFactory) initInformers(rc *routercontroller.RouterController) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if f.NamespaceLabels != nil {
		f.createNamespacesSharedInformer()
	}
	f.createEndpointsSharedInformer()
	f.CreateRoutesSharedInformer()
	if rc.WatchNodes {
		f.createNodesSharedInformer()
	}
	for _, informer := range f.informers {
		go informer.Run(utilwait.NeverStop)
	}
	for objType, informer := range f.informers {
		if !kcache.WaitForCacheSync(utilwait.NeverStop, informer.HasSynced) {
			utilruntime.HandleError(fmt.Errorf("failed to sync cache for %+v shared informer", objType))
		}
	}
}
func (f *RouterControllerFactory) registerInformerEventHandlers(rc *routercontroller.RouterController) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if f.NamespaceLabels != nil {
		f.registerSharedInformerEventHandlers(&kapi.Namespace{}, rc.HandleNamespace)
	}
	f.registerSharedInformerEventHandlers(&kapi.Endpoints{}, rc.HandleEndpoints)
	f.registerSharedInformerEventHandlers(&routev1.Route{}, rc.HandleRoute)
	if rc.WatchNodes {
		f.registerSharedInformerEventHandlers(&kapi.Node{}, rc.HandleNode)
	}
}
func (f *RouterControllerFactory) informerStoreList(obj runtime.Object) []interface{} {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	objType := reflect.TypeOf(obj)
	informer, ok := f.informers[objType]
	if !ok {
		utilruntime.HandleError(fmt.Errorf("listing items failed: %+v shared informer not found", objType))
		return []interface{}{obj}
	}
	return informer.GetStore().List()
}
func (f *RouterControllerFactory) processExistingItems(rc *routercontroller.RouterController) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if f.NamespaceLabels != nil {
		items := f.informerStoreList(&kapi.Namespace{})
		if len(items) == 0 {
			rc.UpdateNamespaces()
		} else {
			for _, item := range items {
				rc.HandleNamespace(watch.Added, item.(*kapi.Namespace))
			}
		}
	}
	for _, item := range f.informerStoreList(&kapi.Endpoints{}) {
		rc.HandleEndpoints(watch.Added, item.(*kapi.Endpoints))
	}
	items := []routev1.Route{}
	for _, item := range f.informerStoreList(&routev1.Route{}) {
		items = append(items, *(item.(*routev1.Route)))
	}
	sort.Sort(routeAge(items))
	for i := range items {
		rc.HandleRoute(watch.Added, &items[i])
	}
	if rc.WatchNodes {
		for _, item := range f.informerStoreList(&kapi.Node{}) {
			rc.HandleNode(watch.Added, item.(*kapi.Node))
		}
	}
}
func (f *RouterControllerFactory) setSelectors(options *v1.ListOptions) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	options.LabelSelector = f.LabelSelector
	options.FieldSelector = f.FieldSelector
}
func (f *RouterControllerFactory) createEndpointsSharedInformer() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	lw := &kcache.ListWatch{ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
		return f.KClient.Core().Endpoints(f.Namespace).List(options)
	}, WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
		return f.KClient.Core().Endpoints(f.Namespace).Watch(options)
	}}
	ep := &kapi.Endpoints{}
	objType := reflect.TypeOf(ep)
	indexers := kcache.Indexers{kcache.NamespaceIndex: kcache.MetaNamespaceIndexFunc}
	informer := kcache.NewSharedIndexInformer(lw, ep, f.ResyncInterval, indexers)
	f.informers[objType] = informer
}
func (f *RouterControllerFactory) CreateRoutesSharedInformer() kcache.SharedIndexInformer {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	rt := &routev1.Route{}
	objType := reflect.TypeOf(rt)
	if informer, ok := f.informers[objType]; ok {
		return informer
	}
	lw := &kcache.ListWatch{ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
		f.setSelectors(&options)
		routeList, err := f.RClient.Route().Routes(f.Namespace).List(options)
		if err != nil {
			return nil, err
		}
		if f.RouteModifierFn != nil {
			for i := range routeList.Items {
				f.RouteModifierFn(&routeList.Items[i])
			}
		}
		sort.Sort(routeAge(routeList.Items))
		return routeList, nil
	}, WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
		f.setSelectors(&options)
		w, err := f.RClient.Route().Routes(f.Namespace).Watch(options)
		if err != nil {
			return nil, err
		}
		if f.RouteModifierFn != nil {
			w = watch.Filter(w, func(in watch.Event) (watch.Event, bool) {
				if route, ok := in.Object.(*routev1.Route); ok {
					f.RouteModifierFn(route)
				}
				return in, true
			})
		}
		return w, nil
	}}
	indexers := kcache.Indexers{kcache.NamespaceIndex: kcache.MetaNamespaceIndexFunc}
	informer := kcache.NewSharedIndexInformer(lw, rt, f.ResyncInterval, indexers)
	f.informers[objType] = informer
	return informer
}
func (f *RouterControllerFactory) createNodesSharedInformer() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	ifactory := informerfactory.NewSharedInformerFactory(f.KClient, f.ResyncInterval)
	informer := ifactory.Core().V1().Nodes().Informer()
	objType := reflect.TypeOf(&kapi.Node{})
	f.informers[objType] = informer
}
func (f *RouterControllerFactory) createNamespacesSharedInformer() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	lw := &kcache.ListWatch{ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
		options.LabelSelector = f.NamespaceLabels.String()
		return f.KClient.Core().Namespaces().List(options)
	}, WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
		options.LabelSelector = f.NamespaceLabels.String()
		return f.KClient.Core().Namespaces().Watch(options)
	}}
	ns := &kapi.Namespace{}
	objType := reflect.TypeOf(ns)
	indexers := kcache.Indexers{kcache.NamespaceIndex: kcache.MetaNamespaceIndexFunc}
	informer := kcache.NewSharedIndexInformer(lw, ns, f.ResyncInterval, indexers)
	f.informers[objType] = informer
}
func (f *RouterControllerFactory) registerSharedInformerEventHandlers(obj runtime.Object, handleFunc func(watch.EventType, interface{})) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	objType := reflect.TypeOf(obj)
	informer, ok := f.informers[objType]
	if !ok {
		utilruntime.HandleError(fmt.Errorf("register event handler failed: %+v shared informer not found", objType))
		return
	}
	informer.AddEventHandler(kcache.ResourceEventHandlerFuncs{AddFunc: func(obj interface{}) {
		handleFunc(watch.Added, obj)
	}, UpdateFunc: func(_, obj interface{}) {
		handleFunc(watch.Modified, obj)
	}, DeleteFunc: func(obj interface{}) {
		if objType != reflect.TypeOf(obj) {
			tombstone, ok := obj.(kcache.DeletedFinalStateUnknown)
			if !ok {
				glog.Errorf("Couldn't get object from tombstone: %+v", obj)
				return
			}
			obj = tombstone.Obj
			if objType != reflect.TypeOf(obj) {
				glog.Errorf("Tombstone contained object that is not a %s: %+v", objType, obj)
				return
			}
		}
		handleFunc(watch.Deleted, obj)
	}})
}

type routeAge []routev1.Route

func (r routeAge) Len() int {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return len(r)
}
func (r routeAge) Swap(i, j int) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	r[i], r[j] = r[j], r[i]
}
func (r routeAge) Less(i, j int) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return routeapihelpers.RouteLessThan(&r[i], &r[j])
}
