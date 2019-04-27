package f5

import (
	"fmt"
	"net"
	"github.com/golang/glog"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	routev1 "github.com/openshift/api/route/v1"
)

type F5Plugin struct {
	F5Client	*f5LTM
	VtepMap		map[types.UID]string
}
type F5PluginConfig struct {
	Host		string
	Username	string
	Password	string
	HttpVserver	string
	HttpsVserver	string
	PrivateKey	string
	Insecure	bool
	PartitionPath	string
	VxlanGateway	string
	InternalAddress	string
}

func NewF5Plugin(cfg F5PluginConfig) (*F5Plugin, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	f5LTMCfg := f5LTMCfg{host: cfg.Host, username: cfg.Username, password: cfg.Password, httpVserver: cfg.HttpVserver, httpsVserver: cfg.HttpsVserver, privkey: cfg.PrivateKey, insecure: cfg.Insecure, partitionPath: cfg.PartitionPath, vxlanGateway: cfg.VxlanGateway, internalAddress: cfg.InternalAddress}
	f5, err := newF5LTM(f5LTMCfg)
	if err != nil {
		return nil, err
	}
	return &F5Plugin{f5, map[types.UID]string{}}, f5.Initialize()
}
func (p *F5Plugin) ensurePoolExists(poolname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	poolExists, err := p.F5Client.PoolExists(poolname)
	if err != nil {
		glog.V(4).Infof("F5Client.PoolExists failed: %v", err)
		return err
	}
	if !poolExists {
		err = p.F5Client.CreatePool(poolname)
		if err != nil {
			glog.V(4).Infof("Error creating pool %s: %v", poolname, err)
			return err
		}
	}
	return nil
}
func (p *F5Plugin) updatePool(poolname string, endpoints *kapi.Endpoints) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	members, err := p.F5Client.GetPoolMembers(poolname)
	if err != nil {
		glog.V(4).Infof("F5Client.GetPoolMembers failed: %v", err)
		return err
	}
	needToDelete := map[string]bool{}
	for member := range members {
		if members[member] {
			needToDelete[member] = true
		}
	}
	for _, subset := range endpoints.Subsets {
		for _, addr := range subset.Addresses {
			for _, port := range subset.Ports {
				dest := fmt.Sprintf("%s:%d", addr.IP, port.Port)
				exists := needToDelete[dest]
				needToDelete[dest] = false
				if exists {
					glog.V(4).Infof("  Skipping %s because it already exists.", dest)
				} else {
					glog.V(4).Infof("  Adding %s...", dest)
					err = p.F5Client.AddPoolMember(poolname, dest)
					if err != nil {
						glog.V(4).Infof("  Error adding endpoint %s to pool %s: %v", dest, poolname, err)
					}
				}
			}
		}
	}
	for member := range needToDelete {
		if needToDelete[member] {
			glog.V(4).Infof("  Deleting %s...", member)
			err = p.F5Client.DeletePoolMember(poolname, member)
			if err != nil {
				glog.V(4).Infof("  Error deleting endpoint %s from pool %s: %v", member, poolname, err)
			}
		}
	}
	return nil
}
func (p *F5Plugin) deletePool(poolname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	poolExists, err := p.F5Client.PoolExists(poolname)
	if err != nil {
		glog.V(4).Infof("F5Client.PoolExists failed: %v", err)
		return err
	}
	if poolExists {
		err = p.F5Client.DeletePool(poolname)
		if err != nil {
			glog.V(4).Infof("Error deleting pool %s: %v", poolname, err)
			return err
		}
	}
	return nil
}
func (p *F5Plugin) deletePoolIfEmpty(poolname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	poolExists, err := p.F5Client.PoolExists(poolname)
	if err != nil {
		glog.V(4).Infof("F5Client.PoolExists failed: %v", err)
		return err
	}
	if poolExists {
		members, err := p.F5Client.GetPoolMembers(poolname)
		if err != nil {
			glog.V(4).Infof("F5Client.GetPoolMembers failed: %v", err)
			return err
		}
		if len(members) == 0 {
			err = p.F5Client.DeletePool(poolname)
			if err != nil {
				glog.V(4).Infof("Error deleting pool %s: %v", poolname, err)
				return err
			}
		}
	}
	return nil
}
func poolName(endpointsNamespace, endpointsName string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return fmt.Sprintf("openshift_%s_%s", endpointsNamespace, endpointsName)
}
func (p *F5Plugin) HandleEndpoints(eventType watch.EventType, endpoints *kapi.Endpoints) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Processing %d Endpoints for Name: %v (%v)", len(endpoints.Subsets), endpoints.Name, eventType)
	for i, s := range endpoints.Subsets {
		glog.V(4).Infof("  Subset %d : %#v", i, s)
	}
	switch eventType {
	case watch.Added, watch.Modified:
		poolname := poolName(endpoints.Namespace, endpoints.Name)
		if len(endpoints.Subsets) == 0 {
			glog.V(4).Infof("Deleting endpoints for pool %s", poolname)
			err := p.updatePool(poolname, endpoints)
			if err != nil {
				return err
			}
			glog.V(4).Infof("Deleting pool %s", poolname)
			err = p.deletePool(poolname)
			if err != nil {
				return err
			}
		} else {
			glog.V(4).Infof("Updating endpoints for pool %s", poolname)
			err := p.ensurePoolExists(poolname)
			if err != nil {
				return err
			}
			err = p.updatePool(poolname, endpoints)
			if err != nil {
				return err
			}
		}
	case watch.Deleted:
		poolname := poolName(endpoints.Namespace, endpoints.Name)
		endpoints.Subsets = nil
		err := p.updatePool(poolname, endpoints)
		if err != nil {
			return err
		}
		glog.V(4).Infof("Deleting pool %s", poolname)
		err = p.deletePool(poolname)
		if err != nil {
			return err
		}
	}
	glog.V(4).Infof("Done processing Endpoints for Name: %v.", endpoints.Name)
	return nil
}
func routeName(route routev1.Route) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return fmt.Sprintf("openshift_route_%s_%s", route.Namespace, route.Name)
}
func (p *F5Plugin) addRoute(routename, poolname, hostname, pathname string, tls *routev1.TLSConfig) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Adding route %s...", routename)
	prettyPathname := pathname
	if prettyPathname == "" {
		prettyPathname = "(any)"
	}
	if tls == nil || len(tls.Termination) == 0 {
		glog.V(4).Infof("Adding insecure route %s for pool %s,"+" hostname %s, pathname %s...", routename, poolname, hostname, prettyPathname)
		err := p.F5Client.AddInsecureRoute(routename, poolname, hostname, pathname)
		if err != nil {
			glog.V(4).Infof("Error adding insecure route for pool %s: %v", poolname, err)
			return err
		}
	} else if tls.Termination == routev1.TLSTerminationPassthrough {
		glog.V(4).Infof("Adding passthrough route %s for pool %s, hostname %s...", routename, poolname, hostname)
		err := p.F5Client.AddPassthroughRoute(routename, poolname, hostname)
		if err != nil {
			glog.V(4).Infof("Error adding passthrough route for pool %s: %v", poolname, err)
			return err
		}
	} else {
		glog.V(4).Infof("Adding secure route %s for pool %s,"+" hostname %s, pathname %s...", routename, poolname, hostname, prettyPathname)
		err := p.F5Client.AddSecureRoute(routename, poolname, hostname, prettyPathname)
		if err != nil {
			glog.V(4).Infof("Error adding secure route for pool %s: %v", poolname, err)
			return err
		}
		err = p.F5Client.AddCert(routename, hostname, tls.Certificate, tls.Key, tls.DestinationCACertificate)
		if err != nil {
			glog.V(4).Infof("Error adding TLS profile for route %s: %v", routename, err)
			return err
		}
		if tls.Termination == routev1.TLSTerminationReencrypt {
			glog.V(4).Infof("Adding re-encrypt route %s for pool %s,"+" hostname %s, pathname %s...", routename, poolname, hostname, prettyPathname)
			p.F5Client.AddReencryptRoute(routename, poolname, hostname)
		}
		if tls.Termination == routev1.TLSTerminationEdge && tls.InsecureEdgeTerminationPolicy == routev1.InsecureEdgeTerminationPolicyAllow {
			glog.V(4).Infof("Allowing insecure route %s for pool %s, hostname %s, pathname %s...", routename, poolname, hostname, prettyPathname)
			err := p.F5Client.AddInsecureRoute(routename, poolname, hostname, pathname)
			if err != nil {
				glog.V(4).Infof("Error allowing insecure route for pool %s: %v", poolname, err)
				return err
			}
		}
	}
	return nil
}
func (p *F5Plugin) deleteRoute(routename string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Deleting route %s...", routename)
	secureRouteExists, err := p.F5Client.SecureRouteExists(routename)
	if err != nil {
		glog.V(4).Infof("F5Client.SecureRouteExists failed: %v", err)
		return err
	}
	if secureRouteExists {
		glog.V(4).Infof("Deleting SSL profiles for secure route %s...", routename)
		err := p.F5Client.DeleteCert(routename)
		if err != nil {
			f5err, ok := err.(F5Error)
			if ok && f5err.httpStatusCode == 404 {
				glog.V(4).Infof("Secure route %s does not have TLS/SSL configured.", routename)
			} else {
				glog.V(4).Infof("Error deleting SSL profiles for secure route %s: %v", routename, err)
				return err
			}
		}
		glog.V(4).Infof("Deleting secure route %s...", routename)
		err = p.F5Client.DeleteSecureRoute(routename)
		if err != nil {
			f5err, ok := err.(F5Error)
			if ok && f5err.httpStatusCode == 404 {
				glog.V(4).Infof("Secure route for %s does not exist.", routename)
			} else {
				glog.V(4).Infof("Error deleting secure route %s: %v", routename, err)
				return err
			}
		}
	}
	insecureRouteExists, err := p.F5Client.InsecureRouteExists(routename)
	if err != nil {
		glog.V(4).Infof("F5Client.InsecureRouteExists failed: %v", err)
		return err
	}
	if insecureRouteExists {
		glog.V(4).Infof("Deleting insecure route %s...", routename)
		err := p.F5Client.DeleteInsecureRoute(routename)
		if err != nil {
			f5err, ok := err.(F5Error)
			if ok && f5err.httpStatusCode == 404 {
				glog.V(4).Infof("Insecure route for %s does not exist.", routename)
			} else {
				glog.V(4).Infof("Error deleting insecure route %s: %v", routename, err)
				return err
			}
		}
	}
	passthroughRouteExists, err := p.F5Client.PassthroughRouteExists(routename)
	if err != nil {
		glog.V(4).Infof("F5Client.PassthroughRouteExists failed: %v", err)
		return err
	}
	if passthroughRouteExists {
		err = p.F5Client.DeletePassthroughRoute(routename)
		if err != nil {
			f5err, ok := err.(F5Error)
			if ok && f5err.httpStatusCode == 404 {
				glog.V(4).Infof("Passthrough route %s does not exist.", routename)
			} else {
				glog.V(4).Infof("Error deleting passthrough route %s: %v", routename, err)
				return err
			}
		}
	} else {
		reencryptRouteExists, err := p.F5Client.ReencryptRouteExists(routename)
		if err != nil {
			glog.V(4).Infof("F5Client.ReencryptRouteExists failed: %v", err)
			return err
		}
		if reencryptRouteExists {
			err = p.F5Client.DeleteReencryptRoute(routename)
			if err != nil {
				f5err, ok := err.(F5Error)
				if ok && f5err.httpStatusCode == 404 {
					glog.V(4).Infof("Reencrypt route %s does not exist.", routename)
				} else {
					glog.V(4).Infof("Error deleting reencrypt route %s: %v", routename, err)
					return err
				}
			}
		}
	}
	return nil
}
func getNodeIP(node *kapi.Node) (string, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(node.Status.Addresses) > 0 && node.Status.Addresses[0].Address != "" {
		return node.Status.Addresses[0].Address, nil
	}
	return getNodeIPByName(node.Name)
}
func getNodeIPByName(nodeName string) (string, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	ip := net.ParseIP(nodeName)
	if ip == nil {
		addrs, err := net.LookupIP(nodeName)
		if err != nil {
			return "", fmt.Errorf("Failed to lookup IP address for node %s: %v", nodeName, err)
		}
		for _, addr := range addrs {
			if addr.IsLoopback() || addr.To4() == nil {
				glog.V(5).Infof("Skipping loopback/non-IPv4 addr: %q for node %s", addr.String(), nodeName)
				continue
			}
			ip = addr
			break
		}
	} else if ip.IsLoopback() || ip.To4() == nil {
		glog.V(5).Infof("Skipping loopback/non-IPv4 addr: %q for node %s", ip.String(), nodeName)
		ip = nil
	}
	if ip == nil || len(ip.String()) == 0 {
		return "", fmt.Errorf("Failed to obtain IP address from node name: %s", nodeName)
	}
	return ip.String(), nil
}
func (p *F5Plugin) HandleNamespaces(namespaces sets.String) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return fmt.Errorf("namespace limiting for F5 is not implemented")
}
func (p *F5Plugin) HandleNode(eventType watch.EventType, node *kapi.Node) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	switch eventType {
	case watch.Added, watch.Modified:
		ip, err := getNodeIP(node)
		if err != nil {
			glog.Warningf("Error in obtaining IP address of newly added node %s - %v", node.Name, err)
			return nil
		}
		uid := node.ObjectMeta.UID
		if oldNodeIP, ok := p.VtepMap[uid]; ok && (oldNodeIP == ip) {
			break
		}
		err = p.F5Client.AddVtep(ip)
		if err != nil {
			glog.Errorf("Error in adding node '%s' to F5s FDB - %v", ip, err)
			return err
		}
		p.VtepMap[uid] = ip
	case watch.Deleted:
		ip, err := getNodeIP(node)
		if err != nil {
			glog.Warningf("Error in obtaining IP address of deleted node %s - %v", node.Name, err)
			return nil
		}
		err = p.F5Client.RemoveVtep(ip)
		if err != nil {
			glog.Errorf("Error in removing node '%s' from F5s FDB - %v", ip, err)
			return err
		}
		uid := node.ObjectMeta.UID
		delete(p.VtepMap, uid)
	}
	return nil
}
func (p *F5Plugin) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Processing route for service: %v (%v)", route.Spec.To, route)
	poolname := poolName(route.Namespace, route.Spec.To.Name)
	hostname := route.Spec.Host
	pathname := route.Spec.Path
	routename := routeName(*route)
	switch eventType {
	case watch.Modified:
		glog.V(4).Infof("Updating route %s...", routename)
		err := p.deleteRoute(routename)
		if err != nil {
			return err
		}
		err = p.ensurePoolExists(poolname)
		if err != nil {
			return err
		}
		err = p.addRoute(routename, poolname, hostname, pathname, route.Spec.TLS)
		if err != nil {
			return err
		}
	case watch.Deleted:
		err := p.deleteRoute(routename)
		if err != nil {
			return err
		}
		err = p.deletePoolIfEmpty(poolname)
		if err != nil {
			return err
		}
	case watch.Added:
		err := p.ensurePoolExists(poolname)
		if err != nil {
			return err
		}
		err = p.addRoute(routename, poolname, hostname, pathname, route.Spec.TLS)
		if err != nil {
			return err
		}
	}
	glog.V(4).Infof("Done processing route %s.", routename)
	return nil
}
func (p *F5Plugin) Commit() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return nil
}
