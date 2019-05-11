package router

import (
	"errors"
	"fmt"
	"os"
	"time"
	"github.com/MakeNowJust/heredoc"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/pkg/version"
	routev1 "github.com/openshift/api/route/v1"
	projectclient "github.com/openshift/client-go/project/clientset/versioned"
	routeclientset "github.com/openshift/client-go/route/clientset/versioned"
	routelisters "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/router/pkg/router"
	"github.com/openshift/router/pkg/router/controller"
	f5plugin "github.com/openshift/router/pkg/router/f5"
	"github.com/openshift/router/pkg/router/writerlease"
)

var f5Long = heredoc.Doc(`
		Start an F5 route synchronizer

		This command launches a process that will synchronize an F5 to the route configuration of your master.

		You may restrict the set of routes exposed to a single project (with --namespace), projects your client has
		access to with a set of labels (--project-labels), namespaces matching a label (--namespace-labels), or all
		namespaces (no argument). You can limit the routes to those matching a --labels or --fields selector. Note
		that you must have a cluster-wide administrative role to view all namespaces.`)

type F5RouterOptions struct {
	Config	*Config
	F5Router
	RouterSelection
}
type F5Router struct {
	Host			string
	Username		string
	Password		string
	HttpVserver		string
	HttpsVserver	string
	PrivateKey		string
	Insecure		bool
	PartitionPath	string
	VxlanGateway	string
	InternalAddress	string
}

func (o *F5Router) Bind(flag *pflag.FlagSet) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	flag.StringVar(&o.Host, "f5-host", env("ROUTER_EXTERNAL_HOST_HOSTNAME", ""), "The host of F5 BIG-IP's management interface")
	flag.StringVar(&o.Username, "f5-username", env("ROUTER_EXTERNAL_HOST_USERNAME", ""), "The username for F5 BIG-IP's management utility")
	flag.StringVar(&o.Password, "f5-password", env("ROUTER_EXTERNAL_HOST_PASSWORD", ""), "The password for F5 BIG-IP's management utility")
	flag.StringVar(&o.HttpVserver, "f5-http-vserver", env("ROUTER_EXTERNAL_HOST_HTTP_VSERVER", "ose-vserver"), "The F5 BIG-IP virtual server for HTTP connections")
	flag.StringVar(&o.HttpsVserver, "f5-https-vserver", env("ROUTER_EXTERNAL_HOST_HTTPS_VSERVER", "https-ose-vserver"), "The F5 BIG-IP virtual server for HTTPS connections")
	flag.StringVar(&o.PrivateKey, "f5-private-key", env("ROUTER_EXTERNAL_HOST_PRIVKEY", ""), "The path to the F5 BIG-IP SSH private key file")
	flag.BoolVar(&o.Insecure, "f5-insecure", isTrue(env("ROUTER_EXTERNAL_HOST_INSECURE", "")), "Skip strict certificate verification")
	flag.StringVar(&o.PartitionPath, "f5-partition-path", env("ROUTER_EXTERNAL_HOST_PARTITION_PATH", f5plugin.F5DefaultPartitionPath), "The F5 BIG-IP partition path to use")
	flag.StringVar(&o.InternalAddress, "f5-internal-address", env("ROUTER_EXTERNAL_HOST_INTERNAL_ADDRESS", ""), "The F5 BIG-IP internal interface's IP address")
	flag.StringVar(&o.VxlanGateway, "f5-vxlan-gateway-cidr", env("ROUTER_EXTERNAL_HOST_VXLAN_GW_CIDR", ""), "The F5 BIG-IP gateway-ip-address/cidr-mask for setting up the VxLAN")
}
func (o *F5Router) Validate() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if o.Host == "" {
		return errors.New("F5 host must be specified")
	}
	if o.Username == "" {
		return errors.New("F5 username must be specified")
	}
	if o.Password == "" {
		return errors.New("F5 password must be specified")
	}
	if len(o.HttpVserver) == 0 && len(o.HttpsVserver) == 0 {
		return errors.New("F5 HTTP and HTTPS vservers cannot both be blank")
	}
	valid := (len(o.VxlanGateway) == 0 && len(o.InternalAddress) == 0) || (len(o.VxlanGateway) != 0 && len(o.InternalAddress) != 0)
	if !valid {
		return errors.New("For VxLAN setup, both internal-address and gateway-cidr must be specified")
	}
	return nil
}
func NewCommandF5Router(name string) *cobra.Command {
	_logClusterCodePath()
	defer _logClusterCodePath()
	options := &F5RouterOptions{Config: NewConfig()}
	cmd := &cobra.Command{Use: name, Short: "Start an F5 route synchronizer", Long: f5Long, RunE: func(c *cobra.Command, args []string) error {
		options.RouterSelection.Namespace = c.Flags().Lookup("namespace").Value.String()
		if err := options.Complete(); err != nil {
			return err
		}
		if err := options.Validate(); err != nil {
			return err
		}
		return options.Run()
	}}
	cmd.AddCommand(newCmdVersion(name, version.Get(), os.Stdout))
	flag := cmd.Flags()
	options.Config.Bind(flag)
	options.F5Router.Bind(flag)
	options.RouterSelection.Bind(flag)
	return cmd
}
func (o *F5RouterOptions) Complete() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(o.PartitionPath) == 0 {
		o.PartitionPath = f5plugin.F5DefaultPartitionPath
		glog.Warningf("Partition path was empty, using default: %q", f5plugin.F5DefaultPartitionPath)
	}
	return o.RouterSelection.Complete()
}
func (o *F5RouterOptions) Validate() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return o.F5Router.Validate()
}
func (o *F5RouterOptions) F5RouteAdmitterFunc() controller.RouteAdmissionFunc {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return func(route *routev1.Route) error {
		if err := o.AdmissionCheck(route); err != nil {
			return err
		}
		switch route.Spec.WildcardPolicy {
		case routev1.WildcardPolicyNone:
			return nil
		case routev1.WildcardPolicySubdomain:
			return fmt.Errorf("Wildcard routes are currently not supported by the F5 router")
		}
		return fmt.Errorf("unknown wildcard policy %v", route.Spec.WildcardPolicy)
	}
}
func (o *F5RouterOptions) Run() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cfg := f5plugin.F5PluginConfig{Host: o.Host, Username: o.Username, Password: o.Password, HttpVserver: o.HttpVserver, HttpsVserver: o.HttpsVserver, PrivateKey: o.PrivateKey, Insecure: o.Insecure, PartitionPath: o.PartitionPath, InternalAddress: o.InternalAddress, VxlanGateway: o.VxlanGateway}
	f5Plugin, err := f5plugin.NewF5Plugin(cfg)
	if err != nil {
		return err
	}
	kc, err := o.Config.Clients()
	if err != nil {
		return err
	}
	config, _, err := o.Config.KubeConfig()
	if err != nil {
		return err
	}
	routeclient, err := routeclientset.NewForConfig(config)
	if err != nil {
		return err
	}
	projectclient, err := projectclient.NewForConfig(config)
	if err != nil {
		return err
	}
	factory := o.RouterSelection.NewFactory(routeclient, projectclient.ProjectV1().Projects(), kc)
	factory.RouteModifierFn = o.RouteUpdate
	var plugin router.Plugin = f5Plugin
	var recorder controller.RejectionRecorder = controller.LogRejections
	if o.UpdateStatus {
		lease := writerlease.New(time.Minute, 3*time.Second)
		go lease.Run(wait.NeverStop)
		informer := factory.CreateRoutesSharedInformer()
		tracker := controller.NewSimpleContentionTracker(informer, o.RouterName, o.ResyncInterval/10)
		tracker.SetConflictMessage(fmt.Sprintf("The router detected another process is writing conflicting updates to route status with name %q. Please ensure that the configuration of all routers is consistent. Route status will not be updated as long as conflicts are detected.", o.RouterName))
		go tracker.Run(wait.NeverStop)
		routeLister := routelisters.NewRouteLister(informer.GetIndexer())
		status := controller.NewStatusAdmitter(plugin, routeclient.Route(), routeLister, o.RouterName, o.RouterCanonicalHostname, lease, tracker)
		recorder = status
		plugin = status
	}
	if o.ExtendedValidation {
		plugin = controller.NewExtendedValidator(plugin, recorder)
	}
	plugin = controller.NewUniqueHost(plugin, o.RouterSelection.DisableNamespaceOwnershipCheck, recorder)
	plugin = controller.NewHostAdmitter(plugin, o.F5RouteAdmitterFunc(), o.AllowWildcardRoutes, o.RouterSelection.DisableNamespaceOwnershipCheck, recorder)
	watchNodes := (len(o.InternalAddress) != 0 && len(o.VxlanGateway) != 0)
	controller := factory.Create(plugin, watchNodes)
	controller.Run()
	select {}
}
