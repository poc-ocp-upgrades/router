package haproxy

import (
	routev1 "github.com/openshift/api/route/v1"
)

type BackendConfig struct {
	Name			string
	Host			string
	Path			string
	IsWildcard		bool
	Termination		routev1.TLSTerminationType
	InsecurePolicy	routev1.InsecureEdgeTerminationPolicyType
	HasCertificate	bool
}
type HAProxyMapEntry struct {
	Key		string
	Value	string
}
