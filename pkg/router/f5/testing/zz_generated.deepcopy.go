package testing

func (in Datagroup) DeepCopyInto(out *Datagroup) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	{
		in := &in
		*out = make(Datagroup, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
		return
	}
}
func (in Datagroup) DeepCopy() Datagroup {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if in == nil {
		return nil
	}
	out := new(Datagroup)
	in.DeepCopyInto(out)
	return *out
}
func (in *PolicyCondition) DeepCopyInto(out *PolicyCondition) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	*out = *in
	if in.Values != nil {
		in, out := &in.Values, &out.Values
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}
func (in *PolicyCondition) DeepCopy() *PolicyCondition {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if in == nil {
		return nil
	}
	out := new(PolicyCondition)
	in.DeepCopyInto(out)
	return out
}
func (in *PolicyRule) DeepCopyInto(out *PolicyRule) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]PolicyCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}
func (in *PolicyRule) DeepCopy() *PolicyRule {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if in == nil {
		return nil
	}
	out := new(PolicyRule)
	in.DeepCopyInto(out)
	return out
}
func (in Pool) DeepCopyInto(out *Pool) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	{
		in := &in
		*out = make(Pool, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
		return
	}
}
func (in Pool) DeepCopy() Pool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if in == nil {
		return nil
	}
	out := new(Pool)
	in.DeepCopyInto(out)
	return *out
}
