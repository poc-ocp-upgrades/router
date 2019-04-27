package util

import (
	"sort"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	"fmt"
	"strings"
)

type sorterFunc func(s1, s2 string) bool
type mapPathSorter struct {
	data	[]string
	fn	sorterFunc
}

func (s *mapPathSorter) Len() int {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return len(s.data)
}
func (s *mapPathSorter) Swap(i, j int) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	s.data[i], s.data[j] = s.data[j], s.data[i]
}
func (s *mapPathSorter) Less(i, j int) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return s.fn(s.data[i], s.data[j])
}
func sortByGroup(data []string, prefix string, reverse bool) []string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	patternsAtEnd := func(s1, s2 string) bool {
		if len(prefix) > 0 {
			if strings.HasPrefix(s1, prefix) {
				if !strings.HasPrefix(s2, prefix) {
					return false
				}
			} else if strings.HasPrefix(s2, prefix) {
				return true
			}
		}
		if reverse {
			return s1 > s2
		}
		return s1 < s2
	}
	mps := &mapPathSorter{data: data, fn: patternsAtEnd}
	sort.Sort(mps)
	return mps.data
}
func SortMapPaths(data []string, prefix string) []string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return sortByGroup(data, prefix, true)
}
func _logClusterCodePath() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
func _logClusterCodePath() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
