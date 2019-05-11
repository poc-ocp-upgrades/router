package haproxy

import (
	"strings"
)

const (
	HAPROXY_MAX_LINE_ARGS			= 64
	HAPROXY_MAX_WHITELIST_LENGTH	= HAPROXY_MAX_LINE_ARGS - 3
)

func ValidateWhiteList(value string) ([]string, bool) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	values := strings.Split(value, " ")
	cidrs := make([]string, 0)
	for _, v := range values {
		if len(v) > 0 {
			cidrs = append(cidrs, v)
		}
	}
	return cidrs, len(cidrs) <= HAPROXY_MAX_WHITELIST_LENGTH
}
