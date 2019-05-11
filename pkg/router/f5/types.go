package f5

type f5Result struct {
	Code	int		`json:"code"`
	Message	*string	`json:"message"`
}
type F5Error struct {
	f5Result
	verb			string
	url				string
	httpStatusCode	int
	err				error
}
type f5VserverPolicy struct {
	Name		string	`json:"name"`
	Partition	string	`json:"partition"`
	FullPath	string	`json:"fullPath"`
}
type f5VserverPolicies struct {
	Policies []f5VserverPolicy `json:"items"`
}
type f5VserverIRules struct {
	Rules []string `json:"rules"`
}
type f5Pool struct {
	Mode		string	`json:"loadBalancingMode"`
	Monitor		string	`json:"monitor"`
	Partition	string	`json:"partition"`
	Name		string	`json:"name"`
}
type f5PoolMember struct {
	Name string `json:"name"`
}
type f5PoolMemberset struct {
	Members []f5PoolMember `json:"items"`
}
type f5Ver12Policy struct {
	Name		string		`json:"name"`
	TmPartition	string		`json:"tmPartition"`
	Controls	[]string	`json:"controls"`
	Requires	[]string	`json:"requires"`
	Strategy	string		`json:"strategy"`
	Legacy		bool		`json:"legacy"`
}
type f5Policy struct {
	Name		string		`json:"name"`
	Partition	string		`json:"partition"`
	Controls	[]string	`json:"controls"`
	Requires	[]string	`json:"requires"`
	Strategy	string		`json:"strategy"`
}
type f5Rule struct {
	Name string `json:"name"`
}
type f5PolicyRuleset struct {
	Rules []f5Rule `json:"items"`
}
type f5RuleCondition struct {
	Name			string		`json:"name"`
	CaseInsensitive	bool		`json:"caseInsensitive"`
	HttpHost		bool		`json:"httpHost,omitempty"`
	HttpUri			bool		`json:"httpUri,omitempty"`
	PathSegment		bool		`json:"pathSegment,omitempty"`
	Index			int			`json:"index"`
	Equals			bool		`json:"equals"`
	Request			bool		`json:"request"`
	Host			bool		`json:"host,omitempty"`
	Values			[]string	`json:"values"`
}
type f5RuleAction struct {
	Name	string	`json:"name"`
	Forward	bool	`json:"forward"`
	Pool	string	`json:"pool"`
	Request	bool	`json:"request"`
	Select	bool	`json:"select"`
	Vlan	int		`json:"vlanId"`
}
type f5DatagroupRecord struct {
	Key		string	`json:"name"`
	Value	string	`json:"data"`
}
type f5Datagroup struct {
	Name	string				`json:"name,omitempty"`
	Type	string				`json:"type,omitempty"`
	Records	[]f5DatagroupRecord	`json:"records"`
}
type f5IRule struct {
	Name		string	`json:"name"`
	Partition	string	`json:"partition"`
	Code		string	`json:"apiAnonymous"`
}
type f5InstallCommandPayload struct {
	Command		string	`json:"command"`
	Name		string	`json:"name"`
	Filename	string	`json:"from-local-file"`
}
type f5SslProfilePayload struct {
	Certificate	string	`json:"cert,omitempty"`
	Key			string	`json:"key,omitempty"`
	Chain		string	`json:"chain,omitempty"`
	Name		string	`json:"name"`
	ServerName	string	`json:"serverName"`
}
type f5VserverProfilePayload struct {
	Context	string	`json:"context"`
	Name	string	`json:"name"`
}
type f5AddPartitionPathPayload struct {
	Name string `json:"name"`
}
type f5CreateVxLANProfilePayload struct {
	Name			string	`json:"name"`
	Partition		string	`json:"partition"`
	FloodingType	string	`json:"floodingType"`
	Port			int		`json:"port"`
}
type f5CreateVxLANTunnelPayload struct {
	Name			string	`json:"name"`
	Partition		string	`json:"partition"`
	Key				uint32	`json:"key"`
	LocalAddress	string	`json:"localAddress"`
	Mode			string	`json:"mode"`
	Mtu				string	`json:"mtu"`
	Profile			string	`json:"profile"`
	Tos				string	`json:"tos"`
	Transparent		string	`json:"transparent"`
	UsePmtu			string	`json:"usePmtu"`
}
type f5CreateNetSelfPayload struct {
	Name					string	`json:"name"`
	Partition				string	`json:"partition"`
	Address					string	`json:"address"`
	AddressSource			string	`json:"addressSource"`
	Floating				string	`json:"floating"`
	InheritedTrafficGroup	string	`json:"inheritedTrafficGroup"`
	TrafficGroup			string	`json:"trafficGroup"`
	Unit					uint32	`json:"unit"`
	Vlan					string	`json:"vlan"`
	AllowService			string	`json:"allowService"`
}
type f5AddFDBRecordPayload struct {
	Name		string	`json:"name"`
	Endpoint	string	`json:"endpoint"`
}
