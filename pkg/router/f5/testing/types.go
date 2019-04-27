package testing

type MockF5State struct {
	Policies		map[string]map[string]PolicyRule
	VserverPolicies		map[string]map[string]bool
	Certs			map[string]bool
	Keys			map[string]bool
	ServerSslProfiles	map[string]bool
	ClientSslProfiles	map[string]bool
	VserverProfiles		map[string]map[string]bool
	Datagroups		map[string]Datagroup
	IRules			map[string]IRule
	VserverIRules		map[string][]string
	PartitionPaths		map[string]string
	Pools			map[string]Pool
}
type PolicyCondition struct {
	HttpHost	bool		`json:"httpHost,omitempty"`
	HttpUri		bool		`json:"httpUri,omitempty"`
	PathSegment	bool		`json:"pathSegment,omitempty"`
	Index		int		`json:"index"`
	Host		bool		`json:"host,omitempty"`
	Values		[]string	`json:"values"`
}
type PolicyRule struct{ Conditions []PolicyCondition }
type Datagroup map[string]string
type IRule string
type Pool map[string]bool
