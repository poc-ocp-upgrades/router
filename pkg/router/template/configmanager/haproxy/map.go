package haproxy

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	showMapListHeader	= "id (file) description"
	showMapHeader		= "id name value"
)

type mapListEntry struct {
	ID		string	`csv:"id"`
	Name	string	`csv:"(file)"`
	Unused	string	`csv:"-"`
}
type HAProxyMapEntry struct {
	ID		string	`csv:"id"`
	Name	string	`csv:"name"`
	Value	string	`csv:"value"`
}
type HAProxyMap struct {
	name	string
	client	*Client
	entries	[]*HAProxyMapEntry
	dirty	bool
}

func buildHAProxyMaps(c *Client) ([]*HAProxyMap, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	entries := []*mapListEntry{}
	converter := NewCSVConverter(showMapListHeader, &entries, fixupMapListOutput)
	if _, err := c.RunCommand("show map", converter); err != nil {
		return []*HAProxyMap{}, err
	}
	maps := make([]*HAProxyMap, len(entries))
	for k, v := range entries {
		m := newHAProxyMap(v.Name, c)
		maps[k] = m
	}
	return maps, nil
}
func newHAProxyMap(name string, client *Client) *HAProxyMap {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &HAProxyMap{name: name, client: client, entries: make([]*HAProxyMapEntry, 0), dirty: true}
}
func (m *HAProxyMap) Refresh() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cmd := fmt.Sprintf("show map %s", m.name)
	converter := NewCSVConverter(showMapHeader, &m.entries, nil)
	if _, err := m.client.RunCommand(cmd, converter); err != nil {
		return err
	}
	m.dirty = false
	return nil
}
func (m *HAProxyMap) Commit() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return nil
}
func (m *HAProxyMap) Name() string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return m.name
}
func (m *HAProxyMap) Find(k string) ([]HAProxyMapEntry, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	found := make([]HAProxyMapEntry, 0)
	if m.dirty {
		if err := m.Refresh(); err != nil {
			return found, err
		}
	}
	for _, entry := range m.entries {
		if entry.Name == k {
			clonedEntry := HAProxyMapEntry{ID: entry.ID, Name: entry.Name, Value: entry.Value}
			found = append(found, clonedEntry)
		}
	}
	return found, nil
}
func (m *HAProxyMap) Add(k, v string, replace bool) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if replace {
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	return m.addEntry(k, v)
}
func (m *HAProxyMap) Delete(k string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	entries, err := m.Find(k)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := m.deleteEntry(entry.ID); err != nil {
			return err
		}
	}
	return nil
}
func (m *HAProxyMap) DeleteEntry(id string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return m.deleteEntry(id)
}
func (m *HAProxyMap) addEntry(k, v string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	keyExpr := escapeKeyExpr(k)
	cmd := fmt.Sprintf("add map %s %s %s", m.name, keyExpr, v)
	responseBytes, err := m.client.Execute(cmd)
	if err != nil {
		return err
	}
	response := strings.TrimSpace(string(responseBytes))
	if len(response) > 0 {
		return fmt.Errorf("adding map %s entry %s: %v", m.name, keyExpr, string(response))
	}
	m.dirty = true
	return nil
}
func (m *HAProxyMap) deleteEntry(id string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cmd := fmt.Sprintf("del map %s #%s", m.name, id)
	if _, err := m.client.Execute(cmd); err != nil {
		return err
	}
	m.dirty = true
	return nil
}
func escapeKeyExpr(k string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	v := strings.Replace(k, `\`, `\\`, -1)
	return strings.Replace(v, `.`, `\.`, -1)
}

var listMapOutputRE *regexp.Regexp = regexp.MustCompile(`(?m)^(-|)([0-9]*) \((.*)?\).*$`)

func fixupMapListOutput(data []byte) ([]byte, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	replacement := []byte(`$1$2 $3 loaded`)
	return listMapOutputRE.ReplaceAll(data, replacement), nil
}
