package metricsd

import "github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyyaml"

// OMap is a Python dict for replies: keys in insertion order, floats
// written as Python's json.dumps writes them.
type OMap = pyyaml.Map

// NewOMap returns an empty OMap.
func NewOMap() *OMap { return pyyaml.NewMap() }

// omap builds an OMap from key, value pairs.
func omap(kv ...any) *OMap {
	m := pyyaml.NewMap()
	for i := 0; i+1 < len(kv); i += 2 {
		m.Set(kv[i].(string), kv[i+1])
	}
	return m
}
