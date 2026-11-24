// Package app is the Go port of the Flask application in
// docker/app/haproxy_admin: the same endpoints (by Flask endpoint name), the
// same templates rendered by internal/jinja, and the same answers. The
// Python code is the specification; each file names the module it ports.
package app

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type flaskRule struct {
	endpoint      string
	rule          string
	methods       []string
	strictSlashes bool
}

type ruleArg struct {
	name      string
	converter string // "default" or "path"
}

type compiledRule struct {
	flaskRule
	re      *regexp.Regexp
	args    []ruleArg
	parts   []string // literal parts between args, len(args)+1
	weight  [2]int
	methods map[string]bool
}

var ruleArgRe = regexp.MustCompile(`<(?:([a-z]+):)?([a-z_][a-z0-9_]*)>`)

func compileRule(r flaskRule) *compiledRule {
	c := &compiledRule{flaskRule: r, methods: map[string]bool{}}
	for _, m := range r.methods {
		c.methods[m] = true
	}
	if c.methods["GET"] {
		c.methods["HEAD"] = true
	}
	c.methods["OPTIONS"] = true
	var pattern strings.Builder
	pattern.WriteString("^")
	last := 0
	staticChars := 0
	for _, m := range ruleArgRe.FindAllStringSubmatchIndex(r.rule, -1) {
		lit := r.rule[last:m[0]]
		c.parts = append(c.parts, lit)
		staticChars += len(lit)
		pattern.WriteString(regexp.QuoteMeta(lit))
		conv := "default"
		if m[2] >= 0 {
			conv = r.rule[m[2]:m[3]]
		}
		name := r.rule[m[4]:m[5]]
		c.args = append(c.args, ruleArg{name: name, converter: conv})
		if conv == "path" {
			pattern.WriteString(`(?P<` + name + `>[^/].*?)`)
		} else {
			pattern.WriteString(`(?P<` + name + `>[^/]+)`)
		}
		last = m[1]
	}
	tail := r.rule[last:]
	c.parts = append(c.parts, tail)
	staticChars += len(tail)
	pattern.WriteString(regexp.QuoteMeta(tail))
	pattern.WriteString("$")
	c.re = regexp.MustCompile(pattern.String())
	pathArgs := 0
	for _, a := range c.args {
		if a.converter == "path" {
			pathArgs++
		}
	}
	// Werkzeug tries static rules before dynamic ones, and greedy path
	// converters last.
	c.weight = [2]int{len(c.args) + 10*pathArgs, -staticChars}
	return c
}

// Router matches request paths to Flask endpoints like werkzeug's MapAdapter.
type Router struct {
	rules      []*compiledRule
	byEndpoint map[string]*compiledRule
}

// NewRouter compiles rules.
func NewRouter(rules []flaskRule) *Router {
	rt := &Router{byEndpoint: map[string]*compiledRule{}}
	for _, r := range rules {
		c := compileRule(r)
		rt.rules = append(rt.rules, c)
		if _, ok := rt.byEndpoint[r.endpoint]; !ok {
			rt.byEndpoint[r.endpoint] = c
		}
	}
	sort.SliceStable(rt.rules, func(i, j int) bool {
		a, b := rt.rules[i].weight, rt.rules[j].weight
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		return a[1] < b[1]
	})
	return rt
}

// MatchResult is the outcome of matching a request.
type MatchResult struct {
	Rule     *compiledRule
	Args     map[string]string
	Redirect string   // strict-slashes redirect target (308)
	Allowed  []string // methods for an automatic OPTIONS response or a 405
}

// Match finds the endpoint for method and path.
func (rt *Router) Match(method, path string) MatchResult {
	allowed := map[string]bool{}
	for _, c := range rt.rules {
		m := c.re.FindStringSubmatch(path)
		if m == nil {
			continue
		}
		if method == "OPTIONS" || !c.methods[method] {
			for k := range c.methods {
				allowed[k] = true
			}
			continue
		}
		args := map[string]string{}
		for i, name := range c.re.SubexpNames() {
			if i > 0 && name != "" {
				args[name] = m[i]
			}
		}
		return MatchResult{Rule: c, Args: args}
	}
	if len(allowed) == 0 && !strings.HasSuffix(path, "/") {
		// A rule ending in a slash matches the path without it via a redirect.
		for _, c := range rt.rules {
			if !c.strictSlashes || !strings.HasSuffix(c.rule, "/") {
				continue
			}
			if c.re.MatchString(path+"/") && (c.methods[method]) {
				return MatchResult{Rule: c, Redirect: path + "/"}
			}
		}
	}
	if len(allowed) > 0 {
		out := make([]string, 0, len(allowed))
		for k := range allowed {
			out = append(out, k)
		}
		sort.Strings(out)
		return MatchResult{Allowed: out}
	}
	return MatchResult{}
}

// urlQuoteSafe is werkzeug's safe set for URL path segments.
const urlQuoteSafe = "!$&'()*+,/:;=@-._~"

func quotePath(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte(urlQuoteSafe, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(strconv.FormatInt(int64(c)>>4, 16)) + strings.ToUpper(strconv.FormatInt(int64(c)&15, 16)))
	}
	return b.String()
}

// QueryValue is one url_for keyword: Value is its str() form.
type QueryValue struct {
	Key   string
	Value string
}

// Build is url_for(endpoint, **values) for an absolute endpoint name.
func (rt *Router) Build(endpoint string, path map[string]string, query []QueryValue) (string, bool) {
	c, ok := rt.byEndpoint[endpoint]
	if !ok {
		return "", false
	}
	var b strings.Builder
	for i, a := range c.args {
		b.WriteString(c.parts[i])
		v, ok := path[a.name]
		if !ok {
			return "", false
		}
		b.WriteString(quotePath(v))
	}
	b.WriteString(c.parts[len(c.parts)-1])
	if len(query) > 0 {
		pairs := make([]string, 0, len(query))
		for _, q := range query {
			pairs = append(pairs, queryEscape(q.Key)+"="+queryEscape(q.Value))
		}
		b.WriteString("?" + strings.Join(pairs, "&"))
	}
	return b.String(), true
}

// queryEscape is urllib's quote_plus with werkzeug's safe characters.
func queryEscape(s string) string {
	const safe = "!$'()*,/:;?@-._~"
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte(safe, c) >= 0:
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			b.WriteString("%" + strings.ToUpper(strconv.FormatInt(int64(c)>>4, 16)) + strings.ToUpper(strconv.FormatInt(int64(c)&15, 16)))
		}
	}
	return b.String()
}

// ArgNames lists the rule arguments of an endpoint.
func (rt *Router) ArgNames(endpoint string) []string {
	c, ok := rt.byEndpoint[endpoint]
	if !ok {
		return nil
	}
	out := make([]string, len(c.args))
	for i, a := range c.args {
		out[i] = a.name
	}
	return out
}
