// Package audit implements an append-only administrative change log with
// recursive secret redaction, filtering, and retention caps matching
// docker/app/haproxy_admin/audit.py.
package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultDenied  = "denied"

	ActorUser   = "user"
	ActorSystem = "system"

	MaxRows         = 200_000
	MaxSummaryChars = 500
	MaxJSONBytes    = 8192
)

var (
	Results      = []string{ResultSuccess, ResultFailure, ResultDenied}
	sensitiveRe  = regexp.MustCompile(`(?i)pass|secret|token|credential|private|passphrase|cookie|authorization|session|salt|hash|_key$|^key$|apikey|api_key`)
	redactedMark = "***"
)

// Event represents one recorded administrative operation.
type Event struct {
	ID         int64  `json:"id"`
	TS         int64  `json:"ts"`
	ActorType  string `json:"actor_type"`
	Actor      string `json:"actor"`
	SourceIP   string `json:"source_ip"`
	Action     string `json:"action"`
	ObjectType string `json:"object_type"`
	ObjectID   string `json:"object_id"`
	Result     string `json:"result"`
	Summary    string `json:"summary"`
	BeforeJSON string `json:"before_json,omitempty"`
	AfterJSON  string `json:"after_json,omitempty"`
	Detail     string `json:"detail"`
}

// QueryFilter specifies filters for audit log queries.
type QueryFilter struct {
	Actor      string
	Action     string
	ObjectType string
	Result     string
	Since      int64
	Limit      int
	Offset     int
}

// Redact recursively replaces values under sensitive key names with "***".
func Redact(v any) any {
	return redactDepth(v, 0)
}

func redactDepth(v any, depth int) any {
	if depth > 6 {
		return "..."
	}
	switch x := v.(type) {
	case map[string]any:
		clean := make(map[string]any, len(x))
		for k, item := range x {
			if sensitiveRe.MatchString(k) {
				if item == nil || item == "" {
					clean[k] = nil
				} else {
					clean[k] = redactedMark
				}
			} else {
				clean[k] = redactDepth(item, depth+1)
			}
		}
		return clean
	case []any:
		n := len(x)
		if n > 100 {
			n = 100
		}
		out := make([]any, n)
		for i := 0; i < n; i++ {
			out[i] = redactDepth(x[i], depth+1)
		}
		return out
	case string:
		if len(x) > 1000 {
			return x[:1000] + "…"
		}
		return x
	default:
		return v
	}
}

func dumpJSON(v any) string {
	if v == nil {
		return ""
	}
	raw, err := json.Marshal(Redact(v))
	if err != nil {
		return ""
	}
	if len(raw) > MaxJSONBytes {
		return string(raw[:MaxJSONBytes])
	}
	return string(raw)
}

// Store persists audit events as JSONL next to the configured audit path and
// keeps an in-memory ring for sub-millisecond filtered queries.
// Failures to persist never abort the caller's operation.
type Store struct {
	path      string
	mu        sync.RWMutex
	events    []Event
	nextID    int64
	available bool
	lastError string
}

// Open initializes an audit Store at path (using a `.jsonl` companion file when
// given a `.db` path so it never corrupts a SQLite file owned by Python).
func Open(path string) *Store {
	storePath := strings.TrimSpace(path)
	if storePath != "" && strings.HasSuffix(strings.ToLower(storePath), ".db") {
		storePath = strings.TrimSuffix(storePath, filepath.Ext(storePath)) + ".jsonl"
	}
	s := &Store{
		path:      storePath,
		nextID:    1,
		available: true,
	}
	s.loadExisting()
	return s
}

func (s *Store) loadExisting() {
	if s.path == "" {
		return
	}
	f, err := os.Open(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			s.available = false
			s.lastError = err.Error()
		}
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev Event
		if json.Unmarshal([]byte(line), &ev) == nil {
			s.events = append(s.events, ev)
			if ev.ID >= s.nextID {
				s.nextID = ev.ID + 1
			}
		}
	}
	if len(s.events) > MaxRows {
		s.events = s.events[len(s.events)-MaxRows:]
	}
}

// Record appends one event to memory and disk. Errors are captured in stats,
// never returned to disrupt operations.
func (s *Store) Record(actor, sourceIP, action, objectType, objectID, result, summary, detail string, before, after any) {
	if result == "" {
		result = ResultSuccess
	}
	if len(summary) > MaxSummaryChars {
		summary = summary[:MaxSummaryChars]
	}
	if len(detail) > MaxSummaryChars {
		detail = detail[:MaxSummaryChars]
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ev := Event{
		ID:         s.nextID,
		TS:         time.Now().Unix(),
		ActorType:  ActorUser,
		Actor:      actor,
		SourceIP:   sourceIP,
		Action:     action,
		ObjectType: objectType,
		ObjectID:   objectID,
		Result:     result,
		Summary:    summary,
		BeforeJSON: dumpJSON(before),
		AfterJSON:  dumpJSON(after),
		Detail:     detail,
	}
	if actor == "" {
		ev.ActorType = ActorSystem
	}
	s.nextID++
	s.events = append(s.events, ev)
	if len(s.events) > MaxRows {
		s.events = s.events[len(s.events)-MaxRows:]
	}

	if s.path == "" {
		return
	}
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			s.available = false
			s.lastError = err.Error()
			return
		}
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.available = false
		s.lastError = err.Error()
		return
	}
	_, werr := f.Write(append(line, '\n'))
	cerr := f.Close()
	if werr != nil {
		s.available = false
		s.lastError = werr.Error()
	} else if cerr != nil {
		s.available = false
		s.lastError = cerr.Error()
	} else {
		s.available = true
		s.lastError = ""
	}
}

// Query returns matching events newest-first along with total count.
func (s *Store) Query(f QueryFilter) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := f.Limit
	if limit < 1 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	matched := make([]Event, 0)
	for i := len(s.events) - 1; i >= 0; i-- {
		ev := s.events[i]
		if f.Since > 0 && ev.TS < f.Since {
			continue
		}
		if f.Actor != "" && ev.Actor != f.Actor {
			continue
		}
		if f.Action != "" && ev.Action != f.Action {
			continue
		}
		if f.ObjectType != "" && ev.ObjectType != f.ObjectType {
			continue
		}
		if f.Result != "" && ev.Result != f.Result {
			continue
		}
		matched = append(matched, ev)
	}

	total := len(matched)
	if offset >= total {
		matched = []Event{}
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		matched = matched[offset:end]
	}

	return map[string]any{
		"available": s.available,
		"error":     s.lastError,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
		"events":    matched,
	}
}

// Distinct returns sorted unique non-empty values for actor, action, or object_type.
func (s *Store) Distinct(field string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := make(map[string]struct{})
	for _, ev := range s.events {
		var val string
		switch field {
		case "actor":
			val = ev.Actor
		case "action":
			val = ev.Action
		case "object_type":
			val = ev.ObjectType
		}
		if val != "" {
			seen[val] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Stats returns audit store health metadata.
func (s *Store) Stats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{
		"available":  s.available,
		"error":      s.lastError,
		"path":       s.path,
		"row_count":  len(s.events),
		"max_rows":   MaxRows,
	}
}
