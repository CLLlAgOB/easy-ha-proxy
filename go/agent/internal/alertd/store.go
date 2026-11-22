package alertd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// AlertState represents one (rule, subject) row matching alert_state schema.
type AlertState struct {
	Rule           string `json:"rule"`
	Subject        string `json:"subject"`
	State          string `json:"state"`
	Severity       string `json:"severity"`
	SinceTS        int64  `json:"since_ts"`
	FirstSeenTS    int64  `json:"first_seen_ts"`
	LastSeenTS     int64  `json:"last_seen_ts"`
	LastNotifiedTS int64  `json:"last_notified_ts"`
	NotifyCount    int    `json:"notify_count"`
	Summary        string `json:"summary"`
	Detail         string `json:"detail"`
	TriggerDelay   *int   `json:"trigger_delay"`
	Recipient      string `json:"recipient"`
	AcknowledgedTS int64  `json:"acknowledged_ts"`
	AcknowledgedBy string `json:"acknowledged_by"`
	MutedUntil     int64  `json:"muted_until"`
	StaleSinceTS   int64  `json:"stale_since_ts"`
}

// AlertEvent represents one row in alert_events history.
type AlertEvent struct {
	ID            int64  `json:"id"`
	TS            int64  `json:"ts"`
	Rule          string `json:"rule"`
	Subject       string `json:"subject"`
	Transition    string `json:"transition"`
	Severity      string `json:"severity"`
	Summary       string `json:"summary"`
	Detail        string `json:"detail"`
	Delivered     string `json:"delivered"`
	DeliveryError string `json:"delivery_error"`
}

// EventFilter filters alert history queries.
type EventFilter struct {
	Rule     string
	Severity string
	Since    int64
	Until    int64
	Limit    int
	Offset   int
}

// StoreStats summarizes persisted alert state counts and file size.
type StoreStats struct {
	Firing        int   `json:"firing"`
	Pending       int   `json:"pending"`
	Events        int   `json:"events"`
	DatabaseBytes int64 `json:"database_bytes"`
}

type stateKey struct {
	rule    string
	subject string
}

type persistedSnapshot struct {
	SchemaVersion int          `json:"schema_version"`
	NextEventID   int64        `json:"next_event_id"`
	States        []AlertState `json:"states"`
	Events        []AlertEvent `json:"events"`
}

// Store provides thread-safe, crash-safe atomic persistence for alertd with zero CGO dependencies.
type Store struct {
	mu          sync.Mutex
	path        string
	nextEventID int64
	states      map[stateKey]AlertState
	events      []AlertEvent
}

// NewStore opens or creates an atomic file-backed alert store.
// When path is empty, the store operates purely in memory (useful for tests).
func NewStore(path string) (*Store, error) {
	s := &Store{
		path:        path,
		nextEventID: 1,
		states:      make(map[stateKey]AlertState),
	}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			var snap persistedSnapshot
			if err := json.Unmarshal(data, &snap); err == nil {
				if snap.NextEventID > 0 {
					s.nextEventID = snap.NextEventID
				}
				for _, st := range snap.States {
					s.states[stateKey{st.Rule, st.Subject}] = st
				}
				s.events = snap.Events
				for _, ev := range s.events {
					if ev.ID >= s.nextEventID {
						s.nextEventID = ev.ID + 1
					}
				}
			}
		}
	}
	return s, nil
}

func (s *Store) flushLocked() {
	if s.path == "" {
		return
	}
	states := make([]AlertState, 0, len(s.states))
	for _, st := range s.states {
		states = append(states, st)
	}
	snap := persistedSnapshot{
		SchemaVersion: 2,
		NextEventID:   s.nextEventID,
		States:        states,
		Events:        s.events,
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".alerts-state.*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	_ = tmp.Chmod(0o640)
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	_ = os.Rename(tmpName, s.path)
}

func (s *Store) GetState(rule, subject string) (AlertState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[stateKey{rule, subject}]
	return st, ok
}

// PutState inserts or updates state while preserving operator quiet fields
// (acknowledged_ts, acknowledged_by, muted_until) and clearing stale_since_ts.
func (s *Store) PutState(st AlertState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := stateKey{st.Rule, st.Subject}
	if prev, ok := s.states[k]; ok {
		st.AcknowledgedTS = prev.AcknowledgedTS
		st.AcknowledgedBy = prev.AcknowledgedBy
		st.MutedUntil = prev.MutedUntil
	}
	st.StaleSinceTS = 0
	s.states[k] = st
	s.flushLocked()
}

func (s *Store) SetQuiet(rule, subject string, ackTS int64, ackBy string, mutedUntil int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := stateKey{rule, subject}
	st, ok := s.states[k]
	if !ok {
		return false
	}
	if len(ackBy) > 120 {
		ackBy = ackBy[:120]
	}
	st.AcknowledgedTS = ackTS
	st.AcknowledgedBy = ackBy
	st.MutedUntil = mutedUntil
	s.states[k] = st
	s.flushLocked()
	return true
}

func (s *Store) ClearAcknowledgement(rule, subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := stateKey{rule, subject}
	if st, ok := s.states[k]; ok {
		st.AcknowledgedTS = 0
		st.AcknowledgedBy = ""
		s.states[k] = st
		s.flushLocked()
	}
}

func (s *Store) DropState(rule, subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, stateKey{rule, subject})
	s.flushLocked()
}

func (s *Store) MarkStale(rule, subject string, since int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := stateKey{rule, subject}
	if st, ok := s.states[k]; ok {
		st.StaleSinceTS = since
		s.states[k] = st
		s.flushLocked()
	}
}

func (s *Store) OpenStates() []AlertState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AlertState, 0)
	for _, st := range s.states {
		if st.State != StateOK {
			out = append(out, st)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SinceTS > out[j].SinceTS })
	return out
}

func (s *Store) ActiveAlerts() []AlertState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AlertState, 0)
	for _, st := range s.states {
		if st.State == StateFiring {
			out = append(out, st)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SinceTS > out[j].SinceTS })
	return out
}

func (s *Store) AddEvent(ev AlertEvent) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev.ID = s.nextEventID
	s.nextEventID++
	s.events = append(s.events, ev)
	s.flushLocked()
	return ev.ID
}

func (s *Store) SetDelivery(eventID int64, delivered, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(errMsg) > MaxTextChars {
		errMsg = errMsg[:MaxTextChars]
	}
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].ID == eventID {
			s.events[i].Delivered = delivered
			s.events[i].DeliveryError = errMsg
			s.flushLocked()
			return
		}
	}
}

func (s *Store) Events(f EventFilter) (int, []AlertEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := clampInt(f.Limit, 1, 500)
	if f.Limit == 0 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	matched := make([]AlertEvent, 0)
	for _, ev := range s.events {
		if f.Rule != "" && ev.Rule != f.Rule {
			continue
		}
		if ValidSeverity(f.Severity) && ev.Severity != f.Severity {
			continue
		}
		if f.Since > 0 && ev.TS < f.Since {
			continue
		}
		if f.Until > 0 && ev.TS > f.Until {
			continue
		}
		matched = append(matched, ev)
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].TS != matched[j].TS {
			return matched[i].TS > matched[j].TS
		}
		return matched[i].ID > matched[j].ID
	})
	total := len(matched)
	if offset >= total {
		return total, []AlertEvent{}
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return total, matched[offset:end]
}

func (s *Store) DeleteEvents(ids []int64, everything bool, before int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	beforeCount := len(s.events)
	if everything {
		s.events = nil
		s.flushLocked()
		return beforeCount
	}
	if before > 0 {
		kept := s.events[:0]
		for _, ev := range s.events {
			if ev.TS >= before {
				kept = append(kept, ev)
			}
		}
		s.events = kept
		removed := beforeCount - len(s.events)
		if removed > 0 {
			s.flushLocked()
		}
		return removed
	}
	if len(ids) == 0 {
		return 0
	}
	if len(ids) > 1000 {
		ids = ids[:1000]
	}
	drop := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		drop[id] = struct{}{}
	}
	kept := s.events[:0]
	for _, ev := range s.events {
		if _, rm := drop[ev.ID]; !rm {
			kept = append(kept, ev)
		}
	}
	s.events = kept
	removed := beforeCount - len(s.events)
	if removed > 0 {
		s.flushLocked()
	}
	return removed
}

func (s *Store) NotificationsSince(since int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, ev := range s.events {
		if ev.TS >= since && (ev.Transition == TransitionFired || ev.Transition == TransitionRepeated) {
			count++
		}
	}
	return count
}

func (s *Store) Prune(now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now - int64(RetentionDays)*86400
	kept := s.events[:0]
	for _, ev := range s.events {
		if ev.TS >= cutoff {
			kept = append(kept, ev)
		}
	}
	if len(kept) > MaxEventRows {
		kept = kept[len(kept)-MaxEventRows:]
	}
	s.events = kept

	for k, st := range s.states {
		if st.State == StateOK && st.LastSeenTS < cutoff {
			delete(s.states, k)
		}
	}
	if len(s.states) > MaxStateRows {
		all := make([]AlertState, 0, len(s.states))
		for _, st := range s.states {
			all = append(all, st)
		}
		sort.Slice(all, func(i, j int) bool { return all[i].LastSeenTS > all[j].LastSeenTS })
		s.states = make(map[stateKey]AlertState, MaxStateRows)
		for _, st := range all[:MaxStateRows] {
			s.states[stateKey{st.Rule, st.Subject}] = st
		}
	}
	s.flushLocked()
}

func (s *Store) Stats() StoreStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	var st StoreStats
	st.Events = len(s.events)
	for _, row := range s.states {
		switch row.State {
		case StateFiring:
			st.Firing++
		case StatePending:
			st.Pending++
		}
	}
	if s.path != "" {
		if info, err := os.Stat(s.path); err == nil {
			st.DatabaseBytes = info.Size()
		}
	}
	return st
}
