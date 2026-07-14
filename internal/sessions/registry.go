// Package sessions is the live-session registry shared between the SSH data
// path (which registers sessions) and the control-plane API (which lists and
// terminates them). It is a small leaf package so neither internal/session nor
// internal/dialer needs to import internal/api — the data path never depends on
// the control plane.
package sessions

import (
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Info is a snapshot of one live session (safe to serialize; no control hooks).
type Info struct {
	ID       string    `json:"id"`
	User     string    `json:"user"`
	SourceIP string    `json:"source_ip"`
	Target   string    `json:"target,omitempty"`
	Start    time.Time `json:"start"`
	Channels int       `json:"channels"`
}

// entry is the registry's internal record: an Info plus the terminate hook.
type entry struct {
	info      Info
	terminate func() error
}

// Event is a live supervision event: a lightweight projection of what a session
// is doing, streamed to attached supervisors. It carries no secret.
type Event struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"` // channel_open | channel_close | session_end | ...
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Registry tracks live sessions and fans out live supervision events. Safe for
// concurrent use.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*entry

	submu   sync.Mutex
	nextSub int
	subs    map[string]map[int]chan Event // session id -> subscriber channels
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]*entry{}, subs: map[string]map[int]chan Event{}}
}

// Publish fans a supervision event out to every supervisor attached to id.
// Non-blocking: a slow subscriber drops events rather than stalling the session.
func (r *Registry) Publish(id string, ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	r.submu.Lock()
	defer r.submu.Unlock()
	for _, ch := range r.subs[id] {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Subscribe attaches a supervisor to session id's live event stream. It returns
// a channel of events and an unsubscribe func the caller must invoke.
func (r *Registry) Subscribe(id string) (<-chan Event, func()) {
	ch := make(chan Event, 64)
	r.submu.Lock()
	r.nextSub++
	sub := r.nextSub
	if r.subs[id] == nil {
		r.subs[id] = map[int]chan Event{}
	}
	r.subs[id][sub] = ch
	r.submu.Unlock()
	return ch, func() {
		r.submu.Lock()
		if m := r.subs[id]; m != nil {
			delete(m, sub)
			if len(m) == 0 {
				delete(r.subs, id)
			}
		}
		r.submu.Unlock()
		close(ch)
	}
}

// Register adds a session and returns its id and a deregister func to call when
// it ends. terminate closes the underlying SSH connection when the API asks to
// kill the session; it may be nil (the session is then listable but not
// killable).
func (r *Registry) Register(info Info, terminate func() error) (id string, deregister func()) {
	id = uuid.NewString()
	info.ID = id
	if info.Start.IsZero() {
		info.Start = time.Now().UTC()
	}
	r.mu.Lock()
	r.entries[id] = &entry{info: info, terminate: terminate}
	r.mu.Unlock()
	return id, func() {
		r.mu.Lock()
		delete(r.entries, id)
		r.mu.Unlock()
	}
}

// AddChannels adjusts the reported channel count for a session (delta may be
// negative). Unknown ids are ignored.
func (r *Registry) AddChannels(id string, delta int) {
	r.mu.Lock()
	if e, ok := r.entries[id]; ok {
		e.info.Channels += delta
		if e.info.Channels < 0 {
			e.info.Channels = 0
		}
	}
	r.mu.Unlock()
}

// List returns a snapshot of all live sessions, ordered by start time.
func (r *Registry) List() []Info {
	r.mu.RLock()
	out := make([]Info, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e.info)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// Get returns one session snapshot.
func (r *Registry) Get(id string) (Info, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[id]
	if !ok {
		return Info{}, false
	}
	return e.info, true
}

// Terminate invokes the session's terminate hook (closing its SSH connection).
// It returns ErrNotFound for an unknown id and ErrNotTerminable if the session
// registered no hook.
func (r *Registry) Terminate(id string) error {
	r.mu.RLock()
	e, ok := r.entries[id]
	r.mu.RUnlock()
	if !ok {
		return ErrNotFound
	}
	if e.terminate == nil {
		return ErrNotTerminable
	}
	return e.terminate()
}
