// Package metrics exposes the gateway's Prometheus metrics. Counting is done by
// decorating the evidence sink (CountingSink): the emit path that already runs
// on every security event increments atomic counters, so there is NO extra
// instrumentation in the data-path hot loop and this package does NOT import the
// control plane (it is a leaf importing only internal/evidence). The /metrics
// handler reads only atomic values, so a scrape never blocks SSH.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sync/atomic"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

type counter struct{ v atomic.Int64 }

func (c *counter) inc()       { c.v.Add(1) }
func (c *counter) get() int64 { return c.v.Load() }

// Metrics holds the gateway counters and an active-sessions gauge source.
type Metrics struct {
	authSuccess, authFailure         counter
	mfaApproved, mfaDenied           counter
	tunnelAllow, tunnelDeny          counter
	approvalGranted, approvalRefused counter
	inspectClean, inspectBlocked     counter
	recordings, transfers            counter
	evidenceEmitFailures             counter

	activeFn func() int64
}

// New returns a Metrics with a zero active gauge.
func New() *Metrics { return &Metrics{activeFn: func() int64 { return 0 }} }

// SetActiveFn wires the active-sessions gauge to a source (e.g. the session
// registry's live count).
func (m *Metrics) SetActiveFn(fn func() int64) {
	if fn != nil {
		m.activeFn = fn
	}
}

// CountingSink returns an evidence.Sink that increments counters by event type
// then delegates to inner. An inner emit failure increments a counter too, so
// evidence-pipeline degradation is observable.
func (m *Metrics) CountingSink(inner evidence.Sink) evidence.Sink {
	return &countingSink{m: m, inner: inner}
}

type countingSink struct {
	m     *Metrics
	inner evidence.Sink
}

func (c *countingSink) Emit(e evidence.Event) error {
	c.m.record(e)
	err := c.inner.Emit(e)
	if err != nil {
		c.m.evidenceEmitFailures.inc()
	}
	return err
}

func (c *countingSink) Close() error { return c.inner.Close() }

func allowed(e evidence.Event) bool { return e.Allow != nil && *e.Allow }

func (m *Metrics) record(e evidence.Event) {
	switch e.Type {
	case evidence.TypeAuth:
		pick(allowed(e), &m.authSuccess, &m.authFailure)
	case evidence.TypeMFA:
		pick(allowed(e), &m.mfaApproved, &m.mfaDenied)
	case evidence.TypeTunnelDecision:
		pick(allowed(e), &m.tunnelAllow, &m.tunnelDeny)
	case evidence.TypeApproval:
		// Bucket only TERMINAL outcomes. The dialer emits a non-terminal
		// "requested" event (Allow=false) per gated session; counting it as a
		// refusal would double every approval flow into the refused total.
		switch e.Outcome {
		case "granted":
			m.approvalGranted.inc()
		case "refused":
			m.approvalRefused.inc()
		}
	case evidence.TypeInspection:
		if e.Verdict == "clean" {
			m.inspectClean.inc()
		} else {
			m.inspectBlocked.inc() // blocked | error | modified all count as blocked
		}
	case evidence.TypeRecording:
		m.recordings.inc()
	case evidence.TypeTransfer:
		m.transfers.inc()
	}
}

func pick(ok bool, yes, no *counter) {
	if ok {
		yes.inc()
	} else {
		no.inc()
	}
}

// Handler renders Prometheus text-format metrics.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		m.WriteText(w)
	})
}

// WriteText writes the metrics in Prometheus exposition format.
func (m *Metrics) WriteText(w io.Writer) {
	fmt.Fprintf(w, "# HELP omnisag_active_sessions Current active SSH sessions\n# TYPE omnisag_active_sessions gauge\nomnisag_active_sessions %d\n", m.activeFn())
	ctr := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP omnisag_%s %s\n# TYPE omnisag_%s counter\nomnisag_%s %d\n", name, help, name, name, v)
	}
	ctr("auth_success_total", "Successful authentications", m.authSuccess.get())
	ctr("auth_failure_total", "Failed authentications", m.authFailure.get())
	ctr("mfa_approved_total", "MFA second factor approved", m.mfaApproved.get())
	ctr("mfa_denied_total", "MFA second factor denied", m.mfaDenied.get())
	ctr("tunnel_allow_total", "Tunnel decisions allowed", m.tunnelAllow.get())
	ctr("tunnel_deny_total", "Tunnel decisions denied", m.tunnelDeny.get())
	ctr("approval_granted_total", "Four-eyes approvals granted", m.approvalGranted.get())
	ctr("approval_refused_total", "Four-eyes approvals refused", m.approvalRefused.get())
	ctr("inspection_clean_total", "Content inspections clean", m.inspectClean.get())
	ctr("inspection_blocked_total", "Content inspections blocked/quarantined", m.inspectBlocked.get())
	ctr("recordings_total", "Session recordings produced", m.recordings.get())
	ctr("transfers_total", "SFTP transfers", m.transfers.get())
	ctr("evidence_emit_failures_total", "Evidence emit failures", m.evidenceEmitFailures.get())
}
