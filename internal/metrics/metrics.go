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
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

type counter struct{ v atomic.Int64 }

func (c *counter) inc()       { c.v.Add(1) }
func (c *counter) get() int64 { return c.v.Load() }

// Latency bucket boundaries, in seconds, as package-level vars so a deployment
// with different expectations can tune them in one place. Both are ascending
// and exclude +Inf, which every histogram appends itself.
var (
	// SetupBuckets suit the sub-second-to-a-minute work of admitting a
	// connection: an SSH handshake and directory bind land in the low
	// milliseconds, a slow directory or a far target in the seconds.
	SetupBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

	// LifetimeBuckets suit whole sessions, which range from a scripted
	// command that ends at once to a shell parked for a working day.
	LifetimeBuckets = []float64{1, 5, 15, 30, 60, 300, 900, 1800, 3600, 14400, 28800}
)

// histogram is a lock-free Prometheus histogram over a fixed bucket set. Like
// the counters above it is written from the data path and read by a scrape,
// so every field is atomic and observe() never allocates.
type histogram struct {
	bounds  []float64
	buckets []atomic.Int64 // per-bucket, NOT cumulative; summed at render time
	sumBits atomic.Uint64  // float64 seconds, CAS-updated
	count   atomic.Int64
}

func newHistogram(bounds []float64) *histogram {
	return &histogram{bounds: bounds, buckets: make([]atomic.Int64, len(bounds))}
}

// observe records one duration. The bucket is incremented before the count so
// a concurrent scrape can only ever read a cumulative bucket total <= _count,
// never a bucket larger than the +Inf bucket (which would be invalid output).
func (h *histogram) observe(d time.Duration) {
	v := d.Seconds()
	if i := sort.SearchFloat64s(h.bounds, v); i < len(h.bounds) {
		h.buckets[i].Add(1) // bounds[i] is the first boundary with v <= le
	}
	for {
		old := h.sumBits.Load()
		if h.sumBits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+v)) {
			break
		}
	}
	h.count.Add(1)
}

// write emits the _bucket/_sum/_count series for one histogram. labels is the
// already-rendered label set this series carries ("" for an unlabeled family).
// An untouched histogram still writes every series, at zero.
func (h *histogram) write(w io.Writer, name, labels string) {
	le := func(v string) string {
		if labels == "" {
			return fmt.Sprintf("{le=%q}", v)
		}
		return fmt.Sprintf("{%s,le=%q}", labels, v)
	}
	suffix := ""
	if labels != "" {
		suffix = "{" + labels + "}"
	}
	var cum int64
	for i, b := range h.bounds {
		cum += h.buckets[i].Load()
		fmt.Fprintf(w, "omnisag_%s_bucket%s %d\n", name, le(formatFloat(b)), cum)
	}
	count := h.count.Load()
	fmt.Fprintf(w, "omnisag_%s_bucket%s %d\n", name, le("+Inf"), count)
	fmt.Fprintf(w, "omnisag_%s_sum%s %s\n", name, suffix, formatFloat(math.Float64frombits(h.sumBits.Load())))
	fmt.Fprintf(w, "omnisag_%s_count%s %d\n", name, suffix, count)
}

func formatFloat(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

// Metrics holds the gateway counters and an active-sessions gauge source.
type Metrics struct {
	authSuccess, authFailure         counter
	mfaApproved, mfaDenied           counter
	tunnelAllow, tunnelDeny          counter
	approvalGranted, approvalRefused counter
	inspectClean, inspectBlocked     counter
	recordings, transfers            counter
	evidenceEmitFailures             counter

	// exportDropped counts events dropped by the (optional) SIEM export
	// fan-out, keyed by exporter name. A map, not a fixed field like the
	// counters above, because exporter names are config-driven (internal/
	// eventexport), not a fixed known set.
	exportDropped sync.Map // string -> *counter

	// Latency histograms. Split by outcome where the data path already knows
	// it; no user, source-IP or target label is ever attached, so the series
	// count stays fixed no matter how many distinct principals or hosts the
	// gateway serves.
	authOK, authFail   *histogram
	setupOK, setupFail *histogram
	sessionLifetime    *histogram

	activeFn             func() int64
	otelExportFailuresFn func() int64
}

// IncExportDrop increments the drop counter for the named export
// destination (internal/eventexport's onDrop callback). Safe to call
// concurrently for any exporter name, including one seen for the first time.
func (m *Metrics) IncExportDrop(exporter string) {
	v, _ := m.exportDropped.LoadOrStore(exporter, &counter{})
	v.(*counter).inc()
}

// New returns a Metrics with a zero active gauge and empty histograms.
func New() *Metrics {
	return &Metrics{
		authOK:               newHistogram(SetupBuckets),
		authFail:             newHistogram(SetupBuckets),
		setupOK:              newHistogram(SetupBuckets),
		setupFail:            newHistogram(SetupBuckets),
		sessionLifetime:      newHistogram(LifetimeBuckets),
		activeFn:             func() int64 { return 0 },
		otelExportFailuresFn: func() int64 { return 0 },
	}
}

// ObserveAuth records how long a client connection took to reach its
// authentication decision, measured from the moment the connection was
// accepted. ok distinguishes an authenticated connection from a rejected one:
// the two have very different shapes and averaging them hides both.
func (m *Metrics) ObserveAuth(d time.Duration, ok bool) {
	pickHist(ok, m.authOK, m.authFail).observe(d)
}

// ObserveSessionSetup records how long it took to establish the gateway's
// second SSH leg to the target (credential resolution, TCP dial and target
// handshake) — the wait between an authenticated client asking for a session
// and that session being usable. Observed once per gateway connection, on
// first use, for shell/SFTP/scp sessions.
func (m *Metrics) ObserveSessionSetup(d time.Duration, ok bool) {
	pickHist(ok, m.setupOK, m.setupFail).observe(d)
}

// ObserveSessionLifetime records how long an authenticated connection lived,
// from the completed handshake to teardown. Unsplit: a session that ends
// because the client left and one that ends because the target died look the
// same from here.
func (m *Metrics) ObserveSessionLifetime(d time.Duration) {
	m.sessionLifetime.observe(d)
}

func pickHist(ok bool, yes, no *histogram) *histogram {
	if ok {
		return yes
	}
	return no
}

// SetActiveFn wires the active-sessions gauge to a source (e.g. the session
// registry's live count).
func (m *Metrics) SetActiveFn(fn func() int64) {
	if fn != nil {
		m.activeFn = fn
	}
}

// SetOTelExportFailuresFn wires the OTLP export-failures counter to a source
// (otelexport.Providers.ExportFailures). Unset (the default, OTel disabled)
// reports zero. Mirrors SetActiveFn.
func (m *Metrics) SetOTelExportFailuresFn(fn func() int64) {
	if fn != nil {
		m.otelExportFailuresFn = fn
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
		// Bucket only TERMINAL outcomes. Both the dialer and the SFTP
		// quarantine-release path emit a non-terminal "requested" event
		// (Allow left nil/unset — a pending request is neither an allow nor
		// a deny) per gated session; switching on Outcome rather than Allow
		// means "requested" simply falls through here without a bucket,
		// so counting it as a refusal never double-counts an approval flow
		// into the refused total.
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

// Snapshot returns the current value of every fixed-name counter, keyed by
// the same name used in the Prometheus text output (without the omnisag_
// prefix). Used by the optional OTLP metrics exporter (internal/otelexport)
// to register observable counters that read these same atomics — there is
// no second counting decorator, so Prometheus stays the single source of
// truth and this is purely an additional read path.
func (m *Metrics) Snapshot() map[string]int64 {
	return map[string]int64{
		"auth_success_total":           m.authSuccess.get(),
		"auth_failure_total":           m.authFailure.get(),
		"mfa_approved_total":           m.mfaApproved.get(),
		"mfa_denied_total":             m.mfaDenied.get(),
		"tunnel_allow_total":           m.tunnelAllow.get(),
		"tunnel_deny_total":            m.tunnelDeny.get(),
		"approval_granted_total":       m.approvalGranted.get(),
		"approval_refused_total":       m.approvalRefused.get(),
		"inspection_clean_total":       m.inspectClean.get(),
		"inspection_blocked_total":     m.inspectBlocked.get(),
		"recordings_total":             m.recordings.get(),
		"transfers_total":              m.transfers.get(),
		"evidence_emit_failures_total": m.evidenceEmitFailures.get(),
		"otel_export_failures_total":   m.otelExportFailuresFn(),
	}
}

// histSeries pairs one histogram with the label set it is exposed under. A
// family's HELP/TYPE is written once, then every series beneath it.
type histSeries struct {
	labels string
	h      *histogram
}

func writeHistogram(w io.Writer, name, help string, series ...histSeries) {
	fmt.Fprintf(w, "# HELP omnisag_%s %s\n# TYPE omnisag_%s histogram\n", name, help, name)
	for _, s := range series {
		s.h.write(w, name, s.labels)
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
	ctr("otel_export_failures_total", "OTLP export failures/drops", m.otelExportFailuresFn())

	writeHistogram(w, "auth_duration_seconds",
		"Time from connection accepted to authentication decision",
		histSeries{`result="success"`, m.authOK}, histSeries{`result="failure"`, m.authFail})
	writeHistogram(w, "session_setup_duration_seconds",
		"Time to establish the target connection for a shell/SFTP/scp session (excludes -L tunnel dials)",
		histSeries{`result="success"`, m.setupOK}, histSeries{`result="failure"`, m.setupFail})
	writeHistogram(w, "session_duration_seconds",
		"Lifetime of an authenticated connection, handshake to teardown",
		histSeries{"", m.sessionLifetime})

	// exportDropped is a labeled counter (one series per exporter name), so
	// it can't use the fixed-name ctr helper above; emit HELP/TYPE once then
	// one line per exporter, sorted for stable output.
	var names []string
	m.exportDropped.Range(func(k, _ any) bool {
		names = append(names, k.(string))
		return true
	})
	sort.Strings(names)
	fmt.Fprintf(w, "# HELP omnisag_eventexport_dropped_total Events dropped by a SIEM export destination\n# TYPE omnisag_eventexport_dropped_total counter\n")
	for _, name := range names {
		v, _ := m.exportDropped.Load(name)
		fmt.Fprintf(w, "omnisag_eventexport_dropped_total{exporter=%q} %d\n", name, v.(*counter).get())
	}
}
