# Event export / SIEM integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stream omni-sag's evidence events to SIEMs in real time via a pluggable **format × transport** matrix, with **multiple concurrent exporters**, **best-effort async** delivery that never blocks the session hot path.

**Architecture:** A `ForwardingSink` decorator wraps the durable evidence sink (file/S3/bus): `Emit` writes durable inline (authoritative), then non-blocking-`offer`s the event to each configured `asyncExporter`. Each exporter = a `Formatter` (json|ecs|cef) + a `Transport` (file|syslog|http) draining a bounded buffer in its own goroutine; overflow/outage drops with a metric. Reuses the existing `evidence.Sink` seam and the `metrics.CountingSink` decorator pattern.

**Spec:** `docs/superpowers/specs/2026-07-19-event-export-siem-design.md` (read it — field-mapping table, config schema, rationale).

**Tech Stack:** Go stdlib (`log/syslog` is insufficient for RFC5424+TLS — use a small hand-rolled RFC 5424 framing over `net`/`crypto/tls`), `net/http` for the http transport. No new heavy deps.

## Global Constraints

- **Opt-in, default OFF** (`export.enabled: false`). Consistent with `enable_scp`/`tunnel_inspection`.
- **Best-effort, never blocks.** `offer` is a non-blocking channel send; full buffer → increment a drop metric, return immediately. A slow/dead SIEM must never stall a session or fail an `Emit` (the durable write already succeeded and is the authoritative record).
- **Multiple concurrent exporters** — `export.exporters` is a list; e.g. cef+syslog→ArcSight AND ecs+file→Elastic simultaneously.
- **Formats:** `json` | `ecs` | `cef`. **Transports:** `file` | `syslog` | `http`. Unknown enum = boot error.
- **Transport interface is `Write(payload []byte) error` / `Flush() error` / `Close() error`** — canonical; the future OTel `otlp` transport must match this shape (see the OTel spec's boundary section).
- **Durable sink stays authoritative.** The SIEM stream is a detective feed; gaps reconcile from the hash-chained/WORM evidence.
- Reuse the existing event set unchanged (`auth`, `tunnel_decision`, `session_start/end`, `transfer`, `inspection`, `credential`, `approval`, `supervision`, `tunnel_protocol`). No new instrumentation, no `evidence.Event` change in this feature.
- New package `internal/eventexport` — a leaf that imports only `internal/evidence` (+ stdlib); it must NOT import `session`/`dialer`.
- Default `buffer_size: 10000`.

---

### Task 1: `internal/eventexport` — Formatter interface + `json` + `cef` + `ecs`

**Files:**
- Create: `internal/eventexport/format.go`, `internal/eventexport/format_cef.go`, `internal/eventexport/format_ecs.go`
- Test: `internal/eventexport/format_test.go`

**Interfaces:**
- Produces: `type Formatter interface { Format(evidence.Event) ([]byte, error); ContentType() string }`; `func NewFormatter(name string) (Formatter, error)` (`json`|`ecs`|`cef`); consumed by Tasks 3–4.

- [ ] **Step 1: Write failing golden tests** (`format_test.go`) — one representative event per formatter, asserting required fields:

```go
package eventexport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

func sampleEvent() evidence.Event {
	deny := false
	return evidence.Event{
		Time: time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC),
		Type: evidence.TypeTunnelDecision, User: "alice", SourceIP: "10.0.0.1",
		Target: "db1:5432", Allow: &deny, Reason: "administratively prohibited",
	}
}

func TestJSONFormatter(t *testing.T) {
	f, _ := NewFormatter("json")
	out, err := f.Format(sampleEvent())
	if err != nil { t.Fatal(err) }
	var back evidence.Event
	if err := json.Unmarshal(out, &back); err != nil { t.Fatalf("json not round-trippable: %v", err) }
	if back.User != "alice" || back.Type != evidence.TypeTunnelDecision {
		t.Fatalf("json missing fields: %s", out)
	}
}

func TestCEFFormatter(t *testing.T) {
	f, _ := NewFormatter("cef")
	out := string(mustFormat(t, f, sampleEvent()))
	// CEF:0|vendor|product|version|sig|name|severity|ext...
	if !strings.HasPrefix(out, "CEF:0|omni-sag|gateway|") {
		t.Fatalf("bad CEF header: %s", out)
	}
	for _, want := range []string{"suser=alice", "src=10.0.0.1", "outcome=", "administratively prohibited"} {
		if !strings.Contains(out, want) { t.Fatalf("CEF missing %q: %s", want, out) }
	}
}

func TestECSFormatter(t *testing.T) {
	f, _ := NewFormatter("ecs")
	var m map[string]any
	if err := json.Unmarshal(mustFormat(t, f, sampleEvent()), &m); err != nil { t.Fatal(err) }
	if m["user.name"] != "alice" && deepGet(m, "user", "name") != "alice" {
		t.Fatalf("ECS user.name missing: %v", m)
	}
	if deepGet(m, "event", "outcome") != "failure" {
		t.Fatalf("ECS event.outcome should be failure for a denied event: %v", m)
	}
}

func TestNewFormatter_Unknown(t *testing.T) {
	if _, err := NewFormatter("nope"); err == nil { t.Fatal("want error for unknown format") }
}
```

(Provide `mustFormat` + `deepGet` test helpers; `deepGet` walks nested ECS objects.)

- [ ] **Step 2: Run to verify fail** (package doesn't exist).

- [ ] **Step 3: Implement.** `format.go` — the interface, `NewFormatter` switch, and the `json` formatter (`json.Marshal(e)` — the Event already has json tags; `ContentType()` = `application/json`). `format_cef.go` — CEF header (`CEF:0|omni-sag|gateway|<version>|<Type>|<Type>|<sev>|`) + extension `key=value` pairs from the spec's field-mapping table, with CEF escaping (`\`, `=`, `|`, newline). Severity by type (auth-fail/deny/blocked → 7-9, else 3). `format_ecs.go` — build a `map[string]any` with ECS nested keys (`@timestamp`, `user.name`, `source.ip`, `destination.address/.port`, `event.action`, `event.outcome` = success/failure from `Allow`, `message`, `network.protocol` from `Protocol`), `json.Marshal`. Use the spec table as the authoritative mapping. Emit one line each (no trailing newline — the transport frames).

- [ ] **Step 4: Run tests + gofmt + vet.**
- [ ] **Step 5: Commit** `feat(eventexport): json/ecs/cef formatters`.

---

### Task 2: Transport interface + `file` + `syslog` + `http`

**Files:**
- Create: `internal/eventexport/transport.go`, `transport_file.go`, `transport_syslog.go`, `transport_http.go`
- Test: `internal/eventexport/transport_test.go`

**Interfaces:**
- Produces: `type Transport interface { Write(payload []byte) error; Flush() error; Close() error }`; constructors `newFileTransport(cfg)`, `newSyslogTransport(cfg)`, `newHTTPTransport(cfg)`; consumed by Task 4.

- [ ] **Step 1: Failing tests** — each transport against a local sink:
  - `file`: writes newline-framed lines to a temp file; assert bytes + newline framing; reopen/append safe.
  - `syslog`: spin a local `net.Listen("tcp")`, point the transport at it, `Write` one payload, assert an RFC 5424 frame arrives (`<PRI>1 TIMESTAMP host app - - - MSG`, octet-counting or newline framing per config); assert **reconnect** after the listener drops and re-accepts.
  - `http`: `httptest.Server`; assert batched POST body contains the payloads, correct `Content-Type`, `flush_interval`/`batch_size` honored, and best-effort (a 500 response does NOT return a fatal that blocks — it's logged/counted, retry-none in v1).

```go
func TestFileTransport(t *testing.T) {
	p := filepath.Join(t.TempDir(), "e.jsonl")
	tr, err := newFileTransport(fileConfig{Path: p}); if err != nil { t.Fatal(err) }
	if err := tr.Write([]byte(`{"a":1}`)); err != nil { t.Fatal(err) }
	tr.Flush(); tr.Close()
	b, _ := os.ReadFile(p)
	if string(b) != "{\"a\":1}\n" { t.Fatalf("got %q", b) }
}
func TestSyslogTransport_FramesAndReconnects(t *testing.T) { /* local TCP listener; assert frame; drop+reaccept; assert reconnect */ }
func TestHTTPTransport_BatchesAndFlushes(t *testing.T) { /* httptest.Server; assert batch body + content-type */ }
```

- [ ] **Step 2-3: implement.** `file` = buffered append + newline. `syslog` = dial (udp/tcp/tls per `protocol`), RFC 5424 framing (PRI = facility*8+severity; app-name `omni-sag`), lazy reconnect on write error (mark broken, redial next Write; a persistent failure surfaces via the async engine's drop metric, not a block). `http` = accumulate up to `batch_size`, POST on batch-full or `Flush()` (called on `flush_interval` by the engine), bearer/basic auth from env, TLS config; a non-2xx increments a failure count and drops the batch (best-effort, no spool in v1).

- [ ] **Step 4-5: tests, gofmt, vet, commit** `feat(eventexport): file/syslog/http transports`.

---

### Task 3: Async engine — `asyncExporter` (offer + run + drop metric)

**Files:**
- Create: `internal/eventexport/exporter.go`
- Test: `internal/eventexport/exporter_test.go`

**Interfaces:**
- Consumes: `Formatter`, `Transport` (Tasks 1-2).
- Produces: `type asyncExporter struct{...}`; `func newAsyncExporter(name string, f Formatter, t Transport, bufSize int, onDrop func()) *asyncExporter`; methods `offer(evidence.Event)`, `start(ctx)`, `shutdown()`; consumed by Task 4.

- [ ] **Step 1: Failing tests** — the reliability contract:
  - `offer` never blocks: fill the buffer, then `offer` again inside a goroutine with a 2s timeout guard; assert it returns immediately and `onDrop` fired (mirror the scp `TestScpCopyBody` timeout-guard pattern so a blocking regression fails loudly, not hangs).
  - drained events are formatted + written in order (per-exporter ordering).
  - a failing Transport (Write returns error) does NOT crash the goroutine or block offers — the engine keeps draining, drops/counts.
  - `shutdown` flushes and stops the goroutine (bounded).

- [ ] **Step 2-3: implement.**
```go
func (a *asyncExporter) offer(e evidence.Event) {
	select {
	case a.buf <- e:
	default:
		a.onDrop() // best-effort: durable evidence reconciles the gap
	}
}
func (a *asyncExporter) start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(a.flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				a.drainAndFlush(); _ = a.tr.Close(); close(a.done); return
			case e := <-a.buf:
				if b, err := a.fmtr.Format(e); err == nil {
					if werr := a.tr.Write(b); werr != nil { a.onDrop() /* + log once */ }
				}
			case <-ticker.C:
				_ = a.tr.Flush()
			}
		}
	}()
}
```
The drop metric is wired via `onDrop` (Task 5 connects it to the metrics registry as `eventexport_dropped_total{exporter=...}`).

- [ ] **Step 4-5: tests (with the timeout guard), gofmt, vet, commit** `feat(eventexport): bounded best-effort async exporter`.

---

### Task 4: `ForwardingSink` fan-out + `Config` construction

**Files:**
- Create: `internal/eventexport/sink.go`, `internal/eventexport/config.go`
- Test: `internal/eventexport/sink_test.go`

**Interfaces:**
- Produces: `func New(inner evidence.Sink, cfg Config, metrics DropCounter) (*ForwardingSink, error)` implementing `evidence.Sink`; `type Config` (mirrors the yaml — list of exporter specs); consumed by Task 5 + Task 6 config.

- [ ] **Step 1: Failing fan-out test** — two exporters (json+file, cef+file to two temp files) both receive every event, AND the inner durable sink receives every event, AND `Emit` returns the inner sink's error (never an exporter's). Use a `MemSink` as inner + two file transports; drive N events; assert all three destinations have N.

```go
func TestForwardingSink_FanOutAndDurableAuthoritative(t *testing.T) {
	inner := evidence.NewMemSink()
	cfg := Config{Enabled: true, Exporters: []ExporterConfig{
		{Name: "a", Format: "json", Transport: "file", File: fileConfig{Path: fileA}},
		{Name: "b", Format: "cef",  Transport: "file", File: fileConfig{Path: fileB}},
	}}
	fs, _ := New(inner, cfg, noopDrop{})
	for i := 0; i < 50; i++ { _ = fs.Emit(evidence.Event{Type: evidence.TypeAuth, User: "u"}) }
	fs.Close() // drains
	// assert inner has 50, fileA has 50 json lines, fileB has 50 CEF lines
}
```

- [ ] **Step 2-3: implement.** `ForwardingSink{ inner evidence.Sink; exporters []*asyncExporter; ctx; cancel }`. `Emit(e)` → `err := inner.Emit(e)` (inline, authoritative); then `for _, x := range exporters { x.offer(e) }`; `return err`. `Close()` cancels the ctx (draining exporters) then `inner.Close()`. `New` builds each exporter from config via `NewFormatter`/`newXTransport`, validates enums (return a boot error on unknown), starts their goroutines.

- [ ] **Step 4-5: tests, gofmt, vet, commit** `feat(eventexport): fan-out ForwardingSink over durable sink`.

---

### Task 5: Config wiring — `export` block in `internal/config` + `cmd/omni-sag/main.go`

**Files:**
- Modify: `internal/config/config.go` (`File.Export *ExportConfig` + structs + validation)
- Modify: `cmd/omni-sag/main.go` (wrap the durable sink with `eventexport.New(...)` before it's handed to dialer/session; boot log; drop-metric wiring; shutdown)
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Failing config test** — the multi-exporter YAML from the spec parses; defaults (`buffer_size`=10000); invalid `format`/`transport` rejected; `enabled: false` (default) yields nil/disabled.

- [ ] **Step 2-3: implement.** Add `ExportConfig` + `ExporterConfig` + transport sub-structs (`syslog`/`file`/`http`) to `internal/config`, mapping to `eventexport.Config`. In `main.go`, after building the durable `sink` (the `evidenceSystem`), if `cfg.Export != nil && cfg.Export.Enabled`, wrap: `sink = eventexport.New(sink, cfg.Export.toEventExport(), met.DropCounter("eventexport"))` — BEFORE the `met.CountingSink` wrap so counting still sees every event, or after (either is fine; document the order). Boot-log the active exporters (names + format/transport, never secrets). On shutdown, `sink.Close()` drains (the existing close hook).

- [ ] **Step 4-5:** config tests + `go build ./...` + example-config parse test; gofmt; vet; commit `feat(cmd): wire event export into the gateway`.

---

### Task 6: Best-effort / non-block integration test through the real sink path

**Files:**
- Test: `internal/eventexport/integration_test.go`

- [ ] **Step 1-4: write + run** a test proving a **dead/slow transport never blocks or fails Emit**: an exporter whose Transport.Write blocks forever (or a syslog transport pointed at a black-hole address); drive events through `ForwardingSink.Emit`; assert every `Emit` returns promptly (timeout-guarded) with the inner sink's result, the buffer overflows to drops (drop counter > 0), and no goroutine leaks after `Close()`. This is the reliability ground truth at the sink level.
- [ ] **Step 5: commit** `test(eventexport): dead-SIEM never blocks the emit path`.

---

### Task 7: Ground-truth lab interop — real CEF-over-syslog receiver

**Files:**
- Create: `scripts/lab-test-eventexport.sh`; Modify: `Makefile`

- [ ] **Step 1-4:** Script (mirrors `scripts/lab-test-scp.sh`): start a tiny local TCP syslog receiver (a few lines of Go or `nc -l`), run the gateway with a derived config adding `export: { enabled: true, exporters: [{name: soc, format: cef, transport: syslog, syslog: {address: 127.0.0.1:<port>, protocol: tcp}}] }`, drive a real session/tunnel against the dev lab, and assert **well-formed CEF lines for real events** (`auth`, `tunnel_decision`/`session_start`) arrive at the receiver. Ground truth that the formatter+transport interoperate with a real syslog consumer, not just Go tests. `ALL PASS`.
- [ ] **Step 5: commit** `test: real CEF-over-syslog event-export lab check`.

---

### Task 8: Docs — example config + README

**Files:**
- Modify: `deploy/compose/config.example.yaml`, `README.md`

- [ ] **Step 1-3:** Document the `export` block (opt-in, the multi-exporter list, the three formats/transports, best-effort caveat) in the example config; add a short README "Event export / SIEM" subsection (formats, transports, filebeat-tail path, best-effort posture, DORA/PCI driver). Note `otlp` transport arrives with the OpenTelemetry feature.
- [ ] **Step 4-5:** example-config parse test; commit `docs: event export / SIEM integration`.

---

## Self-Review Notes
- **Spec coverage:** Formatter matrix (T1) ✓; Transport matrix incl. http (T2) ✓; async best-effort engine + drop metric (T3) ✓; fan-out over durable + multiple concurrent (T4) ✓; config + wiring (T5) ✓; dead-SIEM-never-blocks (T6) ✓; real syslog interop ground truth (T7) ✓; docs (T8) ✓.
- **Risk is reliability, not format:** the non-block/best-effort contract is tested three ways (T3 offer-never-blocks, T6 sink-level dead-transport, T7 real receiver) with timeout guards so a blocking regression fails loudly.
- **Composition:** `ForwardingSink` is a plain `evidence.Sink` decorator — composes with the existing `CountingSink`, and the `Transport` interface (`Write/Flush/Close`) is the exact seam the future OTel `otlp` transport plugs into.
- **No `evidence.Event` change** in this feature (the trace_id/span_id fields are the OpenTelemetry feature's, per that spec).
