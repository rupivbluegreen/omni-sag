# Event export / SIEM integration — design

**Status:** Approved (brainstorming), not yet implemented
**Date:** 2026-07-19
**Issue:** #19 (epic #18 — DORA Art. 10 detection arc)

> New feature; move to its own branch (fresh from master) before implementation.

## Context

omni-sag captures a complete tamper-evident audit trail (hash-chained,
optionally WORM-archived) but **emits nothing in real time** — every
downstream detection/reporting obligation assumes machine-readable events
leave the box. This feature streams the existing evidence events out to a
SIEM, in real time, in the format/transport the target expects.

**Regulatory driver (cited):** DORA (Reg. (EU) 2022/2554) Art. 10 (detection)
+ Art. 17 (incident management); **PCI-DSS 4.0 Req 10.4.1.1 — automated log
review, mandatory since 31 Mar 2025**; NIS2 Art. 21(2)/23; SWIFT CSCF 6.4.
This is the foundation of the DORA Art. 10 detection arc (#18): anomaly
detection (#20) and incident classification (#21) both need events leaving
the box first.

## What it reuses (no new event plumbing)

The event model + composition seam already exist:
- `evidence.Sink` interface (`Emit(Event) error` / `Close()`),
  `internal/evidence/evidence.go:71`.
- Implementations: `FileSink` (JSONL), `S3Sink`, the pipeline `bus`, `MemSink`.
- The **decorator pattern is proven**: `metrics.CountingSink`
  (`internal/metrics/metrics.go:50`) wraps an inner sink. Event export is the
  same shape — a fan-out decorator around the durable sink.

Every security event already flows through the sink: `auth`,
`tunnel_decision`, `session_start/end`, `transfer`, `inspection`,
`credential`, `approval`, `supervision`, `tunnel_protocol`. Export adds a
destination + a wire-format mapping, not new instrumentation.

## Non-goals / limits

- **The SIEM stream is a detective feed, not the system of record.** The
  hash-chained/WORM evidence pipeline remains authoritative. Export is
  **best-effort**: it may drop under overflow/outage, reconciled from the
  durable store. (User-chosen posture.)
- Not a log *storage* system, not a query interface — it forwards.
- No PII redaction here (that is #24); events already exclude secrets by
  construction.

## Architecture

A **format × transport matrix**, with **multiple concurrent exporters**
(e.g. CEF→ArcSight AND ECS→Elastic simultaneously), each async and
best-effort, fanned out alongside the durable sink.

```
session/dialer emit ─▶ ForwardingSink.Emit(e)
                         ├─▶ inner (durable: file/S3/bus)  [inline, authoritative]
                         ├─▶ exporter[0].offer(e)  [non-blocking → async ArcSight]
                         └─▶ exporter[1].offer(e)  [non-blocking → async Elastic]
```

Two small interfaces:

```go
// Formatter renders an evidence.Event to a target wire format.
type Formatter interface {
    Format(e evidence.Event) ([]byte, error)
    ContentType() string // for http transport / framing hints
}

// Transport delivers formatted payloads to a destination.
type Transport interface {
    Write(payload []byte) error // one event (file/syslog) or buffered (http)
    Flush() error
    Close() error
}
```

**Formatters** (`format:` flag): `json` (generic; the Event already
JSON-marshals), `ecs` (Elastic Common Schema field mapping), `cef` (ArcSight
Common Event Format — header + `key=value` extension).

**Transports** (`transport:` flag): `file` (append newline-delimited, for
filebeat/logbeat to tail), `syslog` (RFC 5424 over UDP/TCP/**TLS**, with
reconnect), `http` (batched POST — Elastic `_bulk` / HEC / generic; auth +
TLS + batch/flush).

### The async engine (best-effort, never blocks the hot path)

```go
type asyncExporter struct {
    name      string
    fmtr      Formatter
    tr        Transport
    buf       chan evidence.Event // bounded (buffer_size)
    dropped   metric counter      // exported via the existing metrics registry
}
// offer is non-blocking: full buffer → increment dropped, return immediately.
func (a *asyncExporter) offer(e evidence.Event) {
    select {
    case a.buf <- e:
    default:
        a.dropped.Inc() // best-effort: durable evidence reconciles the gap
    }
}
// run drains buf → Format → Transport.Write in a single goroutine per
// exporter (preserves per-exporter ordering), with periodic Flush for http.
```

`ForwardingSink` wraps the durable sink: `Emit` calls `inner.Emit(e)` inline
(authoritative — its error is the returned error), then `offer`s to every
exporter. A slow/broken SIEM can never stall a session, and can never fail an
`Emit` (the durable write already succeeded).

Wiring: build `ForwardingSink(durableSink, exporters...)` in `cmd/omni-sag/
main.go` where the durable sink is handed to dialer/session today (around the
`met.CountingSink(...)` wrap). Compose cleanly with `CountingSink` (both are
decorators).

## Config schema

```yaml
export:
  enabled: true
  exporters:
    - name: arcsight
      format: cef
      transport: syslog
      buffer_size: 10000
      syslog: { address: "arcsight:6514", protocol: tls, facility: local0,
                tls: { ca: "ca.pem", cert: "c.pem", key: "k.pem" } }
    - name: elastic-filebeat
      format: ecs
      transport: file
      buffer_size: 10000
      file: { path: "/var/log/omni-sag/events.ecs.jsonl" }
    - name: elastic-direct
      format: ecs
      transport: http
      buffer_size: 10000
      http: { url: "https://es:9200/_bulk", batch_size: 100,
              flush_interval_seconds: 5, auth: { bearer_env: "ES_TOKEN" },
              tls: { ca: "es-ca.pem" } }
```

Opt-in (`enabled` default false). Validation: each exporter needs a valid
`format` ∈ {json,ecs,cef}, `transport` ∈ {file,syslog,http}, and the matching
transport sub-block; `buffer_size` defaults 10000. An unknown format/transport
is a boot error. `otlp` transport is intentionally **reserved for the
OpenTelemetry design** (separate spec) — OTLP-logs should be an exporter
transport here rather than a parallel path; coordinate the enum with that spec.

## Field mapping (per formatter)

Common projection from `evidence.Event`:
| concept | Event field | ECS | CEF |
|---|---|---|---|
| timestamp | `Time` | `@timestamp` | `rt` |
| actor | `User` | `user.name` | `suser` |
| source | `SourceIP` | `source.ip` | `src` |
| target | `Target` (host:port) | `destination.address`/`.port` | `dst`/`dpt` |
| action | `Type` | `event.action` | CEF `name` + `cat` |
| outcome | `Allow` | `event.outcome` (success/failure) | `outcome` |
| reason | `Reason` | `message` | `msg` |
| protocol | `Protocol` | `network.protocol` | `app` |
| object | `ObjectKey`/`SHA256`/`Path` | `file.*` | custom ext |

CEF header: `CEF:0|omni-sag|gateway|<ver>|<Type>|<Type>|<sev>|<ext>`; severity
mapped by type (auth-fail/deny/blocked → higher). ECS emits one JSON object
per line. `json` emits the raw Event (already the JSONL shape).

## Testing plan
- Formatter unit tests: golden output per event type for `json`/`ecs`/`cef`
  (assert required fields; CEF header well-formed; ECS validates against a
  minimal ECS field check).
- Transport unit tests: `file` (bytes appended, newline-framed); `syslog`
  (RFC 5424 framing; reconnect on drop — use a local TCP listener); `http`
  (batching + flush + retry-none best-effort — use `httptest.Server`).
- Async engine: `offer` never blocks; buffer-overflow increments `dropped`
  and does NOT block; per-exporter ordering preserved; `Emit` returns the
  durable sink's error only (a broken exporter never fails Emit). Use a
  goroutine + timeout guard so a regression (blocking offer) fails loudly.
- Fan-out integration: two exporters concurrently (cef+syslog, ecs+file) both
  receive every event; durable sink still gets all events.
- Config: multi-exporter parse + defaults + invalid enum rejection.
- Real-SIEM-ish interop (ground truth): a lab test that runs the gateway with
  a `syslog`+`cef` exporter pointed at a local TCP syslog listener (a small
  netcat/Go receiver) and asserts well-formed CEF lines arrive for real
  sessions — mirrors the scp lab-test discipline.

## Rollout
1. Ship `file`/`syslog`/`http` × `json`/`ecs`/`cef`, multiple concurrent,
   best-effort. Covers ArcSight (cef+syslog), Elastic-via-filebeat (ecs+file),
   Elastic-direct (ecs+http), generic syslog.
2. `otlp` transport lands with the OpenTelemetry work (separate spec),
   reusing this engine.
3. Feeds #20 (anomaly detection) and #21 (incident classification).

## Out of scope
- OTLP transport / OpenTelemetry traces+metrics (separate spec).
- Guaranteed delivery / durable spool (best-effort by decision; durable
  evidence is the backstop).
- SIEM-side content (dashboards, correlation rules).
- PII redaction (#24).
