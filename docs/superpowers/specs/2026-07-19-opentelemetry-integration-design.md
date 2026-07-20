# OpenTelemetry (OTLP) integration — design

**Status:** Approved (brainstorming), not yet implemented
**Date:** 2026-07-19

> Note: this spec is for a NEW feature. Move it to its own branch (fresh from
> master) before implementation. It deliberately **composes with** the in-flight
> event-export / SIEM feature (#19) — read the "Boundary with #19" section
> before touching the logs path.

## Context

omni-sag already produces two of the three OpenTelemetry signals in
omni-sag-shaped form:

- **Evidence** — a hash-chained, Ed25519-signed, WORM-archived event stream
  (`internal/evidence`), the tamper-evident *compliance record*. Every
  subsystem emits into it through the ordered `Bus` (`bus.go`).
- **Metrics** — Prometheus counters/gauge, produced by decorating the evidence
  sink (`metrics.CountingSink`) and exposed on an out-of-band `/metrics`
  listener (`internal/metrics`).

What it has **no** story for today is **distributed tracing**: there is no way
to see a single privileged connection as one causal timeline — accept →
handshake/auth → policy decision → approval wait → credential fetch → target
dial → data pump — with per-hop latencies and parent/child structure. Operators
who already run an OpenTelemetry Collector (feeding Tempo/Jaeger/Datadog/etc.)
want that timeline, and want omni-sag's signals to arrive over **OTLP** like the
rest of their fleet.

This feature adds an **opt-in, default-off** OTLP egress for omni-sag:

- **Traces** — the genuinely new, high-value part: a span tree over the request
  lifecycle, correlated to the evidence event IDs. This is the headline
  deliverable.
- **Metrics** — an *optional* OTLP metrics path that **coexists with** (never
  replaces) the existing Prometheus endpoint.
- **Logs** — evidence-events-as-OTLP-logs, which **overlap the #19 exporter
  matrix** and are therefore delivered as a transport *inside* #19, not as a
  second parallel log path.

**Design posture (non-negotiable, inherited from the rest of the codebase):**
opt-in and default off; **never block a session** (all export is async, bounded,
best-effort, drop-on-overflow); **do not remove Prometheus**; keep the OTel
dependency surface localized to one leaf package.

## Non-goals / honest limits (stated up front)

- **OTLP is telemetry, not the audit record.** The evidence bus stays the
  single source of truth and the compliance artifact. OTLP spans/logs are
  *best-effort* and **droppable** — a collector outage loses telemetry, and that
  is acceptable *precisely because* the durable, signed, WORM evidence chain is
  unaffected. Nothing in the compliance story depends on a span arriving.
- **The OTel Go logs SDK is pre-GA (verified — see Dependencies).** The log API
  (`go.opentelemetry.io/otel/log`) is at **v0.x** and explicitly *does not follow
  standard Go versioning* (methods may be added to interfaces without a major
  bump). We treat OTLP-logs as **experimental**, isolate it behind one adapter,
  and never gate a GA-quality deliverable on it. **Traces and metrics are v1
  stable** and carry the feature.
- **Gateway-local traces only.** Spans cover activity *at the gateway*. We do
  **not** inject `traceparent` into the target-facing SSH stream, so the trace
  does not continue *inside* the target host. (Possible future; out of scope.)
- **No auto-instrumentation / eBPF / profiling signal.** Manual, explicit spans
  at the seams listed below.
- **Prometheus is not being migrated or removed.** Existing dashboards and
  alerts keep working byte-for-byte.

## Architecture

One new **leaf** package, `internal/otelexport`, owns *all* OTel SDK wiring —
resource construction, `TracerProvider` / `MeterProvider` / (`LoggerProvider`),
exporters, samplers, and a single `Shutdown(ctx)`. It imports the OTel
SDK; **nothing else in the tree does**, except the thin instrumentation call
sites (which use only the *global* API, `otel.Tracer(...)`, never the SDK). This
mirrors the codebase's leaf-package discipline (`internal/metrics` importing only
`internal/evidence`; `internal/protoident` importing nothing).

```go
package otelexport

// Providers holds the constructed SDK providers and a single shutdown hook.
// When config.enabled is false, Setup returns a zero Providers whose Shutdown
// is a no-op and installs NOTHING globally — so every instrumentation call
// site transparently gets the OTel no-op implementation (zero allocation, zero
// goroutines, zero export).
type Providers struct {
    shutdown func(context.Context) error
    // exportFailures lets main.go surface a Prometheus counter for dropped/
    // failed exports, mirroring evidence_emit_failures_total.
    ExportFailures func() int64
}

// Setup builds providers from cfg, registers them as the global
// TracerProvider/MeterProvider/LoggerProvider (via otel.SetTracerProvider etc.),
// and returns a Providers whose Shutdown flushes + closes with a bounded
// timeout. Called once at boot from the composition root.
func Setup(ctx context.Context, cfg Config) (*Providers, error)

func (p *Providers) Shutdown(ctx context.Context) error
```

**Boot / teardown (composition root, `cmd/omni-sag/main.go`):**

1. If `cfg.OTel == nil || !cfg.OTel.Enabled` → skip entirely. The global no-op
   tracer means instrumented code paths cost nothing.
2. Else `otelexport.Setup(...)` → register providers globally → defer
   `Shutdown` **into the drain sequence, after** `srv.Drain(...)` so in-flight
   sessions' final spans get flushed, with a **hard bounded timeout** so a dead
   collector can never hang shutdown.

**The instrumentation seams** (where spans are created) are exactly the request-
lifecycle functions the evidence system already threads a `context.Context`
through, so instrumentation needs no new plumbing — it derives a span-bearing
context and passes *that* down the existing `ctx` parameter:

| Seam (existing code) | Span |
|---|---|
| `session.go handleConn` (post-accept) | root `omnisag.connection` |
| `ssh.NewServerConn` call inside `handleConn` | `omnisag.auth` (handshake+LDAP+MFA) |
| `session.go` per-channel goroutine | `omnisag.channel` |
| `handleDirectTCPIP` | `omnisag.tunnel` → `omnisag.splice` |
| `interactive.go handleSession` → shell/sftp/scp dispatch | `omnisag.session` → `omnisag.shell` / `omnisag.sftp` / `omnisag.scp` |
| `dialer.go DialTarget` | `omnisag.policy.decide`, `omnisag.approval`, `omnisag.credential.resolve`, `omnisag.dial` |
| `sftp.go` per-file transfer + inspect | `omnisag.transfer` → `omnisag.inspect` |

### Traces (the new, high-value signal)

**One trace = one SSH connection.** Span tree:

```
omnisag.connection                       (SERVER, root; whole connection lifetime)
├── omnisag.auth                         (handshake + LDAP bind + MFA)
├── omnisag.channel  {type=session}
│   └── omnisag.session
│       ├── omnisag.shell                (interactive PTY bridge)
│       ├── omnisag.sftp
│       │   └── omnisag.transfer {N}     (one per file; +omnisag.inspect child)
│       └── omnisag.scp                  (legacy -O transfer)
└── omnisag.channel  {type=direct-tcpip}
    └── omnisag.tunnel
        ├── omnisag.policy.decide        (from dialer.DialTarget)
        ├── omnisag.approval             (four-eyes wait — captures human latency)
        ├── omnisag.credential.resolve   (CyberArk CCP fetch)
        ├── omnisag.dial                 (netDial to target)
        └── omnisag.splice               (byte pump; ends on close, records bytes)
```

Notes on placement:

- The root starts in `handleConn` **right after `net.Conn` accept, before
  `ssh.NewServerConn`**, so handshake+auth latency is inside the trace. The
  per-attempt user/groups are unknown until after the handshake, so they are set
  as attributes on the root *after* `principalFrom` (the span is still open).
- `omnisag.policy.decide` / `omnisag.approval` / `omnisag.credential.resolve`
  are created **inside `dialer.DialTarget`**, which already receives `ctx`; they
  become children of whichever channel span is on that context (tunnel for
  `-L`; the session/sftp span for interactive/SFTP, which also dial the target).
- The four-eyes `omnisag.approval` span is uniquely valuable: it measures how
  long a privileged session waited for a *human* second approver — impossible to
  see today.

**Span kinds & semantic conventions.** Use OTel semconv where it genuinely fits,
custom `omnisag.*` where the domain has no convention:

- Root/inbound channel spans: `SpanKind = SERVER`. Attributes:
  `client.address` (source IP), `network.transport = "tcp"`.
- `omnisag.dial` / target-facing spans: `SpanKind = CLIENT`, `server.address` +
  `server.port` = the target host:port, `network.peer.address` = resolved IP.
- **User identity:** the `enduser.*` semconv has churned across spec versions, so
  use a stable custom attribute `omnisag.user` (+ `omnisag.groups.count`) rather
  than betting on a moving convention. Documented as an intentional choice.
- Domain attributes (custom namespace, stable): `omnisag.target.host`,
  `omnisag.policy.matched_role`, `omnisag.record.mode`, `omnisag.channel.type`,
  `omnisag.transfer.bytes`, `omnisag.transfer.direction`,
  `omnisag.inspection.verdict`, `omnisag.credential.mode`,
  `omnisag.approval.outcome`, `omnisag.tunnel.protocol` (if the
  tunnel-protocol-identification feature is present).
- **Span status:** a policy deny / credential-refused / approval-refused / dial
  failure sets `codes.Error` with the reason; a normal deny is a *legitimate*
  outcome, so record the reason but keep it non-alarming (the reason string, not
  a stack trace).

**Correlation to evidence (both directions, one required, one optional):**

- *Required (baseline):* every span that corresponds to an evidence event sets
  `omnisag.evidence.id = Event.ID` (the existing UUID). This lets an operator
  pivot from a span to the exact signed evidence record.
- *Optional (additive, recommended):* add `TraceID` / `SpanID` as **additive,
  omitempty** fields on `evidence.Event`, populated **only when tracing is
  active**. `evidence.go` already documents that "fields are additive: new event
  kinds add fields rather than repurposing existing ones," so this is
  in-idiom and backward-compatible — old records simply omit them, and the
  hash-chain/Merkle canonicalization already tolerates optional fields. This
  makes the *evidence* record jump-to-trace-able. Keep it lean: the fields are
  populated from `trace.SpanFromContext(ctx).SpanContext()` at emit time and are
  empty (zero-cost) when OTel is off.

**Sampling.** A privileged-access gateway is **low-volume, high-value** — every
session matters — so the default when tracing is enabled is **`always_on`**
(`parentbased_always_on`), unlike a high-QPS web service. Config exposes
`always_on | always_off | traceidratio | parentbased_traceidratio` + a ratio for
operators who want head sampling anyway.

### Metrics (Prometheus coexistence — the decision)

**Decision: keep the Prometheus endpoint exactly as-is; offer OTLP metrics as an
opt-in, secondary, additive path; do NOT migrate.** Justification: the existing
`/metrics` listener, its atomic-counter design (zero hot-path instrumentation),
and any operator dashboards/alerts built on it are load-bearing and risk-free —
ripping them out buys nothing. Two ways to *also* get the numbers over OTLP:

1. **Collector-scrape bridge (recommended default, zero omni-sag code):** the
   operator points their OTel Collector's `prometheus` receiver at omni-sag's
   existing `/metrics`, and the collector re-emits over OTLP. No new code, no
   double-counting, no new failure mode in the gateway.
2. **Native OTLP metric exporter (opt-in code path):** a thin adapter registers
   **observable** instruments on an OTel `MeterProvider` whose callbacks *read
   the same atomic counters* already in `metrics.Metrics`. Crucially this
   **reuses the existing counters** — it does **not** add a second counting
   decorator on the evidence path, so there is exactly one source of truth and
   no risk of divergence.

Recommend shipping the bridge as the documented default and implementing (2)
only as an opt-in convenience (`otel.metrics.enabled: true`), clearly marked
secondary to Prometheus.

### Logs — boundary with #19 (the key composition)

Evidence-events-as-OTLP-logs **overlap** the in-flight #19 event-export / SIEM
feature, whose exporter matrix is **Formatter** (`json | ecs | cef`) ×
**Transport** (`file | syslog | http`), multiple concurrent exporters fanned out
alongside the durable sink via a `CountingSink`-style decorator, best-effort and
bounded.

**Recommendation: OTLP-logs is a 4th transport (`otlp`) in the #19 matrix — NOT
a second parallel log path.** Rationale:

- #19 *already* has the exact engine OTLP-logs needs: the fan-out decorator, the
  bounded async buffer, drop-with-metric-on-overflow, and the config list of
  concurrent exporters. Building a second best-effort log pump would duplicate
  all of it and give operators two places to configure "ship my events
  somewhere."
- The evidence `Event` → wire-record mapping #19 performs for ECS/CEF is the
  same shape an OTLP `LogRecord` needs. Reusing it keeps one canonical field map.

**So the split of ownership is:**

- **This design owns** (a) the **evidence.Event → OTLP `LogRecord` mapping**
  (Timestamp = `Event.Time`; `SeverityNumber` derived from type/verdict/allow;
  `Body` = a short human string; `Attributes` = the same promoted field set the
  ECS formatter maps — user, source_ip, target, type, verdict, etc.; **plus
  `TraceId`/`SpanId` when a span is on the context**, which is what auto-
  correlates logs↔traces in the backend), and (b) the tiny `otlp` **transport
  adapter** that hands a batch to the OTel log SDK's `BatchProcessor` + OTLP log
  exporter.
- **#19 owns** the fan-out engine, the bounded buffer, the drop metric, and the
  config list. The `otlp` transport is *just another Transport implementation*
  registered in #19's matrix.

**Honest sequencing + stability caveats:**

- The OTel logs SDK is **pre-GA (v0.x, non-standard versioning)**. The `otlp`
  log transport therefore ships **experimental**, pinned, and isolated so a
  breaking 0.x bump touches only the adapter. If the logs SDK is still unstable
  when #19 lands, the `otlp` transport can be flagged experimental or deferred —
  **the stable traces deliverable does not depend on it.**
- If **#19 is not yet merged** when this feature is implemented: ship traces (+
  optional OTLP metrics) independently now, and land the OTLP-logs mapping +
  `otlp` transport as a follow-up once #19's Transport interface exists. This
  spec defines the mapping so #19 can absorb it cleanly. Under no circumstance
  build a standalone OTLP-logs pump to avoid waiting — that is the duplication
  this boundary exists to prevent.

### Reliability (async / non-blocking / bounded — same posture as #19)

- **Traces:** `BatchSpanProcessor` — span `End()` is a cheap in-memory enqueue;
  a **background** goroutine batches and exports. The queue is **bounded**
  (`max_queue_size`); on overflow spans are **dropped**, not blocked. Session
  code never touches the exporter.
- **Logs:** the OTel `BatchLogProcessor` provides the identical bounded-async
  behavior, sitting behind #19's own bounded buffer — belt and suspenders.
- **Exporter failure:** the OTLP client retries with backoff internally; on
  persistent failure the batch processor drops (bounded). We surface a Prometheus
  counter `omnisag_otel_export_failures_total` (and dropped-span count) so
  telemetry-pipeline degradation is observable — mirroring
  `evidence_emit_failures_total`. Note the pleasing property: **OTel's own health
  is reported through the Prometheus endpoint we deliberately kept.**
- **Dead collector never stalls anything:** exporter connect/export timeouts are
  bounded; the batch queue absorbs bursts; `Shutdown` flush has a hard timeout.
- **Startup:** OTLP uses a *non-blocking* dial — an unreachable collector at boot
  does not delay or fail gateway startup; export simply retries in the
  background.

### Config schema

New optional top-level block (opt-in, **default off** — consistent with the
project's posture for every new surface):

```yaml
otel:
  enabled: false                    # master switch (default off)
  endpoint: "localhost:4317"        # OTLP collector endpoint (host:port)
  protocol: grpc                    # grpc | http
  insecure: false                   # allow plaintext to the collector (dev only)
  tls:                              # optional; verify/authenticate to the collector
    ca_cert: ""                     # PEM CA verifying the collector
    client_cert: ""                 # optional mTLS client cert
    client_key: ""
  headers:                          # optional static headers (e.g. SaaS OTLP auth)
    # authorization: "Bearer ..."
  resource:                         # merged into the OTel Resource; service.name
    service.name: omni-sag          # defaults to "omni-sag" if omitted
    # service.namespace: prod
    # deployment.environment: eu-west-1
  traces:
    enabled: true                   # traces on by default WHEN otel.enabled
    sampler: parentbased_always_on  # always_on|always_off|traceidratio|parentbased_traceidratio
    sample_ratio: 1.0               # used only by *ratio samplers
    max_queue_size: 2048            # bounded async queue; overflow drops
    max_export_batch_size: 512
    export_timeout_seconds: 10
  metrics:
    enabled: false                  # default off; Prometheus stays authoritative
    interval_seconds: 60            # OTLP metric push interval
  logs:
    enabled: false                  # default off; EXPERIMENTAL (OTel logs SDK is pre-GA).
                                    # When true, registered as the `otlp` transport
                                    # in the #19 exporter matrix — NOT a separate path.
```

Each signal is independently toggleable under the one master switch. Documented
in `deploy/compose/config.example.yaml`.

### Dependencies (versions verified 2026-07-19 via web — do not trust memory)

Latest OTel Go release at time of writing: **v1.44.0 / v0.66.0 / v0.20.0**
(2026-05-27), per the
[opentelemetry-go CHANGELOG](https://github.com/open-telemetry/opentelemetry-go/blob/main/CHANGELOG.md)
and [releases](https://github.com/open-telemetry/opentelemetry-go/releases).

| Module | Version | Stability |
|---|---|---|
| `go.opentelemetry.io/otel` (API), `/sdk`, `/trace`, `/metric`, `/sdk/metric` | **v1.44.0** | **Stable (v1)** |
| `/exporters/otlp/otlptrace/{otlptracegrpc,otlptracehttp}` | **v1.44.0** | **Stable** |
| `/exporters/otlp/otlpmetric/{otlpmetricgrpc,otlpmetrichttp}` | **v1.44.0** | **Stable** |
| `/semconv/v1.x` (semantic conventions) | **v1.42.0** | Versioned to spec |
| `/sdk/log`, `/exporters/otlp/otlplog/{otlploggrpc,otlploghttp}`, `/exporters/prometheus` | **v0.66.0** | **Experimental (v0.x)** |
| `/log` (logs API) | **v0.20.0** | **Experimental — non-standard versioning** ([pkg.go.dev](https://pkg.go.dev/go.opentelemetry.io/otel/log)) |

- **Pure Go, no CGO.** The SDK and exporters are pure Go; adding them does not
  introduce a CGO toolchain requirement (preserves the static UBI9 non-root
  image).
- **Dependency weight:** the **gRPC** exporter pulls `google.golang.org/grpc` +
  `google.golang.org/protobuf` + `genproto` (non-trivial). The **HTTP** exporter
  (`otlptracehttp`, binary protobuf over HTTP) avoids the gRPC tree and is the
  lighter option for size-sensitive builds. Recommend defaulting to `grpc` (the
  conventional OTLP transport) while keeping `http` available so a deployment can
  skip gRPC. All OTel imports are confined to `internal/otelexport`, so the rest
  of the build is untouched; when `otel.enabled=false` the deps are compiled in
  but inert. (A `//go:build otel` build tag to exclude them entirely from a
  minimal build is noted as a future option, not required for v1.)
- **Take only the stable modules for the core feature.** The experimental log
  modules are pulled in **only** when the OTLP-logs transport is built (per the
  #19 boundary), keeping the pre-GA surface out of the default dependency set.

## Testing plan

- **Unit:** `otel` config parse + defaults + validation (bad protocol/sampler
  rejected; TLS material honored); `Resource` builder; `evidence.Event` →
  `LogRecord` mapping (field-by-field, severity derivation, TraceId/SpanId
  presence when a span is on context); span attribute mapping helpers.
- **Trace integration (in-memory exporter):** use the OTel
  `tracetest.InMemoryExporter` / `SpanRecorder`, drive a real in-process session
  through the existing `internal/session` test harness (the same one the scp and
  tunnel specs reuse), and assert **span-tree shape** (connection → auth →
  channel → session/tunnel → transfer/splice), parent/child linkage, span kinds,
  the domain attributes, and `omnisag.evidence.id` correlation to the emitted
  evidence event's `ID`. Cover a deny path → span status `Error` + reason.
- **Non-blocking assertion (the reliability guarantee):** install a **black-hole
  / always-erroring** exporter and assert session latency is unchanged and no
  deadlock — mirroring the tunnel spec's zero-added-latency assertion. Assert the
  `omnisag_otel_export_failures_total` counter moves.
- **Disabled-path assertion:** with `otel.enabled=false`, assert no provider is
  installed, no exporter goroutine starts, and instrumented paths produce zero
  spans at zero added cost (global no-op tracer).
- **Metrics coexistence:** with `otel.metrics.enabled=true`, assert `/metrics`
  still serves the identical Prometheus output *and* the OTLP metric callbacks
  read the same counter values (no divergence, no double count).
- **Ground truth — real OTel Collector interop (in the plan):** run a real
  `otel/opentelemetry-collector` in Docker with a debug/logging exporter, drive a
  real session against the gateway, and assert the spans (and, when built, the
  logs) actually arrive and parse — the same "real binary in a lab" discipline
  the scp plan uses for the real `scp` client.

## Rollout (why this is safe)

1. Ship **traces** (stable modules) opt-in → operators enable, point at their
   collector, see the connection timeline. Prometheus and evidence untouched.
2. Add **OTLP metrics** via the collector-scrape bridge (zero code) or the opt-in
   native exporter — Prometheus stays authoritative throughout.
3. Land **OTLP-logs** as the `otlp` transport once #19's Transport interface
   exists, flagged experimental until the OTel logs SDK is GA.

## Out of scope

- Trace-context propagation *into* targets (injecting `traceparent` into the
  target-facing SSH stream so the trace continues on the target host).
- Replacing or migrating off the Prometheus endpoint.
- Treating OTLP logs as the compliance/audit record — the signed, WORM evidence
  bus remains authoritative; OTLP is best-effort telemetry.
- Auto-instrumentation, eBPF, or the OTel profiling signal.
- A standalone OTLP-logs pump independent of #19 (explicitly rejected above).
