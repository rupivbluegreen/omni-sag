# OpenTelemetry (OTLP) integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** `docs/superpowers/specs/2026-07-19-opentelemetry-integration-design.md` —
read it first for the full rationale, the #19 logs boundary, and the honest
logs-SDK-stability caveat. This plan implements it.

**Goal:** Add an **opt-in, default-off** OTLP egress for omni-sag. Ship the
**stable** signals first — distributed **traces** over the connection lifecycle
(correlated to evidence event IDs) and an **optional** OTLP **metrics** path that
**coexists with** the existing Prometheus endpoint — then the **experimental**
evidence-as-OTLP-**logs** mapping delivered as the `otlp` transport inside the
#19 exporter matrix.

**Architecture:** One new leaf package `internal/otelexport` owns all OTel SDK
wiring (resource, providers, exporters, sampler, one `Shutdown`). Nothing else
imports the SDK; instrumentation call sites use only the global API
(`otel.Tracer(...)`), which is a **no-op when OTel is disabled** — so the
disabled path costs nothing and pulls in no goroutines. Spans are threaded
through the `context.Context` the request lifecycle already carries
(`handleConn` → `handleSession`/`handleDirectTCPIP` → `dialer.DialTarget`), so
instrumentation needs almost no new plumbing.

**Tech Stack:** Go, `go.opentelemetry.io/otel` **v1.44.0** (stable: API, sdk,
trace, metric, otlptrace/otlpmetric exporters, semconv v1.42.0) and — only for
the logs task — the **experimental v0.x** log modules (`/log` v0.20.0,
`/sdk/log` + `/exporters/otlp/otlplog` v0.66.0). Pure Go, **no CGO**. Versions
verified 2026-07-19 against the opentelemetry-go CHANGELOG/releases; re-verify
with `go list -m -versions go.opentelemetry.io/otel` before pinning.

## Global Constraints

- **Opt-in, default off.** Absent `otel:` block ⇒ zero behavior change, zero
  active OTel goroutines, global no-op tracer.
- **Never block a session.** All export is async via Batch processors with a
  **bounded** queue; overflow **drops** (records a counter), never blocks the
  session hot path. No synchronous export on any request path.
- **Do not remove Prometheus.** The `/metrics` listener and its atomic counters
  stay exactly as-is and remain authoritative. OTLP metrics is additive/opt-in.
- **Localize the dependency.** OTel SDK imports live **only** in
  `internal/otelexport`. The experimental log modules are imported **only** in
  the logs task, not the core feature.
- **Traces & metrics use stable v1 modules; logs is experimental and isolated.**
  A breaking 0.x logs bump must touch only the one log adapter file.
- **Evidence is unaffected.** OTLP is best-effort telemetry, not the audit
  record. The only touch to `internal/evidence` is two *optional, additive,
  omitempty* fields (Task 6), populated only when a span is active.
- **Bounded shutdown.** Provider `Shutdown` runs inside the drain sequence with a
  hard timeout so a dead collector cannot hang exit.
- **A dead/unreachable collector is a non-event.** Non-blocking dial at boot;
  bounded export timeouts; the gateway starts and serves regardless.

---

### Task 1: `otel` config schema + validation + defaults

**Files:**
- Modify: `internal/config/config.go` (add `OTel *OTelConfig` to `File`; new
  structs; defaulting + validation in `validate()`)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.OTelConfig` (+ `OTelTLS`, `OTelTraces`, `OTelMetrics`,
  `OTelLogs`) with `File.OTel *OTelConfig` (yaml `otel`, nil ⇒ disabled),
  consumed by Task 3 (`main.go`) and Task 2 (`otelexport.Config` is built from
  it). Add `OTelConfig` accessor helpers for defaults (mirroring
  `DrainGraceSeconds()` style), e.g. `Endpoint()`, `Protocol()`, `Sampler()`,
  `MaxQueueSize()`, `ExportTimeout()`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/config/config_test.go`, following the file's
`Load(writeTemp(t, yaml))` convention (not `File{}` literals):

```go
func TestLoad_OTelDefaultsWhenBlockPresent(t *testing.T) {
	y := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
otel:
  enabled: true
  endpoint: "collector:4317"
`
	f, err := Load(writeTemp(t, y))
	if err != nil {
		t.Fatal(err)
	}
	if f.OTel == nil || !f.OTel.Enabled {
		t.Fatal("otel should be enabled")
	}
	if f.OTel.Protocol() != "grpc" {
		t.Fatalf("default protocol = %q, want grpc", f.OTel.Protocol())
	}
	if f.OTel.Sampler() != "parentbased_always_on" {
		t.Fatalf("default sampler = %q", f.OTel.Sampler())
	}
	// traces default ON when otel enabled; metrics/logs default OFF
	if !f.OTel.TracesEnabled() {
		t.Fatal("traces should default enabled")
	}
	if f.OTel.MetricsEnabled() || f.OTel.LogsEnabled() {
		t.Fatal("metrics and logs should default disabled")
	}
}

func TestLoad_OTelAbsentIsNil(t *testing.T) {
	y := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
`
	f, err := Load(writeTemp(t, y))
	if err != nil {
		t.Fatal(err)
	}
	if f.OTel != nil {
		t.Fatal("absent otel block must be nil (feature off)")
	}
}

func TestLoad_OTelRejectsBadProtocolAndSampler(t *testing.T) {
	for _, bad := range []string{
		"otel:\n  enabled: true\n  protocol: carrier-pigeon\n",
		"otel:\n  enabled: true\n  traces:\n    sampler: sometimes\n",
	} {
		y := "listen: \":2222\"\nevidence:\n  file: \"e.jsonl\"\npolicy:\n  roles: []\n" + bad
		if _, err := Load(writeTemp(t, y)); err == nil {
			t.Fatalf("expected validation error for %q", bad)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/... -run TestLoad_OTel -v`
Expected: FAIL to compile — `OTelConfig`/accessors undefined.

- [ ] **Step 3: Add the structs, defaults, and validation**

In `internal/config/config.go` add `OTel *OTelConfig` to the `File` struct
(yaml `otel`), then the structs mirroring the spec's Config schema
(`OTelConfig{Enabled bool; Endpoint,Protocol string; Insecure bool; TLS OTelTLS;
Headers map[string]string; Resource map[string]string; Traces OTelTraces;
Metrics OTelMetrics; Logs OTelLogs}`). Add accessor methods that apply defaults
(`grpc`, `parentbased_always_on`, `sample_ratio 1.0`, `max_queue_size 2048`,
`max_export_batch_size 512`, `export_timeout_seconds 10`, `interval_seconds 60`;
`Traces.Enabled` defaults **true** when the pointer/field is unset — use a
`*bool` so "unset" is distinguishable — `Metrics`/`Logs` default **false**).

In `validate()`, when `f.OTel != nil && f.OTel.Enabled`: require `Endpoint`
non-empty; reject `Protocol` not in `{grpc, http}`; reject `Traces.Sampler` not
in `{always_on, always_off, traceidratio, parentbased_always_on,
parentbased_traceidratio}`. Keep messages in the existing `config: ...` style.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/... -v`
Expected: PASS, including the pre-existing config tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add opt-in otel (OTLP) configuration block"
```

---

### Task 2: `internal/otelexport` — providers, exporters, disabled no-op path (traces only)

**Files:**
- Create: `internal/otelexport/otelexport.go` (Config, Setup, Providers,
  Shutdown, resource + sampler + trace exporter + BatchSpanProcessor)
- Test: `internal/otelexport/otelexport_test.go`

**Interfaces:**
- Produces (consumed by Task 3): `otelexport.Config` (a plain struct built from
  `config.OTelConfig` by main.go — **otelexport does NOT import internal/config**,
  to keep it a leaf), `otelexport.Setup(ctx, Config) (*Providers, error)`,
  `(*Providers).Shutdown(ctx) error`, `(*Providers).ExportFailures() int64`.

- [ ] **Step 1: Write the failing tests**

Create `internal/otelexport/otelexport_test.go`. Two anchors: the **disabled**
path installs nothing, and an **enabled** path with an in-memory exporter records
spans. (Use `go.opentelemetry.io/otel/sdk/trace/tracetest` for the in-memory
exporter; for Setup's own exporter you may inject a test exporter via an unexported
seam or assert against the global tracer.)

```go
package otelexport

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestSetup_DisabledInstallsNoopAndNoShutdownWork(t *testing.T) {
	p, err := Setup(context.Background(), Config{Enabled: false})
	if err != nil {
		t.Fatalf("Setup(disabled): %v", err)
	}
	// Global tracer must remain the no-op (Setup installed nothing).
	if _, ok := otel.GetTracerProvider().(interface{ Tracer(string, ...trace.TracerOption) }); !ok {
		_ = ok // shape check; the real assertion is: no panic, Shutdown is a no-op
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(disabled) should be a no-op nil, got %v", err)
	}
	_ = noop.NewTracerProvider
}

func TestSetup_EnabledBuildsProviderAndShutsDownCleanly(t *testing.T) {
	// endpoint unreachable on purpose: Setup must NOT block or fail on a dead
	// collector (non-blocking dial), and Shutdown must return within timeout.
	p, err := Setup(context.Background(), Config{
		Enabled:  true,
		Endpoint: "127.0.0.1:4317",
		Protocol: "grpc",
		Insecure: true,
		Traces:   TracesConfig{Enabled: true, Sampler: "always_on", MaxQueueSize: 8},
	})
	if err != nil {
		t.Fatalf("Setup(enabled): %v", err)
	}
	tr := otel.Tracer("test")
	_, span := tr.Start(context.Background(), "probe")
	span.End()
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/otelexport/... -v`
Expected: FAIL to compile — package/symbols don't exist. Add the OTel modules:
`go get go.opentelemetry.io/otel@v1.44.0 go.opentelemetry.io/otel/sdk@v1.44.0 go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@v1.44.0 go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@v1.44.0`
(then `go mod tidy`). Re-verify the version resolves: `go list -m go.opentelemetry.io/otel`.

- [ ] **Step 3: Implement `Setup`/`Providers`**

Create `internal/otelexport/otelexport.go`:
- `Config` mirrors the spec schema as a plain struct (no `internal/config`
  import). `TracesConfig`, `MetricsConfig`, `LogsConfig`, `TLS` sub-structs.
- `Setup`: if `!cfg.Enabled` → return `&Providers{shutdown: func(context.Context) error { return nil }}` and install nothing. Else:
  - Build a `resource.Resource` from `service.name` (default `omni-sag`) +
    `cfg.Resource` + SDK/telemetry attributes (`semconv.ServiceNameKey`, etc.,
    from `go.opentelemetry.io/otel/semconv/v1.42.0`).
  - Build the OTLP **trace** exporter: `otlptracegrpc.New(ctx, ...)` or
    `otlptracehttp.New(ctx, ...)` per `cfg.Protocol`, with endpoint, insecure/TLS,
    headers, and a **non-blocking** client (do NOT use a blocking dial option) and
    a bounded export timeout.
  - `sdktrace.NewTracerProvider(WithResource, WithSampler(map cfg.Traces.Sampler),
    WithBatcher(exporter, WithMaxQueueSize, WithMaxExportBatchSize,
    WithBatchTimeout/ExportTimeout))`.
  - `otel.SetTracerProvider(tp)` + `otel.SetTextMapPropagator(...)`.
  - Track export failures: register an `sdktrace.SpanExporter` wrapper or use the
    processor's error handler (`otel.SetErrorHandler`) to increment an atomic
    counter exposed via `ExportFailures()`.
  - `shutdown` calls `tp.Shutdown(ctx)` (and later mp/lp) — caller supplies a
    bounded ctx.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/otelexport/... -v`
Expected: PASS. The enabled test must complete quickly (non-blocking dial), NOT
hang against the dead endpoint.

- [ ] **Step 5: `go vet` + tidy check**

Run: `go vet ./internal/otelexport/... && go mod tidy && git diff --exit-code go.mod go.sum || echo "go.mod/sum changed — review the new OTel deps are the stable v1.44.0 set + their transitive grpc/protobuf only"`

- [ ] **Step 6: Commit**

```bash
git add internal/otelexport/ go.mod go.sum
git commit -m "feat(otelexport): OTLP trace provider setup with disabled no-op path"
```

---

### Task 3: Wire providers into `main.go` (boot + bounded drain-shutdown + export-failure metric)

**Files:**
- Modify: `cmd/omni-sag/main.go` (build `otelexport.Config` from `cfg.OTel`,
  `Setup`, register, shut down in drain)
- Modify: `internal/metrics/metrics.go` (add an `omnisag_otel_export_failures_total`
  counter fed from a source fn, mirroring `SetActiveFn`)
- Test: covered by Task 2 unit + Task 9 interop; add a `main`-level smoke only if
  a `run()`-level harness already exists (it does not — keep this task
  build+manual).

**Interfaces:**
- Consumes: `config.OTelConfig` (Task 1), `otelexport.Setup` (Task 2),
  `metrics.Metrics` (existing).

- [ ] **Step 1: Build + register providers at boot**

In `run()` (after `buildEvidence`, near the other subsystem wiring), add:

```go
var otelProviders *otelexport.Providers
if cfg.OTel != nil && cfg.OTel.Enabled {
	otelProviders, err = otelexport.Setup(ctx, otelexport.Config{ /* mapped from cfg.OTel */ })
	if err != nil {
		return err
	}
	log.Printf("omni-sag: OpenTelemetry OTLP export enabled (endpoint=%s protocol=%s)", cfg.OTel.Endpoint, cfg.OTel.Protocol())
	if cfg.OTel.LogsEnabled() {
		log.Printf("omni-sag: WARNING OTLP logs export is EXPERIMENTAL (OTel logs SDK is pre-GA)")
	}
}
```

- [ ] **Step 2: Surface export failures on the Prometheus endpoint**

In `internal/metrics/metrics.go` add an `otelExportFailuresFn func() int64`
field with a `SetOTelExportFailuresFn(fn)` setter (mirroring `SetActiveFn`), and
emit `ctr("otel_export_failures_total", "OTLP export failures/drops", ...)` in
`WriteText`. In `main.go`, after Setup: `met.SetOTelExportFailuresFn(otelProviders.ExportFailures)`.
(Nice property: OTel's own health rides the Prometheus endpoint we kept.)

- [ ] **Step 3: Shut down inside the drain sequence with a hard timeout**

After `srv.Drain(grace)` returns (so in-flight sessions' final spans are
recorded first), add:

```go
if otelProviders != nil {
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := otelProviders.Shutdown(shutCtx); err != nil {
		log.Printf("omni-sag: otel shutdown: %v", err)
	}
}
```

- [ ] **Step 4: Build + boot-with-dead-collector smoke**

Run: `go build ./...`
Then a manual smoke: run the gateway with `otel.enabled: true` pointing at a
**closed** port and confirm it **still starts and serves SSH** (non-blocking
dial) and shuts down within the timeout. Document the observation in the commit.

- [ ] **Step 5: Commit**

```bash
git add cmd/omni-sag/main.go internal/metrics/metrics.go
git commit -m "feat(main): wire OTLP providers into boot/drain; export-failure metric"
```

---

### Task 4: Trace instrumentation — root connection span + auth span

**Files:**
- Modify: `internal/session/session.go` (`handleConn`)
- Test: `internal/session/otel_trace_test.go` (new)

**Interfaces:**
- Consumes: global `otel.Tracer("github.com/rupivbluegreen/omni-sag/internal/session")`
  (a package-level tracer var). No new option needed — the global tracer is
  no-op when OTel is off, so this is safe unconditionally.

- [ ] **Step 1: Write the failing test (in-memory SpanRecorder)**

Create `internal/session/otel_trace_test.go`. Install a `tracetest.SpanRecorder`
via a `sdktrace.NewTracerProvider(WithSpanProcessor(sr))` set as the global
provider for the test, drive one real session through the existing harness
(reuse `startServerWith`/`sshClient`/`wireFakeSFTPTarget` from the scp/sftp
tests), then assert a root span `omnisag.connection` exists with an
`omnisag.auth` **child**, `SpanKind=SERVER`, and attributes `omnisag.user` and
`client.address` set. Also add `TestTracing_DisabledProducesNoSpans` (no provider
installed → recorder empty) and `TestTracing_ExporterErrorDoesNotBlockSession`
(black-hole processor → session still completes, latency sane).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/session/... -run TestTracing -v`
Expected: FAIL — no spans recorded (instrumentation not added yet).

- [ ] **Step 3: Instrument `handleConn`**

- Add a package tracer: `var tracer = otel.Tracer("github.com/rupivbluegreen/omni-sag/internal/session")`.
- At the **top of `handleConn`, right after accept / before `ssh.NewServerConn`**:
  `ctx, root := tracer.Start(ctx, "omnisag.connection", trace.WithSpanKind(trace.SpanKindServer))` and `defer root.End()`. Thread this `ctx` onward (it already flows to the channel handlers).
- Wrap the handshake: `hsCtx, authSpan := tracer.Start(ctx, "omnisag.auth")` immediately before `ssh.NewServerConn`, `authSpan.End()` immediately after (set `codes.Error` + reason on `err`). Keep the deadline logic intact.
- After `principalFrom`, set `root.SetAttributes(omnisagUser(pr.User), semconv.ClientAddress(srcIP), attribute.Int("omnisag.groups.count", len(pr.Groups)))`.
- Pass the span-bearing `ctx` into `handleDirectTCPIP` / `handleSession` (they already take `ctx`).

Keep helpers (`omnisagUser`, etc.) in a new `internal/session/otel.go` so the
attribute-key strings live in one place.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/session/... -run TestTracing -v`
Expected: PASS (root+auth span tree, attributes, disabled=empty, error=non-block).

- [ ] **Step 5: Full session regression + race**

Run: `go test -race ./internal/session/... 2>&1 | tail -30`
Expected: PASS — instrumentation is additive and the disabled global tracer is
a no-op for every existing test.

- [ ] **Step 6: Commit**

```bash
git add internal/session/session.go internal/session/otel.go internal/session/otel_trace_test.go
git commit -m "feat(session): root connection + auth trace spans"
```

---

### Task 5: Trace instrumentation — channel, tunnel, and dialer child spans

**Files:**
- Modify: `internal/session/session.go` (`handleConn` per-channel goroutine,
  `handleDirectTCPIP`)
- Modify: `internal/dialer/dialer.go` (`DialTarget`, `gateApproval`,
  `resolveCredential`, and the `netDial` call)
- Test: `internal/session/otel_trace_test.go` (append tunnel case),
  `internal/dialer/otel_trace_test.go` (new)

**Interfaces:**
- Consumes: global tracer (add `var tracer = otel.Tracer(".../internal/dialer")`
  in dialer). `DialTarget` already receives `ctx`, so its child spans attach to
  whatever channel span is on the context.

- [ ] **Step 1: Write the failing tests**

- In dialer test: drive `DialTarget` (with the existing test doubles/fake
  transport) under a SpanRecorder and assert children `omnisag.policy.decide`,
  `omnisag.dial`, and — for an approval-gated / inject target —
  `omnisag.approval` / `omnisag.credential.resolve`, each with the right
  attributes (`omnisag.target.host`, `omnisag.policy.matched_role`,
  `server.address`/`server.port`, `omnisag.credential.mode`,
  `omnisag.approval.outcome`) and `omnisag.evidence.id` matching the emitted
  event.
- In session test: drive a `direct-tcpip` channel and assert
  `omnisag.channel{type=direct-tcpip}` → `omnisag.tunnel` → (`omnisag.dial` via
  DialTarget) → `omnisag.splice` with `omnisag.transfer.bytes` recorded.

- [ ] **Step 2: Run to verify they fail** — `go test ./internal/dialer/... ./internal/session/... -run TestTracing -v` → FAIL (spans absent).

- [ ] **Step 3: Instrument**

- Per-channel goroutine in `handleConn`: `ctx, chSpan := tracer.Start(ctx, "omnisag.channel", trace.WithAttributes(attribute.String("omnisag.channel.type", ct)))`, `defer chSpan.End()`; pass `ctx` into the handler.
- `handleDirectTCPIP`: `ctx, tun := tracer.Start(ctx, "omnisag.tunnel")`; set target attrs; on `DialTarget` error set span status; wrap the `dialer.Splice` call in `omnisag.splice` and record `omnisag.transfer.bytes` from Splice's byte counts (Splice returns copied byte counts today, or extend it minimally to report them).
- `DialTarget`: `ctx, dec := tracer.Start(ctx, "omnisag.policy.decide")` around `Decide`, end with matched-role/allow attrs + `omnisag.evidence.id` = the decision event's ID. Wrap `gateApproval` in `omnisag.approval`, `resolveCredential` in `omnisag.credential.resolve`, and the `netDial` in `omnisag.dial` (CLIENT kind, `server.address`/`server.port`, `network.peer.address` = resolved IP). Each sets `codes.Error`+reason on the fail-closed paths.
- To set `omnisag.evidence.id`, capture the `Event.ID` the sink assigns. `Event.ID` is currently filled inside the file sink; expose it by generating the UUID at emit time in `dialer.emit` (or read it back) so the span and the record share the same id. Keep this minimal and additive.

- [ ] **Step 4: Run to verify pass** — same commands → PASS.

- [ ] **Step 5: Race + full regression** — `go test -race ./internal/dialer/... ./internal/session/... 2>&1 | tail -30` → PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/session/session.go internal/dialer/dialer.go internal/session/otel_trace_test.go internal/dialer/otel_trace_test.go
git commit -m "feat(traces): channel, tunnel, splice, and dialer child spans"
```

---

### Task 6: Trace instrumentation — session channel spans + per-transfer spans + evidence correlation

**Files:**
- Modify: `internal/session/interactive.go` (`handleSession` dispatch,
  `runRecordedShell`), `internal/session/sftp.go` (transfer + inspect),
  `internal/session/scp.go` (`runSCP`)
- Modify: `internal/evidence/evidence.go` (add optional additive `TraceID`,
  `SpanID` `omitempty` fields — populated only when a span is active)
- Test: `internal/session/otel_trace_test.go` (append shell/sftp/scp cases)

- [ ] **Step 1: Write the failing tests**

Assert, under the SpanRecorder + real harness:
- session channel → `omnisag.session` → `omnisag.shell` for an interactive
  session; `omnisag.sftp` → `omnisag.transfer{path,bytes,direction}` (+
  `omnisag.inspect{verdict}` child when inspection is on) for an SFTP put/get;
  `omnisag.scp` for a legacy scp transfer.
- The emitted `evidence.TypeTransfer` event carries `TraceID`/`SpanID` equal to
  the enclosing transfer span, **and** the span carries `omnisag.evidence.id` =
  the event `ID` (two-way correlation).
- A backward-compat test: with OTel disabled, the new evidence fields are empty
  and the JSONL is byte-identical to pre-feature output (omitempty).

- [ ] **Step 2: Run to verify they fail** → FAIL.

- [ ] **Step 3: Instrument + add the additive evidence fields**

- Add `TraceID string \`json:"trace_id,omitempty"\`` and `SpanID string \`json:"span_id,omitempty"\`` to `evidence.Event` (respect the file's "fields are additive" doctrine; place them near the freeform `Detail`).
- In `s.emit` (session) and `d.emit` (dialer), if `trace.SpanFromContext(ctx).SpanContext().IsValid()`, fill `TraceID`/`SpanID` before writing. This requires `emit` to see the `ctx`; where `emit` has no ctx today, pass it (small signature touch) or set the fields at the call site. Keep the change surgical.
- Wrap `runRecordedShell` in `omnisag.shell`, `runSFTP` in `omnisag.sftp`, each
  per-file operation in `omnisag.transfer` (attrs from the transfer manifest),
  the ICAP call in `omnisag.inspect` (verdict/status), and `runSCP` in
  `omnisag.scp`.
- Set `omnisag.evidence.id` on each span from the corresponding event ID.

- [ ] **Step 4: Run to verify pass** → PASS, including the byte-identical
  disabled-path evidence test.

- [ ] **Step 5: Evidence-package regression (hash chain tolerates new fields)**

Run: `go test ./internal/evidence/... -v 2>&1 | tail -30`
Expected: PASS — canonicalization/Merkle already handle optional fields; confirm
no golden-file test hard-codes the field set (fix any that do to use omitempty).

- [ ] **Step 6: Commit**

```bash
git add internal/session/interactive.go internal/session/sftp.go internal/session/scp.go internal/evidence/evidence.go internal/session/otel_trace_test.go
git commit -m "feat(traces): session/transfer spans + two-way evidence correlation"
```

---

### Task 7: OPTIONAL OTLP metrics exporter (reads existing counters; Prometheus stays authoritative)

**Files:**
- Modify: `internal/otelexport/otelexport.go` (add metric provider when
  `cfg.Metrics.Enabled`)
- Modify: `internal/metrics/metrics.go` (expose counter values as a snapshot
  the OTel observable callbacks can read — a `Snapshot() map[string]int64` or
  per-counter getters; the atomics already exist)
- Modify: `cmd/omni-sag/main.go` (pass the metrics snapshot source into
  `otelexport.Setup`)
- Test: `internal/otelexport/metrics_test.go`, plus a coexistence assertion.

**Interfaces:**
- Consumes: existing `metrics.Metrics` atomics (read-only). **Does NOT** add a
  second counting decorator — single source of truth.

- [ ] **Step 1: Write the failing test**

Assert: enabling metrics builds an OTel `MeterProvider` with an OTLP metric
exporter (`otlpmetricgrpc`/`otlpmetrichttp`, **stable v1.44.0**), that observable
counters are registered for each omni-sag counter, and that their callback values
equal the atomic counter values (drive a couple of events, read back). Add a
coexistence test asserting `/metrics` Prometheus text is unchanged when OTLP
metrics is on.

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement**

- `go get go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc@v1.44.0` (+ http variant), `go mod tidy`.
- In `Setup`, when `cfg.Metrics.Enabled`: build the OTLP metric exporter +
  `sdkmetric.NewMeterProvider(WithReader(NewPeriodicReader(exporter, WithInterval)))`,
  `otel.SetMeterProvider(mp)`, and register **async observable** Int64 counters
  whose callbacks read the injected snapshot fn. Extend `shutdown` to also close
  the meter provider.
- In `metrics.go`, add read-only getters/snapshot (the atomics already support
  `get()`); wire the source through main.go into the Config.

- [ ] **Step 4: Run to verify pass** → PASS (values match; Prometheus unchanged).

- [ ] **Step 5: Commit**

```bash
git add internal/otelexport/ internal/metrics/metrics.go cmd/omni-sag/main.go go.mod go.sum
git commit -m "feat(otelexport): optional OTLP metrics reading existing counters (Prometheus unchanged)"
```

---

### Task 8: EXPERIMENTAL — evidence.Event → OTLP LogRecord mapping + the `otlp` transport for #19

> **Read the spec's "Boundary with #19" first.** This is the ONLY task that
> pulls in the **experimental v0.x** OTel log modules. If #19's Transport
> interface is not yet merged, implement the **mapper** (pure, testable) now and
> stage the transport adapter behind a build tag / clearly-experimental package
> until #19 lands — do **not** build a standalone OTLP-logs pump.

**Files:**
- Create: `internal/otelexport/logmap.go` (pure `evidence.Event → log.Record`
  mapping — no I/O), `internal/otelexport/logmap_test.go`
- Create (or contribute to #19): `internal/otelexport/otlplog.go` — the `otlp`
  Transport adapter feeding an OTel `BatchProcessor` + OTLP log exporter.
- Modify: `internal/otelexport/otelexport.go` (build a `LoggerProvider` when
  `cfg.Logs.Enabled`)

**Interfaces:**
- Produces: `func EventToLogRecord(e evidence.Event, sc trace.SpanContext) log.Record`
  (pure; sets Timestamp, SeverityNumber, Body, Attributes = the same promoted
  field set #19's ECS formatter uses, plus TraceId/SpanId from `sc` when valid).
- The `otlp` transport implements #19's Transport interface (whatever #19 names
  it: `Emit(Event)` / `Flush` / `Close`), delegating to the OTel log SDK's
  bounded `BatchProcessor` — reusing #19's fan-out + best-effort engine, NOT
  duplicating it.

- [ ] **Step 1: Write the failing mapper test**

Table-driven: for representative events (auth allow/deny, tunnel_decision,
transfer, inspection blocked, approval granted) assert the produced `log.Record`
Timestamp, SeverityNumber (deny/blocked ⇒ WARN/ERROR; normal ⇒ INFO), Body, and
Attributes (user, source_ip, target, type, verdict, evidence id), and that
TraceId/SpanId appear iff the passed `SpanContext` is valid.

- [ ] **Step 2: Run to verify fail** → FAIL to compile (log modules absent).

`go get go.opentelemetry.io/otel/log@v0.20.0 go.opentelemetry.io/otel/sdk/log@v0.66.0 go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc@v0.66.0` (+ http), `go mod tidy`. **Re-verify these v0.x versions resolve** — the log SDK moves fast; pin whatever the current v0.x is and record it in the commit.

- [ ] **Step 3: Implement the mapper (+ provider + transport)**

- `logmap.go`: pure mapping as specced. Isolate every `go.opentelemetry.io/otel/log` type reference to this file + `otlplog.go` so a breaking 0.x bump is contained.
- In `Setup`, when `cfg.Logs.Enabled`: build the OTLP log exporter +
  `sdklog.NewLoggerProvider(WithProcessor(NewBatchProcessor(exporter)))`,
  `global.SetLoggerProvider(lp)`; extend `shutdown`.
- `otlplog.go`: the Transport adapter that #19 fans out to.

- [ ] **Step 4: Run to verify pass** → mapper tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/otelexport/logmap.go internal/otelexport/logmap_test.go internal/otelexport/otlplog.go internal/otelexport/otelexport.go go.mod go.sum
git commit -m "feat(otelexport): experimental evidence->OTLP LogRecord mapping + otlp transport (#19)"
```

---

### Task 9: Ground-truth — real OTel Collector interop lab test

> Mirrors the scp plan's "real `scp` binary in a lab" discipline: assert spans
> (and, if Task 8 landed, logs) actually arrive at a **real** collector.

**Files:**
- Create: `scripts/otel-lab/docker-compose.yaml` (an `otel/opentelemetry-collector`
  with a `debug`/`logging` exporter and OTLP receiver on 4317/4318)
- Create: `scripts/otel-lab/collector-config.yaml`
- Create: `scripts/otel-lab/README.md` (run steps) and/or a
  `//go:build interop`-tagged Go test `internal/otelexport/interop_test.go`

- [ ] **Step 1: Author the collector compose + config**

Collector with `receivers.otlp` (grpc+http), `exporters.debug` (verbosity
detailed) or a file exporter, pipelines for `traces` (and `logs` if Task 8
present). Expose 4317.

- [ ] **Step 2: Author the interop check**

Either a scripted check (README) or a `//go:build interop` Go test that: starts
the gateway with `otel.enabled: true endpoint: 127.0.0.1:4317 insecure: true`,
drives one real session (reuse an end-to-end harness or a shell script with the
`ssh`/`sftp` client), then asserts the collector received a trace whose root is
`omnisag.connection` with the expected child spans (parse the collector's
file/debug output). If logs built, assert an evidence log record with matching
TraceId arrived.

- [ ] **Step 3: Run the lab (manual/CI-gated)**

Run:
```bash
docker compose -f scripts/otel-lab/docker-compose.yaml up -d
go test -tags interop ./internal/otelexport/... -run TestInterop -v
docker compose -f scripts/otel-lab/docker-compose.yaml down
```
Expected: the collector logs show the `omnisag.connection` trace tree; the
interop test passes. This is the real ground-truth proof that OTLP export works
end-to-end. Document the observed span tree in the commit message.

- [ ] **Step 4: Commit**

```bash
git add scripts/otel-lab/ internal/otelexport/interop_test.go
git commit -m "test(otel): real OTel Collector interop lab (ground-truth span/log arrival)"
```

---

### Task 10: Docs — example config + README

**Files:**
- Modify: `deploy/compose/config.example.yaml` (add the commented `otel:` block)
- Modify: `README.md` (one line in the feature list; note traces stable / logs
  experimental / Prometheus unchanged)

- [ ] **Step 1: Add the example config block**

Add the full `otel:` block from the spec's Config schema, **commented out**
(default off), with inline notes: opt-in; traces stable; metrics coexists with
Prometheus; logs experimental (OTel logs SDK pre-GA) and wired as the `otlp`
transport in the event-export matrix.

- [ ] **Step 2: Config example still parses**

Run: `go test ./internal/config/... -run TestLoad_ComposeExampleConfigParses -v`
Expected: PASS (a commented block changes nothing; if you add an *active*
example, ensure it validates).

- [ ] **Step 3: README line**

One exact-feature line consistent with the README's minimal style (no LLM
vomit): OTLP export (traces + optional metrics + experimental evidence-logs),
opt-in, Prometheus retained.

- [ ] **Step 4: Commit**

```bash
git add deploy/compose/config.example.yaml README.md
git commit -m "docs: document opt-in OTLP (OpenTelemetry) export"
```

---

## Sequencing notes

- **Tasks 1–6 are the stable, shippable core** (config, provider, wiring,
  traces). They depend only on v1 modules and can merge without #19.
- **Task 7 (OTLP metrics)** is optional and independent; ship when wanted.
- **Task 8 (OTLP logs)** is **experimental** and **depends on #19's Transport
  interface** for its final form — land the pure mapper first, wire the transport
  when #19 exists. Never build a standalone logs pump.
- **Task 9** is the ground-truth gate; run it before declaring the feature done.
- Re-verify every OTel module version with `go list -m -versions` at
  implementation time — the v0.x log modules in particular move quickly.
