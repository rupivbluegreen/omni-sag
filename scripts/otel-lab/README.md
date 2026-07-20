# OTel Collector interop lab

Ground-truth proof that omni-sag's OTLP export (`internal/otelexport`) really
interoperates with a real OpenTelemetry Collector over the wire — not just
this repo's own in-memory `SpanRecorder` unit tests.

## What it does

`docker-compose.yaml` runs `otel/opentelemetry-collector-contrib`, listening
for OTLP on `4317` (gRPC) and `4318` (HTTP), and writes every received
trace/log batch as JSON to `./output/otel-output.jsonl` (via the `file`
exporter) in addition to logging them (`debug` exporter, `docker compose
logs`).

`internal/otelexport/interop_test.go` (build-tag `interop`, so it never runs
under the normal `go test ./...`) boots a real `internal/session.Server` +
`internal/dialer.Dialer` (a fake in-process authenticator and a loopback echo
target — no LDAP/target containers needed, since this lab is about the OTLP
wire path, not authentication), points `internal/otelexport.Setup` at the
collector above, drives one real `-L` forward over a real SSH connection, and
asserts the collector's file output contains the expected span names.

## Run

```bash
mkdir -p scripts/otel-lab/output
chmod 777 scripts/otel-lab/output
touch scripts/otel-lab/output/otel-output.jsonl && chmod 666 scripts/otel-lab/output/otel-output.jsonl

docker compose -f scripts/otel-lab/docker-compose.yaml up -d

go test -tags interop ./internal/otelexport/... -run TestInterop -v

docker compose -f scripts/otel-lab/docker-compose.yaml down
rm -rf scripts/otel-lab/output
```

The `output` dir/file must exist and be world-writable before `up -d` — the
collector image runs as a non-root user and cannot create the file itself
inside the bind mount (permission denied otherwise). If you restart the
collector without recreating a fresh output file, keep in mind an external
truncate (`: > output/otel-output.jsonl`) while the container still holds the
old file open leaves stale/garbled bytes at the front of the new content;
`docker compose down` + delete + recreate the file is the clean way to reset.

## Observed span tree (2026-07-20 run)

```
omnisag.connection  {omnisag.user: alice, client.address: 127.0.0.1, omnisag.groups.count: 1}
  omnisag.auth  {}
  omnisag.channel  {omnisag.channel.type: direct-tcpip}
    omnisag.tunnel  {omnisag.target.host: 127.0.0.1, server.port: <port>}
      omnisag.splice  {omnisag.transfer.bytes: 8}
      omnisag.policy.decide  {omnisag.policy.matched_role: dba, omnisag.evidence.id: <uuid>}
      omnisag.credential.resolve  {omnisag.credential.mode: passthrough}
      omnisag.dial  {server.address: 127.0.0.1, server.port: <port>, network.peer.address: 127.0.0.1}
```

Matches the design doc's span tree exactly: one root per connection, `auth`
and `channel` as its children, `tunnel` under the direct-tcpip channel, and
`policy.decide`/`credential.resolve`/`dial`/`splice` all as siblings under
`tunnel` — confirming the dialer's spans (a separate package/tracer) nest
correctly under the session's spans via the shared `context.Context`, over
real OTLP wire delivery to a real collector.
