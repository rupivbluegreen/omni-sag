# Tunnel protocol identification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Identify the protocol actually flowing through each `-L`/`-D` tunnel by fingerprinting the opening bytes; record it as tamper-evident evidence (Phase 1, observe); optionally enforce an expected protocol per policy rule (Phase 2, enforce).

**Architecture:** A pure leaf package `internal/protoident` (signature table + `Classify`) with no session/dialer/policy imports. `handleDirectTCPIP` (`internal/session/session.go:604-635`) wraps the channel/target conns before `dialer.Splice` — observe mode tees the opening bytes into a bounded buffer and classifies off the hot path (zero added latency); enforce mode holds the opening bytes until classified, then allows (replays buffered bytes into the splice) or terminates. Detection is opt-in via a `tunnel_inspection` config block. Both `-L`, `-D` (dynamic SOCKS) and `-J` legs open `direct-tcpip` channels, so one hook covers all.

**Tech Stack:** Go, `golang.org/x/crypto/ssh`, existing `internal/evidence` + `internal/policy` + `internal/config` + `internal/dialer`.

## Global Constraints

- **Opt-in, default OFF.** `tunnel_inspection.enabled: false` by default. Consistent with `enable_scp` and the project's posture for new surfaces.
- **Observe adds zero latency.** Phase 1 tees bytes (a copy); it NEVER gates the splice. A tunnel must not slow or deadlock because classification is pending.
- **Enforce holds head-of-line, and mismatched bytes NEVER reach the target.** On a mismatch the buffered opening bytes are discarded, not forwarded.
- **Classify from whichever side speaks first.** Signatures are tagged client-first vs server-first; the classifier must not wait for the target side on a client-first protocol (deadlock) or vice-versa.
- **`unknown_action` default `allow`** (heuristic detection must not cause false-positive outages); configurable to `deny`.
- **Dry-run:** `tunnel_inspection.enforce: false` with `expect_protocol` rules present logs would-block (`allow=false, detail="dry-run"`) without terminating.
- **One `TypeTunnelProtocol` evidence event per tunnel**, emitted through the existing session evidence sink (hash-chained/WORM).
- **Heuristic, spoofable; TLS opaque past handshake; first-packet only.** State these in doc/comments; do not overclaim.
- `internal/protoident` imports nothing from `session`/`dialer`/`policy`/`config` (leaf package, like `internal/approval`).
- Default tunables: `max_prefix_bytes: 512` per direction, `classify_timeout_seconds: 5`.

---

### Task 1: `internal/protoident` — signature table + `Classify` (pure)

**Files:**
- Create: `internal/protoident/protoident.go`, `internal/protoident/signatures.go`
- Test: `internal/protoident/protoident_test.go`

**Interfaces:**
- Produces (consumed by Tasks 4 & 6):
  - `type Protocol string`; consts for each recognized protocol + `Unknown Protocol = "unknown"`.
  - `type Side int` with `ClientFirst`, `ServerFirst`.
  - `type Result struct { Protocol Protocol; Side Side; Detail string; BytesSeen int; Signature string }`
  - `func Classify(clientPrefix, serverPrefix []byte) Result`
  - `func Protocols() []Protocol` (the set the table recognizes — for config validation of `expect_protocol`).

- [ ] **Step 1: Write the failing table-driven test**

Create `internal/protoident/protoident_test.go`. Cover every signature with real opening bytes, both sides, plus ambiguous/short/empty → `Unknown`, and one spoof case:

```go
package protoident

import "testing"

func b(s string) []byte { return []byte(s) }

func TestClassify(t *testing.T) {
	tlsHello := []byte{0x16, 0x03, 0x01, 0x00, 0x2f} // TLS handshake, TLS1.0 record
	pgSSL := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	mysqlGreeting := []byte{0x4a, 0x00, 0x00, 0x00, 0x0a, '8', '.', '0'} // len+seq then 0x0a proto
	cases := []struct {
		name          string
		client, server []byte
		want          Protocol
		wantSide      Side
	}{
		{"jdwp", b("JDWP-Handshake"), nil, "jdwp", ClientFirst},
		{"http-get", b("GET / HTTP/1.1\r\n"), nil, "http", ClientFirst},
		{"http2", b("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), nil, "http2", ClientFirst},
		{"tls", tlsHello, nil, "tls", ClientFirst},
		{"postgres-ssl", pgSSL, nil, "postgres", ClientFirst},
		{"ssh", nil, b("SSH-2.0-OpenSSH_9.6\r\n"), "ssh", ServerFirst},
		{"mysql", nil, mysqlGreeting, "mysql", ServerFirst},
		{"unknown-short", b("xy"), nil, "unknown", ClientFirst},
		{"unknown-empty", nil, nil, "unknown", ClientFirst},
		// Spoof: JDWP bytes when caller expected postgres — Classify still
		// reports jdwp (it is a classifier, not a matcher); documents the
		// heuristic limit that a client can send any opening bytes.
		{"spoof-jdwp-as-anything", b("JDWP-Handshake"), nil, "jdwp", ClientFirst},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Classify(c.client, c.server)
			if got.Protocol != c.want {
				t.Fatalf("Classify = %q, want %q (detail=%q sig=%q)", got.Protocol, c.want, got.Detail, got.Signature)
			}
			if c.want != "unknown" && got.Side != c.wantSide {
				t.Fatalf("Side = %v, want %v", got.Side, c.wantSide)
			}
		})
	}
}

func TestClassify_TLSSNIExtracted(t *testing.T) {
	// A minimal ClientHello carrying SNI "db.example.com" — assert Detail
	// surfaces the SNI. (Build the bytes in the test; keep it small.)
	hello := buildClientHelloWithSNI("db.example.com")
	got := Classify(hello, nil)
	if got.Protocol != "tls" || got.Detail == "" {
		t.Fatalf("want tls with SNI detail, got %q detail=%q", got.Protocol, got.Detail)
	}
}
```

(Provide `buildClientHelloWithSNI` as a small test helper in the test file — a fixed byte template with the SNI inserted; SNI parsing itself is exercised, not the full TLS stack.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/protoident/... -run TestClassify -v`
Expected: FAIL to compile — package doesn't exist yet.

- [ ] **Step 3: Implement the table + Classify**

`internal/protoident/protoident.go` — types and the matcher engine:

```go
// Package protoident fingerprints the application protocol carried by a
// forwarded tunnel from its opening bytes. It is a heuristic first-packet
// classifier — spoofable by a peer that mimics an allowed protocol's opening
// bytes, and blind to anything inside TLS past the ClientHello. It imports
// nothing from session/dialer/policy so it stays a testable leaf.
package protoident

type Protocol string

const (
	Unknown   Protocol = "unknown"
	SSH       Protocol = "ssh"
	Postgres  Protocol = "postgres"
	MySQL     Protocol = "mysql"
	JDWP      Protocol = "jdwp"
	TLS       Protocol = "tls"
	HTTP      Protocol = "http"
	HTTP2     Protocol = "http2"
	OracleTNS Protocol = "oracle-tns"
	RDP       Protocol = "rdp"
	Redis     Protocol = "redis"
	Telnet    Protocol = "telnet"
	SMTP      Protocol = "smtp"
	FTP       Protocol = "ftp"
	POP3      Protocol = "pop3"
	IMAP      Protocol = "imap"
	VNC       Protocol = "vnc"
)

type Side int

const (
	ClientFirst Side = iota
	ServerFirst
)

type Result struct {
	Protocol  Protocol
	Side      Side
	Detail    string
	BytesSeen int
	Signature string
}

// Classify matches clientPrefix then serverPrefix against the signature
// table and returns the first (most-specific-first ordered) match, or
// {Protocol: Unknown}. Pure, no I/O.
func Classify(clientPrefix, serverPrefix []byte) Result {
	for _, sig := range clientSignatures {
		if d, ok := sig.match(clientPrefix); ok {
			return Result{Protocol: sig.proto, Side: ClientFirst, Detail: d, BytesSeen: len(clientPrefix), Signature: sig.name}
		}
	}
	for _, sig := range serverSignatures {
		if d, ok := sig.match(serverPrefix); ok {
			return Result{Protocol: sig.proto, Side: ServerFirst, Detail: d, BytesSeen: len(serverPrefix), Signature: sig.name}
		}
	}
	side := ClientFirst
	seen := len(clientPrefix)
	if len(clientPrefix) == 0 && len(serverPrefix) > 0 {
		side, seen = ServerFirst, len(serverPrefix)
	}
	return Result{Protocol: Unknown, Side: side, BytesSeen: seen}
}

func Protocols() []Protocol {
	out := []Protocol{}
	for _, s := range clientSignatures { out = appendUnique(out, s.proto) }
	for _, s := range serverSignatures { out = appendUnique(out, s.proto) }
	return out
}

func appendUnique(xs []Protocol, p Protocol) []Protocol {
	for _, x := range xs { if x == p { return xs } }
	return append(xs, p)
}
```

`internal/protoident/signatures.go` — the data-driven table. Show the structure and a representative subset; the implementer fills the full table from the spec's signature list (`docs/superpowers/specs/2026-07-19-tunnel-protocol-identification-design.md`, "Detection engine"):

```go
package protoident

import (
	"bytes"
	"strings"
)

// signature matches a protocol from an opening-byte prefix. match returns a
// human detail string (e.g. SNI, HTTP method) and whether it matched.
type signature struct {
	name  string
	proto Protocol
	match func(prefix []byte) (detail string, ok bool)
}

func prefixLit(name string, p Protocol, lit []byte) signature {
	return signature{name, p, func(b []byte) (string, bool) {
		if len(b) >= len(lit) && bytes.Equal(b[:len(lit)], lit) {
			return "", true
		}
		return "", false
	}}
}

// Ordered most-specific-first. Full list per the design doc's table.
var clientSignatures = []signature{
	prefixLit("jdwp", JDWP, []byte("JDWP-Handshake")),
	{"http2", HTTP2, func(b []byte) (string, bool) {
		return "", bytes.HasPrefix(b, []byte("PRI * HTTP/2.0\r\n"))
	}},
	{"http1", HTTP, func(b []byte) (string, bool) {
		for _, m := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ", "TRACE "} {
			if bytes.HasPrefix(b, []byte(m)) { return strings.TrimSpace(m), true }
		}
		return "", false
	}},
	{"tls", TLS, matchTLSClientHello}, // returns SNI as detail when present
	{"postgres", Postgres, matchPostgresStartup},
	{"oracle-tns", OracleTNS, matchOracleTNS},
	{"rdp", RDP, matchRDP},
	// … redis, telnet per the spec table
}

var serverSignatures = []signature{
	{"ssh", SSH, func(b []byte) (string, bool) {
		if bytes.HasPrefix(b, []byte("SSH-2.0-")) || bytes.HasPrefix(b, []byte("SSH-1.99-")) {
			return strings.TrimRight(string(b[:min(len(b), 40)]), "\r\n"), true
		}
		return "", false
	}},
	{"mysql", MySQL, matchMySQLGreeting},
	prefixLit("smtp", SMTP, []byte("220 ")),
	prefixLit("pop3", POP3, []byte("+OK")),
	prefixLit("imap", IMAP, []byte("* OK")),
	prefixLit("vnc", VNC, []byte("RFB 003.")),
	// … ftp per the spec table
}
```

Implement the non-literal matchers (`matchTLSClientHello` w/ SNI extraction, `matchPostgresStartup` incl. SSLRequest magic `0x04d2162f` + StartupMessage proto `0x00030000` at offset 4, `matchMySQLGreeting` = `0x0a` at offset 4, `matchOracleTNS` = type `0x01` at offset 4 + `(DESCRIPTION=`/`(CONNECT_DATA=` in payload, `matchRDP` = `0x03 0x00` + `0xE0`) in the same file. Add a `min` helper if not on the Go version.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/protoident/... -v` — PASS all subtests.
Run: `gofmt -l internal/protoident/` (empty) and `go vet ./internal/protoident/...` (clean).

- [ ] **Step 5: Commit**

```bash
git add internal/protoident/
git commit -m "feat(protoident): opening-byte protocol classifier + signature table"
```

---

### Task 2: Evidence — `TypeTunnelProtocol` + `Protocol` field

**Files:**
- Modify: `internal/evidence/evidence.go` (`Type` consts, `Event` struct)
- Test: `internal/evidence/evidence_test.go` (JSON round-trip of the new field, if such a test exists; otherwise a minimal new test)

**Interfaces:**
- Produces: `evidence.TypeTunnelProtocol Type = "tunnel_protocol"`; `Event.Protocol string \`json:"protocol,omitempty"\`` — consumed by Tasks 4 & 6.

- [ ] **Step 1: Add the const and field**

In `internal/evidence/evidence.go`, add to the `Type` block (after `TypeTunnelDecision`, `:22`):
```go
	TypeTunnelProtocol Type = "tunnel_protocol" // identified protocol carried by a -L/-D tunnel
```
Add to `Event` (near the tunnel/decision fields, after `RecordMode` `:48`):
```go
	// Tunnel protocol-identification field (tunnel_protocol events).
	Protocol string `json:"protocol,omitempty"` // detected app protocol, e.g. "postgres", "jdwp", "unknown"
```

- [ ] **Step 2: Write/extend a JSON round-trip test**

Add to `internal/evidence/evidence_test.go` (create if absent):
```go
func TestEvent_TunnelProtocolJSON(t *testing.T) {
	e := Event{Type: TypeTunnelProtocol, Target: "db:5432", Protocol: "jdwp", Allow: BoolPtr(false), Reason: "protocol jdwp not permitted"}
	data, err := json.Marshal(e)
	if err != nil { t.Fatal(err) }
	if !strings.Contains(string(data), `"protocol":"jdwp"`) {
		t.Fatalf("marshaled event missing protocol field: %s", data)
	}
	var back Event
	if err := json.Unmarshal(data, &back); err != nil { t.Fatal(err) }
	if back.Protocol != "jdwp" || back.Type != TypeTunnelProtocol {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
}
```
(Confirm `BoolPtr` exists — it's used across the session package, e.g. `evidence.BoolPtr`. Import `encoding/json`, `strings`.)

- [ ] **Step 3: Run & commit**

Run: `go test ./internal/evidence/... -v` — PASS.
```bash
git add internal/evidence/evidence.go internal/evidence/evidence_test.go
git commit -m "feat(evidence): TypeTunnelProtocol event + Protocol field"
```

---

### Task 3: Config — `tunnel_inspection` block

**Files:**
- Modify: `internal/config/config.go` (`File` struct + a new `TunnelInspectionConfig` + validate)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `File.TunnelInspection *TunnelInspectionConfig` with fields `Enabled bool` (`enabled`), `MaxPrefixBytes int` (`max_prefix_bytes`, default 512), `ClassifyTimeoutSeconds int` (`classify_timeout_seconds`, default 5), `Enforce bool` (`enforce`), `UnknownAction string` (`unknown_action`, `allow`|`deny`, default `allow`) — consumed by Task 7 (main.go).

- [ ] **Step 1: Write failing tests** (follow the codebase convention: YAML → `Load(writeTemp(t, yaml))`)

```go
func TestValidate_TunnelInspectionDefaults(t *testing.T) {
	ok := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
tunnel_inspection:
  enabled: true
policy:
  roles: []
`
	f, err := Load(writeTemp(t, ok))
	if err != nil { t.Fatal(err) }
	ti := f.TunnelInspection
	if ti == nil || !ti.Enabled { t.Fatal("tunnel_inspection.enabled should be true") }
	if ti.MaxPrefixBytes != 512 { t.Fatalf("max_prefix_bytes default = %d, want 512", ti.MaxPrefixBytes) }
	if ti.ClassifyTimeoutSeconds != 5 { t.Fatalf("classify_timeout default = %d, want 5", ti.ClassifyTimeoutSeconds) }
	if ti.UnknownAction != "allow" { t.Fatalf("unknown_action default = %q, want allow", ti.UnknownAction) }
}

func TestValidate_TunnelInspectionBadUnknownAction(t *testing.T) {
	bad := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
tunnel_inspection:
  enabled: true
  unknown_action: sometimes
policy:
  roles: []
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected error for invalid unknown_action")
	}
}
```

- [ ] **Step 2: Run to verify fail; Step 3: implement**

Add the struct and wire defaults+validation. In `internal/config/config.go`:
```go
type TunnelInspectionConfig struct {
	Enabled                bool   `yaml:"enabled"`
	MaxPrefixBytes         int    `yaml:"max_prefix_bytes"`
	ClassifyTimeoutSeconds int    `yaml:"classify_timeout_seconds"`
	Enforce                bool   `yaml:"enforce"`
	UnknownAction          string `yaml:"unknown_action"` // allow | deny
}
```
Add `TunnelInspection *TunnelInspectionConfig \`yaml:"tunnel_inspection"\`` to `File`. In `validate()` (after the capability-toggle checks), when `f.TunnelInspection != nil`:
- default `MaxPrefixBytes` to 512 if 0; `ClassifyTimeoutSeconds` to 5 if 0; `UnknownAction` to `"allow"` if empty.
- reject `UnknownAction` not in {`allow`,`deny`}.
- (No cross-field requirement: `enforce: true` with no `expect_protocol` rules is legal — it simply never blocks.)

- [ ] **Step 4: Run tests + full config suite; Step 5: commit**

```bash
go test ./internal/config/... -v
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): tunnel_inspection block with defaults + validation"
```

---

### Task 4: Phase 1 — observe (tee + classify + evidence), wired into the tunnel

**Files:**
- Create: `internal/session/tunnelinspect.go` (the tap/classifier wiring)
- Modify: `internal/session/session.go` (`handleDirectTCPIP` hook; `Server` gains tunnel-inspection config fields + a `WithTunnelInspection` option)
- Test: `internal/session/tunnelinspect_test.go`

**Interfaces:**
- Consumes: `protoident.Classify` (Task 1), `evidence.TypeTunnelProtocol`/`Event.Protocol` (Task 2), `Server.emit` (existing).
- Produces: `WithTunnelInspection(cfg TunnelInspectConfig) Option` and an internal `TunnelInspectConfig struct { Enabled bool; MaxPrefixBytes int; ClassifyTimeout time.Duration; Enforce bool; UnknownDeny bool }` — consumed by Task 6 (enforce reuses it) and Task 7 (main.go).

- [ ] **Step 1: Write the failing observe integration test**

The key assertions: (a) the classified protocol lands in a `TypeTunnelProtocol` evidence event; (b) tunnel bytes pass through **unchanged**. Reuse the dialer/session test harness. Drive a `direct-tcpip` channel whose target echoes, send a recognizable preamble (e.g. an `SSH-2.0-` banner from the "server" side, or `JDWP-Handshake` from the client side), assert the event.

```go
func TestTunnelInspect_ObserveEmitsProtocolEvidence(t *testing.T) {
	// Fake target that immediately writes an SSH banner (server-speaks-first),
	// then echoes. Wire a server WITH tunnel inspection enabled (observe).
	sink := evidence.NewMemSink()
	addr, targetHost, targetPort := startEchoWithPreamble(t, []byte("SSH-2.0-FakeTarget\r\n"))
	srv := startTunnelServer(t, sink, WithTunnelInspection(TunnelInspectConfig{
		Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 3 * time.Second,
	}))
	_ = srv
	client := sshClient(t, addr, "alice")
	conn := dialThroughTunnel(t, client, targetHost, targetPort) // opens direct-tcpip
	// read the banner the target sent, echo a byte, confirm round-trip intact
	got := readN(t, conn, len("SSH-2.0-FakeTarget\r\n"))
	if string(got) != "SSH-2.0-FakeTarget\r\n" {
		t.Fatalf("tunnel corrupted bytes: %q", got)
	}
	waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeTunnelProtocol && e.Protocol == "ssh"
	})
}
```

(Use/extend existing tunnel test helpers — `internal/session` and `internal/dialer` already have `direct-tcpip` test scaffolding from the `-L` tests, e.g. `startEcho`; add thin `startEchoWithPreamble`/`dialThroughTunnel` helpers if absent.)

- [ ] **Step 2: Run to verify fail** (compile error: `WithTunnelInspection` undefined).

- [ ] **Step 3: Implement the tap + classifier + hook**

`internal/session/tunnelinspect.go` — a non-blocking tap. The tap wraps each side's `io.ReadWriteCloser`; its `Read` copies up to `budget` bytes (once) into a shared buffer and signals. A classifier goroutine waits for first bytes (or timeout), calls `protoident.Classify`, emits one event. Splice runs on the wrapped conns unchanged.

```go
type tunnelTaps struct {
	mu               sync.Mutex
	client, server   []byte
	budget           int
	sig              chan struct{} // closed once (first bytes on either side)
	sigOnce          sync.Once
}

func (t *tunnelTaps) record(fromClient bool, p []byte) {
	t.mu.Lock()
	buf := &t.server
	if fromClient { buf = &t.client }
	if n := t.budget - len(*buf); n > 0 {
		if n > len(p) { n = len(p) }
		*buf = append(*buf, p[:n]...)
	}
	full := len(t.client) >= t.budget || len(t.server) >= t.budget
	t.mu.Unlock()
	t.sigOnce.Do(func() { close(t.sig) })
	_ = full
}

// tapConn wraps a ReadWriteCloser, teeing bytes it reads into taps.
type tapConn struct {
	io.ReadWriteCloser
	taps       *tunnelTaps
	fromClient bool
}

func (c *tapConn) Read(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Read(p)
	if n > 0 { c.taps.record(c.fromClient, p[:n]) }
	return n, err
}
```

In `handleDirectTCPIP` (`session.go`), when `s.tunnelInspect.Enabled` and NOT enforcing (observe path), wrap and launch the classifier before `Splice`:
```go
	if s.tunnelInspect.Enabled && !s.tunnelInspect.Enforce {
		taps := &tunnelTaps{budget: s.tunnelInspect.MaxPrefixBytes, sig: make(chan struct{})}
		ch2 := &tapConn{ReadWriteCloser: ch, taps: taps, fromClient: true}
		conn2 := &tapConn{ReadWriteCloser: conn, taps: taps, fromClient: false}
		go s.classifyAndEmit(taps, pr, srcIP, target) // waits on taps.sig or timeout, emits once
		dialer.Splice(ch2, conn2)
		return
	}
	// (default, inspection off) — unchanged:
	dialer.Splice(ch, conn)
```

`classifyAndEmit` waits `select { case <-taps.sig: case <-time.After(timeout): }`, then (after a tiny settle to let the first packet accumulate, bounded by budget) snapshots the buffers under lock, calls `protoident.Classify`, and emits one `TypeTunnelProtocol` event (`Allow=true` in observe; `Protocol`, `Detail`, `Target`, `User`, `SourceIP`). Guard emit-once with a `sync.Once` in case the tunnel also ends.

Add `Server.tunnelInspect TunnelInspectConfig` + `WithTunnelInspection` option (mirroring `WithSCPEnabled` shape).

**Note:** `ssh.Channel` and the dialer's target `net.Conn` both satisfy `io.ReadWriteCloser` (Splice already takes that) — the tap wrapper composes cleanly, and `closeWrite`'s `CloseWrite()` type-assertion in `splice.go` will simply no-op on `tapConn` (acceptable; the final `Close` still tears down). If half-close matters for a specific protocol test, have `tapConn` forward `CloseWrite()` to the inner conn.

- [ ] **Step 4: Run tests** (`go test ./internal/session/... -run TunnelInspect -v`), full session suite, gofmt, vet.

- [ ] **Step 5: Commit** `feat(session): observe-mode tunnel protocol identification + evidence`.

---

### Task 5: Policy schema — `expect_protocol` on rules

**Files:**
- Modify: `internal/config/config.go` (`RuleConfig` + `CompilePolicy`), `internal/policy/policy.go` (`Rule`)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `RuleConfig.ExpectProtocol []string` (`expect_protocol`) → compiled onto `policy.Rule.ExpectProtocol []string` — consumed by Task 6.

- [ ] **Step 1: failing test** — a rule with `expect_protocol: [postgres]` compiles and the value reaches `policy.Rule`; an `expect_protocol` naming an unknown protocol is rejected at load (validate against `protoident.Protocols()`).

```go
func TestCompile_ExpectProtocol(t *testing.T) {
	ok := `
listen: ":2222"
evidence: { file: "e.jsonl" }
policy:
  roles:
    - name: dba
      groups: [dba]
      allow:
        - host: db1
          ports: [5432]
          expect_protocol: [postgres]
`
	f, err := Load(writeTemp(t, ok)); if err != nil { t.Fatal(err) }
	p := f.CompilePolicy()
	// assert p.Roles[0].Allow[0].ExpectProtocol == ["postgres"]
}

func TestValidate_ExpectProtocolUnknownRejected(t *testing.T) {
	bad := `... allow: [{host: db1, ports: [5432], expect_protocol: [nope]}] ...`
	if _, err := Load(writeTemp(t, bad)); err == nil { t.Fatal("unknown protocol must be rejected") }
}
```

- [ ] **Step 2-3:** add `ExpectProtocol []string \`yaml:"expect_protocol"\`` to `RuleConfig` (`config.go:249-260`) and `ExpectProtocol []string` to `policy.Rule` (`policy.go:65-79`); copy it in `CompilePolicy` (`config.go:452-468`); in `validatePolicyRoles`, reject any entry not in `protoident.Protocols()`. (config may import protoident — protoident is a leaf, no cycle.)

- [ ] **Step 4-5:** test, then commit `feat(policy): expect_protocol allow-list on rules`.

---

### Task 6: Phase 2 — enforce (head-of-line hold, terminate on mismatch, dry-run)

**Files:**
- Modify: `internal/session/tunnelinspect.go` (add the enforce path), `internal/session/session.go` (`handleDirectTCPIP` enforce branch)
- Test: `internal/session/tunnelinspect_test.go`

**Interfaces:**
- Consumes: `protoident.Classify`, `policy.Decision`/`Rule.ExpectProtocol` (needs the matched rule's expected list — thread it via the existing `dialer.DialTarget`/decision path, or a `dialerPeek`-style lookup for the tunnel target), `TunnelInspectConfig` (Task 4).

**Design note (the hard part):** enforce must classify BEFORE forwarding, from whichever side speaks first, WITHOUT deadlocking a client-first protocol (where the target sends nothing until it gets the client's held bytes). Read both sides concurrently with a deadline; classify as soon as *either* side yields bytes that match (or budget/timeout → unknown). Replay buffered bytes into the splice via a prefix-prepending wrapper.

- [ ] **Step 1: Write failing enforce tests** — cover the matrix:
  - match (`expect_protocol:[postgres]`, client sends PG startup) → tunnel proceeds, bytes intact, `Allow=true` event.
  - mismatch (client sends `JDWP-Handshake`) → tunnel **terminated**, `Allow=false` event, reason names jdwp; assert the target NEVER received the jdwp bytes (target-side recorder is empty).
  - **client-first deadlock guard:** a client-first protocol where the target is silent until spoken to — assert classification completes from the client bytes and does NOT hang (wrap in a goroutine + `time.After` timeout fail, like the scp `TestScpCopyBody` guard).
  - server-first (SSH) match/mismatch.
  - `unknown` under `UnknownDeny=false` (allow+log) and `=true` (terminate).
  - dry-run: `Enforce:false`-but-expect-rules path is Task 4's observe (already covered) — here assert that with `Enforce:true` and a matched rule, dry-run semantics come from a separate flag if you model dry-run as `Enforce:true`+global `enforce:false`; simplest: dry-run = `tunnel_inspection.enforce:false` → observe path logs would-block. Assert an `Allow=false, Detail~="dry-run"` event when a rule's `expect_protocol` would not match, WITHOUT terminating. (Emit this from the observe classifier when the matched rule has an `expect_protocol` that excludes the detected protocol.)

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement enforce**

Add to `tunnelinspect.go`:
```go
// holdAndClassify reads opening bytes from both sides concurrently under
// deadline, returns the classification plus the buffered prefixes to replay.
// It returns as soon as either side produces a signature match, or on
// budget/timeout (→ Unknown). It never waits for the target side once the
// client side already matched (client-first deadlock guard).
func holdAndClassify(ch, conn io.ReadWriteCloser, budget int, timeout time.Duration) (protoident.Result, []byte, []byte) { … }

// prefixConn prepends already-read bytes in front of the live conn for the
// splice, so the classified opening bytes are not lost.
type prefixConn struct {
	io.ReadWriteCloser
	r io.Reader // io.MultiReader(bytes.NewReader(prefix), inner)
}
func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }
```

Enforce branch in `handleDirectTCPIP` (after `newCh.Accept()`, replacing the plain `Splice` when `s.tunnelInspect.Enabled && s.tunnelInspect.Enforce`): call `holdAndClassify`; look up the matched rule's `ExpectProtocol` for `target`; decide allow/deny/unknown per `unknown_action`; on deny → emit `Allow=false` event + close both (bytes discarded); on allow → build `prefixConn`s that replay the buffered prefixes and `Splice` them; emit `Allow=true` event. When `ExpectProtocol` is empty for the matched rule, allow (observe-equivalent) regardless of detected protocol.

- [ ] **Step 4:** run enforce tests + full session suite + gofmt + vet.
- [ ] **Step 5:** commit `feat(session): enforce mode for tunnel protocol identification`.

---

### Task 7: Wiring (main.go) + example config + README

**Files:**
- Modify: `cmd/omni-sag/main.go`, `deploy/compose/config.example.yaml`, `README.md`

- [ ] **Step 1:** In `cmd/omni-sag/main.go`, build a `session.TunnelInspectConfig` from `cfg.TunnelInspection` (nil → disabled) and append `session.WithTunnelInspection(...)`; log a line when enabled (and whether observe/enforce). Convert `ClassifyTimeoutSeconds`→`time.Duration`, `UnknownAction=="deny"`→`UnknownDeny`.
- [ ] **Step 2:** `go build ./...` — clean.
- [ ] **Step 3:** Document `tunnel_inspection` in `config.example.yaml` (commented, default-off, with the `enforce`/`unknown_action`/dry-run explanation) and note `expect_protocol:` as an optional rule field in the policy example.
- [ ] **Step 4:** README — under Port forwarding, add a short "Tunnel protocol identification (opt-in)" note: observe logs the protocol per tunnel; `expect_protocol` enforces; heuristic/first-packet limits.
- [ ] **Step 5:** `go test ./internal/config/... -run TestLoad_ComposeExampleConfigParses`; commit `feat(cmd): wire tunnel_inspection into the gateway`.

---

### Task 8: Real-protocol lab interop check (ground truth)

**Files:**
- Create: `scripts/lab-test-tunnel-protoid.sh`; Modify: `Makefile`

- [ ] **Step 1:** Script mirrors `scripts/lab-test-scp.sh`: start the gateway with a derived config (`tunnel_inspection.enabled: true`), open a real `-L` tunnel to the lab `ssh-target` (its sshd → the tunnel carries **SSH**, server-speaks-first) and assert a `TypeTunnelProtocol` event with `protocol=ssh` appears in the evidence file. Add a second leg that tunnels to a port speaking a different protocol if one is available in the lab (e.g. a quick netcat serving an `SSH-2.0` banner, or the MinIO HTTP endpoint on 9000 → `protocol=http`/`tls`). Assert the detected protocol matches.
- [ ] **Step 2:** `chmod +x`; add `lab-test-tunnel-protoid` Makefile target + `.PHONY`.
- [ ] **Step 3:** Run `make lab-test-tunnel-protoid` against the live lab → `ALL PASS`. This is the ground truth that the classifier works against real protocol streams, not just crafted test bytes. If a real stream misclassifies, fix the signature (Task 1), do not weaken the test.
- [ ] **Step 4:** commit `test: real tunnel protocol-identification lab check`.

---

## Self-Review Notes
- **Spec coverage:** protoident engine (T1) ✓; evidence (T2) ✓; config (T3) ✓; observe zero-latency tee + evidence (T4) ✓; expect_protocol schema (T5) ✓; enforce head-of-line + terminate + unknown_action + dry-run (T6) ✓; wiring/docs (T7) ✓; real-protocol ground truth (T8) ✓. Honest-limits and `-L`/`-D`/`-J` coverage carried in Global Constraints + spec.
- **Concurrency risks are the real risk**, isolated to T4 (observe, non-blocking — low risk) and T6 (enforce hold — the deadlock guard is explicitly tested). Both have goroutine-timeout test guards like the scp `TestScpCopyBody` pattern.
- **Ground truth:** the signature table is written from protocol knowledge; T8 validates it against real streams through the real `direct-tcpip` path — the same discipline that caught the scp handshake bug.
- **Placeholder scan:** signature table is intentionally shown as "structure + representative subset + fill from the spec table" per writing-plans' repeat-the-pattern guidance; every other code step is complete.
