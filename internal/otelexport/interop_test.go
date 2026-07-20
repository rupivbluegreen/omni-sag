//go:build interop

// Ground-truth interop test: drives one real SSH session through the real
// internal/session + internal/dialer library code, with internal/otelexport
// pointed at a REAL OTel Collector (scripts/otel-lab), and asserts the
// collector's file exporter actually received the omnisag.connection trace
// tree — proof the OTLP wire path works end-to-end, not just this repo's own
// in-memory SpanRecorder tests.
//
// Run:
//
//	docker compose -f scripts/otel-lab/docker-compose.yaml up -d
//	go test -tags interop ./internal/otelexport/... -run TestInterop -v
//	docker compose -f scripts/otel-lab/docker-compose.yaml down
package otelexport

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/session"
)

func dialerPolicy(host string, port int) policy.Policy {
	return policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: host, Ports: []int{port}}},
	}}}
}

// fakeAuth accepts any username with password "pw" — the interop lab has no
// LDAP dependency; it exercises the OTLP wire path, not authentication.
type fakeAuth struct{}

func (fakeAuth) Authenticate(_ context.Context, username, password string) (authn.Identity, error) {
	if password != "pw" {
		return authn.Identity{}, fmt.Errorf("bad password")
	}
	return authn.Identity{User: username, Groups: []string{"dba"}}, nil
}

func startEchoTarget(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	var port64 int
	fmt.Sscanf(p, "%d", &port64)
	return h, port64
}

func TestInterop_ConnectionSpanTreeArrivesAtRealCollector(t *testing.T) {
	endpoint := os.Getenv("OTEL_LAB_ENDPOINT")
	if endpoint == "" {
		endpoint = "127.0.0.1:4317"
	}
	outputPath := os.Getenv("OTEL_LAB_OUTPUT")
	if outputPath == "" {
		outputPath = filepath.Join("..", "..", "scripts", "otel-lab", "output", "otel-output.jsonl")
	}

	ctx := context.Background()
	providers, err := Setup(ctx, Config{
		Enabled:  true,
		Endpoint: endpoint,
		Protocol: "grpc",
		Insecure: true,
		Traces:   TracesConfig{Enabled: true, Sampler: "always_on"},
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	echoHost, echoPort := startEchoTarget(t)
	sink := evidence.NewMemSink()
	d := dialer.New(dialerPolicy(echoHost, echoPort), sink, dialer.WithLoopbackTargetsAllowed())
	hostKey, err := session.NewEphemeralHostKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := session.New(hostKey, fakeAuth{}, d, sink)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(srvCtx, ln)

	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", echoHost, echoPort))
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	client.Close()
	// Give handleConn's per-channel goroutine and the connection teardown a
	// moment to run and end their spans (root/channel/tunnel/splice all end
	// only once their enclosing function actually returns, asynchronously
	// from this client-side Close) before flushing to the collector.
	time.Sleep(150 * time.Millisecond)

	// Flush + close: bounded, so a slow/dead collector wouldn't hang this
	// test either, but here the collector is real and reachable.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := providers.Shutdown(shutCtx); err != nil {
		t.Fatalf("Shutdown (flush to collector): %v", err)
	}

	// Give the collector a moment to fsync its file exporter batch.
	var body string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(outputPath)
		if err == nil && len(b) > 0 {
			body = string(b)
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if body == "" {
		t.Fatalf("collector output file %s is empty or missing — is the lab running? (docker compose -f scripts/otel-lab/docker-compose.yaml up -d)", outputPath)
	}

	for _, want := range []string{"omnisag.connection", "omnisag.auth", "omnisag.channel", "omnisag.tunnel", "omnisag.dial", "omnisag.splice"} {
		if !strings.Contains(body, want) {
			t.Errorf("collector output missing span %q", want)
		}
	}
	t.Logf("collector received %d bytes of span data; span names verified present", len(body))
}
