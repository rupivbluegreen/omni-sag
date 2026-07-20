package session

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// startEchoWithPreamble starts a TCP listener that writes preamble once per
// accepted connection (a server-speaks-first target, e.g. an SSH banner),
// then echoes anything it subsequently receives.
func startEchoWithPreamble(t *testing.T, preamble []byte) (string, int) {
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
			go func() {
				if _, err := c.Write(preamble); err != nil {
					c.Close()
					return
				}
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func TestTunnelInspect_ObserveEmitsProtocolEvidence(t *testing.T) {
	sink := evidence.NewMemSink()
	preamble := []byte("SSH-2.0-FakeTarget\r\n")
	targetHost, targetPort := startEchoWithPreamble(t, preamble)

	p := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: targetHost, Ports: []int{targetPort}}},
	}}}
	addr := startServerWith(t, p, dbaAuth(), sink, WithTunnelInspection(TunnelInspectConfig{
		Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 3 * time.Second,
	}))

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()

	got := make([]byte, len(preamble))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read preamble through tunnel: %v", err)
	}
	if string(got) != string(preamble) {
		t.Fatalf("tunnel corrupted bytes: got %q, want %q", got, preamble)
	}

	waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeTunnelProtocol && e.Protocol == "ssh"
	})
}
