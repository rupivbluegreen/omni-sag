package session

import (
	"fmt"
	"testing"

	"github.com/pkg/sftp"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// Independent capability toggles (WithSSHDisabled, WithTunnelDisabled,
// WithSFTPDisabled) each reject only their own request/channel type,
// leaving the other two capabilities unaffected.

func TestTunnelDisabled_DirectTCPIPRejected(t *testing.T) {
	echoHost, echoPort := startEcho(t)
	p := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: echoHost, Ports: []int{echoPort}}},
	}}}
	sink := evidence.NewMemSink()
	addr := startServerWith(t, p, dbaAuth(), sink, WithTunnelDisabled(true))

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", echoHost, echoPort))
	if err == nil {
		conn.Close()
		t.Fatal("-L forward must be rejected when tunnel is disabled")
	}
}

func TestSSHDisabled_ShellRequestRejected(t *testing.T) {
	targetHost, targetOpts := wireFakeTarget(t, "targetpw", nil)
	sink := evidence.NewMemSink()
	opts := append(append([]Option{}, targetOpts...), WithSSHDisabled(true))
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, opts...)
	client := sshClient(t, addr, "alice%"+targetHost)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if err := sess.Shell(); err == nil {
		t.Fatal("shell request must be rejected when ssh is disabled")
	}
}

func TestSFTPDisabled_SubsystemRejected(t *testing.T) {
	targetHost, targetOpts := wireFakeSFTPTarget(t, nil)
	sink := evidence.NewMemSink()
	opts := append(append([]Option{}, targetOpts...), WithSFTPDisabled(true))
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, opts...)
	client := sshClient(t, addr, "alice%"+targetHost)

	if _, err := sftp.NewClient(client); err == nil {
		t.Fatal("sftp subsystem must be rejected when sftp is disabled")
	}
}

// TestSSHAndSFTPDisabled_OnlyTunnelWorks reproduces the earlier tunnel_only
// use case (shell + SFTP off, tunnel on) via two independent flags, proving
// that combination is still reachable end-to-end on the same connection.
func TestSSHAndSFTPDisabled_OnlyTunnelWorks(t *testing.T) {
	echoHost, echoPort := startEcho(t)
	p := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: echoHost, Ports: []int{echoPort}}},
	}}}
	targetHost, targetOpts := wireFakeSFTPTarget(t, nil)
	sink := evidence.NewMemSink()
	opts := append(append([]Option{}, targetOpts...), WithSSHDisabled(true), WithSFTPDisabled(true))
	addr := startServerWith(t, p, dbaAuth(), sink, opts...)

	// Tunnel still works.
	tunnelClient := sshClient(t, addr, "alice")
	conn, err := tunnelClient.Dial("tcp", fmt.Sprintf("%s:%d", echoHost, echoPort))
	if err != nil {
		t.Fatalf("-L forward should still be allowed: %v", err)
	}
	conn.Close()

	// Shell and SFTP both fail on the same (session-channel) connection.
	sessionClient := sshClient(t, addr, "alice%"+targetHost)
	sess, err := sessionClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Shell(); err == nil {
		t.Fatal("shell request must be rejected")
	}

	sftpClient := sshClient(t, addr, "alice%"+targetHost)
	if _, err := sftp.NewClient(sftpClient); err == nil {
		t.Fatal("sftp subsystem must be rejected")
	}
}
