package session

import (
	"net"
	"path"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// startFakeSFTPTarget runs an in-process SSH server that serves the "sftp"
// subsystem with a real github.com/pkg/sftp request server backed by
// sftp.InMemHandler(), seeded with the given files, and returns a client-side
// net.Conn to dial (a fresh connection, independent of the one used to seed
// the files below — see the deviation note). It runs until the test ends.
//
// Two deliberate deviations from a naive first draft of this helper, found
// while implementing this task:
//
//  1. It listens on TCP loopback and dials it (like Task 7's
//     target_test.go's fakeTargetPipe helper), not net.Pipe(): a raw
//     net.Pipe() is fully synchronous with zero internal buffering, and the
//     SSH transport's version exchange has both sides write their
//     identification line before reading the peer's — over net.Pipe that
//     deadlocks every time (see fakeTargetPipe's doc comment for the full
//     explanation). A listener is used here, rather than fakeTargetPipe
//     itself, because this helper needs a second, internal connection to
//     seed files (deviation 2 below) in addition to the one returned to the
//     caller.
//
//  2. It backs the fake server with sftp.InMemHandler() (a pure in-memory
//     virtual filesystem), not sftp.NewServer(ch, sftp.WithServerWorkingDirectory(dir))
//     over a real temp dir. sftp.NewServer's workDir option only rewrites
//     *relative* request paths (see server_unix.go: "if s.workDir != "" &&
//     !path.IsAbs(p)"); every request this package's remoteFS/memFS sends is
//     made absolute first by cleanPath (path.Clean("/"+p)), so workDir never
//     applies and sftp.NewServer instead serves the real OS filesystem
//     rooted at "/". Confirmed the hard way: an earlier version of this test
//     requesting "/etc/motd" silently returned the *test runner's own*
//     /etc/motd instead of the seeded temp-dir file, and only failed because
//     the content happened to differ. sftp.InMemHandler() cannot leak host
//     files at all, for any path, so it is used instead — it is still a real
//     wire-protocol SFTP server (sftp.NewRequestServer + Handlers, the same
//     shape production runSFTP uses), just backed by memory instead of disk.
func startFakeSFTPTarget(t *testing.T, files map[string][]byte) net.Conn {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(testHostKey(t))

	// Shared across every connection this fake target accepts, so a
	// seeding connection (below) and the caller's own connection observe
	// the same virtual filesystem.
	handlers := sftp.InMemHandler()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startFakeSFTPTarget: listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	serveConn := func(conn net.Conn) {
		sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				_ = newCh.Reject(ssh.UnknownChannelType, "")
				continue
			}
			ch, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func() {
				// The request server does not close ch itself when Serve
				// returns (only conn-level errors trigger that internally):
				// closing here is required so the client's sftp.Client.Close
				// (which waits for the channel's read side to reach EOF)
				// doesn't block forever after Serve exits.
				defer ch.Close()
				for req := range reqs {
					isSubsystem := req.Type == "subsystem"
					req.Reply(isSubsystem, nil)
					if isSubsystem {
						_ = sftp.NewRequestServer(ch, handlers).Serve()
						return
					}
				}
			}()
		}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed on test cleanup
			}
			go serveConn(conn)
		}
	}()

	// Seed the requested files over a throwaway connection/client, before
	// handing the caller their own connection to the same shared handlers.
	seedConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("startFakeSFTPTarget: seed dial: %v", err)
	}
	// seedClient.Close() below only closes the SFTP subsystem session, not
	// the underlying ssh.Client/net.Conn (pkg/sftp's Client.Close tears down
	// its own session but doesn't own the transport it was built over) — so
	// the raw conn needs its own cleanup or its server- and client-side
	// transport goroutines leak for the life of the test binary.
	t.Cleanup(func() { seedConn.Close() })
	seedClient, err := sftp.NewClient(sshClientOver(t, seedConn))
	if err != nil {
		t.Fatalf("startFakeSFTPTarget: seed sftp client: %v", err)
	}
	for name, content := range files {
		if dir := path.Dir(name); dir != "/" && dir != "." {
			if err := seedClient.MkdirAll(dir); err != nil {
				t.Fatalf("seed file %s: mkdir %s: %v", name, dir, err)
			}
		}
		f, err := seedClient.Create(name)
		if err != nil {
			t.Fatalf("seed file %s: create: %v", name, err)
		}
		if _, err := f.Write(content); err != nil {
			t.Fatalf("seed file %s: write: %v", name, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("seed file %s: close: %v", name, err)
		}
	}
	if err := seedClient.Close(); err != nil {
		t.Fatalf("startFakeSFTPTarget: seed client close: %v", err)
	}

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("startFakeSFTPTarget: dial: %v", err)
	}
	t.Cleanup(func() { clientConn.Close() })
	return clientConn
}

// sshClientOver completes an ssh.ClientConfig handshake over conn for test
// use (no auth, insecure host key check — the fake target above requires
// neither).
func sshClientOver(t *testing.T, conn net.Conn) *ssh.Client {
	t.Helper()
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, "target", &ssh.ClientConfig{
		User: "test", Auth: nil, HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("ssh.NewClientConn: %v", err)
	}
	return ssh.NewClient(clientConn, chans, reqs)
}

func TestRemoteFS_FilereadProxiesRealTarget(t *testing.T) {
	fakeConn := startFakeSFTPTarget(t, map[string][]byte{"/etc/motd": []byte("hello from target\n")})
	client, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer client.Close()

	fs := &remoteFS{client: client, gate: nil}
	r, err := fs.Fileread(&sftp.Request{Method: "Get", Filepath: "/etc/motd"})
	if err != nil {
		t.Fatalf("Fileread: %v", err)
	}
	buf := make([]byte, 32)
	n, _ := r.ReadAt(buf, 0)
	if got := string(buf[:n]); got != "hello from target\n" {
		t.Fatalf("Fileread content = %q, want %q", got, "hello from target\n")
	}
}
