package session

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

// These fuzz targets exercise the SSH channel/request payload parsers that sit
// directly on attacker-controlled bytes: a client fully controls the
// direct-tcpip channel ExtraData and the pty-req / subsystem request payloads.
// ssh.Unmarshal must reject garbage with an error, never panic, hang, or OOM,
// and the fields the handlers read afterwards must be safe to consume.

// FuzzDirectTCPIPUnmarshal fuzzes the direct-tcpip channel-open payload parser
// used by handleDirectTCPIP (session.go). The bytes come from newCh.ExtraData(),
// which is entirely client-controlled.
func FuzzDirectTCPIPUnmarshal(f *testing.F) {
	// Realistic well-formed payloads: host, port, originator ip, originator port.
	f.Add(marshalDirectTCPIP("10.0.0.5", 22, "192.168.1.2", 51000))
	f.Add(marshalDirectTCPIP("example.internal", 443, "10.1.2.3", 40000))
	f.Add(marshalDirectTCPIP("", 0, "", 0))
	// Degenerate / truncated seeds.
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x04})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		var d directTCPIP
		if err := ssh.Unmarshal(data, &d); err != nil {
			return // rejected cleanly — the handler would Reject the channel
		}
		// On success the handler builds a policy.Target from these fields; make
		// sure reading them is safe (no huge-alloc, no panic).
		host, port := policyTargetFrom(d)
		_, _ = host, port
	})
}

// FuzzPtyRequestUnmarshal fuzzes the pty-req payload parser in interactive.go.
func FuzzPtyRequestUnmarshal(f *testing.F) {
	f.Add(marshalPtyReq("xterm-256color", 80, 24))
	f.Add(marshalPtyReq("vt100", 132, 43))
	f.Add(marshalPtyReq("", 0, 0))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0xff, 'x'})

	f.Fuzz(func(t *testing.T, data []byte) {
		var p ptyRequest
		if err := ssh.Unmarshal(data, &p); err != nil {
			return
		}
		// handleSession reads Cols/Rows; make sure the int conversion the handler
		// performs cannot misbehave.
		_ = int(p.Cols)
		_ = int(p.Rows)
	})
}

// FuzzSubsystemRequestUnmarshal fuzzes the subsystem request payload parser.
func FuzzSubsystemRequestUnmarshal(f *testing.F) {
	f.Add(marshalSubsystem("sftp"))
	f.Add(marshalSubsystem("exec"))
	f.Add(marshalSubsystem(""))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x10, 's'})

	f.Fuzz(func(t *testing.T, data []byte) {
		var sub subsystemRequest
		if err := ssh.Unmarshal(data, &sub); err != nil {
			return
		}
		_ = sub.Name == "sftp"
	})
}

func policyTargetFrom(d directTCPIP) (string, int) {
	return d.HostToConnect, int(d.PortToConnect)
}

func marshalDirectTCPIP(host string, port uint32, oip string, oport uint32) []byte {
	return ssh.Marshal(directTCPIP{
		HostToConnect: host, PortToConnect: port,
		OriginatorIP: oip, OriginatorPort: oport,
	})
}

func marshalPtyReq(term string, cols, rows uint32) []byte {
	return ssh.Marshal(ptyRequest{Term: term, Cols: cols, Rows: rows})
}

func marshalSubsystem(name string) []byte {
	return ssh.Marshal(subsystemRequest{Name: name})
}
