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

// Protocols returns the set of protocols the signature table recognizes, for
// config validation of expect_protocol rules.
func Protocols() []Protocol {
	out := []Protocol{}
	for _, s := range clientSignatures {
		out = appendUnique(out, s.proto)
	}
	for _, s := range serverSignatures {
		out = appendUnique(out, s.proto)
	}
	return out
}

func appendUnique(xs []Protocol, p Protocol) []Protocol {
	for _, x := range xs {
		if x == p {
			return xs
		}
	}
	return append(xs, p)
}
