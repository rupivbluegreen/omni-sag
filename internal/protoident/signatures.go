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

// Ordered most-specific-first.
var clientSignatures = []signature{
	prefixLit("jdwp", JDWP, []byte("JDWP-Handshake")),
	{"http2", HTTP2, func(b []byte) (string, bool) {
		return "", bytes.HasPrefix(b, []byte("PRI * HTTP/2.0\r\n"))
	}},
	{"http1", HTTP, func(b []byte) (string, bool) {
		for _, m := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ", "TRACE "} {
			if bytes.HasPrefix(b, []byte(m)) {
				return strings.TrimSpace(m), true
			}
		}
		return "", false
	}},
	{"tls", TLS, matchTLSClientHello}, // returns SNI as detail when present
	{"postgres", Postgres, matchPostgresStartup},
	{"oracle-tns", OracleTNS, matchOracleTNS},
	{"rdp", RDP, matchRDP},
	{"redis", Redis, matchRedis},
	{"telnet", Telnet, func(b []byte) (string, bool) {
		return "", len(b) > 0 && b[0] == 0xFF
	}},
}

var serverSignatures = []signature{
	{"ssh", SSH, func(b []byte) (string, bool) {
		if bytes.HasPrefix(b, []byte("SSH-2.0-")) || bytes.HasPrefix(b, []byte("SSH-1.99-")) {
			return strings.TrimRight(string(b[:min(len(b), 40)]), "\r\n"), true
		}
		return "", false
	}},
	{"mysql", MySQL, matchMySQLGreeting},
	// SMTP and FTP servers both commonly greet with a "220 " banner (RFC 5321
	// / RFC 959 use the same response code for "service ready") — the opening
	// bytes alone do not disambiguate them. ftp is checked first and claims
	// the match only when the banner text itself mentions FTP; anything else
	// starting "220 " falls through to smtp. Documented heuristic limit, not
	// a bug: see the package doc and design doc "Ambiguity handling".
	{"ftp", FTP, func(b []byte) (string, bool) {
		if !bytes.HasPrefix(b, []byte("220 ")) {
			return "", false
		}
		if bytes.Contains(bytes.ToUpper(b), []byte("FTP")) {
			return strings.TrimSpace(string(b[:min(len(b), 40)])), true
		}
		return "", false
	}},
	{"smtp", SMTP, func(b []byte) (string, bool) {
		if !bytes.HasPrefix(b, []byte("220 ")) {
			return "", false
		}
		return strings.TrimSpace(string(b[:min(len(b), 40)])), true
	}},
	prefixLit("pop3", POP3, []byte("+OK")),
	prefixLit("imap", IMAP, []byte("* OK")),
	prefixLit("vnc", VNC, []byte("RFB 003.")),
}

// matchTLSClientHello matches a TLS record carrying a handshake message
// (ClientHello, in practice, for the client-first direction we inspect) —
// content type 0x16, major version 0x03. It never inspects past the
// handshake: TLS is opaque past the ClientHello by design (see package doc).
func matchTLSClientHello(b []byte) (string, bool) {
	if len(b) < 3 || b[0] != 0x16 || b[1] != 0x03 || b[2] > 0x04 {
		return "", false
	}
	if sni := parseTLSSNI(b); sni != "" {
		return "sni=" + sni, true
	}
	return "", true
}

// parseTLSSNI extracts the server_name extension's hostname from a TLS
// record containing a ClientHello, if present. Every step is bounds-checked;
// any malformed or truncated input yields "" rather than a panic — first-
// packet fingerprinting only, not a full TLS parser.
func parseTLSSNI(b []byte) string {
	if len(b) < 5 {
		return ""
	}
	recLen := int(b[3])<<8 | int(b[4])
	rec := b[5:]
	if len(rec) > recLen {
		rec = rec[:recLen]
	}
	if len(rec) < 4 || rec[0] != 0x01 { // ClientHello handshake type
		return ""
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	body := rec[4:]
	if len(body) > hsLen {
		body = body[:hsLen]
	}
	if len(body) < 34 { // client_version(2) + random(32)
		return ""
	}
	off := 34
	sidLen := int(body[off])
	off++
	off += sidLen
	if off+2 > len(body) {
		return ""
	}
	csLen := int(body[off])<<8 | int(body[off+1])
	off += 2 + csLen
	if off+1 > len(body) {
		return ""
	}
	compLen := int(body[off])
	off++
	off += compLen
	if off+2 > len(body) {
		return ""
	}
	extTotalLen := int(body[off])<<8 | int(body[off+1])
	off += 2
	extEnd := off + extTotalLen
	if extEnd > len(body) {
		extEnd = len(body)
	}
	for off+4 <= extEnd {
		extType := int(body[off])<<8 | int(body[off+1])
		extLen := int(body[off+2])<<8 | int(body[off+3])
		off += 4
		if off+extLen > len(body) {
			return ""
		}
		if extType == 0x0000 {
			return parseServerNameExt(body[off : off+extLen])
		}
		off += extLen
	}
	return ""
}

// parseServerNameExt extracts the hostname from a server_name extension's
// contents (a ServerNameList of one-or-more ServerName entries; only the
// host_name (type 0) case is handled — the only type in practice).
func parseServerNameExt(b []byte) string {
	if len(b) < 5 || b[2] != 0x00 { // b[2] = name_type, 0 = host_name
		return ""
	}
	nameLen := int(b[3])<<8 | int(b[4])
	name := b[5:]
	if len(name) > nameLen {
		name = name[:nameLen]
	}
	return string(name)
}

// matchPostgresStartup matches the PostgreSQL wire protocol's opening
// message: SSLRequest, GSSENCRequest, or a plain StartupMessage (protocol
// version 3.0), all identified by the 4-byte code at offset 4 (after the
// 4-byte message length).
func matchPostgresStartup(b []byte) (string, bool) {
	if len(b) < 8 {
		return "", false
	}
	code := b[4:8]
	switch {
	case bytes.Equal(code, []byte{0x04, 0xd2, 0x16, 0x2f}):
		return "sslrequest", true
	case bytes.Equal(code, []byte{0x04, 0xd2, 0x16, 0x30}):
		return "gssencrequest", true
	case bytes.Equal(code, []byte{0x00, 0x03, 0x00, 0x00}):
		return "startup", true
	}
	return "", false
}

// matchMySQLGreeting matches the MySQL/MariaDB server greeting packet: a
// 3-byte payload length, a 1-byte sequence number, then protocol-version
// 0x0a at offset 4.
func matchMySQLGreeting(b []byte) (string, bool) {
	if len(b) < 5 {
		return "", false
	}
	return "", b[4] == 0x0a
}

// matchOracleTNS matches a TNS CONNECT packet: 8-byte header with packet
// type 0x01 at offset 4, and connect-data ASCII in the payload.
func matchOracleTNS(b []byte) (string, bool) {
	if len(b) < 8 || b[4] != 0x01 {
		return "", false
	}
	payload := b[8:]
	if bytes.Contains(payload, []byte("(DESCRIPTION=")) || bytes.Contains(payload, []byte("(CONNECT_DATA=")) {
		return "", true
	}
	return "", false
}

// matchRDP matches an RDP X.224 Connection Request wrapped in a TPKT header.
func matchRDP(b []byte) (string, bool) {
	if len(b) < 6 {
		return "", false
	}
	return "", b[0] == 0x03 && b[1] == 0x00 && b[5] == 0xE0
}

// matchRedis matches a RESP array (the wire format for real client commands)
// or a plain inline command using one of the common verbs.
func matchRedis(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	if b[0] == '*' {
		return "", true
	}
	for _, v := range []string{"PING", "AUTH", "HELLO", "SELECT", "COMMAND"} {
		if bytes.HasPrefix(b, []byte(v)) {
			return v, true
		}
	}
	return "", false
}
