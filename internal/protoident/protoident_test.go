package protoident

import "testing"

func b(s string) []byte { return []byte(s) }

func TestClassify(t *testing.T) {
	tlsHello := []byte{0x16, 0x03, 0x01, 0x00, 0x2f} // TLS handshake, TLS1.0 record
	pgSSL := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	mysqlGreeting := []byte{0x4a, 0x00, 0x00, 0x00, 0x0a, '8', '.', '0'} // len+seq then 0x0a proto
	cases := []struct {
		name           string
		client, server []byte
		want           Protocol
		wantSide       Side
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

// buildClientHelloWithSNI constructs a minimal but well-formed TLS
// ClientHello record carrying a server_name extension for host, so
// matchTLSClientHello's SNI parsing can be exercised without a real TLS
// stack.
func buildClientHelloWithSNI(host string) []byte {
	hostBytes := []byte(host)

	serverName := []byte{0x00} // name_type = host_name
	serverName = append(serverName, u16(len(hostBytes))...)
	serverName = append(serverName, hostBytes...)

	serverNameList := u16(len(serverName))
	serverNameList = append(serverNameList, serverName...)

	sniExt := []byte{0x00, 0x00} // extension type = server_name
	sniExt = append(sniExt, u16(len(serverNameList))...)
	sniExt = append(sniExt, serverNameList...)

	extensions := sniExt

	random := make([]byte, 32)
	cipherSuites := []byte{0x00, 0x2f}
	compression := []byte{0x00}

	body := []byte{0x03, 0x03} // client_version TLS1.2
	body = append(body, random...)
	body = append(body, 0x00) // session_id length = 0
	body = append(body, u16(len(cipherSuites))...)
	body = append(body, cipherSuites...)
	body = append(body, byte(len(compression)))
	body = append(body, compression...)
	body = append(body, u16(len(extensions))...)
	body = append(body, extensions...)

	handshake := []byte{0x01} // ClientHello
	handshake = append(handshake, u24(len(body))...)
	handshake = append(handshake, body...)

	record := []byte{0x16, 0x03, 0x01}
	record = append(record, u16(len(handshake))...)
	record = append(record, handshake...)
	return record
}

func u16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }
func u24(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }
