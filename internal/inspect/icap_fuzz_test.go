package inspect

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// These fuzz targets exercise the ICAP response parsers, which sit on bytes
// returned by the ICAP server (a network peer): the status line, the
// Encapsulated header offset list, and the HTTP/1.1 chunked body decoder. None
// may panic, hang, or allocate unboundedly on hostile input.

// FuzzParseEncapsulated fuzzes the Encapsulated header offset parser.
func FuzzParseEncapsulated(f *testing.F) {
	f.Add("req-hdr=0, res-hdr=45, res-body=100")
	f.Add("req-hdr=0, req-body=120")
	f.Add("null-body=0")
	f.Add("res-body=0")
	f.Add("")
	f.Add("=,=,,")
	f.Add("res-body=-1")
	f.Add("res-body=99999999999999999999")

	f.Fuzz(func(t *testing.T, v string) {
		secs := parseEncapsulated(v)
		for _, s := range secs {
			_ = s.name
			_ = s.offset
		}
	})
}

// FuzzReadResponseHead fuzzes the ICAP status line + MIME header parser.
func FuzzReadResponseHead(f *testing.F) {
	f.Add("ICAP/1.0 204 No Modification\r\n\r\n")
	f.Add("ICAP/1.0 200 OK\r\nEncapsulated: res-body=0\r\nX-Infection-Found: Type=0\r\n\r\n")
	f.Add("ICAP/1.0 100 Continue\r\n\r\n")
	f.Add("garbage without crlf")
	f.Add("ICAP/1.0\r\n\r\n")
	f.Add("ICAP/1.0 abc Bad\r\n\r\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, resp string) {
		br := bufio.NewReader(strings.NewReader(resp))
		status, hdr, err := readResponseHead(br)
		if err != nil {
			return
		}
		_ = status
		if hdr != nil {
			_, _ = blockReason(hdr)
		}
	})
}

// FuzzReadChunked fuzzes the chunked-body decoder directly. This is the parser
// most likely to be tricked into an unbounded allocation by a hostile chunk
// size line, so it is fuzzed on raw bytes.
func FuzzReadChunked(f *testing.F) {
	f.Add([]byte("5\r\nhello\r\n0\r\n\r\n"))
	f.Add([]byte("0\r\n\r\n"))
	f.Add([]byte("3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"))
	f.Add([]byte("a; ext=1\r\n0123456789\r\n0\r\n\r\n"))
	// Hostile: enormous declared chunk size with no data behind it.
	f.Add([]byte("ffffffff\r\n"))
	f.Add([]byte("7fffffff\r\nshort\r\n"))
	f.Add([]byte("zz\r\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		br := bufio.NewReader(bytes.NewReader(data))
		out, err := readChunked(br)
		if err != nil {
			return
		}
		// A successful decode must not have produced more bytes than the input
		// (each output byte is copied from an input chunk).
		if len(out) > len(data) {
			t.Fatalf("readChunked produced %d bytes from %d input bytes", len(out), len(data))
		}
	})
}

// FuzzReadModifiedBody fuzzes the 200-response body extractor end to end: it
// parses the Encapsulated offset list, skips the encapsulated HTTP headers, and
// de-chunks the body. Both the header value and the stream are fuzzed.
func FuzzReadModifiedBody(f *testing.F) {
	f.Add("res-hdr=0, res-body=19", "HTTP/1.1 200 OK\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
	f.Add("res-body=0", "5\r\nhello\r\n0\r\n\r\n")
	f.Add("null-body=0", "anything")
	f.Add("res-body=999999999", "0\r\n\r\n")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, encapsulated, stream string) {
		br := bufio.NewReader(strings.NewReader(stream))
		body, err := readModifiedBody(br, encapsulated)
		if err != nil {
			return
		}
		_ = body
	})
}

// FuzzFinish fuzzes the full final-response mapping: status line + headers +
// (for 200) encapsulated body. This mirrors what exchange() does after writing
// the request, so it covers the verdict-header handling path too.
func FuzzFinish(f *testing.F) {
	c := &Client{cfg: Config{}}
	f.Add("ICAP/1.0 204 No Modification\r\n\r\n")
	f.Add("ICAP/1.0 200 OK\r\nEncapsulated: res-body=0\r\n\r\n0\r\n\r\n")
	f.Add("ICAP/1.0 200 OK\r\nEncapsulated: res-body=0\r\nX-Infection-Found: Type=0; Threat=EICAR;\r\n\r\n0\r\n\r\n")
	f.Add("ICAP/1.0 500 Server Error\r\nX-ICAP-Reason: boom\r\n\r\n")
	f.Add("ICAP/1.0 200 OK\r\nEncapsulated: res-body=100000000\r\n\r\nffffffff\r\n")

	f.Fuzz(func(t *testing.T, resp string) {
		br := bufio.NewReader(strings.NewReader(resp))
		status, hdr, err := readResponseHead(br)
		if err != nil {
			return
		}
		res, err := c.finish(br, status, hdr)
		if err != nil {
			return
		}
		_ = res.Verdict
	})
}
