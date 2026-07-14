package inspect

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// mockICAP is a minimal ICAP server for tests. It reads a REQMOD/RESPMOD
// request (honoring Preview/100-continue), then calls onBody with the fully
// reassembled payload to decide the response. onPreview, if set, may decide
// from the preview slice alone (returns non-nil to short-circuit).
type mockICAP struct {
	ln        net.Listener
	addr      string
	onBody    func(method string, hdr textproto.MIMEHeader, body []byte) mockResp
	onPreview func(preview []byte, ieof bool) *mockResp
	// hooks for fault injection:
	rawReply  string // if non-empty, sent verbatim as the whole response (garbage tests)
	dropAfter bool   // close the connection without replying
	stall     bool   // accept, read, then hold the connection open until Close
	stallCh   chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

type mockResp struct {
	status   int
	headers  map[string]string
	resHdr   string // encapsulated HTTP response header block (for 200)
	modified []byte // encapsulated modified body (for 200)
}

const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func newMockICAP(t testing.TB) *mockICAP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &mockICAP{ln: ln, addr: ln.Addr().String(), stallCh: make(chan struct{})}
	// Default policy: EICAR anywhere in the body -> blocked; else clean (204).
	m.onBody = func(method string, hdr textproto.MIMEHeader, body []byte) mockResp {
		if strings.Contains(string(body), eicar) {
			return mockResp{
				status:   200,
				headers:  map[string]string{"X-Infection-Found": "Type=0; Resolution=2; Threat=EICAR-Test;"},
				resHdr:   "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n",
				modified: []byte("blocked by AV\n"),
			}
		}
		return mockResp{status: 204}
	}
	m.wg.Add(1)
	go m.serve()
	t.Cleanup(m.Close)
	return m
}

func (m *mockICAP) Close() {
	m.closeOnce.Do(func() {
		close(m.stallCh) // release any stalled handler first
		_ = m.ln.Close()
		m.wg.Wait()
	})
}

func (m *mockICAP) serve() {
	defer m.wg.Done()
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return // listener closed
		}
		m.handle(conn)
		_ = conn.Close()
	}
}

func (m *mockICAP) handle(conn net.Conn) {
	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)

	reqLine, err := tp.ReadLine()
	if err != nil {
		return
	}
	method := strings.Fields(reqLine)[0]
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return
	}

	if m.stall {
		<-m.stallCh // hold the connection open (never reply) until Close
		return
	}
	if m.dropAfter {
		return // simulate a server that hangs up mid-exchange
	}
	if m.rawReply != "" {
		_, _ = io.WriteString(conn, m.rawReply)
		return
	}

	// Skip the encapsulated HTTP header bytes that precede the body.
	bodyOffset, hasBody := bodyOffsetFromEncap(hdr.Get("Encapsulated"))
	if hasBody && bodyOffset > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(bodyOffset)); err != nil {
			return
		}
	}

	_, hasPreview := hdr["Preview"]
	if hasPreview && hasBody {
		preview, ieof, err := readChunksIEOF(br)
		if err != nil {
			return
		}
		if m.onPreview != nil {
			if r := m.onPreview(preview, ieof); r != nil {
				writeMockResp(conn, *r)
				return
			}
		}
		if ieof {
			writeMockResp(conn, m.onBody(method, hdr, preview))
			return
		}
		// Ask for the rest.
		_, _ = io.WriteString(conn, "ICAP/1.0 100 Continue\r\n\r\n")
		rest, _, err := readChunksIEOF(br)
		if err != nil {
			return
		}
		full := append(append([]byte{}, preview...), rest...)
		writeMockResp(conn, m.onBody(method, hdr, full))
		return
	}

	var body []byte
	if hasBody {
		body, _, err = readChunksIEOF(br)
		if err != nil {
			return
		}
	}
	writeMockResp(conn, m.onBody(method, hdr, body))
}

func writeMockResp(conn net.Conn, r mockResp) {
	switch r.status {
	case 204:
		_, _ = io.WriteString(conn, "ICAP/1.0 204 No Modification\r\nISTag: \"omnisag-mock\"\r\nEncapsulated: null-body=0\r\n\r\n")
	case 200:
		var b strings.Builder
		b.WriteString("ICAP/1.0 200 OK\r\n")
		b.WriteString("ISTag: \"omnisag-mock\"\r\n")
		for k, v := range r.headers {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
		resHdr := r.resHdr
		if resHdr == "" {
			resHdr = "HTTP/1.1 200 OK\r\n\r\n"
		}
		fmt.Fprintf(&b, "Encapsulated: res-hdr=0, res-body=%d\r\n\r\n", len(resHdr))
		b.WriteString(resHdr)
		conn.Write([]byte(b.String()))
		// chunked modified body
		if len(r.modified) > 0 {
			fmt.Fprintf(conn, "%x\r\n", len(r.modified))
			conn.Write(r.modified)
			io.WriteString(conn, "\r\n")
		}
		io.WriteString(conn, "0\r\n\r\n")
	default:
		fmt.Fprintf(conn, "ICAP/1.0 %d Error\r\nEncapsulated: null-body=0\r\n\r\n", r.status)
	}
}

// readChunksIEOF de-chunks a body, reporting whether the terminating chunk
// carried the ICAP "ieof" extension (preview contained the whole body).
func readChunksIEOF(br *bufio.Reader) ([]byte, bool, error) {
	var out []byte
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, false, err
		}
		field := strings.TrimSpace(line)
		ieof := false
		if i := strings.IndexByte(field, ';'); i >= 0 {
			ieof = strings.Contains(field[i:], "ieof")
			field = strings.TrimSpace(field[:i])
		}
		n, err := strconv.ParseUint(field, 16, 32)
		if err != nil {
			return nil, false, fmt.Errorf("bad chunk size %q", field)
		}
		if n == 0 {
			_, _ = br.ReadString('\n') // trailing CRLF
			return out, ieof, nil
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, false, err
		}
		out = append(out, buf...)
		if _, err := br.Discard(2); err != nil {
			return nil, false, err
		}
	}
}

func bodyOffsetFromEncap(v string) (int, bool) {
	for _, s := range parseEncapsulated(v) {
		switch s.name {
		case "res-body", "req-body", "opt-body":
			return s.offset, true
		}
	}
	return 0, false
}
