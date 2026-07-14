package inspect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// defaultPreviewBytes is a conservative ICAP preview size when none is set.
const defaultPreviewBytes = 4096

// defaultTimeout bounds a whole inspection (dial + exchange) so a stalled ICAP
// server cannot hang a transfer indefinitely.
const defaultTimeout = 30 * time.Second

// streamBufBytes is the copy buffer for streaming the post-preview body.
const streamBufBytes = 32 * 1024

// defaultDialContext is the SOLE TCP dial in this package. inspect is an
// allow-listed integration client: it dials ONLY the operator-configured ICAP
// endpoint, never a session target, so the single-target-dialer invariant
// (internal/dialer is the only path that dials targets) is unaffected. The
// check-imports allow-list keys on the marker comment on the dial line.
var defaultDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{} // omni-sag:integration-dial — operator-configured ICAP endpoint only, never a session target
	return d.DialContext(ctx, network, addr)
}

// Config configures the ICAP client.
type Config struct {
	Endpoint     string        // ICAP server host:port
	Service      string        // service path, e.g. "avscan"
	Method       Method        // default method when TransferMeta.Method is empty (default RESPMOD)
	PreviewBytes int           // ICAP preview size; 0 uses the default, negative disables preview
	Timeout      time.Duration // per-inspection timeout
	OriginHost   string        // Host header for the encapsulated HTTP message
}

// Client is an ICAP (RFC 3507) Inspector. It is safe for concurrent use: each
// Inspect opens its own connection.
type Client struct {
	cfg         Config
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// New returns an ICAP client for cfg, applying defaults.
func New(cfg Config) *Client {
	if cfg.Method == "" {
		cfg.Method = RESPMOD
	}
	if cfg.PreviewBytes == 0 {
		cfg.PreviewBytes = defaultPreviewBytes
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.OriginHost == "" {
		cfg.OriginHost = "omni-sag"
	}
	cfg.Service = strings.TrimPrefix(cfg.Service, "/")
	return &Client{cfg: cfg, dialContext: defaultDialContext}
}

var _ Inspector = (*Client)(nil)

// Inspect sends the payload to the ICAP server and returns its verdict. Any
// transport or protocol failure returns an error; callers must treat that as a
// block (fail closed).
func (c *Client) Inspect(ctx context.Context, meta TransferMeta, body io.Reader) (Result, error) {
	method := meta.Method
	if method == "" {
		method = c.cfg.Method
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	conn, err := c.dialContext(ctx, "tcp", c.cfg.Endpoint)
	if err != nil {
		return Result{}, fmt.Errorf("icap: dial %s: %w", c.cfg.Endpoint, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	br := bufio.NewReader(conn)
	res, err := c.exchange(conn, br, method, meta, body)
	if err != nil {
		return Result{}, fmt.Errorf("icap: %w", err)
	}
	return res, nil
}

// exchange performs one ICAP request/response, including the preview handshake.
func (c *Client) exchange(conn net.Conn, br *bufio.Reader, method Method, meta TransferMeta, body io.Reader) (Result, error) {
	encHdr := encapsulatedHTTPHeaders(method, meta, c.cfg.OriginHost)

	preview := c.cfg.PreviewBytes
	usePreview := preview > 0

	// Read the preview slice up front so we know whether the body ends within
	// it (ieof) and can size the Preview header.
	var previewBuf []byte
	bodyEndedInPreview := false
	if usePreview {
		previewBuf = make([]byte, preview)
		n, rerr := io.ReadFull(body, previewBuf)
		switch rerr {
		case nil:
			// exactly preview bytes read; more may follow
		case io.EOF, io.ErrUnexpectedEOF:
			bodyEndedInPreview = true
		default:
			return Result{}, fmt.Errorf("read preview: %w", rerr)
		}
		previewBuf = previewBuf[:n]
	}

	// Request line + ICAP headers.
	var head strings.Builder
	fmt.Fprintf(&head, "%s icap://%s/%s ICAP/1.0\r\n", method, c.cfg.Endpoint, c.cfg.Service)
	fmt.Fprintf(&head, "Host: %s\r\n", c.cfg.Endpoint)
	head.WriteString("Allow: 204\r\n")
	if usePreview {
		fmt.Fprintf(&head, "Preview: %d\r\n", len(previewBuf))
	}
	fmt.Fprintf(&head, "Encapsulated: %s\r\n", encHdr.encapsulatedValue())
	head.WriteString("\r\n")

	if _, err := io.WriteString(conn, head.String()); err != nil {
		return Result{}, fmt.Errorf("write header: %w", err)
	}
	if _, err := conn.Write(encHdr.bytes); err != nil {
		return Result{}, fmt.Errorf("write encapsulated header: %w", err)
	}

	if usePreview {
		if err := writeChunk(conn, previewBuf); err != nil {
			return Result{}, fmt.Errorf("write preview chunk: %w", err)
		}
		if err := writeLastChunk(conn, bodyEndedInPreview); err != nil {
			return Result{}, fmt.Errorf("write preview terminator: %w", err)
		}

		status, hdr, err := readResponseHead(br)
		if err != nil {
			return Result{}, err
		}
		if status != 100 {
			// Server decided from the preview alone (204/200/error).
			return c.finish(br, status, hdr)
		}
		// 100 Continue: send the remainder of the body.
		if err := streamBody(conn, body); err != nil {
			return Result{}, fmt.Errorf("stream body: %w", err)
		}
	} else {
		if err := streamBody(conn, body); err != nil {
			return Result{}, fmt.Errorf("stream body: %w", err)
		}
	}

	status, hdr, err := readResponseHead(br)
	if err != nil {
		return Result{}, err
	}
	if status == 100 {
		return Result{}, fmt.Errorf("unexpected 100 Continue after full body")
	}
	return c.finish(br, status, hdr)
}

// streamBody writes the remaining body as chunks followed by the terminator.
func streamBody(conn net.Conn, body io.Reader) error {
	buf := make([]byte, streamBufBytes)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if werr := writeChunk(conn, buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return writeLastChunk(conn, false)
}

// finish maps a final ICAP status + headers (and any modified body) to a Result.
func (c *Client) finish(br *bufio.Reader, status int, hdr textproto.MIMEHeader) (Result, error) {
	switch {
	case status == 204:
		return Result{Verdict: VerdictClean, ICAPStatus: status}, nil
	case status == 200:
		modified, err := readModifiedBody(br, hdr.Get("Encapsulated"))
		if err != nil {
			return Result{}, fmt.Errorf("read modified body: %w", err)
		}
		if reason, blocked := blockReason(hdr); blocked {
			return Result{Verdict: VerdictBlocked, Reason: reason, ICAPStatus: status}, nil
		}
		return Result{Verdict: VerdictModified, Modified: modified, ICAPStatus: status}, nil
	default:
		return Result{}, fmt.Errorf("ICAP status %d %s", status, hdr.Get("X-ICAP-Reason"))
	}
}

// blockReason reports whether the response headers indicate the content was
// flagged (infection or DLP violation) and a human-readable reason.
func blockReason(hdr textproto.MIMEHeader) (string, bool) {
	for _, key := range []string{"X-Infection-Found", "X-Virus-Id", "X-Violations-Found", "X-Blocked-Reason"} {
		if v := hdr.Get(key); v != "" {
			return fmt.Sprintf("%s: %s", key, v), true
		}
	}
	return "", false
}

// readResponseHead reads an ICAP status line and header block. It returns the
// numeric status and the parsed headers.
func readResponseHead(br *bufio.Reader) (int, textproto.MIMEHeader, error) {
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return 0, nil, fmt.Errorf("read status line: %w", err)
	}
	// "ICAP/1.0 204 No Modification"
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "ICAP/") {
		return 0, nil, fmt.Errorf("malformed ICAP status line %q", line)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, fmt.Errorf("bad ICAP status %q", parts[1])
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return 0, nil, fmt.Errorf("read response headers: %w", err)
	}
	return status, hdr, nil
}

// readModifiedBody extracts the modified payload from a 200 response, if any.
// It skips the encapsulated HTTP headers and de-chunks the body section.
func readModifiedBody(br *bufio.Reader, encapsulated string) ([]byte, error) {
	sections := parseEncapsulated(encapsulated)
	bodyOffset, hasBody := -1, false
	for _, s := range sections {
		switch s.name {
		case "res-body", "req-body", "opt-body":
			bodyOffset, hasBody = s.offset, true
		}
	}
	if !hasBody {
		return nil, nil // null-body: nothing modified to read
	}
	if bodyOffset > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(bodyOffset)); err != nil {
			return nil, fmt.Errorf("skip encapsulated headers: %w", err)
		}
	}
	return readChunked(br)
}

type encSection struct {
	name   string
	offset int
}

// parseEncapsulated parses an Encapsulated header value, e.g.
// "req-hdr=0, res-hdr=45, res-body=100".
func parseEncapsulated(v string) []encSection {
	var out []encSection
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		off, err := strconv.Atoi(strings.TrimSpace(kv[1]))
		if err != nil {
			continue
		}
		out = append(out, encSection{name: strings.TrimSpace(kv[0]), offset: off})
	}
	return out
}
