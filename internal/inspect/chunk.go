package inspect

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ICAP encapsulated bodies use HTTP/1.1 chunked transfer-coding. These helpers
// implement just enough of it for the client; the standard library's chunked
// reader/writer live in internal packages we cannot import.

// maxChunkedBodyBytes bounds the total decoded size of a chunked ICAP body.
// Without it a hostile or broken ICAP server can declare a chunk size of up to
// 2^32-1 (e.g. "7fffffff") and force an unbounded make([]byte, n) — an OOM/DoS
// via a single response line, before io.ReadFull ever notices the body is
// short. The cap is checked against the remaining budget BEFORE any allocation.
const maxChunkedBodyBytes = 64 << 20 // 64 MiB

// writeChunk writes a single non-empty chunk: <hexlen>CRLF <data> CRLF.
func writeChunk(w io.Writer, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "%x\r\n", len(data)); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

// writeLastChunk writes the terminating zero chunk. When ieof is true it emits
// the ICAP preview "0; ieof" marker, signalling that the preview contained the
// entire body.
func writeLastChunk(w io.Writer, ieof bool) error {
	term := "0\r\n\r\n"
	if ieof {
		term = "0; ieof\r\n\r\n"
	}
	_, err := io.WriteString(w, term)
	return err
}

// readChunked reads a complete chunked body from r and returns the decoded
// bytes. It stops after the zero-length terminating chunk.
func readChunked(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("chunk size line: %w", err)
		}
		// A chunk size line may carry extensions after ';' (e.g. "0; ieof").
		sizeField := strings.TrimSpace(line)
		if i := strings.IndexByte(sizeField, ';'); i >= 0 {
			sizeField = strings.TrimSpace(sizeField[:i])
		}
		n, err := strconv.ParseUint(sizeField, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("bad chunk size %q: %w", sizeField, err)
		}
		if n == 0 {
			// Consume the trailing CRLF after the terminating chunk.
			if _, err := r.ReadString('\n'); err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return out, nil
		}
		// Bound total decoded size before allocating, so a hostile chunk-size
		// line cannot force a giant allocation.
		if n > uint64(maxChunkedBodyBytes-len(out)) {
			return nil, fmt.Errorf("chunked body exceeds %d-byte limit", maxChunkedBodyBytes)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("chunk data: %w", err)
		}
		out = append(out, buf...)
		// Consume the CRLF terminating this chunk's data.
		if _, err := r.Discard(2); err != nil {
			return nil, fmt.Errorf("chunk trailer: %w", err)
		}
	}
}
