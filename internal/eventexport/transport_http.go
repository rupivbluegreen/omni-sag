package eventexport

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

const httpRequestTimeout = 3 * time.Second

// httpTransport batches payloads and POSTs them as newline-delimited JSON
// (NDJSON — one event per line). NDJSON was chosen over a JSON array
// because it needs no framing beyond the join (no closing bracket/comma
// bookkeeping) and is what Elastic's `_bulk` endpoint and most HTTP log
// intakes (Splunk HEC, generic collectors) already expect line-by-line.
//
// Delivery is best-effort, matching the spec's no-spool decision: a
// transport error or non-2xx response is logged once and the batch is
// dropped — Write/Flush still return the error so the caller (the async
// engine, a later task) can count it, but there is no retry queue.
type httpTransport struct {
	mu        sync.Mutex
	cfg       httpConfig
	batchSize int
	client    *http.Client
	buf       [][]byte
}

func newHTTPTransport(cfg httpConfig) (*httpTransport, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("eventexport: http transport: url required")
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 1
	}
	tlsCfg, err := cfg.TLS.build()
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout:   httpRequestTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	return &httpTransport{cfg: cfg, batchSize: batchSize, client: client}, nil
}

// Write queues payload and, once the batch reaches batch_size, POSTs it.
func (t *httpTransport) Write(payload []byte) error {
	t.mu.Lock()
	cp := make([]byte, len(payload))
	copy(cp, payload)
	t.buf = append(t.buf, cp)
	full := len(t.buf) >= t.batchSize
	t.mu.Unlock()

	if full {
		return t.send()
	}
	return nil
}

// Flush forces out a partial batch (called by the async engine on
// flush_interval, or once at Close).
func (t *httpTransport) Flush() error { return t.send() }

func (t *httpTransport) Close() error { return t.send() }

// send POSTs whatever is currently buffered, if anything, and clears the
// buffer regardless of outcome — a failed batch is dropped, not retried.
func (t *httpTransport) send() error {
	t.mu.Lock()
	if len(t.buf) == 0 {
		t.mu.Unlock()
		return nil
	}
	batch := t.buf
	t.buf = nil
	t.mu.Unlock()

	body := append(bytes.Join(batch, []byte("\n")), '\n')

	req, err := http.NewRequest(http.MethodPost, t.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("eventexport: http transport: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	setHTTPAuth(req, t.cfg.Auth)

	resp, err := t.client.Do(req)
	if err != nil {
		log.Printf("eventexport: http transport: request failed, dropping batch of %d: %v", len(batch), err)
		return fmt.Errorf("eventexport: http transport: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("eventexport: http transport: status %d, dropping batch of %d", resp.StatusCode, len(batch))
		return fmt.Errorf("eventexport: http transport: status %d", resp.StatusCode)
	}
	return nil
}

// setHTTPAuth reads credentials from the environment variables named in
// auth — never from inline config values, so secrets never land in the
// config file or logs.
func setHTTPAuth(req *http.Request, auth httpAuthConfig) {
	if auth.BearerEnv != "" {
		if tok := os.Getenv(auth.BearerEnv); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		return
	}
	if auth.UserEnv != "" || auth.PassEnv != "" {
		req.SetBasicAuth(os.Getenv(auth.UserEnv), os.Getenv(auth.PassEnv))
	}
}
