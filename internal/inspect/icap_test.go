package inspect

import (
	"context"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func clientFor(m *mockICAP, preview int) *Client {
	return New(Config{
		Endpoint:     m.addr,
		Service:      "avscan",
		PreviewBytes: preview,
		Timeout:      5 * time.Second,
	})
}

func inspectString(t *testing.T, c *Client, meta TransferMeta, s string) (Result, error) {
	t.Helper()
	return c.Inspect(context.Background(), meta, strings.NewReader(s))
}

func TestInspect_CleanRespmod(t *testing.T) {
	m := newMockICAP(t)
	c := clientFor(m, 4096)
	res, err := inspectString(t, c, TransferMeta{Filename: "report.txt", ContentType: "text/plain"}, "a perfectly benign document")
	if err != nil {
		t.Fatalf("clean inspect errored: %v", err)
	}
	if res.Verdict != VerdictClean || res.ICAPStatus != 204 {
		t.Fatalf("want clean/204, got %s/%d", res.Verdict, res.ICAPStatus)
	}
}

func TestInspect_EicarBlocked(t *testing.T) {
	m := newMockICAP(t)
	c := clientFor(m, 4096)
	res, err := inspectString(t, c, TransferMeta{Filename: "eicar.com"}, eicar)
	if err != nil {
		t.Fatalf("eicar inspect errored: %v", err)
	}
	if res.Verdict != VerdictBlocked {
		t.Fatalf("want blocked, got %s (%s)", res.Verdict, res.Reason)
	}
	if !strings.Contains(res.Reason, "X-Infection-Found") {
		t.Fatalf("reason should carry the infection header, got %q", res.Reason)
	}
}

func TestInspect_Reqmod(t *testing.T) {
	m := newMockICAP(t)
	c := clientFor(m, 4096)
	clean, err := inspectString(t, c, TransferMeta{Method: REQMOD, Filename: "upload.bin"}, "clean upload")
	if err != nil || clean.Verdict != VerdictClean {
		t.Fatalf("reqmod clean: verdict=%s err=%v", clean.Verdict, err)
	}
	bad, err := inspectString(t, c, TransferMeta{Method: REQMOD, Filename: "upload.bin"}, "prefix "+eicar+" suffix")
	if err != nil || bad.Verdict != VerdictBlocked {
		t.Fatalf("reqmod eicar: verdict=%s err=%v", bad.Verdict, err)
	}
}

func TestInspect_PreviewThenContinue_CleanLargeBody(t *testing.T) {
	m := newMockICAP(t)
	c := clientFor(m, 8) // tiny preview forces a 100-continue for the rest
	body := strings.Repeat("clean-", 10000)
	res, err := inspectString(t, c, TransferMeta{Filename: "big.txt"}, body)
	if err != nil {
		t.Fatalf("large clean errored: %v", err)
	}
	if res.Verdict != VerdictClean {
		t.Fatalf("want clean, got %s", res.Verdict)
	}
}

func TestInspect_EicarAfterPreview(t *testing.T) {
	m := newMockICAP(t)
	c := clientFor(m, 8) // signature is past the preview window
	body := strings.Repeat("x", 5000) + eicar
	res, err := inspectString(t, c, TransferMeta{Filename: "sneaky.bin"}, body)
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if res.Verdict != VerdictBlocked {
		t.Fatalf("infection past the preview must still be caught, got %s", res.Verdict)
	}
}

func TestInspect_DecideFromPreviewAlone(t *testing.T) {
	m := newMockICAP(t)
	// Server blocks from the preview slice without ever asking for the rest.
	m.onPreview = func(preview []byte, ieof bool) *mockResp {
		if strings.Contains(string(preview), eicar) {
			return &mockResp{status: 200, headers: map[string]string{"X-Infection-Found": "Threat=EICAR;"}, resHdr: "HTTP/1.1 403 Forbidden\r\n\r\n", modified: []byte("blocked")}
		}
		return nil
	}
	c := clientFor(m, 128)
	res, err := inspectString(t, c, TransferMeta{Filename: "e.com"}, eicar+strings.Repeat("y", 9000))
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if res.Verdict != VerdictBlocked {
		t.Fatalf("want blocked from preview, got %s", res.Verdict)
	}
}

func TestInspect_Modified(t *testing.T) {
	m := newMockICAP(t)
	// 200 with a modified body but no infection header -> VerdictModified.
	m.onBody = func(method string, hdr textproto.MIMEHeader, body []byte) mockResp {
		return mockResp{status: 200, resHdr: "HTTP/1.1 200 OK\r\n\r\n", modified: []byte("REDACTED")}
	}
	c := clientFor(m, 4096)
	res, err := inspectString(t, c, TransferMeta{Filename: "dlp.txt"}, "ssn 123-45-6789")
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if res.Verdict != VerdictModified || string(res.Modified) != "REDACTED" {
		t.Fatalf("want modified/REDACTED, got %s/%q", res.Verdict, res.Modified)
	}
}

func TestInspect_NoPreview(t *testing.T) {
	m := newMockICAP(t)
	c := clientFor(m, -1) // disable preview
	res, err := inspectString(t, c, TransferMeta{Filename: "x"}, "clean, sent whole")
	if err != nil || res.Verdict != VerdictClean {
		t.Fatalf("no-preview clean: verdict=%s err=%v", res.Verdict, err)
	}
	bad, err := inspectString(t, c, TransferMeta{Filename: "x"}, eicar)
	if err != nil || bad.Verdict != VerdictBlocked {
		t.Fatalf("no-preview eicar: verdict=%s err=%v", bad.Verdict, err)
	}
}

// --- fail-closed paths ---

func TestInspect_FailClosed_ServerDown(t *testing.T) {
	// Nothing listening on this port.
	c := New(Config{Endpoint: "127.0.0.1:1", Service: "avscan", Timeout: time.Second})
	_, err := inspectString(t, c, TransferMeta{Filename: "x"}, "data")
	if err == nil {
		t.Fatal("server-down must fail closed (error), not pass")
	}
}

func TestInspect_FailClosed_ConnectionDropped(t *testing.T) {
	m := newMockICAP(t)
	m.dropAfter = true
	c := clientFor(m, 4096)
	_, err := inspectString(t, c, TransferMeta{Filename: "x"}, "data")
	if err == nil {
		t.Fatal("dropped connection must fail closed")
	}
}

func TestInspect_FailClosed_GarbageResponse(t *testing.T) {
	m := newMockICAP(t)
	m.rawReply = "not an icap response at all\r\n\r\n"
	c := clientFor(m, 4096)
	_, err := inspectString(t, c, TransferMeta{Filename: "x"}, "data")
	if err == nil {
		t.Fatal("garbage response must fail closed")
	}
}

func TestInspect_FailClosed_ErrorStatus(t *testing.T) {
	m := newMockICAP(t)
	m.rawReply = "ICAP/1.0 500 Internal Server Error\r\nEncapsulated: null-body=0\r\n\r\n"
	c := clientFor(m, 4096)
	_, err := inspectString(t, c, TransferMeta{Filename: "x"}, "data")
	if err == nil {
		t.Fatal("5xx must fail closed")
	}
}

func TestInspect_FailClosed_Timeout(t *testing.T) {
	m := newMockICAP(t)
	m.stall = true // accepts, reads, holds the connection open without replying
	c := New(Config{Endpoint: m.addr, Service: "avscan", PreviewBytes: 4096, Timeout: 300 * time.Millisecond})
	start := time.Now()
	_, err := inspectString(t, c, TransferMeta{Filename: "x"}, "data")
	if err == nil {
		t.Fatal("timeout must fail closed")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout not enforced (%v)", time.Since(start))
	}
}
