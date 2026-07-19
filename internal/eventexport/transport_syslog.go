package eventexport

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	syslogAppName    = "omni-sag"
	syslogSeverity   = 6  // informational
	syslogFacilityLo = 16 // local0, the default when Facility is unset/unrecognized

	syslogDialTimeout  = 3 * time.Second
	syslogWriteTimeout = 3 * time.Second
)

var syslogFacilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

func syslogFacilityNumber(name string) int {
	if n, ok := syslogFacilities[strings.ToLower(name)]; ok {
		return n
	}
	return syslogFacilityLo
}

// syslogTransport frames each payload as an RFC 5424 message and writes it
// to a udp/tcp/tls destination.
//
// Framing choice: UDP is inherently message-delimited (one datagram = one
// syslog message), so no extra framing is applied. For TCP/TLS this uses
// RFC 6587 octet-counting ("<len> <frame>") rather than newline-delimited
// framing: octet-counting is unambiguous even if a message body happens to
// contain a newline, with no escaping needed.
//
// Reconnect: dialing is lazy — the constructor does no I/O, so an
// unreachable destination never fails construction or blocks gateway boot.
// A Write error marks the connection broken; the next Write redials before
// sending. A persistently down destination just keeps returning an error
// from Write — the caller (the async engine, a later task) counts that as
// a drop. Write never blocks indefinitely (bounded dial/write deadlines)
// and never panics.
type syslogTransport struct {
	mu       sync.Mutex
	cfg      SyslogConfig
	tlsCfg   *tls.Config
	pri      int
	hostname string
	conn     net.Conn
}

func newSyslogTransport(cfg SyslogConfig) (*syslogTransport, error) {
	switch cfg.Protocol {
	case "udp", "tcp", "tls":
	default:
		return nil, fmt.Errorf("eventexport: syslog transport: unknown protocol %q", cfg.Protocol)
	}
	if cfg.Address == "" {
		return nil, fmt.Errorf("eventexport: syslog transport: address required")
	}
	var tlsCfg *tls.Config
	if cfg.Protocol == "tls" {
		var err error
		tlsCfg, err = cfg.TLS.build()
		if err != nil {
			return nil, err
		}
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "-"
	}
	return &syslogTransport{
		cfg:      cfg,
		tlsCfg:   tlsCfg,
		pri:      syslogFacilityNumber(cfg.Facility)*8 + syslogSeverity,
		hostname: host,
	}, nil
}

// redialLocked dials a fresh connection. Callers must hold t.mu.
func (t *syslogTransport) redialLocked() error {
	var conn net.Conn
	var err error
	switch t.cfg.Protocol {
	case "udp":
		conn, err = net.DialTimeout("udp", t.cfg.Address, syslogDialTimeout)
	case "tcp":
		conn, err = net.DialTimeout("tcp", t.cfg.Address, syslogDialTimeout)
	case "tls":
		d := &net.Dialer{Timeout: syslogDialTimeout}
		conn, err = tls.DialWithDialer(d, "tcp", t.cfg.Address, t.tlsCfg)
	}
	if err != nil {
		return fmt.Errorf("eventexport: syslog transport: dial: %w", err)
	}
	t.conn = conn
	return nil
}

// frame renders payload as an RFC 5424 message: <PRI>1 TIMESTAMP HOSTNAME
// omni-sag - - - MSG. The three "-" fields are PROCID, MSGID, and
// STRUCTURED-DATA (NILVALUE) — omni-sag emits none of these.
func (t *syslogTransport) frame(payload []byte) []byte {
	ts := time.Now().UTC().Format(time.RFC3339)
	return []byte(fmt.Sprintf("<%d>1 %s %s %s - - - %s", t.pri, ts, t.hostname, syslogAppName, payload))
}

func octetCount(frame []byte) []byte {
	return append([]byte(fmt.Sprintf("%d ", len(frame))), frame...)
}

func (t *syslogTransport) Write(payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		if err := t.redialLocked(); err != nil {
			return err
		}
	}

	frame := t.frame(payload)
	if t.cfg.Protocol != "udp" {
		frame = octetCount(frame)
	}

	t.conn.SetWriteDeadline(time.Now().Add(syslogWriteTimeout))
	if _, err := t.conn.Write(frame); err != nil {
		t.conn.Close()
		t.conn = nil // mark broken; next Write redials
		return fmt.Errorf("eventexport: syslog transport: write: %w", err)
	}
	return nil
}

// Flush is a no-op: syslog writes are sent immediately, there is no
// client-side buffer to drain.
func (t *syslogTransport) Flush() error { return nil }

func (t *syslogTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn = nil
	return err
}
