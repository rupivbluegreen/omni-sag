package eventexport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/rupivbluegreen/omni-sag/internal/fips"
)

// Transport delivers formatted payloads to an export destination. Write
// takes one already-formatted event's bytes; framing (newline, syslog
// octet-count, HTTP batching) is each transport's own job. All three
// methods are best-effort: a broken/unreachable destination must return an
// error, never block or panic — the async engine (a later task) counts
// failures and keeps the durable evidence pipeline as the system of record.
type Transport interface {
	Write(payload []byte) error
	Flush() error
	Close() error
}

// FileConfig configures the file transport.
type FileConfig struct {
	Path string
}

// SyslogConfig configures the syslog transport.
type SyslogConfig struct {
	Address  string // host:port
	Protocol string // udp | tcp | tls
	Facility string // e.g. "local0"; defaults to local0
	TLS      *TLSConfig
}

// HTTPAuthConfig names environment variables holding auth credentials —
// never inline secrets in config.
type HTTPAuthConfig struct {
	BearerEnv string // env var holding a bearer token
	UserEnv   string // env var holding basic-auth username
	PassEnv   string // env var holding basic-auth password
}

// HTTPConfig configures the http transport.
type HTTPConfig struct {
	URL                  string
	BatchSize            int
	FlushIntervalSeconds int
	Auth                 HTTPAuthConfig
	TLS                  *TLSConfig
}

// TLSConfig names PEM files for a client TLS connection: CA to verify the
// server (required for any real deployment — no InsecureSkipVerify here),
// and an optional client Cert/Key for mutual TLS.
type TLSConfig struct {
	CA   string
	Cert string
	Key  string
}

// build loads the PEM files named in c into a *tls.Config suitable for a
// client connection (syslog or http). A nil c yields the platform default
// trust store with no client certificate. This is a gateway-built TLS egress
// carrying audit events off-box, so mode warn/enforce routes it through
// fips.Harden the same as the other integration TLS clients (LDAPS, CyberArk
// CCP).
func (c *TLSConfig) build(mode fips.Mode) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c != nil {
		if c.CA != "" {
			pem, err := os.ReadFile(c.CA)
			if err != nil {
				return nil, fmt.Errorf("eventexport: tls ca: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("eventexport: tls ca: no certificates parsed")
			}
			cfg.RootCAs = pool
		}
		if c.Cert != "" || c.Key != "" {
			cert, err := tls.LoadX509KeyPair(c.Cert, c.Key)
			if err != nil {
				return nil, fmt.Errorf("eventexport: tls client cert: %w", err)
			}
			cfg.Certificates = []tls.Certificate{cert}
		}
	}
	if err := fips.Harden(cfg, mode); err != nil {
		return nil, fmt.Errorf("eventexport: %w", err)
	}
	return cfg, nil
}
