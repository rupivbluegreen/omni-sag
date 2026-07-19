package eventexport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
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

// fileConfig configures the file transport.
type fileConfig struct {
	Path string
}

// syslogConfig configures the syslog transport.
type syslogConfig struct {
	Address  string // host:port
	Protocol string // udp | tcp | tls
	Facility string // e.g. "local0"; defaults to local0
	TLS      *tlsConfig
}

// httpAuthConfig names environment variables holding auth credentials —
// never inline secrets in config.
type httpAuthConfig struct {
	BearerEnv string // env var holding a bearer token
	UserEnv   string // env var holding basic-auth username
	PassEnv   string // env var holding basic-auth password
}

// httpConfig configures the http transport.
type httpConfig struct {
	URL                  string
	BatchSize            int
	FlushIntervalSeconds int
	Auth                 httpAuthConfig
	TLS                  *tlsConfig
}

// tlsConfig names PEM files for a client TLS connection: CA to verify the
// server (required for any real deployment — no InsecureSkipVerify here),
// and an optional client Cert/Key for mutual TLS.
type tlsConfig struct {
	CA   string
	Cert string
	Key  string
}

// build loads the PEM files named in c into a *tls.Config suitable for a
// client connection (syslog or http). A nil c yields the platform default
// trust store with no client certificate.
func (c *tlsConfig) build() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c == nil {
		return cfg, nil
	}
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
	return cfg, nil
}
