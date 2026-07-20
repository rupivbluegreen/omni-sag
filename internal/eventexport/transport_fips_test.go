package eventexport

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/fips"
)

func TestNewSyslogTransport_TLS_OffModeUnchanged(t *testing.T) {
	tr, err := newSyslogTransport(SyslogConfig{Address: "127.0.0.1:0", Protocol: "tls"}, fips.ModeOff)
	if err != nil {
		t.Fatalf("newSyslogTransport: %v", err)
	}
	if tr.tlsCfg.CipherSuites != nil {
		t.Fatalf("off mode must not restrict cipher suites, got %v", tr.tlsCfg.CipherSuites)
	}
	if tr.tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("off mode should keep the baseline MinVersion, got 0x%04x", tr.tlsCfg.MinVersion)
	}
}

func TestNewSyslogTransport_TLS_EnforceModeHardened(t *testing.T) {
	tr, err := newSyslogTransport(SyslogConfig{Address: "127.0.0.1:0", Protocol: "tls"}, fips.ModeEnforce)
	if err != nil {
		t.Fatalf("newSyslogTransport: %v", err)
	}
	if err := fips.ValidateTLSConfig(tr.tlsCfg); err != nil {
		t.Fatalf("enforce-mode syslog TLS config should be FIPS-acceptable: %v", err)
	}
	if len(tr.tlsCfg.CipherSuites) == 0 {
		t.Fatal("expected cipher suites to be restricted under enforce")
	}
}

func TestNewHTTPTransport_TLS_OffModeUnchanged(t *testing.T) {
	tr, err := newHTTPTransport(HTTPConfig{URL: "https://siem.example/ingest", BatchSize: 1}, fips.ModeOff)
	if err != nil {
		t.Fatalf("newHTTPTransport: %v", err)
	}
	tc := tr.client.Transport.(*http.Transport).TLSClientConfig
	if tc.CipherSuites != nil {
		t.Fatalf("off mode must not restrict cipher suites, got %v", tc.CipherSuites)
	}
	if tc.MinVersion != tls.VersionTLS12 {
		t.Fatalf("off mode should keep the baseline MinVersion, got 0x%04x", tc.MinVersion)
	}
}

func TestNewHTTPTransport_TLS_EnforceModeHardened(t *testing.T) {
	tr, err := newHTTPTransport(HTTPConfig{URL: "https://siem.example/ingest", BatchSize: 1}, fips.ModeEnforce)
	if err != nil {
		t.Fatalf("newHTTPTransport: %v", err)
	}
	tc := tr.client.Transport.(*http.Transport).TLSClientConfig
	if err := fips.ValidateTLSConfig(tc); err != nil {
		t.Fatalf("enforce-mode HTTP TLS config should be FIPS-acceptable: %v", err)
	}
	if len(tc.CipherSuites) == 0 {
		t.Fatal("expected cipher suites to be restricted under enforce")
	}
}
