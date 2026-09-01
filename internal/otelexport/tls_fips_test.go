package otelexport

import (
	"crypto/tls"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/fips"
)

// The collector connection is a TLS egress client like LDAPS, the CyberArk CCP
// client and event export, so it must honour the same FIPS posture. It was the
// only one that did not.

func TestBuildTLSConfig_OffModeUnchanged(t *testing.T) {
	tc, err := buildTLSConfig(TLSConfig{}, fips.ModeOff)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if tc.CipherSuites != nil {
		t.Fatalf("off mode must not restrict cipher suites, got %v", tc.CipherSuites)
	}
	if tc.MinVersion != tls.VersionTLS12 {
		t.Fatalf("off mode should keep the baseline MinVersion, got 0x%04x", tc.MinVersion)
	}
}

func TestBuildTLSConfig_EnforceModeHardened(t *testing.T) {
	tc, err := buildTLSConfig(TLSConfig{}, fips.ModeEnforce)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if err := fips.ValidateTLSConfig(tc); err != nil {
		t.Fatalf("enforce-mode collector TLS config should be FIPS-acceptable: %v", err)
	}
	if len(tc.CipherSuites) == 0 {
		t.Fatal("expected cipher suites to be restricted under enforce")
	}
}

func TestBuildTLSConfig_WarnModeHardened(t *testing.T) {
	tc, err := buildTLSConfig(TLSConfig{}, fips.ModeWarn)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if len(tc.CipherSuites) == 0 {
		t.Fatal("warn mode should also pin approved suites")
	}
}
