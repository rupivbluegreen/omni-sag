package config

import (
	"fmt"

	"github.com/rupivbluegreen/omni-sag/internal/fips"
)

// FIPSMode returns the parsed FIPS posture (ModeOff when unset). The mode string
// is validated at Load time, so the error is discarded here.
func (f *File) FIPSMode() fips.Mode {
	if f.FIPS == nil {
		return fips.ModeOff
	}
	m, _ := fips.ParseMode(f.FIPS.Mode)
	return m
}

// validateFIPS rejects config that is inconsistent with an enforced FIPS
// posture — notably the LDAPS certificate-verification escape hatch, which would
// otherwise silently defeat TLS under a declared fips.mode=enforce.
func (f *File) validateFIPS() error {
	if f.FIPSMode() == fips.ModeEnforce && f.LDAP.InsecureTLS {
		return fmt.Errorf("config: ldap.insecure_tls must not be set when fips.mode=enforce")
	}
	return nil
}

// FIPSConfig configures the gateway's FIPS-readiness posture. It is optional;
// when absent the posture is "off" and non-FIPS default builds are unaffected.
//
// Mode is one of:
//
//	off      (default) no FIPS requirement
//	warn     log a warning at boot if the runtime is not in FIPS mode
//	enforce  refuse to start unless the runtime is in FIPS mode
//
// The runtime enters FIPS mode via GODEBUG=fips140=on (Go 1.24+) or a
// boringcrypto toolchain — see docs/fips.md.
type FIPSConfig struct {
	Mode string `yaml:"mode"`
}
