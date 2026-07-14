package config

import "github.com/rupivbluegreen/omni-sag/internal/fips"

// FIPSMode returns the parsed FIPS posture (ModeOff when unset). The mode string
// is validated at Load time, so the error is discarded here.
func (f *File) FIPSMode() fips.Mode {
	if f.FIPS == nil {
		return fips.ModeOff
	}
	m, _ := fips.ParseMode(f.FIPS.Mode)
	return m
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
