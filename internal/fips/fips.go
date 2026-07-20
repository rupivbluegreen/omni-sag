// Package fips implements the gateway's FIPS-readiness posture. It is a leaf
// package: it imports only the standard library and never any other internal
// package, so it can be consulted from anywhere (boot wiring, tests) without
// creating an import edge.
//
// The gateway itself does not implement cryptography — that is the job of the
// Go runtime's crypto libraries. What this package provides is (a) a way to
// declare an operational FIPS posture (off / warn / enforce), (b) a runtime
// probe of whether the process is actually running with FIPS-approved crypto
// (Go 1.24+ native FIPS 140-3 mode via GODEBUG=fips140=on, or a boringcrypto
// toolchain), and (c) a static self-check of the core primitives (Ed25519
// signing, SHA-256 hashing). TLS-parameter conformance for LDAPS / CyberArk CCP
// / the control-plane API is NOT part of Check; it is provided by the exported
// ValidateTLSConfig / ApprovedTLSConfig helpers for callers to apply, and the
// LDAPS insecure_tls escape hatch and a cleartext control-plane API are
// separately rejected under fips.mode=enforce by config validation.
//
// Default builds are unaffected: with no GODEBUG the runtime is not in FIPS
// mode, Mode defaults to Off, and Check is a no-op that always succeeds.
package fips

import (
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
)

// Mode is the operator-declared FIPS posture.
type Mode int

const (
	// ModeOff is the default: no FIPS requirement. Check always succeeds. This
	// keeps non-FIPS default builds working unchanged.
	ModeOff Mode = iota
	// ModeWarn requires nothing but records a warning in the Report when the
	// runtime is not in FIPS mode, so an operator who intends FIPS can see they
	// forgot the GODEBUG/toolchain without the process refusing to boot.
	ModeWarn
	// ModeEnforce requires the runtime to be in FIPS mode. Check returns an
	// error (so the daemon refuses to start) when it is not.
	ModeEnforce
)

// String renders the mode as its config token.
func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeWarn:
		return "warn"
	case ModeEnforce:
		return "enforce"
	default:
		return fmt.Sprintf("Mode(%d)", int(m))
	}
}

// ParseMode parses a config token ("", "off", "warn", "enforce") into a Mode.
// The empty string maps to ModeOff so an absent config block means "no FIPS
// requirement".
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "disabled", "false":
		return ModeOff, nil
	case "warn", "warning", "audit":
		return ModeWarn, nil
	case "enforce", "on", "require", "required", "strict":
		return ModeEnforce, nil
	default:
		return ModeOff, fmt.Errorf("fips: invalid mode %q (want off|warn|enforce)", s)
	}
}

// RuntimeEnabled reports whether the process is running with FIPS-approved
// cryptography. It reflects the Go 1.24+ native FIPS 140-3 module, controlled by
// GODEBUG=fips140=on (or =only). A boringcrypto toolchain also reports enabled
// here.
//
// It is a package-level variable so tests can simulate both a FIPS and a
// non-FIPS runtime without needing to actually re-exec under GODEBUG.
var RuntimeEnabled = fips140.Enabled

// Report is the outcome of a Check. It is always safe to log: it contains no
// secret material.
type Report struct {
	Mode           Mode     // the declared posture
	RuntimeFIPS    bool     // whether the runtime crypto module is in FIPS mode
	SelfTestPassed bool     // whether the algorithm self-test passed
	Warnings       []string // non-fatal advisories (e.g. warn-mode with no runtime FIPS)
}

// Summary renders a one-line, log-friendly status string.
func (r Report) Summary() string {
	rt := "not-active"
	if r.RuntimeFIPS {
		rt = "active"
	}
	st := "fail"
	if r.SelfTestPassed {
		st = "pass"
	}
	return fmt.Sprintf("fips: mode=%s runtime=%s self-test=%s", r.Mode, rt, st)
}

// Check performs the boot-time FIPS readiness check for the given mode and
// returns a Report. In ModeEnforce it returns a non-nil error when the runtime
// is not in FIPS mode or the algorithm self-test fails, so the daemon refuses to
// start. In ModeWarn it never errors but populates Report.Warnings. In ModeOff
// it still runs the (cheap) self-test for observability but never errors and
// never warns.
func Check(mode Mode) (Report, error) {
	r := Report{Mode: mode, RuntimeFIPS: RuntimeEnabled()}
	if err := SelfTest(); err != nil {
		r.SelfTestPassed = false
		if mode == ModeEnforce {
			return r, fmt.Errorf("fips: self-test failed under enforce mode: %w", err)
		}
		if mode == ModeWarn {
			r.Warnings = append(r.Warnings, fmt.Sprintf("algorithm self-test failed: %v", err))
		}
		return r, nil
	}
	r.SelfTestPassed = true

	if !r.RuntimeFIPS {
		switch mode {
		case ModeEnforce:
			return r, fmt.Errorf("fips: enforce mode requires FIPS-approved crypto but the runtime is not in FIPS mode; " +
				"rebuild/run with GODEBUG=fips140=on (Go 1.24+) or a boringcrypto toolchain (see docs/fips.md)")
		case ModeWarn:
			r.Warnings = append(r.Warnings, "declared FIPS posture 'warn' but the runtime is NOT in FIPS mode; "+
				"set GODEBUG=fips140=on (Go 1.24+) or use a boringcrypto build (see docs/fips.md)")
		}
	}
	return r, nil
}

// SelfTest exercises the exact primitives this codebase depends on and confirms
// they are FIPS-acceptable and functioning: an Ed25519 sign/verify round-trip
// (evidence signing) and a SHA-256 digest (hash chain, recording ids, ICAP).
// It is deliberately cheap so it can run on every boot. When the process is in
// FIPS 'only' mode a non-approved primitive would panic/error here, surfacing
// the problem at startup rather than mid-session.
func SelfTest() error {
	// SHA-256 (an approved SHS function) must produce a stable, correct digest.
	// "abc" has a well-known SHA-256 value; a mismatch means the hash primitive
	// is broken or substituted.
	got := sha256.Sum256([]byte("abc"))
	const wantHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if hexEncode(got[:]) != wantHex {
		return fmt.Errorf("sha256 known-answer test failed")
	}

	// Ed25519 (approved as EdDSA in FIPS 186-5) sign/verify round-trip.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ed25519 keygen: %w", err)
	}
	msg := []byte("omni-sag fips self-test")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("ed25519 sign/verify round-trip failed")
	}
	// A tampered message must NOT verify.
	if ed25519.Verify(pub, []byte("tampered"), sig) {
		return fmt.Errorf("ed25519 verified a tampered message")
	}
	return nil
}

// hexEncode is a tiny local hex encoder so SelfTest has no dependency beyond the
// crypto primitives it is validating.
func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// --- TLS parameter approval ---------------------------------------------------
//
// The gateway makes TLS connections to operator-configured integration
// endpoints (LDAPS, CyberArk CCP) and serves the control-plane API over TLS.
// FIPS 140-3 constrains which protocol versions and cipher suites are
// acceptable. These helpers let the boot wiring validate a *tls.Config and let
// operators construct a known-good baseline.

// approvedCipherSuites is the set of TLS 1.2 cipher suites acceptable under FIPS
// 140-3: ECDHE key exchange with AES-GCM AEAD. ChaCha20-Poly1305, CBC-mode, RC4,
// and 3DES suites are excluded. (TLS 1.3 suites are negotiated separately and
// are handled by ApprovedTLS13Suite.)
var approvedCipherSuites = map[uint16]bool{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
}

// ApprovedCipherSuites returns the FIPS-acceptable TLS 1.2 cipher suite IDs.
func ApprovedCipherSuites() []uint16 {
	out := make([]uint16, 0, len(approvedCipherSuites))
	for id := range approvedCipherSuites {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CipherSuiteApproved reports whether a TLS 1.2 cipher suite id is FIPS-acceptable.
func CipherSuiteApproved(id uint16) bool { return approvedCipherSuites[id] }

// ApprovedTLS13Suite reports whether a TLS 1.3 cipher suite id is FIPS-acceptable.
// TLS_CHACHA20_POLY1305_SHA256 is excluded because ChaCha20-Poly1305 is not a
// FIPS-approved AEAD.
func ApprovedTLS13Suite(id uint16) bool {
	switch id {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384:
		return true
	default:
		return false
	}
}

// TLSVersionApproved reports whether a TLS protocol version is FIPS-acceptable.
// FIPS 140-3 permits TLS 1.2 and TLS 1.3; SSLv3/TLS 1.0/1.1 are not acceptable.
func TLSVersionApproved(v uint16) bool {
	return v == tls.VersionTLS12 || v == tls.VersionTLS13
}

// ValidateTLSConfig checks that a *tls.Config is FIPS-acceptable: the minimum
// version is TLS 1.2+, and any explicitly-pinned TLS 1.2 cipher suites are all
// approved. It returns a joined error describing every problem found, or nil if
// the config is acceptable. A nil config is treated as "use library defaults"
// and accepted (under a FIPS runtime the library defaults are already
// constrained).
//
// Note: an empty CipherSuites means "let the library choose"; under a FIPS
// runtime the library's own selection is already constrained, so we only flag
// suites the operator has explicitly pinned to a non-approved value.
func ValidateTLSConfig(c *tls.Config) error {
	if c == nil {
		return nil
	}
	var problems []string
	if c.MinVersion == 0 {
		problems = append(problems, "MinVersion is unset (0); pin it to TLS 1.2 or higher")
	} else if !TLSVersionApproved(c.MinVersion) {
		problems = append(problems, fmt.Sprintf("MinVersion %s is below TLS 1.2", tlsVersionName(c.MinVersion)))
	}
	for _, id := range c.CipherSuites {
		if !CipherSuiteApproved(id) {
			problems = append(problems, fmt.Sprintf("cipher suite %s is not FIPS-approved", tls.CipherSuiteName(id)))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("fips: TLS config not FIPS-acceptable: %s", strings.Join(problems, "; "))
}

// ApprovedTLSConfig returns a *tls.Config baseline that is FIPS-acceptable:
// MinVersion TLS 1.2 and the approved AES-GCM cipher suites. Callers layer their
// own certificates/roots on top. Under TLS 1.3 the CipherSuites field is ignored
// by the library, which already restricts to AES-GCM suites in FIPS mode.
func ApprovedTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: ApprovedCipherSuites(),
	}
}

// Harden applies FIPS-approved TLS parameters to c in place, according to
// mode. ModeOff leaves c untouched. ModeWarn and ModeEnforce raise MinVersion
// to TLS 1.2 (never lowering an already-higher value) and pin CipherSuites to
// the approved set. ModeEnforce additionally validates the result and fails
// closed (returns the validation error) if it is still not FIPS-acceptable. A
// nil config is a no-op.
func Harden(c *tls.Config, mode Mode) error {
	if mode == ModeOff || c == nil {
		return nil
	}
	if c.MinVersion < tls.VersionTLS12 {
		c.MinVersion = tls.VersionTLS12
	}
	c.CipherSuites = ApprovedCipherSuites()
	if mode == ModeEnforce {
		return ValidateTLSConfig(c)
	}
	return nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
