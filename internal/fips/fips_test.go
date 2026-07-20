package fips

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{
		"":            ModeOff,
		"off":         ModeOff,
		"disabled":    ModeOff,
		"warn":        ModeWarn,
		"warning":     ModeWarn,
		"audit":       ModeWarn,
		"enforce":     ModeEnforce,
		"on":          ModeEnforce,
		"required":    ModeEnforce,
		"  Enforce  ": ModeEnforce,
		"ENFORCE":     ModeEnforce,
	}
	for in, want := range cases {
		got, err := ParseMode(in)
		if err != nil {
			t.Fatalf("ParseMode(%q) error: %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseMode(%q) = %v, want %v", in, got, want)
		}
	}

	if _, err := ParseMode("bogus"); err == nil {
		t.Fatal("ParseMode(bogus) should error")
	}
}

func TestModeString(t *testing.T) {
	for _, tc := range []struct {
		m    Mode
		want string
	}{
		{ModeOff, "off"},
		{ModeWarn, "warn"},
		{ModeEnforce, "enforce"},
	} {
		if got := tc.m.String(); got != tc.want {
			t.Fatalf("%d.String() = %q, want %q", int(tc.m), got, tc.want)
		}
	}
}

func TestSelfTestPasses(t *testing.T) {
	if err := SelfTest(); err != nil {
		t.Fatalf("SelfTest should pass on a healthy runtime: %v", err)
	}
}

// withRuntime swaps the RuntimeEnabled probe for the duration of a test.
func withRuntime(t *testing.T, enabled bool) {
	t.Helper()
	orig := RuntimeEnabled
	RuntimeEnabled = func() bool { return enabled }
	t.Cleanup(func() { RuntimeEnabled = orig })
}

func TestCheckOffModeNeverErrorsOrWarns(t *testing.T) {
	for _, rt := range []bool{false, true} {
		withRuntime(t, rt)
		r, err := Check(ModeOff)
		if err != nil {
			t.Fatalf("ModeOff (runtime=%v) errored: %v", rt, err)
		}
		if len(r.Warnings) != 0 {
			t.Fatalf("ModeOff (runtime=%v) produced warnings: %v", rt, r.Warnings)
		}
		if !r.SelfTestPassed {
			t.Fatalf("ModeOff (runtime=%v) self-test should pass", rt)
		}
		if r.RuntimeFIPS != rt {
			t.Fatalf("ModeOff RuntimeFIPS = %v, want %v", r.RuntimeFIPS, rt)
		}
	}
}

func TestCheckEnforceRequiresRuntimeFIPS(t *testing.T) {
	withRuntime(t, false)
	r, err := Check(ModeEnforce)
	if err == nil {
		t.Fatal("enforce mode with no runtime FIPS must error (daemon must refuse to start)")
	}
	if r.RuntimeFIPS {
		t.Fatal("report should record runtime as not FIPS")
	}
	if !strings.Contains(err.Error(), "GODEBUG=fips140=on") {
		t.Fatalf("error should tell the operator how to fix it: %v", err)
	}
}

func TestCheckEnforceSucceedsWhenRuntimeFIPS(t *testing.T) {
	withRuntime(t, true)
	r, err := Check(ModeEnforce)
	if err != nil {
		t.Fatalf("enforce mode with runtime FIPS should succeed: %v", err)
	}
	if !r.RuntimeFIPS || !r.SelfTestPassed {
		t.Fatalf("unexpected report: %+v", r)
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("no warnings expected when fully FIPS: %v", r.Warnings)
	}
}

func TestCheckWarnModeWarnsButDoesNotError(t *testing.T) {
	withRuntime(t, false)
	r, err := Check(ModeWarn)
	if err != nil {
		t.Fatalf("warn mode must not error: %v", err)
	}
	if len(r.Warnings) == 0 {
		t.Fatal("warn mode with no runtime FIPS must produce a warning")
	}
}

func TestCheckWarnModeNoWarningWhenRuntimeFIPS(t *testing.T) {
	withRuntime(t, true)
	r, err := Check(ModeWarn)
	if err != nil {
		t.Fatalf("warn mode must not error: %v", err)
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("warn mode should not warn when runtime is FIPS: %v", r.Warnings)
	}
}

func TestReportSummary(t *testing.T) {
	r := Report{Mode: ModeEnforce, RuntimeFIPS: true, SelfTestPassed: true}
	s := r.Summary()
	for _, want := range []string{"mode=enforce", "runtime=active", "self-test=pass"} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary %q missing %q", s, want)
		}
	}
	r2 := Report{Mode: ModeOff, RuntimeFIPS: false, SelfTestPassed: false}
	s2 := r2.Summary()
	for _, want := range []string{"mode=off", "runtime=not-active", "self-test=fail"} {
		if !strings.Contains(s2, want) {
			t.Fatalf("summary %q missing %q", s2, want)
		}
	}
}

func TestTLSVersionApproved(t *testing.T) {
	approved := []uint16{tls.VersionTLS12, tls.VersionTLS13}
	rejected := []uint16{tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11}
	for _, v := range approved {
		if !TLSVersionApproved(v) {
			t.Fatalf("version 0x%04x should be approved", v)
		}
	}
	for _, v := range rejected {
		if TLSVersionApproved(v) {
			t.Fatalf("version 0x%04x should be rejected", v)
		}
	}
}

func TestCipherSuiteApproval(t *testing.T) {
	approved := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}
	for _, id := range approved {
		if !CipherSuiteApproved(id) {
			t.Fatalf("%s should be approved", tls.CipherSuiteName(id))
		}
	}
	rejected := []uint16{
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
	}
	for _, id := range rejected {
		if CipherSuiteApproved(id) {
			t.Fatalf("%s should NOT be approved", tls.CipherSuiteName(id))
		}
	}
}

func TestApprovedTLS13Suite(t *testing.T) {
	if !ApprovedTLS13Suite(tls.TLS_AES_128_GCM_SHA256) || !ApprovedTLS13Suite(tls.TLS_AES_256_GCM_SHA384) {
		t.Fatal("AES-GCM TLS 1.3 suites should be approved")
	}
	if ApprovedTLS13Suite(tls.TLS_CHACHA20_POLY1305_SHA256) {
		t.Fatal("ChaCha20-Poly1305 TLS 1.3 suite must not be approved")
	}
}

func TestApprovedCipherSuitesSorted(t *testing.T) {
	s := ApprovedCipherSuites()
	if len(s) != 4 {
		t.Fatalf("expected 4 approved suites, got %d", len(s))
	}
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			t.Fatalf("ApprovedCipherSuites not sorted ascending: %v", s)
		}
	}
}

func TestValidateTLSConfig(t *testing.T) {
	// nil is accepted (library defaults).
	if err := ValidateTLSConfig(nil); err != nil {
		t.Fatalf("nil config should be accepted: %v", err)
	}

	// The baseline the package itself produces must validate clean.
	if err := ValidateTLSConfig(ApprovedTLSConfig()); err != nil {
		t.Fatalf("ApprovedTLSConfig must be FIPS-acceptable: %v", err)
	}

	// MinVersion unset is flagged.
	if err := ValidateTLSConfig(&tls.Config{}); err == nil {
		t.Fatal("unset MinVersion should be flagged")
	}

	// MinVersion below 1.2 is flagged.
	if err := ValidateTLSConfig(&tls.Config{MinVersion: tls.VersionTLS10}); err == nil {
		t.Fatal("TLS 1.0 MinVersion should be flagged")
	}

	// A non-approved pinned cipher suite is flagged.
	bad := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
	}
	err := ValidateTLSConfig(bad)
	if err == nil {
		t.Fatal("pinned ChaCha20 suite should be flagged")
	}
	if !strings.Contains(err.Error(), "CHACHA20") {
		t.Fatalf("error should name the offending suite: %v", err)
	}

	// A clean TLS 1.3-min config with no pinned suites validates.
	if err := ValidateTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13}); err != nil {
		t.Fatalf("TLS 1.3 min config should validate: %v", err)
	}
}

func TestHarden(t *testing.T) {
	t.Run("off leaves config untouched", func(t *testing.T) {
		c := &tls.Config{MinVersion: tls.VersionTLS10, CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}}
		if err := Harden(c, ModeOff); err != nil {
			t.Fatalf("off mode must not error: %v", err)
		}
		if c.MinVersion != tls.VersionTLS10 {
			t.Fatalf("off mode changed MinVersion: %v", c.MinVersion)
		}
		if len(c.CipherSuites) != 1 || c.CipherSuites[0] != tls.TLS_RSA_WITH_RC4_128_SHA {
			t.Fatalf("off mode changed CipherSuites: %v", c.CipherSuites)
		}
	})

	t.Run("off does not panic on nil config", func(t *testing.T) {
		if err := Harden(nil, ModeOff); err != nil {
			t.Fatalf("nil config should be a no-op: %v", err)
		}
	})

	t.Run("warn raises MinVersion and pins approved suites", func(t *testing.T) {
		c := &tls.Config{MinVersion: tls.VersionTLS10}
		if err := Harden(c, ModeWarn); err != nil {
			t.Fatalf("warn must not error: %v", err)
		}
		if !TLSVersionApproved(c.MinVersion) {
			t.Fatalf("MinVersion not raised to an approved version: 0x%04x", c.MinVersion)
		}
		if len(c.CipherSuites) == 0 {
			t.Fatal("expected approved cipher suites to be set")
		}
		for _, id := range c.CipherSuites {
			if !CipherSuiteApproved(id) {
				t.Fatalf("cipher suite %s is not approved", tls.CipherSuiteName(id))
			}
		}
	})

	t.Run("warn does not lower an already-higher MinVersion", func(t *testing.T) {
		c := &tls.Config{MinVersion: tls.VersionTLS13}
		if err := Harden(c, ModeWarn); err != nil {
			t.Fatalf("warn must not error: %v", err)
		}
		if c.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion should stay TLS 1.3, got 0x%04x", c.MinVersion)
		}
	})

	t.Run("enforce succeeds for an approved config", func(t *testing.T) {
		c := ApprovedTLSConfig()
		if err := Harden(c, ModeEnforce); err != nil {
			t.Fatalf("enforce should accept an already-approved config: %v", err)
		}
	})

	t.Run("enforce hardens and validates a fixable config", func(t *testing.T) {
		c := &tls.Config{MinVersion: tls.VersionTLS10}
		if err := Harden(c, ModeEnforce); err != nil {
			t.Fatalf("enforce should harden then pass validation: %v", err)
		}
		if err := ValidateTLSConfig(c); err != nil {
			t.Fatalf("hardened config should validate clean: %v", err)
		}
	})

	t.Run("enforce fails closed when the config remains non-approved", func(t *testing.T) {
		// A bogus MinVersion above TLS 1.2 numerically is left alone by Harden
		// (it only raises versions below TLS 1.2) but is still not an approved
		// version, so ValidateTLSConfig must reject it and Harden must propagate
		// that as a fail-closed error.
		c := &tls.Config{MinVersion: 0xfffe}
		if err := Harden(c, ModeEnforce); err == nil {
			t.Fatal("enforce must fail closed on a config that still doesn't validate")
		}
	})
}

// TestApprovedTLSConfigIsUsable makes a real handshake between a server and
// client both restricted to the FIPS baseline, proving the approved parameters
// actually interoperate (not just that they pass a static predicate).
func TestApprovedTLSConfigInteroperates(t *testing.T) {
	// Generate an ephemeral self-signed cert via the same primitives the gateway
	// uses so the handshake is exercised end to end.
	cert := ephemeralCert(t)

	serverCfg := ApprovedTLSConfig()
	serverCfg.Certificates = []tls.Certificate{cert}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("pong"))
	}()

	clientCfg := ApprovedTLSConfig()
	clientCfg.InsecureSkipVerify = true // ephemeral self-signed cert; we test the suite negotiation
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	state := conn.ConnectionState()
	if !TLSVersionApproved(state.Version) {
		t.Fatalf("negotiated non-approved TLS version 0x%04x", state.Version)
	}
	// For TLS 1.2 the suite must be in our approved set; for TLS 1.3 it must be
	// an approved AEAD suite.
	if state.Version == tls.VersionTLS12 && !CipherSuiteApproved(state.CipherSuite) {
		t.Fatalf("negotiated non-approved TLS 1.2 suite %s", tls.CipherSuiteName(state.CipherSuite))
	}
	if state.Version == tls.VersionTLS13 && !ApprovedTLS13Suite(state.CipherSuite) {
		t.Fatalf("negotiated non-approved TLS 1.3 suite %s", tls.CipherSuiteName(state.CipherSuite))
	}
	<-done
}
