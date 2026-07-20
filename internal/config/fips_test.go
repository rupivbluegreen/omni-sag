package config

import (
	"strings"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/fips"
)

const fipsBaseYAML = `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles:
    - name: dba
      groups: ["dba"]
      allow:
        - host: "db1.lab.local"
          ports: [5432]
`

func TestFIPSModeDefaultsOff(t *testing.T) {
	f, err := Load(writeTemp(t, fipsBaseYAML))
	if err != nil {
		t.Fatal(err)
	}
	if f.FIPS != nil {
		t.Fatalf("FIPS block should be nil when absent")
	}
	if f.FIPSMode() != fips.ModeOff {
		t.Fatalf("FIPSMode() = %v, want off", f.FIPSMode())
	}
}

func TestFIPSModeEnforceParses(t *testing.T) {
	f, err := Load(writeTemp(t, fipsBaseYAML+"fips:\n  mode: enforce\n"))
	if err != nil {
		t.Fatal(err)
	}
	if f.FIPSMode() != fips.ModeEnforce {
		t.Fatalf("FIPSMode() = %v, want enforce", f.FIPSMode())
	}
}

func TestFIPSInvalidModeRejected(t *testing.T) {
	_, err := Load(writeTemp(t, fipsBaseYAML+"fips:\n  mode: bogus\n"))
	if err == nil {
		t.Fatal("invalid fips.mode must be rejected at load")
	}
	if !strings.Contains(err.Error(), "fips") {
		t.Fatalf("error should mention fips: %v", err)
	}
}

func TestFIPSEnforceRejectsLDAPInsecureTLS(t *testing.T) {
	yaml := fipsBaseYAML + "fips:\n  mode: enforce\n" + "ldap:\n  insecure_tls: true\n"
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("ldap.insecure_tls must be rejected when fips.mode=enforce")
	}
	if !strings.Contains(err.Error(), "insecure_tls") {
		t.Fatalf("error should name insecure_tls: %v", err)
	}
}

func TestFIPSWarnAllowsLDAPInsecureTLS(t *testing.T) {
	yaml := fipsBaseYAML + "fips:\n  mode: warn\n" + "ldap:\n  insecure_tls: true\n"
	if _, err := Load(writeTemp(t, yaml)); err != nil {
		t.Fatalf("ldap.insecure_tls under fips.mode=warn should not be rejected: %v", err)
	}
}
