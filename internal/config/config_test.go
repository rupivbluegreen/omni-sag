package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

const demoYAML = `
listen: ":2222"
host_key: "hostkey.pem"
ldap:
  url: "ldaps://dc1.lab.local:636"
  base_dn: "DC=lab,DC=local"
  bind_dn: "CN=svc,CN=Users,DC=lab,DC=local"
  bind_password: "secret"
  user_filter: "(sAMAccountName=%s)"
  insecure_tls: true
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

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAndCompile(t *testing.T) {
	f, err := Load(writeTemp(t, demoYAML))
	if err != nil {
		t.Fatal(err)
	}
	if f.Listen != ":2222" {
		t.Fatalf("listen = %q", f.Listen)
	}
	if !f.LDAP.InsecureTLS {
		t.Fatal("insecure_tls should be true")
	}

	p := f.CompilePolicy()
	// compiled policy must produce the same decisions as the demo
	allow := p.Decide(policy.Principal{User: "alice", Groups: []string{"dba"}},
		policy.Target{Host: "db1.lab.local", Port: 5432})
	if !allow.Allow {
		t.Fatalf("dba should be allowed: %s", allow.Reason)
	}
	deny := p.Decide(policy.Principal{User: "bob", Groups: []string{"users"}},
		policy.Target{Host: "db1.lab.local", Port: 5432})
	if deny.Allow {
		t.Fatal("non-dba should be denied")
	}
}

func TestValidate_MissingListen(t *testing.T) {
	if _, err := Load(writeTemp(t, "policy:\n  roles: []\n")); err == nil {
		t.Fatal("expected error for missing listen")
	}
}

func TestValidate_EmptyRuleHost(t *testing.T) {
	bad := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles:
    - name: dba
      groups: ["dba"]
      allow:
        - ports: [5432]
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected error for empty rule host")
	}
}
