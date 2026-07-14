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

func TestValidate_PipelineEvidence(t *testing.T) {
	ok := `
listen: ":2222"
evidence:
  pipeline:
    data_dir: "evidence"
    signing_key: "evidence-key.pem"
policy:
  roles: []
`
	f, err := Load(writeTemp(t, ok))
	if err != nil {
		t.Fatalf("valid pipeline config should load: %v", err)
	}
	if f.Evidence.Pipeline == nil || f.Evidence.Pipeline.DataDir != "evidence" {
		t.Fatal("pipeline config not parsed")
	}

	// Pipeline missing signing_key must be rejected.
	bad := `
listen: ":2222"
evidence:
  pipeline:
    data_dir: "evidence"
policy:
  roles: []
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected error for pipeline without signing_key")
	}

	// Two evidence backends at once must be rejected.
	both := `
listen: ":2222"
evidence:
  file: "e.jsonl"
  pipeline:
    data_dir: "evidence"
    signing_key: "k.pem"
policy:
  roles: []
`
	if _, err := Load(writeTemp(t, both)); err == nil {
		t.Fatal("expected error for two evidence backends")
	}
}

func TestValidate_RecordMode(t *testing.T) {
	base := func(rec string) string {
		return `
listen: ":2222"
evidence:
  file: "e.jsonl"
policy:
  roles:
    - name: dba
      groups: ["dba"]
      allow:
        - host: "db1"
          ports: [5432]
          record: "` + rec + `"
`
	}
	for _, ok := range []string{"none", "metadata-only", "full"} {
		if _, err := Load(writeTemp(t, base(ok))); err != nil {
			t.Fatalf("record %q should be valid: %v", ok, err)
		}
	}
	if _, err := Load(writeTemp(t, base("sometimes"))); err == nil {
		t.Fatal("invalid record value must be rejected")
	}
}

func TestValidate_RecordingBackends(t *testing.T) {
	both := `
listen: ":2222"
evidence:
  file: "e.jsonl"
recording:
  local_dir: "recordings"
  s3:
    endpoint: "x:9000"
    bucket: "b"
policy:
  roles: []
`
	if _, err := Load(writeTemp(t, both)); err == nil {
		t.Fatal("two recording backends must be rejected")
	}
}

func TestCompilePolicy_RecordMode(t *testing.T) {
	cfg := `
listen: ":2222"
evidence:
  file: "e.jsonl"
policy:
  roles:
    - name: dba
      groups: ["dba"]
      allow:
        - host: "full.lab"
          ports: [22]
          record: full
`
	f, err := Load(writeTemp(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	d := f.CompilePolicy().Decide(policy.Principal{User: "a", Groups: []string{"dba"}}, policy.Target{Host: "full.lab", Port: 22})
	if d.RecordMode != policy.RecordFull || d.ForwardingAllowed() {
		t.Fatalf("compiled full record mode not applied: %+v", d)
	}
}

func TestValidate_Inspection(t *testing.T) {
	ok := `
listen: ":2222"
evidence:
  file: "e.jsonl"
inspection:
  enabled: true
  icap:
    endpoint: "127.0.0.1:1344"
    service: "avscan"
  threshold_bytes: 1048576
  quarantine:
    endpoint: "127.0.0.1:9000"
    bucket: "omni-sag-quarantine"
policy:
  roles: []
`
	if _, err := Load(writeTemp(t, ok)); err != nil {
		t.Fatalf("valid inspection config should load: %v", err)
	}

	// enabled without quarantine bucket must fail
	bad := `
listen: ":2222"
evidence:
  file: "e.jsonl"
inspection:
  enabled: true
  icap:
    endpoint: "127.0.0.1:1344"
    service: "avscan"
policy:
  roles: []
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("inspection enabled without quarantine must be rejected")
	}

	// enabled without icap endpoint/service must fail
	bad2 := `
listen: ":2222"
evidence:
  file: "e.jsonl"
inspection:
  enabled: true
  quarantine:
    endpoint: "127.0.0.1:9000"
    bucket: "q"
policy:
  roles: []
`
	if _, err := Load(writeTemp(t, bad2)); err == nil {
		t.Fatal("inspection enabled without icap endpoint/service must be rejected")
	}
}
