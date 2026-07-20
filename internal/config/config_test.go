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
	if f.DisableSSH || f.DisableTunnel || f.DisableSFTP {
		t.Fatal("capability toggles should all default to false (enabled)")
	}

	p := f.CompilePolicy()
	// compiled policy must produce the same decisions as the demo
	allow := p.Decide(policy.Principal{User: "alice", Groups: []string{"dba"}},
		policy.Target{Host: "db1.lab.local", Port: 5432}, nil)
	if !allow.Allow {
		t.Fatalf("dba should be allowed: %s", allow.Reason)
	}
	deny := p.Decide(policy.Principal{User: "bob", Groups: []string{"users"}},
		policy.Target{Host: "db1.lab.local", Port: 5432}, nil)
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

func TestValidate_AllCapabilitiesDisabledRejected(t *testing.T) {
	bad := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
disable_ssh: true
disable_tunnel: true
disable_sftp: true
policy:
  roles: []
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected error when disable_ssh, disable_tunnel, and disable_sftp are all true")
	}
}

func TestValidate_TwoOfThreeCapabilitiesDisabledIsAllowed(t *testing.T) {
	ok := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
disable_ssh: true
disable_sftp: true
policy:
  roles: []
`
	f, err := Load(writeTemp(t, ok))
	if err != nil {
		t.Fatal(err)
	}
	if !f.DisableSSH || !f.DisableSFTP {
		t.Fatal("disable_ssh and disable_sftp should both be true")
	}
	if f.DisableTunnel {
		t.Fatal("disable_tunnel should be false (omitted)")
	}
}

func TestValidate_EnableSCPDefaultsOff(t *testing.T) {
	ok := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
`
	f, err := Load(writeTemp(t, ok))
	if err != nil {
		t.Fatal(err)
	}
	if f.EnableSCP {
		t.Fatal("enable_scp should default to false (legacy scp opt-in, off unless set)")
	}
}

func TestValidate_EnableSCPWithAllOthersDisabledIsAccepted(t *testing.T) {
	// enable_scp is opt-in and NOT part of the "at least one capability must
	// stay enabled" rule: the gateway still serves scp here, but even so the
	// three disable_* toggles govern that rule on their own. Disabling all
	// three is still rejected regardless of enable_scp — asserted separately
	// in TestValidate_AllCapabilitiesDisabledRejected. Here only sftp is
	// disabled, so it must load fine with scp enabled.
	ok := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
disable_sftp: true
enable_scp: true
policy:
  roles: []
`
	f, err := Load(writeTemp(t, ok))
	if err != nil {
		t.Fatal(err)
	}
	if !f.EnableSCP {
		t.Fatal("enable_scp should be true")
	}
	if !f.DisableSFTP {
		t.Fatal("disable_sftp should be true")
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

func TestValidate_CredentialMode(t *testing.T) {
	rule := func(cred string) string {
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
          credential: "` + cred + `"
`
	}
	// passthrough/prompt/deny (and empty) need no CyberArk block.
	for _, ok := range []string{"", "passthrough", "prompt", "deny"} {
		if _, err := Load(writeTemp(t, rule(ok))); err != nil {
			t.Fatalf("credential %q should be valid: %v", ok, err)
		}
	}
	// an invalid mode is rejected.
	if _, err := Load(writeTemp(t, rule("borrow"))); err == nil {
		t.Fatal("invalid credential mode must be rejected")
	}
	// inject without a cyberark block is rejected.
	if _, err := Load(writeTemp(t, rule("inject"))); err == nil {
		t.Fatal("inject without a cyberark block must be rejected")
	}
	// inject with a cyberark block loads.
	withCA := `
listen: ":2222"
evidence:
  file: "e.jsonl"
cyberark:
  base_url: "https://ccp.lab/AIMWebService"
  client_cert: "client.crt"
  client_key: "client.key"
  app_id: "omni-sag"
  safe: "targets"
  object_template: "{host}"
policy:
  roles:
    - name: dba
      groups: ["dba"]
      allow:
        - host: "db1"
          ports: [5432]
          credential: "inject"
`
	if _, err := Load(writeTemp(t, withCA)); err != nil {
		t.Fatalf("inject with cyberark should load: %v", err)
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
	d := f.CompilePolicy().Decide(policy.Principal{User: "a", Groups: []string{"dba"}}, policy.Target{Host: "full.lab", Port: 22}, nil)
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

func TestValidate_RequireApprovalNeedsStore(t *testing.T) {
	// A rule sets require_approval but no approval block is configured -> error.
	bad := `
listen: ":2222"
evidence:
  file: "e.jsonl"
policy:
  roles:
    - name: dba
      groups: ["dba"]
      allow:
        - host: "crown"
          ports: [22]
          require_approval: true
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("require_approval without an approval block must fail validation")
	}

	// With an approval block it loads and compiles the flag.
	good := `
listen: ":2222"
evidence:
  file: "e.jsonl"
approval:
  store_path: "approvals.json"
policy:
  roles:
    - name: dba
      groups: ["dba"]
      allow:
        - host: "crown"
          ports: [22]
          require_approval: true
`
	f, err := Load(writeTemp(t, good))
	if err != nil {
		t.Fatalf("valid approval config should load: %v", err)
	}
	if !f.CompilePolicy().Roles[0].Allow[0].RequireApproval {
		t.Fatal("require_approval flag should compile into the policy rule")
	}
}

func TestCompilePolicy_TargetUser(t *testing.T) {
	f := &File{Policy: PolicyConfig{Roles: []RoleConfig{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []RuleConfig{{Host: "db1.lab.local", TargetUser: "svc_db1"}},
	}}}}
	p := f.CompilePolicy()
	if got := p.Roles[0].Allow[0].TargetUser; got != "svc_db1" {
		t.Fatalf("TargetUser = %q, want svc_db1", got)
	}
}

func TestApprovalConfig_ReleaseTTL_Default(t *testing.T) {
	var a *ApprovalConfig
	if got := a.ReleaseTTL(); got != 86400 {
		t.Fatalf("ReleaseTTL() on nil config = %d, want 86400 (24h)", got)
	}
	a = &ApprovalConfig{}
	if got := a.ReleaseTTL(); got != 86400 {
		t.Fatalf("ReleaseTTL() on zero-value config = %d, want 86400", got)
	}
}

func TestApprovalConfig_ReleaseTTL_Configured(t *testing.T) {
	a := &ApprovalConfig{ReleaseTTLSeconds: 3600}
	if got := a.ReleaseTTL(); got != 3600 {
		t.Fatalf("ReleaseTTL() = %d, want 3600", got)
	}
}

func TestValidatePolicyRoles_MalformedCIDRRejected(t *testing.T) {
	roles := []RoleConfig{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []RuleConfig{{Host: "10.0.0.0/abc"}},
	}}
	if err := validatePolicyRoles(roles); err == nil {
		t.Fatal("a Host containing \"/\" that fails net.ParseCIDR must be rejected at config load, not silently treated as a literal hostname")
	}
}

func TestValidatePolicyRoles_ValidCIDRAccepted(t *testing.T) {
	roles := []RoleConfig{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []RuleConfig{{Host: "10.0.0.0/8"}},
	}}
	if err := validatePolicyRoles(roles); err != nil {
		t.Fatalf("a valid CIDR host must be accepted, got %v", err)
	}
}

func TestPolicyConfig_DisableCIDRHostnameResolutionDefaultsFalse(t *testing.T) {
	f, err := Load(writeTemp(t, demoYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if f.Policy.DisableCIDRHostnameResolution {
		t.Fatal("disable_cidr_hostname_resolution must default to false (resolution enabled) when omitted from YAML")
	}
}

func TestLoad_ComposeExampleConfigParses(t *testing.T) {
	// Regression check: the shipped deploy/compose/config.example.yaml must
	// always be loadable.
	_, err := Load("../../deploy/compose/config.example.yaml")
	if err != nil {
		t.Fatalf("deploy/compose/config.example.yaml failed to load: %v", err)
	}
}

const exportYAML = `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
export:
  enabled: true
  exporters:
    - name: arcsight
      format: cef
      transport: syslog
      buffer_size: 10000
      syslog:
        address: "arcsight:6514"
        protocol: tls
        facility: local0
        tls:
          ca: "ca.pem"
          cert: "c.pem"
          key: "k.pem"
    - name: elastic-filebeat
      format: ecs
      transport: file
      buffer_size: 10000
      file:
        path: "/var/log/omni-sag/events.ecs.jsonl"
    - name: elastic-direct
      format: ecs
      transport: http
      buffer_size: 10000
      http:
        url: "https://es:9200/_bulk"
        batch_size: 100
        flush_interval_seconds: 5
        auth:
          bearer_env: "ES_TOKEN"
        tls:
          ca: "es-ca.pem"
`

func TestExportConfig_ParsesMultiExporterYAML(t *testing.T) {
	f, err := Load(writeTemp(t, exportYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if f.Export == nil || !f.Export.Enabled {
		t.Fatal("export.enabled should be true")
	}
	if got := len(f.Export.Exporters); got != 3 {
		t.Fatalf("exporters = %d, want 3", got)
	}

	arcsight := f.Export.Exporters[0]
	if arcsight.Name != "arcsight" || arcsight.Format != "cef" || arcsight.Transport != "syslog" {
		t.Fatalf("arcsight exporter parsed wrong: %+v", arcsight)
	}
	if arcsight.Syslog == nil || arcsight.Syslog.Address != "arcsight:6514" || arcsight.Syslog.Protocol != "tls" {
		t.Fatalf("arcsight syslog sub-config parsed wrong: %+v", arcsight.Syslog)
	}
	if arcsight.Syslog.TLS == nil || arcsight.Syslog.TLS.CA != "ca.pem" {
		t.Fatalf("arcsight syslog tls sub-config parsed wrong: %+v", arcsight.Syslog.TLS)
	}

	filebeat := f.Export.Exporters[1]
	if filebeat.File == nil || filebeat.File.Path != "/var/log/omni-sag/events.ecs.jsonl" {
		t.Fatalf("filebeat file sub-config parsed wrong: %+v", filebeat.File)
	}

	direct := f.Export.Exporters[2]
	if direct.HTTP == nil || direct.HTTP.URL != "https://es:9200/_bulk" || direct.HTTP.BatchSize != 100 {
		t.Fatalf("direct http sub-config parsed wrong: %+v", direct.HTTP)
	}
	if direct.HTTP.Auth.BearerEnv != "ES_TOKEN" {
		t.Fatalf("direct http auth parsed wrong: %+v", direct.HTTP.Auth)
	}

	// Mapping into the eventexport package's Config must carry every field
	// through, including constructing the (package-private in eventexport)
	// transport sub-configs via the exported mirror structs.
	ee := f.Export.ToEventExport()
	if !ee.Enabled || len(ee.Exporters) != 3 {
		t.Fatalf("toEventExport: %+v", ee)
	}
	if ee.Exporters[0].Syslog == nil || ee.Exporters[0].Syslog.Address != "arcsight:6514" {
		t.Fatalf("toEventExport arcsight syslog: %+v", ee.Exporters[0].Syslog)
	}
	if ee.Exporters[1].File == nil || ee.Exporters[1].File.Path != "/var/log/omni-sag/events.ecs.jsonl" {
		t.Fatalf("toEventExport filebeat file: %+v", ee.Exporters[1].File)
	}
	if ee.Exporters[2].HTTP == nil || ee.Exporters[2].HTTP.URL != "https://es:9200/_bulk" {
		t.Fatalf("toEventExport direct http: %+v", ee.Exporters[2].HTTP)
	}
}

func TestExportConfig_DisabledOrAbsentIsNilOrDisabled(t *testing.T) {
	f, err := Load(writeTemp(t, demoYAML))
	if err != nil {
		t.Fatal(err)
	}
	if f.Export != nil {
		t.Fatalf("export should be nil when absent from yaml, got %+v", f.Export)
	}

	withFalse := demoYAML + "export:\n  enabled: false\n"
	f2, err := Load(writeTemp(t, withFalse))
	if err != nil {
		t.Fatal(err)
	}
	if f2.Export == nil || f2.Export.Enabled {
		t.Fatalf("export.enabled: false should parse but stay disabled, got %+v", f2.Export)
	}
}

func TestExportConfig_InvalidFormatRejected(t *testing.T) {
	bad := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
export:
  enabled: true
  exporters:
    - name: bad
      format: xml
      transport: file
      file:
        path: "e.jsonl"
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected error for invalid export format")
	}
}

func TestExportConfig_InvalidTransportRejected(t *testing.T) {
	bad := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
export:
  enabled: true
  exporters:
    - name: bad
      format: json
      transport: carrier-pigeon
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected error for invalid export transport")
	}
}

func TestExportConfig_MissingSubConfigRejected(t *testing.T) {
	bad := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
export:
  enabled: true
  exporters:
    - name: bad
      format: cef
      transport: syslog
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected error for export exporter missing its transport sub-config")
	}
}

func TestExportConfig_EnabledTrueWithNoExportersRejected(t *testing.T) {
	bad := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
export:
  enabled: true
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected error for export.enabled true with no exporters")
	}
}

func TestExportConfig_BufferSizeDefaultsInEventExport(t *testing.T) {
	f, err := Load(writeTemp(t, demoYAML+`export:
  enabled: true
  exporters:
    - name: a
      format: json
      transport: file
      file:
        path: "e.jsonl"
`))
	if err != nil {
		t.Fatal(err)
	}
	if f.Export.Exporters[0].BufferSize != 0 {
		t.Fatalf("buffer_size should be unset (0) when omitted from yaml, want the default to apply downstream in eventexport, got %d", f.Export.Exporters[0].BufferSize)
	}
	ee := f.Export.ToEventExport()
	if got := ee.Exporters[0].BufferSize; got != 0 {
		t.Fatalf("toEventExport should pass BufferSize through unmodified (eventexport itself defaults <=0), got %d", got)
	}
}

func TestLoad_OTelDefaultsWhenBlockPresent(t *testing.T) {
	y := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
otel:
  enabled: true
  endpoint: "collector:4317"
`
	f, err := Load(writeTemp(t, y))
	if err != nil {
		t.Fatal(err)
	}
	if f.OTel == nil || !f.OTel.Enabled {
		t.Fatal("otel should be enabled")
	}
	if f.OTel.Protocol() != "grpc" {
		t.Fatalf("default protocol = %q, want grpc", f.OTel.Protocol())
	}
	if f.OTel.Sampler() != "parentbased_always_on" {
		t.Fatalf("default sampler = %q", f.OTel.Sampler())
	}
	// traces default ON when otel enabled; metrics/logs default OFF
	if !f.OTel.TracesEnabled() {
		t.Fatal("traces should default enabled")
	}
	if f.OTel.MetricsEnabled() || f.OTel.LogsEnabled() {
		t.Fatal("metrics and logs should default disabled")
	}
}

func TestLoad_OTelAbsentIsNil(t *testing.T) {
	y := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
`
	f, err := Load(writeTemp(t, y))
	if err != nil {
		t.Fatal(err)
	}
	if f.OTel != nil {
		t.Fatal("absent otel block must be nil (feature off)")
	}
}

func TestLoad_OTelRejectsBadProtocolAndSampler(t *testing.T) {
	for _, bad := range []string{
		"otel:\n  enabled: true\n  protocol: carrier-pigeon\n",
		"otel:\n  enabled: true\n  traces:\n    sampler: sometimes\n",
	} {
		y := "listen: \":2222\"\nevidence:\n  file: \"e.jsonl\"\npolicy:\n  roles: []\n" + bad
		if _, err := Load(writeTemp(t, y)); err == nil {
			t.Fatalf("expected validation error for %q", bad)
		}
	}
}

func TestLoad_OTelRequiresEndpointWhenEnabled(t *testing.T) {
	y := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
otel:
  enabled: true
`
	if _, err := Load(writeTemp(t, y)); err == nil {
		t.Fatal("expected validation error for otel.enabled with no endpoint")
	}
}

func TestExportConfig_OTLPTransportRequiresJSONFormat(t *testing.T) {
	y := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
export:
  enabled: true
  exporters:
    - name: otel-logs
      format: ecs
      transport: otlp
`
	if _, err := Load(writeTemp(t, y)); err == nil {
		t.Fatal("expected error: otlp transport requires format json")
	}
}

func TestExportConfig_OTLPTransportWithJSONFormatAccepted(t *testing.T) {
	y := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
policy:
  roles: []
export:
  enabled: true
  exporters:
    - name: otel-logs
      format: json
      transport: otlp
`
	f, err := Load(writeTemp(t, y))
	if err != nil {
		t.Fatalf("otlp transport with format json should be accepted: %v", err)
	}
	if f.Export.Exporters[0].Transport != "otlp" {
		t.Fatalf("transport = %q, want otlp", f.Export.Exporters[0].Transport)
	}
}

func TestValidate_TunnelInspectionDefaults(t *testing.T) {
	ok := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
tunnel_inspection:
  enabled: true
policy:
  roles: []
`
	f, err := Load(writeTemp(t, ok))
	if err != nil {
		t.Fatal(err)
	}
	ti := f.TunnelInspection
	if ti == nil || !ti.Enabled {
		t.Fatal("tunnel_inspection.enabled should be true")
	}
	if ti.MaxPrefixBytes != 512 {
		t.Fatalf("max_prefix_bytes default = %d, want 512", ti.MaxPrefixBytes)
	}
	if ti.ClassifyTimeoutSeconds != 5 {
		t.Fatalf("classify_timeout default = %d, want 5", ti.ClassifyTimeoutSeconds)
	}
	if ti.UnknownAction != "allow" {
		t.Fatalf("unknown_action default = %q, want allow", ti.UnknownAction)
	}
}

func TestCompile_ExpectProtocol(t *testing.T) {
	ok := `
listen: ":2222"
evidence: { file: "e.jsonl" }
policy:
  roles:
    - name: dba
      groups: [dba]
      allow:
        - host: db1
          ports: [5432]
          expect_protocol: [postgres]
`
	f, err := Load(writeTemp(t, ok))
	if err != nil {
		t.Fatal(err)
	}
	p := f.CompilePolicy()
	got := p.Roles[0].Allow[0].ExpectProtocol
	if len(got) != 1 || got[0] != "postgres" {
		t.Fatalf("ExpectProtocol = %v, want [postgres]", got)
	}
}

func TestValidate_ExpectProtocolUnknownRejected(t *testing.T) {
	bad := `
listen: ":2222"
evidence: { file: "e.jsonl" }
policy:
  roles:
    - name: dba
      groups: [dba]
      allow:
        - host: db1
          ports: [5432]
          expect_protocol: [nope]
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("unknown protocol must be rejected")
	}
}

func TestValidate_TunnelInspectionBadUnknownAction(t *testing.T) {
	bad := `
listen: ":2222"
evidence:
  file: "evidence.jsonl"
tunnel_inspection:
  enabled: true
  unknown_action: sometimes
policy:
  roles: []
`
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected error for invalid unknown_action")
	}
}
