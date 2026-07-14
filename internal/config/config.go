// Package config loads the gateway configuration and compiles the policy
// document into an immutable policy.Policy. In Slice 1 the policy is a YAML
// file read once at boot; later slices replace this with CRDs.
package config

import (
	"fmt"
	"os"

	"github.com/rupivbluegreen/omni-sag/internal/fips"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"gopkg.in/yaml.v3"
)

// File is the on-disk configuration document.
type File struct {
	Listen     string            `yaml:"listen"`   // SSH listen address, e.g. ":2222"
	HostKey    string            `yaml:"host_key"` // path to the SSH host key (created if absent)
	LDAP       LDAPConfig        `yaml:"ldap"`
	MFA        MFAConfig         `yaml:"mfa"`
	Evidence   EvidenceConfig    `yaml:"evidence"`
	Recording  *RecordingConfig  `yaml:"recording"`     // optional session-recording store
	Inspection *InspectionConfig `yaml:"inspection"`    // optional SFTP content inspection (ICAP)
	CyberArk   *CyberArkConfig   `yaml:"cyberark"`      // optional; required if any rule uses credential "inject"
	API        *APIConfig        `yaml:"api"`           // optional control-plane API (out-of-band)
	Approval   *ApprovalConfig   `yaml:"approval"`      // optional; required if any rule sets require_approval
	PolicySrc  *PolicySource     `yaml:"policy_source"` // optional; hot-reload policy from a file
	Metrics    *MetricsConfig    `yaml:"metrics"`       // optional Prometheus /metrics listener (out-of-band)
	FIPS       *FIPSConfig       `yaml:"fips"`          // optional FIPS-readiness posture (off|warn|enforce)
	DrainGrace int               `yaml:"drain_grace_seconds"`
	Policy     PolicyConfig      `yaml:"policy"`
}

// MetricsConfig configures the Prometheus metrics endpoint, served on its own
// listener separate from the SSH data path.
type MetricsConfig struct {
	Listen string `yaml:"listen"` // e.g. ":9090"
}

// DrainGraceSeconds returns the rolling-upgrade drain grace period (default 30s).
func (f *File) DrainGraceSeconds() int {
	if f.DrainGrace <= 0 {
		return 30
	}
	return f.DrainGrace
}

// ApprovalConfig configures the durable four-eyes approval store.
type ApprovalConfig struct {
	StorePath  string `yaml:"store_path"`  // durable JSON file for approval requests
	TTLSeconds int    `yaml:"ttl_seconds"` // pending-request lifetime (default 900)
	UseCRD     bool   `yaml:"use_crd"`     // use the (stubbed) CRD store instead of the file store
}

// ApprovalTTL returns the configured TTL or the default.
func (a *ApprovalConfig) ApprovalTTL() int {
	if a == nil || a.TTLSeconds <= 0 {
		return 900
	}
	return a.TTLSeconds
}

// APIConfig configures the control-plane API server. It runs on a listener
// separate from the SSH data path.
type APIConfig struct {
	Listen   string      `yaml:"listen"`    // e.g. ":8443"
	TLSCert  string      `yaml:"tls_cert"`  // PEM server cert; empty ⇒ plain HTTP (dev only)
	TLSKey   string      `yaml:"tls_key"`   // PEM server key
	ClientCA string      `yaml:"client_ca"` // PEM CA to verify client certs; enables mTLS auth
	Tokens   []APIToken  `yaml:"tokens"`    // static bearer tokens (dev/OIDC stand-in)
	CNRoles  []APICNRole `yaml:"cn_roles"`  // client-cert CommonName -> role (mTLS)
}

// APIToken binds a bearer token to a subject and role.
type APIToken struct {
	Token   string `yaml:"token"`
	Subject string `yaml:"subject"`
	Role    string `yaml:"role"` // viewer | operator | admin
}

// APICNRole binds a client-certificate CommonName to a role.
type APICNRole struct {
	CN   string `yaml:"cn"`
	Role string `yaml:"role"`
}

// PolicySource selects where the policy is loaded from and hot-reloaded.
type PolicySource struct {
	File string `yaml:"file"` // policy YAML path; empty ⇒ reuse the gateway config file
}

// CyberArkConfig configures the CyberArk CCP client used by credential mode
// "inject". Authentication to CCP is mutual TLS (client cert + verified server).
type CyberArkConfig struct {
	BaseURL        string `yaml:"base_url"`         // https://ccp.example/AIMWebService
	ClientCertPath string `yaml:"client_cert"`      // PEM client cert (mTLS)
	ClientKeyPath  string `yaml:"client_key"`       // PEM client key
	CACertPath     string `yaml:"ca_cert"`          // PEM CA verifying the CCP server
	AppID          string `yaml:"app_id"`           // CyberArk application id
	Safe           string `yaml:"safe"`             // safe to query
	ObjectTemplate string `yaml:"object_template"`  // object query; {host} is replaced by the target host
	TimeoutSeconds int    `yaml:"timeout_seconds"`  //
	BreakerFails   int    `yaml:"breaker_failures"` // consecutive failures before the circuit opens
	BreakerCoolSec int    `yaml:"breaker_cooldown_seconds"`
}

// InspectionConfig configures ICAP content inspection of SFTP transfers. When
// Enabled, uploads are streamed through the ICAP service; blocked or unscannable
// content is quarantined to an Object-Locked bucket and the transfer refused.
type InspectionConfig struct {
	Enabled        bool              `yaml:"enabled"`
	ICAP           ICAPConfig        `yaml:"icap"`
	ThresholdBytes int64             `yaml:"threshold_bytes"` // files larger than this stream via the holding area
	Holding        *EvidenceS3Conf   `yaml:"holding"`         // transient (non-locked) bucket for large files
	Quarantine     *EvidenceWORMConf `yaml:"quarantine"`      // Object-Locked bucket for blocked content
}

// ICAPConfig configures the ICAP client.
type ICAPConfig struct {
	Endpoint       string `yaml:"endpoint"` // ICAP server host:port
	Service        string `yaml:"service"`  // service path, e.g. "avscan"
	PreviewBytes   int    `yaml:"preview_bytes"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

// RecordingConfig selects where interactive session recordings (asciicast) are
// stored. Exactly one of LocalDir or S3 may be set. Absent disables recording.
type RecordingConfig struct {
	LocalDir string          `yaml:"local_dir"`
	S3       *EvidenceS3Conf `yaml:"s3"`
}

// MFAConfig configures the optional second factor. When Enabled, a successful
// LDAPS primary auth is additionally gated by the configured provider.
type MFAConfig struct {
	Enabled bool          `yaml:"enabled"`
	RADIUS  *RADIUSConfig `yaml:"radius"`
}

// RADIUSConfig configures the RADIUS (MS-CHAPv2) second factor.
type RADIUSConfig struct {
	Server                    string `yaml:"server"`         // host:port
	Secret                    string `yaml:"secret"`         // shared secret
	NASIdentifier             string `yaml:"nas_identifier"` // this gateway's NAS-Identifier
	TimeoutSeconds            int    `yaml:"timeout_seconds"`
	Retries                   int    `yaml:"retries"`
	AllowInteractiveChallenge bool   `yaml:"allow_interactive_challenge"`
}

// EvidenceConfig selects the evidence backend. Exactly one of File, S3, or
// Pipeline must be set. File/S3 are the crude Slice-1 sinks; Pipeline is the
// Slice-3 ordered, hash-chained, signed-checkpoint pipeline.
type EvidenceConfig struct {
	File     string                `yaml:"file"` // JSONL path (Slice 1)
	S3       *EvidenceS3Conf       `yaml:"s3"`   // per-event S3 objects (Slice 1)
	Pipeline *EvidencePipelineConf `yaml:"pipeline"`
}

// EvidenceS3Conf configures the S3/MinIO evidence sink.
type EvidenceS3Conf struct {
	Endpoint  string `yaml:"endpoint"` // host:port, no scheme
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Bucket    string `yaml:"bucket"`
	UseSSL    bool   `yaml:"use_ssl"`
}

// EvidencePipelineConf configures the Slice-3 evidence pipeline: a local
// segment/checkpoint store plus an optional Object-Locked (WORM) S3 archive.
type EvidencePipelineConf struct {
	DataDir     string            `yaml:"data_dir"`     // local root for segments/, checkpoints/, epoch
	SigningKey  string            `yaml:"signing_key"`  // Ed25519 key path (created 0600 if absent)
	SegmentSize int               `yaml:"segment_size"` // records per segment (default 128)
	WORM        *EvidenceWORMConf `yaml:"worm"`         // optional Object-Locked archive
}

// EvidenceWORMConf configures the Object-Locked S3 archive.
type EvidenceWORMConf struct {
	Endpoint      string `yaml:"endpoint"`
	AccessKey     string `yaml:"access_key"`
	SecretKey     string `yaml:"secret_key"`
	Bucket        string `yaml:"bucket"`
	UseSSL        bool   `yaml:"use_ssl"`
	Mode          string `yaml:"mode"`           // COMPLIANCE (default) or GOVERNANCE
	RetentionDays int    `yaml:"retention_days"` // default 3650
}

// LDAPConfig configures the LDAPS bind used for authentication.
type LDAPConfig struct {
	URL          string `yaml:"url"`           // ldaps://dc1.lab.local:636
	BaseDN       string `yaml:"base_dn"`       // DC=lab,DC=local
	BindDN       string `yaml:"bind_dn"`       // service account for lookups
	BindPassword string `yaml:"bind_password"` // service account password
	UserFilter   string `yaml:"user_filter"`   // e.g. (sAMAccountName=%s)
	InsecureTLS  bool   `yaml:"insecure_tls"`  // dev only: skip cert verification
}

// PolicyConfig is the YAML shape of the policy document.
type PolicyConfig struct {
	Roles []RoleConfig `yaml:"roles"`
}

// RoleConfig binds AD groups to allow rules.
type RoleConfig struct {
	Name   string       `yaml:"name"`
	Groups []string     `yaml:"groups"`
	Allow  []RuleConfig `yaml:"allow"`
}

// RuleConfig allows ports on a host. Host "*" matches any host; empty ports
// matches any port. Record sets the recording posture for matching targets:
// "none" (default), "metadata-only", or "full". On "full" targets, port
// forwarding (-L) is refused (PRD FR-10).
type RuleConfig struct {
	Host            string `yaml:"host"`
	Ports           []int  `yaml:"ports"`
	Record          string `yaml:"record"`
	Credential      string `yaml:"credential"`       // inject | prompt | passthrough | deny (empty=passthrough)
	RequireApproval bool   `yaml:"require_approval"` // gate matching targets behind a four-eyes approval
}

// Load reads and parses the configuration file at path.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *File) validate() error {
	if f.Listen == "" {
		return fmt.Errorf("config: listen is required")
	}
	if f.HostKey == "" {
		f.HostKey = "hostkey.pem"
	}
	evCount := 0
	if f.Evidence.File != "" {
		evCount++
	}
	if f.Evidence.S3 != nil {
		evCount++
	}
	if f.Evidence.Pipeline != nil {
		evCount++
	}
	if evCount == 0 {
		return fmt.Errorf("config: one of evidence.file, evidence.s3, or evidence.pipeline is required")
	}
	if evCount > 1 {
		return fmt.Errorf("config: set only one of evidence.file, evidence.s3, or evidence.pipeline")
	}
	if p := f.Evidence.Pipeline; p != nil {
		if p.DataDir == "" {
			return fmt.Errorf("config: evidence.pipeline.data_dir is required")
		}
		if p.SigningKey == "" {
			return fmt.Errorf("config: evidence.pipeline.signing_key is required")
		}
		if p.WORM != nil {
			w := p.WORM
			if w.Endpoint == "" || w.Bucket == "" {
				return fmt.Errorf("config: evidence.pipeline.worm requires endpoint and bucket")
			}
			if w.Mode != "" && w.Mode != "COMPLIANCE" && w.Mode != "GOVERNANCE" {
				return fmt.Errorf("config: evidence.pipeline.worm.mode must be COMPLIANCE or GOVERNANCE")
			}
		}
	}
	if r := f.Recording; r != nil {
		if r.LocalDir == "" && r.S3 == nil {
			return fmt.Errorf("config: recording requires local_dir or s3")
		}
		if r.LocalDir != "" && r.S3 != nil {
			return fmt.Errorf("config: set only one of recording.local_dir or recording.s3")
		}
	}
	if in := f.Inspection; in != nil && in.Enabled {
		if in.ICAP.Endpoint == "" || in.ICAP.Service == "" {
			return fmt.Errorf("config: inspection.icap requires endpoint and service")
		}
		if in.Quarantine == nil || in.Quarantine.Endpoint == "" || in.Quarantine.Bucket == "" {
			return fmt.Errorf("config: inspection.quarantine requires endpoint and bucket")
		}
		if in.Quarantine.Mode != "" && in.Quarantine.Mode != "COMPLIANCE" && in.Quarantine.Mode != "GOVERNANCE" {
			return fmt.Errorf("config: inspection.quarantine.mode must be COMPLIANCE or GOVERNANCE")
		}
	}
	if f.MFA.Enabled {
		if f.MFA.RADIUS == nil {
			return fmt.Errorf("config: mfa.enabled requires an mfa.radius block")
		}
		if f.MFA.RADIUS.Server == "" || f.MFA.RADIUS.Secret == "" {
			return fmt.Errorf("config: mfa.radius requires server and secret")
		}
	}
	if f.FIPS != nil {
		if _, err := fips.ParseMode(f.FIPS.Mode); err != nil {
			return err
		}
	}
	if err := validatePolicyRoles(f.Policy.Roles); err != nil {
		return err
	}
	usesInject := false
	usesApproval := false
	for _, r := range f.Policy.Roles {
		for _, rule := range r.Allow {
			if rule.Credential == "inject" {
				usesInject = true
			}
			if rule.RequireApproval {
				usesApproval = true
			}
		}
	}
	if usesInject {
		if f.CyberArk == nil {
			return fmt.Errorf("config: a rule uses credential \"inject\" but no cyberark block is configured")
		}
		if f.CyberArk.BaseURL == "" || f.CyberArk.ClientCertPath == "" || f.CyberArk.ClientKeyPath == "" {
			return fmt.Errorf("config: cyberark requires base_url, client_cert, and client_key for inject")
		}
	}
	if usesApproval {
		if f.Approval == nil {
			return fmt.Errorf("config: a rule sets require_approval but no approval block is configured")
		}
		if !f.Approval.UseCRD && f.Approval.StorePath == "" {
			return fmt.Errorf("config: approval requires store_path (or use_crd)")
		}
	}
	return nil
}

// validatePolicyRoles rejects semantically-invalid policy roles (empty name,
// empty host, unknown record/credential). It is shared by boot-time validate()
// and the hot-reload path so a parseable-but-invalid policy edit is rejected
// (keeping the last good policy) rather than silently normalized — e.g. an
// invalid record value must NOT downgrade to RecordNone and re-enable
// forwarding on a full-recording target (FR-10).
func validatePolicyRoles(roles []RoleConfig) error {
	for _, r := range roles {
		if r.Name == "" {
			return fmt.Errorf("config: role with empty name")
		}
		for _, rule := range r.Allow {
			if rule.Host == "" {
				return fmt.Errorf("config: role %q has a rule with empty host", r.Name)
			}
			switch rule.Record {
			case "", "none", "metadata-only", "full":
			default:
				return fmt.Errorf("config: role %q rule for %q has invalid record %q (want none|metadata-only|full)", r.Name, rule.Host, rule.Record)
			}
			switch rule.Credential {
			case "", "passthrough", "prompt", "deny", "inject":
			default:
				return fmt.Errorf("config: role %q rule for %q has invalid credential %q (want inject|prompt|passthrough|deny)", r.Name, rule.Host, rule.Credential)
			}
		}
	}
	return nil
}

// CompilePolicyBytes parses, validates, and compiles the policy section of a
// YAML document. The control-plane hot-reload path uses it so a bad edit is
// rejected (last good policy stays in force) instead of silently applied.
func CompilePolicyBytes(data []byte) (policy.Policy, error) {
	var doc struct {
		Policy PolicyConfig `yaml:"policy"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return policy.Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := validatePolicyRoles(doc.Policy.Roles); err != nil {
		return policy.Policy{}, err
	}
	return (&File{Policy: doc.Policy}).CompilePolicy(), nil
}

// CompilePolicy builds the immutable policy.Policy from the config document.
// LoadPolicyDoc reads only the policy section of a YAML document, validates it,
// and compiles it. The control-plane policy source uses it to hot-reload.
func LoadPolicyDoc(path string) (policy.Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return policy.Policy{}, fmt.Errorf("read policy %s: %w", path, err)
	}
	return CompilePolicyBytes(raw)
}

func (f *File) CompilePolicy() policy.Policy {
	roles := make([]policy.Role, 0, len(f.Policy.Roles))
	for _, rc := range f.Policy.Roles {
		rules := make([]policy.Rule, 0, len(rc.Allow))
		for _, ru := range rc.Allow {
			rules = append(rules, policy.Rule{
				Host:            ru.Host,
				Ports:           ru.Ports,
				Record:          policy.RecordMode(ru.Record).Normalize(),
				Credential:      ru.Credential,
				RequireApproval: ru.RequireApproval,
			})
		}
		roles = append(roles, policy.Role{Name: rc.Name, Groups: rc.Groups, Allow: rules})
	}
	return policy.Policy{Roles: roles}
}
