// Package config loads the gateway configuration and compiles the policy
// document into an immutable policy.Policy. In Slice 1 the policy is a YAML
// file read once at boot; later slices replace this with CRDs.
package config

import (
	"fmt"
	"os"

	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"gopkg.in/yaml.v3"
)

// File is the on-disk configuration document.
type File struct {
	Listen   string         `yaml:"listen"`   // SSH listen address, e.g. ":2222"
	HostKey  string         `yaml:"host_key"` // path to the SSH host key (created if absent)
	LDAP     LDAPConfig     `yaml:"ldap"`
	MFA      MFAConfig      `yaml:"mfa"`
	Evidence EvidenceConfig `yaml:"evidence"`
	Policy   PolicyConfig   `yaml:"policy"`
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
// matches any port.
type RuleConfig struct {
	Host  string `yaml:"host"`
	Ports []int  `yaml:"ports"`
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
	if f.MFA.Enabled {
		if f.MFA.RADIUS == nil {
			return fmt.Errorf("config: mfa.enabled requires an mfa.radius block")
		}
		if f.MFA.RADIUS.Server == "" || f.MFA.RADIUS.Secret == "" {
			return fmt.Errorf("config: mfa.radius requires server and secret")
		}
	}
	for _, r := range f.Policy.Roles {
		if r.Name == "" {
			return fmt.Errorf("config: role with empty name")
		}
		for _, rule := range r.Allow {
			if rule.Host == "" {
				return fmt.Errorf("config: role %q has a rule with empty host", r.Name)
			}
		}
	}
	return nil
}

// CompilePolicy builds the immutable policy.Policy from the config document.
func (f *File) CompilePolicy() policy.Policy {
	roles := make([]policy.Role, 0, len(f.Policy.Roles))
	for _, rc := range f.Policy.Roles {
		rules := make([]policy.Rule, 0, len(rc.Allow))
		for _, ru := range rc.Allow {
			rules = append(rules, policy.Rule{Host: ru.Host, Ports: ru.Ports})
		}
		roles = append(roles, policy.Role{Name: rc.Name, Groups: rc.Groups, Allow: rules})
	}
	return policy.Policy{Roles: roles}
}
