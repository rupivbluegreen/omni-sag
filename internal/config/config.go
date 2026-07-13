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

// EvidenceConfig selects the evidence sink. Exactly one of File or S3 must be
// set. Slice 3 replaces this with the full evidence pipeline.
type EvidenceConfig struct {
	File string          `yaml:"file"` // JSONL path
	S3   *EvidenceS3Conf `yaml:"s3"`
}

// EvidenceS3Conf configures the S3/MinIO evidence sink.
type EvidenceS3Conf struct {
	Endpoint  string `yaml:"endpoint"` // host:port, no scheme
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Bucket    string `yaml:"bucket"`
	UseSSL    bool   `yaml:"use_ssl"`
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
	if f.Evidence.File == "" && f.Evidence.S3 == nil {
		return fmt.Errorf("config: evidence.file or evidence.s3 is required")
	}
	if f.Evidence.File != "" && f.Evidence.S3 != nil {
		return fmt.Errorf("config: set only one of evidence.file or evidence.s3")
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
