package credential

import (
	"net"
	"strings"
	"time"
)

// CyberArkParams configures credential injection from CyberArk. Plain types
// so callers (cmd, internal/dialer, internal/session) need not import the CCP
// client type directly.
type CyberArkParams struct {
	BaseURL, ClientCert, ClientKey, CACert string
	AppID, Safe, ObjectTemplate            string
	TimeoutSeconds                         int
	BreakerFailures                        int
	BreakerCooldownSeconds                 int
}

// NewCyberArkProvider builds a Provider that resolves inject-mode secrets
// from CyberArk CCP over mTLS. Errors on bad certs. The returned Provider is
// safe to share between internal/dialer (tunnel targets) and
// internal/session (real-target shell/SFTP second-leg auth) — CyberArk is
// queried by (host, safe, object), which is identical for both call sites.
func NewCyberArkProvider(p CyberArkParams) (*Provider, error) {
	ccp, err := NewCCPClient(CCPConfig{
		BaseURL:        p.BaseURL,
		ClientCertPath: p.ClientCert,
		ClientKeyPath:  p.ClientKey,
		CACertPath:     p.CACert,
		Timeout:        time.Duration(p.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	appID, safe, tmpl := p.AppID, p.Safe, p.ObjectTemplate
	query := func(req Request) Query {
		host := req.Target
		if h, _, err := net.SplitHostPort(req.Target); err == nil {
			host = h
		}
		return Query{AppID: appID, Safe: safe, Object: strings.ReplaceAll(tmpl, "{host}", host)}
	}
	breaker := NewBreaker(BreakerConfig{
		Threshold: p.BreakerFailures,
		Cooldown:  time.Duration(p.BreakerCooldownSeconds) * time.Second,
	})
	return NewProvider(Config{Fetcher: ccp, Query: query, Breaker: breaker}), nil
}
