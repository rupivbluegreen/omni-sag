package credential

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
	"unicode/utf8"
)

// Query identifies the account to fetch from CyberArk.
type Query struct {
	AppID  string
	Safe   string
	Object string
}

// CCPConfig configures the CyberArk Central Credential Provider client.
type CCPConfig struct {
	BaseURL        string // https://ccp.example/AIMWebService
	ClientCertPath string // PEM client cert (mTLS gateway identity)
	ClientKeyPath  string // PEM client key
	CACertPath     string // PEM CA that must sign the CCP server cert (no InsecureSkipVerify)
	Timeout        time.Duration
}

// CCPClient fetches secrets from CyberArk CCP over HTTPS with mutual TLS. The
// http.Client dials the operator-configured endpoint internally, so no raw
// target dialing happens here (the single-target-dialer invariant is preserved).
type CCPClient struct {
	base   string
	client *http.Client
}

// NewCCPClient builds a client. It requires a client cert/key (mTLS) and a CA to
// verify the server; production must not skip verification.
func NewCCPClient(cfg CCPConfig) (*CCPClient, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("ccp: base url required")
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("ccp: client cert: %w", err)
	}
	pool := x509.NewCertPool()
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("ccp: ca cert: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ccp: ca cert: no certificates parsed")
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &CCPClient{
		base: cfg.BaseURL,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					RootCAs:      pool,
					MinVersion:   tls.VersionTLS12,
				},
			},
		},
	}, nil
}

// FetchWithClient lets tests inject an http.Client (e.g. one pinned to a mock
// CCP's TLS). Production uses NewCCPClient.
func FetchWithClient(base string, client *http.Client) *CCPClient {
	return &CCPClient{base: base, client: client}
}

// Fetch retrieves the account content as a Secret. The password is extracted
// into a []byte WITHOUT an intermediate Go string (json.RawMessage + manual
// unquote), and the response buffer is zeroized.
func (c *CCPClient) Fetch(ctx context.Context, q Query) (*Secret, error) {
	u := c.base + "/api/Accounts?" + url.Values{
		"AppID":  {q.AppID},
		"Safe":   {q.Safe},
		"Object": {q.Object},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	defer zero(body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ccp: status %d", resp.StatusCode)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("ccp: decode: %w", err)
	}
	raw, ok := fields["Content"]
	if !ok {
		return nil, fmt.Errorf("ccp: response missing Content")
	}
	secretBytes, err := jsonUnquote(raw)
	if err != nil {
		return nil, fmt.Errorf("ccp: content decode: %w", err)
	}
	return New(secretBytes), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// jsonUnquote decodes a JSON string token (with surrounding quotes) into a fresh
// []byte, handling the standard escapes. It avoids strconv.Unquote so the secret
// never becomes a Go string. (Surrogate pairs in \u escapes are not combined —
// acceptable for credential material; documented limitation.)
func jsonUnquote(raw []byte) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, fmt.Errorf("not a JSON string")
	}
	s := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(s) {
			return nil, fmt.Errorf("truncated escape")
		}
		switch s[i] {
		case '"':
			out = append(out, '"')
		case '\\':
			out = append(out, '\\')
		case '/':
			out = append(out, '/')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'u':
			if i+4 >= len(s) {
				return nil, fmt.Errorf("truncated \\u escape")
			}
			var r rune
			for k := 0; k < 4; k++ {
				d := s[i+1+k]
				r <<= 4
				switch {
				case d >= '0' && d <= '9':
					r |= rune(d - '0')
				case d >= 'a' && d <= 'f':
					r |= rune(d-'a') + 10
				case d >= 'A' && d <= 'F':
					r |= rune(d-'A') + 10
				default:
					return nil, fmt.Errorf("bad hex in \\u escape")
				}
			}
			i += 4
			out = utf8.AppendRune(out, r)
		default:
			return nil, fmt.Errorf("bad escape \\%c", s[i])
		}
	}
	return out, nil
}
