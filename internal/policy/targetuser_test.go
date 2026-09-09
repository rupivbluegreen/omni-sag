package policy

import (
	"errors"
	"testing"
)

func TestResolveTargetUser(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		decision  Decision
		loginUser string
		want      string
		wantDeny  bool
	}{
		{
			name:      "rule pins, client asks for a different account",
			requested: "user01", loginUser: "alice",
			decision: Decision{TargetUser: "svc_db1", CredentialMode: "prompt"},
			wantDeny: true,
		},
		{
			name:      "rule pins, client asks for nothing",
			requested: "", loginUser: "alice",
			decision: Decision{TargetUser: "svc_db1", CredentialMode: "prompt"},
			want:     "svc_db1",
		},
		{
			name:      "rule pins, client asks for the same account",
			requested: "svc_db1", loginUser: "alice",
			decision: Decision{TargetUser: "svc_db1", CredentialMode: "prompt"},
			want:     "svc_db1",
		},
		{
			name:      "no rule account, client asks, listed",
			requested: "user01", loginUser: "alice",
			decision: Decision{CredentialMode: "prompt", AllowTargetUsers: []string{"user01", "user02"}},
			want:     "user01",
		},
		{
			name:      "no rule account, client asks, wildcard",
			requested: "user01", loginUser: "alice",
			decision: Decision{CredentialMode: "passthrough", AllowTargetUsers: []string{"*"}},
			want:     "user01",
		},
		{
			name:      "no rule account, client asks, not listed",
			requested: "root", loginUser: "alice",
			decision: Decision{CredentialMode: "prompt", AllowTargetUsers: []string{"user01"}},
			wantDeny: true,
		},
		{
			name:      "no rule account, client asks, empty allow-list",
			requested: "user01", loginUser: "alice",
			decision: Decision{CredentialMode: "prompt"},
			wantDeny: true,
		},
		{
			name:      "inject mode, client asks, even when listed",
			requested: "user01", loginUser: "alice",
			decision: Decision{CredentialMode: "inject", AllowTargetUsers: []string{"user01"}},
			wantDeny: true,
		},
		{
			name:      "inject mode, client names the rule's own account",
			requested: "svc_db1", loginUser: "alice",
			decision: Decision{TargetUser: "svc_db1", CredentialMode: "inject"},
			want:     "svc_db1",
		},
		{
			name:      "deny mode, client asks",
			requested: "user01", loginUser: "alice",
			decision: Decision{CredentialMode: "deny", AllowTargetUsers: []string{"user01"}},
			wantDeny: true,
		},
		{
			name:      "neither",
			requested: "", loginUser: "alice",
			decision: Decision{CredentialMode: "prompt"},
			want:     "alice",
		},
		{
			name:      "empty credential mode is passthrough",
			requested: "user01", loginUser: "alice",
			decision: Decision{AllowTargetUsers: []string{"user01"}},
			want:     "user01",
		},
		{
			name:      "allow-list match is exact, not case-folded",
			requested: "User01", loginUser: "alice",
			decision: Decision{CredentialMode: "prompt", AllowTargetUsers: []string{"user01"}},
			wantDeny: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ResolveTargetUser(c.requested, c.decision, c.loginUser)
			if c.wantDeny {
				if !errors.Is(err, ErrTargetUserDenied) {
					t.Fatalf("got (%q, %v), want an error wrapping ErrTargetUserDenied", got, err)
				}
				if got != "" {
					t.Fatalf("got user %q on denial, want empty (no silent downgrade)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("got err %v, want nil", err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestDecide_CarriesAllowTargetUsers(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "db1.lab.local", Credential: "prompt", AllowTargetUsers: []string{"user01"}}},
	}}}
	d := p.Decide(Principal{User: "alice", Groups: []string{"dba"}}, Target{Host: "db1.lab.local", Port: 22}, nil)
	if !d.Allow || len(d.AllowTargetUsers) != 1 || d.AllowTargetUsers[0] != "user01" {
		t.Fatalf("got Allow=%v AllowTargetUsers=%v, want true [user01]", d.Allow, d.AllowTargetUsers)
	}
}

func TestDecideHost_CarriesAllowTargetUsers(t *testing.T) {
	p := Policy{Roles: []Role{{
		Name:   "dba",
		Groups: []string{"dba"},
		Allow:  []Rule{{Host: "db1.lab.local", Ports: []int{2200}, Credential: "prompt", AllowTargetUsers: []string{"user01"}}},
	}}}
	d := p.DecideHost(Principal{User: "alice", Groups: []string{"dba"}}, "db1.lab.local", nil)
	if !d.Allow || len(d.AllowTargetUsers) != 1 || d.AllowTargetUsers[0] != "user01" {
		t.Fatalf("got Allow=%v AllowTargetUsers=%v, want true [user01]", d.Allow, d.AllowTargetUsers)
	}
}
