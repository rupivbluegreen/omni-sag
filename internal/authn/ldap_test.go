package authn

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestGroupCNsFromMemberOf(t *testing.T) {
	in := []string{
		"CN=dba,OU=Groups,DC=lab,DC=local",
		"CN=Domain Users,CN=Users,DC=lab,DC=local",
		"OU=weird,DC=lab,DC=local", // no leading CN -> skipped
		"not a dn",                 // unparseable -> skipped
	}
	got := groupCNsFromMemberOf(in)
	want := []string{"dba", "Domain Users"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestGroupCNsFromMemberOf_Empty(t *testing.T) {
	if got := groupCNsFromMemberOf(nil); len(got) != 0 {
		t.Fatalf("expected no groups, got %v", got)
	}
}

func TestAuthenticate_EmptyPasswordRejected(t *testing.T) {
	a := NewLDAP(LDAPConfig{URL: "ldaps://127.0.0.1:636", BaseDN: "DC=lab,DC=local"})
	_, err := a.Authenticate(context.Background(), "alice", "")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("empty password must be rejected with ErrAuth, got %v", err)
	}
}
