package session

import "testing"

func TestSplitTargetUser(t *testing.T) {
	cases := []struct {
		raw            string
		wantUser       string
		wantTarget     string
		wantHasTarget  bool
	}{
		{"alice", "alice", "", false},
		{"alice%db1.lab.local", "alice", "db1.lab.local", true},
		{"alice%db1.lab.local%extra", "alice", "db1.lab.local%extra", true}, // only first % splits
		{"%db1.lab.local", "", "db1.lab.local", true},
		{"alice%", "alice", "", true},
	}
	for _, c := range cases {
		u, h, ok := splitTargetUser(c.raw)
		if u != c.wantUser || h != c.wantTarget || ok != c.wantHasTarget {
			t.Errorf("splitTargetUser(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.raw, u, h, ok, c.wantUser, c.wantTarget, c.wantHasTarget)
		}
	}
}
