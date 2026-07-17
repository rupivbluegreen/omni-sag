package policy

// Property coverage for CIDR rule matching, mirroring policy_prop_test.go's
// independent-reference-implementation approach but scoped to the new
// behavior: a CIDR rule matched via a resolved hostname must always agree
// with the same rule matched via the resolver's raw IP output.

import (
	"net"
	"testing"

	"pgregory.net/rapid"
)

var cidrPool = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

func genCIDRRule(t *rapid.T) Rule {
	cidr := rapid.SampledFrom(cidrPool).Draw(t, "ruleCIDR")
	ports := rapid.SliceOfN(rapid.SampledFrom(portPool), 0, 2).Draw(t, "ruleCIDRPorts")
	return Rule{Host: cidr, Ports: ports}
}

// genIPIn returns a random IP inside n (fixed host bits so the address always
// falls in range regardless of the CIDR's prefix length in cidrPool).
func genIPIn(t *rapid.T, n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	last := rapid.IntRange(1, 254).Draw(t, "lastOctet")
	ip[len(ip)-1] = byte(last)
	return ip
}

// TestProp_CIDRResolvedHostnameMatchesLikeLiteralIP: a CIDR rule granting a
// literal IP must equally grant a hostname that resolves to that same IP —
// the resolution path and the literal-IP path must agree.
func TestProp_CIDRResolvedHostnameMatchesLikeLiteralIP(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rule := genCIDRRule(t)
		n, ok := rule.cidr()
		if !ok {
			t.Fatal("genCIDRRule produced a non-CIDR Host")
		}
		ip := genIPIn(t, n)
		port := rapid.SampledFrom(portPool).Draw(t, "port")

		p := Policy{Roles: []Role{{Name: "r", Groups: []string{"g"}, Allow: []Rule{rule}}}}
		pr := Principal{User: "x", Groups: []string{"g"}}

		literal := p.Decide(pr, Target{Host: ip.String(), Port: port}, nil)
		resolved := p.Decide(pr, Target{Host: "some.host.name", Port: port}, func(string) ([]net.IP, error) {
			return []net.IP{ip}, nil
		})
		if literal.Allow != resolved.Allow {
			t.Fatalf("literal-IP Allow=%v but resolved-hostname Allow=%v for the same IP %s (rule=%+v port=%d)",
				literal.Allow, resolved.Allow, ip, rule, port)
		}
	})
}

// TestProp_CIDRPartialMultiIPNeverAllows: whenever a hostname resolves to 2+
// IPs and at least one falls OUTSIDE every held CIDR rule's range, the
// decision must never be Allow — partial coverage is always a deny.
func TestProp_CIDRPartialMultiIPNeverAllows(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rule := genCIDRRule(t)
		n, ok := rule.cidr()
		if !ok {
			t.Fatal("genCIDRRule produced a non-CIDR Host")
		}
		inRange := genIPIn(t, n)
		outOfRange := net.ParseIP("203.0.113.1") // TEST-NET-3, never in cidrPool's ranges
		port := rapid.SampledFrom(portPool).Draw(t, "port")

		p := Policy{Roles: []Role{{Name: "r", Groups: []string{"g"}, Allow: []Rule{rule}}}}
		pr := Principal{User: "x", Groups: []string{"g"}}

		d := p.Decide(pr, Target{Host: "mixed.host.name", Port: port}, func(string) ([]net.IP, error) {
			return []net.IP{inRange, outOfRange}, nil
		})
		if d.Allow {
			t.Fatalf("a hostname with one IP outside the matched rule's range must never be allowed, got Allow=true (rule=%+v)", rule)
		}
	})
}
