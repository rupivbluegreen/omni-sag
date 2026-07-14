package dialer

import (
	"errors"
	"net"
	"testing"
)

// TestBlockedIP_AdversarialForms enumerates the SSRF payload addresses an
// attacker would try to reach via a policy-allowed hostname that resolves (or
// is rebound) to them, plus the legitimate targets that must stay reachable.
func TestBlockedIP_AdversarialForms(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// Cloud metadata credential-theft target — the headline SSRF payload.
		{"metadata-ipv4", "169.254.169.254", true},
		{"metadata-ipv4-mapped-ipv6", "::ffff:169.254.169.254", true},
		{"metadata-ipv6-hex-form", "::ffff:a9fe:a9fe", true}, // same 169.254.169.254

		// Loopback — reach the bastion itself.
		{"loopback-127.0.0.1", "127.0.0.1", true},
		{"loopback-127.x", "127.1.2.3", true},
		{"loopback-ipv6", "::1", true},
		{"loopback-ipv4-mapped", "::ffff:127.0.0.1", true},

		// Unspecified — undefined connect / common bypass.
		{"unspecified-ipv4", "0.0.0.0", true},
		{"unspecified-ipv6", "::", true},
		{"unspecified-ipv4-mapped", "::ffff:0.0.0.0", true},

		// Link-local (non-metadata) and IPv6 link-local.
		{"link-local-ipv4", "169.254.10.20", true},
		{"link-local-ipv6", "fe80::1", true},

		// Multicast / broadcast — not unicast session targets.
		{"multicast-ipv4", "224.0.0.1", true},
		{"multicast-ipv6", "ff02::1", true},
		{"broadcast", "255.255.255.255", true},

		// Legitimate bastion targets — private ranges MUST stay reachable, that
		// is the whole point of the bastion. These are deliberately allowed.
		{"lab-docker-172", "172.18.0.5", false},
		{"private-10", "10.0.0.5", false},
		{"private-192", "192.168.1.10", false},
		{"cgnat-100.64", "100.64.0.1", false},
		{"public-ipv4", "93.184.216.34", false},
		{"public-ipv6", "2606:2800:220:1:248:1893:25c8:1946", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host := c.ip
			if h, _, err := net.SplitHostPort(c.ip); err == nil {
				host = h // strip brackets from "[...]"
			}
			ip := net.ParseIP(host)
			if ip == nil {
				t.Fatalf("could not parse %q", c.ip)
			}
			got, reason := blockedIP(ip)
			if got != c.blocked {
				t.Fatalf("blockedIP(%s) = %v (%q), want blocked=%v", c.ip, got, reason, c.blocked)
			}
		})
	}
}

// TestGuardResolvedAddr_FailsClosed checks the net.Dialer.Control hook itself:
// a blocked resolved address returns ErrBlockedAddress, an allowed one returns
// nil, and a malformed address fails closed rather than dialing blind.
func TestGuardResolvedAddr_FailsClosed(t *testing.T) {
	if err := guardResolvedAddr("tcp", "169.254.169.254:80", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("metadata IP must be blocked, got %v", err)
	}
	if err := guardResolvedAddr("tcp", "127.0.0.1:22", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("loopback must be blocked, got %v", err)
	}
	if err := guardResolvedAddr("tcp", "[::ffff:169.254.169.254]:80", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("ipv4-mapped metadata must be blocked, got %v", err)
	}
	if err := guardResolvedAddr("tcp", "172.18.0.5:5432", nil); err != nil {
		t.Fatalf("a private lab target must be allowed, got %v", err)
	}
	if err := guardResolvedAddr("tcp", "not-an-ip", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("unparseable address must fail closed, got %v", err)
	}
}

// FuzzGuardResolvedAddr asserts the guard never panics on arbitrary address
// strings AND upholds the invariant that any address the standard library
// classifies as loopback / link-local / unspecified / multicast is refused —
// i.e. no crafted encoding slips a special-range address past the guard.
func FuzzGuardResolvedAddr(f *testing.F) {
	for _, s := range []string{
		"127.0.0.1:22", "169.254.169.254:80", "::1", "[::ffff:7f00:1]:443",
		"0.0.0.0:1", "10.0.0.1:5432", "example:22", "", "[::]:0", "224.0.0.1:9",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, address string) {
		err := guardResolvedAddr("tcp", address, nil) // must not panic

		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			host = address
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return // unparseable ⇒ guard fails closed; nothing more to check
		}
		special := ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
			ip.IsMulticast() || ip.IsUnspecified() || ip.Equal(net.IPv4bcast)
		if special && !errors.Is(err, ErrBlockedAddress) {
			t.Fatalf("special-range address %q (%s) was NOT blocked: err=%v", address, ip, err)
		}
	})
}
