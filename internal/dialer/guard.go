package dialer

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ErrBlockedAddress is returned when the address the OS actually resolved a
// target to falls in a range that is never a legitimate session target for a
// bastion (loopback, link-local — which includes the cloud metadata IP
// 169.254.169.254 — the unspecified address, multicast, or broadcast).
//
// This is the SSRF / DNS-rebinding guard: policy authorizes the *host string*,
// but the socket is opened to the *resolved IP*. A policy-allowed name that
// resolves (or is rebound) to an internal/special address must not be reached.
var ErrBlockedAddress = errors.New("dialer: resolved address blocked (SSRF guard)")

// dialControlFunc is the signature of net.Dialer.Control: it runs after
// resolution, before connect, on the concrete address about to be dialed.
type dialControlFunc = func(network, address string, c syscall.RawConn) error

// WithLoopbackTargetsAllowed relaxes the resolved-address guard to permit
// loopback (127.0.0.0/8, ::1) targets. It exists for test/dev harnesses that
// run the target service on the bastion's own loopback; production deployments
// must NOT use it. Even relaxed, the guard still blocks the dangerous ranges
// (link-local incl. cloud metadata 169.254.169.254, unspecified, multicast,
// broadcast) — loopback is the only additional address permitted.
func WithLoopbackTargetsAllowed() Option {
	return func(d *Dialer) { d.dialControl = guardResolvedAddrAllowLoopback }
}

// guardResolvedAddrAllowLoopback is the relaxed guard (see
// WithLoopbackTargetsAllowed): identical to guardResolvedAddr but loopback is
// permitted.
func guardResolvedAddrAllowLoopback(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return guardResolvedAddr(network, address, c)
}

// guardResolvedAddr is installed as net.Dialer.Control so it runs AFTER the
// resolver has produced a concrete IP and BEFORE the socket connects. Running
// at this point closes the classic TOCTOU / DNS-rebinding gap: whatever the
// resolver returned — including each address when a name has several A/AAAA
// records, and whatever a rebinding attacker swapped in — is the exact address
// validated here, because it is the exact address about to be dialed.
//
// It fails closed: an unparseable address, or any address in a blocked range,
// aborts the connection.
//
// DESIGN DECISION (documented, proportionate): a bastion's entire purpose is to
// reach internal hosts, so RFC1918 private ranges (10/8, 172.16/12, 192.168/16)
// and CGNAT (100.64/10) are NOT blocked here — the lab targets and real
// enterprise targets live there. What is blocked is the set of ranges that are
// never a legitimate remote session target and are the actual SSRF payloads:
// loopback (reach the bastion itself), link-local (cloud metadata credential
// theft at 169.254.169.254), the unspecified address, and multicast/broadcast.
// IPv4-mapped IPv6 forms (e.g. ::ffff:169.254.169.254, ::ffff:127.0.0.1) are
// normalized and classified the same as their IPv4 originals so they cannot be
// used to smuggle a blocked address past the guard.
func guardResolvedAddr(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// No port form we recognize — fail closed rather than dial blind.
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: %s %q resolved to an unparseable address", ErrBlockedAddress, network, address)
	}
	if blocked, reason := blockedIP(ip); blocked {
		return fmt.Errorf("%w: %s -> %s (%s)", ErrBlockedAddress, address, ip, reason)
	}
	return nil
}

// blockedIP classifies an already-resolved IP. It normalizes IPv4-mapped IPv6
// to its IPv4 form first so mapped encodings of a blocked address are caught.
// It returns the reason for observability. Private/CGNAT ranges are allowed on
// purpose (see guardResolvedAddr): they are the bastion's legitimate targets.
func blockedIP(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "nil address"
	}
	// Normalize ::ffff:a.b.c.d to a.b.c.d so the IPv4 predicates below apply.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	switch {
	case ip.IsUnspecified():
		// 0.0.0.0 / :: — connecting here is undefined and a common SSRF bypass.
		return true, "unspecified address"
	case ip.IsLoopback():
		// 127.0.0.0/8, ::1 — reaches the bastion itself.
		return true, "loopback"
	case ip.IsLinkLocalUnicast():
		// 169.254.0.0/16 (incl. the 169.254.169.254 cloud metadata service),
		// fe80::/10 — credential-theft SSRF target.
		return true, "link-local (includes cloud metadata 169.254.169.254)"
	case ip.IsLinkLocalMulticast():
		return true, "link-local multicast"
	case ip.IsInterfaceLocalMulticast():
		return true, "interface-local multicast"
	case ip.IsMulticast():
		// 224.0.0.0/4, ff00::/8 — not a unicast session target.
		return true, "multicast"
	case ip.Equal(net.IPv4bcast):
		// 255.255.255.255 — limited broadcast.
		return true, "broadcast"
	default:
		return false, ""
	}
}
