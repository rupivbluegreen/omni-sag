# CIDR policy rules — design

**Status:** Approved (brainstorming), not yet implemented
**Date:** 2026-07-17

## Context

`internal/policy.Rule.Host` (`internal/policy/policy.go:65`) matches exactly
one of two shapes today: `"*"` (any host) or an exact case-insensitive string
(`Rule.matches`, `Rule.matchesHost`). Every allow rule that wants to cover a
range of addresses — a subnet, a VPC, a docker bridge — has to be written out
host by host. This design adds CIDR notation as a third `Host` shape, used by
both `Decide` (the `-L` forwarding path, host+port) and `DecideHost` (the
real-target shell/SFTP path, host-only, requires unambiguous single-rule/
single-port resolution — `policy.go:209-238`).

The policy evaluator is documented as pure — "inputs -> decision... must not
import internal/session, so the evaluator remains property-testable"
(`policy.go:1-4`). CIDR matching against an IP-literal target preserves that
trivially. CIDR matching against a *hostname* target does not: a CIDR range
means nothing until the hostname resolves to an IP, and resolution is I/O.
This design keeps `Decide`/`DecideHost` pure by making resolution an injected
function parameter rather than hidden state, and treats the resulting
TOCTOU between policy-decision-time resolution and connect-time resolution
as a first-class problem, not an afterthought — see "Rebind defense" below.

## Rule syntax

No new YAML field. `RuleConfig.Host` / `Rule.Host` accepts, in order of
precedence at match time:

1. `"*"` — any host (unchanged)
2. exact string, case-insensitive (unchanged)
3. CIDR notation (e.g. `"10.0.0.0/8"`) — new

Shape is detected once, at policy-compile time in `internal/config`, via
`net.ParseCIDR`. A `Rule` stores the parsed `*net.IPNet` alongside the raw
string so matching never re-parses per request.

## Matching semantics

**IP-literal targets** (`target.Host` / `DecideHost`'s `host` parameter parses
as a valid IP): match directly against the CIDR via `IPNet.Contains`. No
resolution, no new failure mode — same cost as today's exact-string compare.

**Hostname targets**: cheap-first order.

1. Try exact-string / `"*"` rules first — today's behavior, zero I/O. If one
   matches, done; CIDR rules are never consulted.
2. Only if no exact/wildcard rule matched, and at least one CIDR rule exists
   among the principal's roles, resolve the hostname via the injected
   `ResolverFunc` and check membership.

This means policies with no CIDR rules never do DNS, and hostnames that
already resolve via an exact rule never do DNS either.

**Multi-IP fail-closed rule**: if resolution returns more than one IP, ALL
of them must fall inside the *same single* matching CIDR rule. Partial match
(some IPs in range, some not) or a split across two different CIDR rules is
ambiguous and denies, with a `Reason` explaining why — the same fail-closed
posture `DecideHost` already applies to multi-rule host matches
(`policy.go:225-231`).

## Keeping the evaluator testable

`Policy` stays a plain value (`Roles []Role`, unchanged) — no resolver field,
so hot-reload via `internal/policysource` needs no new wiring. Instead,
`Decide` and `DecideHost` take the resolver as a parameter:

```go
type ResolverFunc func(host string) ([]net.IP, error)

func (p Policy) Decide(pr Principal, t Target, resolve ResolverFunc) Decision
func (p Policy) DecideHost(pr Principal, host string, resolve ResolverFunc) Decision
```

Real callers (`internal/dialer.DialTarget`, `Peek`, `PeekHost`) pass a
`net.Resolver`-backed function, or a no-op ("no match") function when the
config toggle below is off. Property tests (`pgregory.net/rapid`, existing
dep) pass a fake deterministic resolver — fuzzing CIDR ranges and resolved-IP
sets stays fully deterministic, just parameterized instead of I/O-free.

Call sites needing updates: `internal/dialer/dialer.go` (`DialTarget`,
`Peek`, `PeekHost`), and every existing test that calls `Decide`/`DecideHost`
directly.

## Config toggle

New `PolicyConfig` field:

```go
type PolicyConfig struct {
	Roles                   []RoleConfig `yaml:"roles"`
	ResolveHostnamesForCIDR *bool        `yaml:"resolve_hostnames_for_cidr"` // default true
}
```

Default **true** (resolve). When `false`, the dialer wires a resolver that
always reports no match for non-IP-literal hosts — CIDR rules silently
degrade to IP-literal-only matching; hostnames still work normally against
exact/`"*"` rules. Documented in `deploy/compose/config.example.yaml`,
matching the existing every-field-documented convention.

## Rebind defense

Policy resolves once, at decision time. The actual connection resolves again,
independently, later — inside `netDial`'s `net.Dialer.Control` callback
(`internal/dialer/dialer.go:46-54`), which today runs `guardResolvedAddr` for
the SSRF/loopback checks. Between those two resolutions, DNS can rebind to an
IP outside the approved CIDR (attacker-controlled DNS, low TTL). Without a
second check, CIDR enforcement against hostname targets would be real only at
decision time and theoretical at connect time.

Fix: `Decision` gains a field carrying the matched rule's `*net.IPNet` when
the matching rule was CIDR-shaped (nil otherwise). `DialTarget` threads it
into the `Control` callback for that specific connection attempt, so
`guardResolvedAddr` re-validates the IP it is about to connect to against the
same range the policy decision was based on — in addition to, not instead of,
the existing static SSRF blocklist checks.

## Testing plan

- `internal/policy`: table + property tests for CIDR `Rule.matches` /
  `matchesHost` — IP-literal in/out of range, hostname resolving to one IP
  in/out of range, multi-IP all-in-range, multi-IP partial (must deny),
  multi-IP split across two CIDR rules (must deny), CIDR rule alongside an
  exact-string rule for the same role (exact takes precedence per the
  cheap-first order), resolver returning an error (must deny, fail-closed,
  not fail-open).
- `internal/config`: `net.ParseCIDR` shape-detection at load (valid CIDR,
  malformed CIDR string treated as literal host vs. rejected — pick reject,
  loud config error beats silently falling back to exact-string match on a
  typo'd CIDR), `resolve_hostnames_for_cidr` default-true when omitted from
  YAML.
- `internal/dialer`: rebind-defense integration test — policy resolves host
  to IP A (in range), connect-time resolution returns IP B (out of range);
  assert the connection is refused, not just that the policy Decision was
  Allow:true.
- Existing property-test suite (`pgregory.net/rapid`) extended with a fake
  resolver generator so `Decide`/`DecideHost` fuzzing continues to cover the
  new parameter, not just the pre-existing exact/wildcard paths.

## Out of scope

- IPv6 CIDR is in scope for the matching logic (`net.IPNet` handles both) but
  not explicitly fuzzed beyond what the property tests generate for free;
  call out if dual-stack needs dedicated cases.
- No change to `Rule.Ports` matching — CIDR only replaces the host predicate.
