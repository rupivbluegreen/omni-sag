# Security Policy 🔒

Omni-SAG is a security gateway, so we take this seriously — but it's also a hobby project run by
humans, so please be kind and patient.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, use GitHub's private reporting:
[**Report a vulnerability**](https://github.com/rupivbluegreen/omni-sag/security/advisories/new)
(Security → Advisories → Report a vulnerability).

Please include:

- What the issue is and which invariant it breaks (e.g. an auth bypass, a fail-*open* path, a secret
  leak, undetected evidence tampering, an SSRF/import-invariant break).
- A concrete reproduction or proof-of-concept if you have one.
- The commit/version you tested against.

We'll acknowledge as soon as we reasonably can, work with you on a fix, and credit you (if you'd
like) when it ships. No bug bounty — this is a hobby project — but very sincere thanks. 🙏

## What counts as a security issue

The things that would make us drop our coffee:

- **Fail-open**: any dependency failure or error path that *grants* access, *delivers* unscanned
  content, or *silently loses* required evidence. (See the [fail-closed matrix](docs/audit/fail-closed-matrix.md).)
- **Auth/authz bypass**: reaching a target without a passing policy decision, or defeating MFA /
  four-eyes / RBAC.
- **Silent credential downgrade**: `inject` falling back to prompt/passthrough.
- **Secret leakage**: a credential ending up in a log, error, evidence record, or a Go `string`.
- **Evidence tampering** that `omni-verify` fails to detect.
- **Single-dialer / SSRF**: reaching an unintended address, or dialing targets outside the dialer.

## Scope notes

Some parts of v1 are deliberate **stand-ins** and are documented as such — the in-memory SFTP
backend, the echo interactive shell, the OIDC static-token stand-in, and the stubbed Kubernetes CRD
sources. Issues in the *controls* around them (inspection, recording, evidence, authz) are in scope;
"the stand-in doesn't proxy to a real backend yet" is a known limitation, not a vulnerability.

Thanks for helping keep the bouncer honest. 🛡️
