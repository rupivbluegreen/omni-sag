# Contributing to Omni-SAG 🛡️

Hey — thanks for even reading this. Omni-SAG is built in the open, and it's a lot
more fun with company. Issues, ideas, docs fixes, and PRs are all genuinely welcome.

## TL;DR

```bash
git clone https://github.com/rupivbluegreen/omni-sag && cd omni-sag
make ci          # build + gofmt + vet + import-rules + tests  (must stay green)
make lab-up      # optional: samba-AD + MinIO + FreeRADIUS for live testing
```

If `make ci` is green and you added a test for your change, you're 90% of the way there.

## Ways to help

- 🐛 **Report a bug** — open an issue. Small repro > long prose.
- 💡 **Suggest a feature** — open an issue and tell us the *why*.
- 📝 **Improve docs** — READMEs, comments, the [audit pack](docs/audit/), typos. Always appreciated.
- 🔨 **Send a PR** — see below. Look for [`good first issue`](https://github.com/rupivbluegreen/omni-sag/labels/good%20first%20issue).
- 🔒 **Found a vulnerability?** Please read [SECURITY.md](SECURITY.md) first — don't open a public issue.

## The house rules (they keep the thing trustworthy)

This is a security gateway, so a few invariants are load-bearing. CI enforces most of them
(`scripts/check-imports.sh`), but keep them in mind:

1. **Single dialer.** Only `internal/dialer` opens sockets to session *targets*. Don't add a
   `net.Dial` elsewhere. Integration clients (LDAP/RADIUS/ICAP/S3/CyberArk) dial their own
   operator-configured endpoints only.
2. **Fail closed.** Any dependency failure must *deny*, never fall open. If you touch an error path,
   ask "what happens if this dependency is down?" — the answer should be "access refused."
3. **The data path never imports the control plane.** `internal/dialer` / `internal/session` /
   `internal/sessions` must not import `internal/api`.
4. **Evidence is non-optional.** Don't swallow `Emit` errors — surface them (log/metric).
5. **Secrets stay `[]byte`.** In `internal/credential`, never turn a secret into a Go `string`.
   There's a lint for it.
6. **`internal/policy` stays pure** (no `internal/session` import) so it stays property-testable.

New invariant, new CI check — that's how the monolith stays modular.

## Sending a PR

1. Branch off `master`.
2. Make the change **test-first** where practical. `make ci` must pass.
3. `gofmt` your code (CI checks it). Match the surrounding style — comment density, naming, idioms.
4. Keep PRs focused. One logical change per PR is easier to review (and to trust).
5. Write a clear description: what changed and *why*. If it touches a security control, say how you
   verified it still fails closed.
6. For non-trivial features, an issue first is nice so we can agree on the shape.

## Project layout

```
cmd/            omni-sag (daemon) · omnisag-ctl (CLI/TUI) · omni-verify (offline verifier) · omnisag-operator
internal/       one package per concern (authn, policy, dialer, session, evidence, …)
api/            openapi.yaml — the control-plane contract
deploy/         compose lab · Helm chart · Containerfile · operator CRDs
docs/           the website, audit pack, and ADRs
```

## Code of Conduct

Be kind. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). We're here to build something cool and learn
stuff, not to win internet arguments.

Thanks for pitching in. 🙌
