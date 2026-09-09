# Client-selected target user — design

**Status:** Approved (brainstorming), not yet implemented
**Date:** 2026-09-09

## Context

The SSH auth-username grammar today is `loginuser[+pcode]%targethost[:port]`,
parsed by three pure splitters in `internal/session/target.go`
(`splitTargetUser` on the first `%`, `splitPcodeSelector` on the first `+`,
`splitTargetHostPort` on an optional bracket-aware trailing `:port`) and
chained at `internal/session/session.go:381-383`.

The account the gateway authenticates as on the target is **not**
client-selectable. It comes from the matched policy rule's `target_user`
(`internal/config/config.go:598` → `internal/policy/policy.go:96` →
`Decision.TargetUser` at `policy.go:125`), and `dialTarget`
(`internal/session/target.go:139`) falls back to the gateway login user when
the rule sets nothing.

That is limiting in the common case where one host is reachable by one rule
but an operator legitimately needs a different local account on it
(`user01` vs `oracle` vs their own name). Today the only way to express that
is a second rule, which also means a second role or a second host entry.

This design lets a client name the target account in the auth username, and —
this is the substance of the change — defines the authorization model that
decides whether the gateway honours the request.

## Prior art: CyberArk PSM for SSH (PSMP)

PSMP solves the same problem and is worth copying deliberately rather than
by accident. Its connection string is:

```
<vaultUser>@<targetUser>[#<domainAddress>]@<targetMachine>[#<sshPort>][#<tunnelPort>]@<proxyAddress>
```

e.g. `ssh john@root#production@target.example.com@psmp.example.com`.

Three lessons, each of which changed this design:

1. **`@` as the target-user separator is the industry-normal shape.** PSMP
   puts the target user between the vault user and the machine, separated by
   `@`. Our grammar arrives at the same reading order —
   `loginuser%targetuser@targethost` — with `%` retained as the existing
   login/target boundary. A user who knows PSMP will read ours correctly.

2. **`@` cannot also carry a domain.** PSMP explicitly does *not* write
   `targetUser@domain`; it uses `#` (`root#production`) precisely because `@`
   is already the field separator, and its documentation states the username
   may contain only one `@`. The claim "`@` is safe because it cannot appear
   in an AD sAMAccountName" is true, but incomplete: AD accounts are routinely
   *written* as UPNs (`svc_db1@corp.local`), and a user who types one will
   produce an ambiguous string. This design therefore **rejects** any target
   segment containing more than one `@` rather than guessing which one splits.
   A `#domain` suffix, if it is ever needed, is a follow-up (see below) and
   the rejection keeps that grammar space free.

3. **PSMP does not let a user name an arbitrary account.** The named account
   must be a provisioned object in a Safe on which the vault user holds
   *List accounts* and *Use accounts*. Naming an account you have no
   permission on fails; there is no "you may connect as anything you know the
   password for" mode. PSMP also never has our `prompt` mode — the vault
   always injects — so it never faces the case where the user supplies the
   target password themselves.

   This is the direct justification for the authorization model below.
   Allowing a client-named account under `prompt` because "the password is
   still the barrier" would put omni-sag *looser* than the product in the same
   category, in the one mode that product does not even offer.

Sources: CyberArk PAM docs and community articles on the PSM for SSH
connection-string syntax and the Safe permissions (*List accounts*,
*Use accounts*) required to connect to a target account.

## Grammar

```
loginuser[+pcode]%[targetuser@]targethost[:port]
```

Parse order (each step consumes what the previous one produced):

1. `splitTargetUser` — first `%` → (`loginuser[+pcode]`, `targetspec`). Only
   the first `%` splits, so an IPv6 zone id in the host (`fe80::1%eth0`) is
   still not truncated.
2. `splitPcodeSelector` — first `+` on the login part → (`loginuser`, `pcode`).
   Unchanged; the selector still applies connection-wide.
3. **`splitTargetAccount` (new)** — the single `@` in `targetspec` →
   (`targetuser`, `hostspec`). No `@` ⇒ (`""`, `targetspec`).
4. `splitTargetHostPort` — bracket-aware trailing `:port` on `hostspec`.

Splitting the account off *before* the port keeps `splitTargetHostPort`
unchanged and leaves bracketed IPv6 working: `u%user01@[2001:db8::1]:22`
reaches step 4 as `[2001:db8::1]:22`, exactly what it handles today.

### Client-side forms

OpenSSH splits its own `[user@]host` argument on the **last** `@`, so the
unquoted form works and needs no quoting:

```console
$ ssh tq58qd%user01@10.156.34.70@gw -p 2323
```

OpenSSH takes `gw` as the host and sends `tq58qd%user01@10.156.34.70` as the
SSH username. The quoted and `-l` forms are equivalent and also supported:

```console
$ ssh 'tq58qd%user01@10.156.34.70'@gw -p 2323
$ ssh -l 'tq58qd%user01@10.156.34.70' gw -p 2323
$ sftp -P 2323 'tq58qd%user01@10.156.34.70'@gw
```

The existing form is unchanged and keeps today's behaviour:

```console
$ ssh tq58qd%10.156.34.70@gw -p 2323
```

### Invalid forms — rejected at auth, fail closed

| Input | Why |
|---|---|
| `u%@host` | empty target account |
| `u%user01@` | empty host |
| `u%user01@host@x` | more than one `@` — ambiguous (see PSMP lesson 2) |
| `u%user01 @host` | whitespace in the account |

A rejected parse fails authentication with the generic
`authentication failed` the rest of `passwordCallback` uses, records an
`evidence.TypeAuth` event with the reason, and counts as a failed attempt for
`bfLimiter`. It never falls back to "ignore the account and connect anyway" —
that would be exactly the silent downgrade FR-18 exists to prevent.

## Authorization

### `allow_target_users`

`policy.Rule` gains `AllowTargetUsers []string` (`allow_target_users` in
YAML). It is the **exhaustive set of accounts a client may name** on this
rule's matches. Default (absent/empty) is **deny**: a client-supplied account
is refused, and the rule behaves exactly as it does today.

Default-deny, not default-allow, for three reasons:

- **No unreviewed widening on upgrade.** Every existing `credential: prompt`
  rule without a `target_user` would otherwise start accepting client-chosen
  accounts on the day this release lands, with no policy edit and no review.
  With default-deny the widening is a per-rule policy diff someone approves.
- **Preventive, not only detective.** A rule that fixes the account is what
  makes "who connected as whom" deterministic rather than merely recorded.
  Shared and service-account passwords are known to more than one person.
- **Repo precedent.** `dialTarget` already refuses to guess on host keys —
  explicit opt-in (`target_insecure_host_key`) or fail closed
  (`target.go:143-151`). Same shape.

`allow_target_users: ["*"]` opts a rule into the loose behaviour explicitly.

**Config validation** (`config.validate`) rejects, with an explicit error
rather than a silent no-op:

- `allow_target_users` together with `target_user` — `target_user` is a hard
  pin (see precedence case 1) and the list would be inert.
- `allow_target_users` on `credential: inject` or `credential: deny` — a
  client-named account is never honoured in those modes.
- an empty string, a whitespace-bearing entry, or `*` mixed with named
  entries.

### Resolution precedence

One pure helper, in `internal/policy`, is the single authority:

```go
func ResolveTargetUser(requested string, d Decision, loginUser string) (string, error)
```

| # | Rule `target_user` | Client requested | Mode | Result |
|---|---|---|---|---|
| 1 | `svc_db1` | `other` | any | **deny** — pinned account is not bypassable |
| 2a | `svc_db1` | *(none)* | any | `svc_db1` |
| 2b | `svc_db1` | `svc_db1` | any | `svc_db1` |
| 3a | *(none)* | `user01`, listed in `allow_target_users` | prompt / passthrough | `user01` |
| 3b | *(none)* | `user01`, **not** listed (incl. empty list) | prompt / passthrough | **deny** |
| 3c | *(none)* | `user01` | inject | **deny** — credential oracle |
| 3d | *(none)* | `user01` | deny | **deny** |
| 4 | *(none)* | *(none)* | any | `loginUser` |

Case 3c is non-negotiable independently of the allow-list: under `inject` the
gateway fetches a secret from CyberArk keyed by the account, so honouring a
client-named account turns the gateway into a credential oracle — it would
hand out access to any vaulted account on an allowed host. Under `inject` the
account is always the rule's, and any client-supplied account that is not
identical to it is denied.

### Error contract

`internal/policy` must stay pure and cannot import `internal/credential`
(CI-enforced, `scripts/check-imports.sh`). `ResolveTargetUser` therefore
returns its own sentinel:

```go
var ErrTargetUserDenied = errors.New("policy: target user denied")
```

The two call sites in `internal/session` wrap it into the existing credential
contract so the rest of the credential path is unchanged: a denial surfaces as
an error wrapping `credential.ErrDenied`, never a usable client and never a
downgrade to a different account.

### Both call sites must agree

`ResolveTargetUser` is called from exactly two places, and they must produce
the same string:

- `dialTarget` (`internal/session/target.go:139`) — the single choke point for
  all three target-bearing flows (`interactive.go:259`, `sftp.go:96`,
  `scp.go:241` all reach the target through it).
- the prompt-mode password prompt (`internal/session/session.go:453-457`) —
  the `"user@host password: "` string shown to the client.

A prompt naming one account while the leg authenticates as another is a bug:
the user would type the password for the account they were shown.

Under `prompt`, resolution runs **before** `challenge()` is called. A denial
must refuse authentication without prompting — otherwise the gateway collects
a password for an account the client is not allowed to use.

## Brute-force accounting on the second leg

Today `bfLimiter.RecordSuccess(srcIP)` fires at `session.go:436` as soon as
gateway authentication succeeds, and a *target-side* auth failure on the
second leg is counted nowhere. That is harmless while the target account is
fixed by policy — there is nothing to guess.

Once a client can name the account, that path becomes an unmetered
username+password spray channel against every allowed host, laundered behind a
valid AD login, with target-side account lockout as a denial-of-service
consequence. This design therefore counts second-leg authentication failures
in `dialTarget` toward `bfLimiter` for the client's source IP. Successes do
not clear the counter a second time (the gateway-auth success already did);
only failures are recorded.

## Evidence and the live-session registry

Accountability is the point of this gateway, so the effective account must be
in the audit trail, not inferable from it.

- `evidence.Event` gains `TargetUser string` with json tag `target_user`,
  next to the existing credential fields (`evidence.go:65-67`). It is
  `omitempty`, so existing consumers and golden fixtures are unaffected when
  no target account is involved.
- `emitTargetCredential` (`target.go:85`) sets it on every credential event,
  for every mode including deny.
- Session start/end events carry it too, so a session can be attributed
  without joining against a credential event.
- On a denial the event records requested-vs-effective explicitly:
  `Reason: "target user denied"`, `Detail: "requested=user01 effective=svc_db1"`.
- The secret is never logged; this change adds no new secret-bearing field.
- `sessions.Info` (`registry.go:17-24`) gains `TargetUser string`
  (`target_user,omitempty`) so `/api/v1/sessions` shows the account the
  session is running as. Additive JSON field; no existing field changes.

## Out of scope / follow-ups

- **`target_user` as a default plus `allow_target_users` as alternatives.**
  This design forbids the combination (a set `target_user` is a hard pin).
  Allowing "default account, these alternatives permitted" is a coherent
  future extension but changes precedence case 1, so it is deliberately not
  built here.
- **`targetuser#domain` (UPN/domain-qualified target accounts).** Rejected by
  the grammar today; PSMP's `#` separator is the shape to adopt if it is ever
  needed.
- **`-L` port forwarding (`internal/dialer`).** No second-leg SSH account is
  involved; unchanged.
- **Policy evaluation semantics.** The requested account is a carrier field
  only. No `Decide`/`DecideHost` matching depends on it.
- **The private control-plane chart's policy files.** They live outside this
  repo and are updated there.
