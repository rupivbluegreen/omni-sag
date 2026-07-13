# Dev lab

A docker-compose lab for developing and demoing the gateway.

- **samba-ad** — Active Directory domain controller (`LAB.LOCAL`), LDAPS on 636.
- **minio** — S3-compatible object store for evidence, API on 9000, console on 9001.
- **freeradius** — RADIUS (MS-CHAPv2) second-factor authority, on 1812/udp.

## Bring it up

```sh
make lab-up     # start samba-AD + MinIO
make lab-seed   # create the demo group + users (idempotent)
```

`lab-seed` creates:

| identity | role | tunnel to a `dba` target |
|----------|------|--------------------------|
| group `dba` | grants the `dba` role | — |
| `alice` | member of `dba` | allowed |
| `bob`   | not in `dba`    | prohibited |

User password defaults to `Passw0rd!` (override with `LAB_USER_PW`).
Domain admin is `Administrator` / `LabAdminPass123!` (from compose env).

## Slice 1 demo

With the lab up and seeded, point the gateway at it (see
`config.example.yaml`, switch the evidence block to the `s3` sink), then run
two `ssh -L` forwards as `alice` and `bob`. `alice` connects; `bob` is
administratively prohibited; both attempts appear as evidence objects under
`s3://omni-sag-evidence/events/`.

Inspect evidence:

```sh
docker run --rm --entrypoint /bin/sh --network compose_default minio/mc:latest -c \
  'mc alias set lab http://minio:9000 omnisag omnisag-dev-secret >/dev/null &&
   mc ls --recursive lab/omni-sag-evidence'
```

## Slice 2 demo (MFA / RADIUS)

The `freeradius` service simulates NPS+Entra MFA outcomes:

| identity | second factor |
|----------|---------------|
| `alice`  | approved (Access-Accept) |
| `bob`    | denied (Access-Reject) |

`alice`'s FreeRADIUS password (`deploy/compose/freeradius/authorize`) must match
the AD password she types at the gateway. Enable MFA by setting `mfa.enabled:
true` in `config.example.yaml`, then log in as each user:

- `alice` → LDAPS primary succeeds, RADIUS MS-CHAPv2 approves → shell/forward.
- `bob` → LDAPS primary succeeds, RADIUS denies → login refused.

Both outcomes are evidenced as `mfa` events (allow true/false). The reusable
password is sent to RADIUS only as an MS-CHAP2-Response — never as PAP. The
MS-CHAPv2 exchange is covered by unit tests (RFC 2759 vectors + a mock RADIUS
server) and was verified live against this FreeRADIUS image.

## Notes

- **Port 53 is not published** to the host: `systemd-resolved` owns it, and the
  gateway resolves targets itself. Samba runs DNS inside its container.
- **FreeRADIUS** relaxes `require_message_authenticator` for the lab because our
  MS-CHAPv2 Access-Requests don't carry Message-Authenticator. Do not do this in
  production.
- **`SYS_ADMIN` + `apparmor:unconfined`** on the samba container are required so
  domain provisioning can set the `security.NTACL` xattr on sysvol. This is a
  dev-lab concession only and is unrelated to the gateway's `restricted-v2`
  production posture (see `docs/decisions/0001-mlock-free-credential-handling.md`).

```sh
make lab-down   # tear down (add `-v` in compose to wipe the domain)
```
