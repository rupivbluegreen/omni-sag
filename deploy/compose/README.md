# Dev lab

A docker-compose lab for developing and demoing the gateway.

- **samba-ad** — Active Directory domain controller (`LAB.LOCAL`), LDAPS on 636.
- **minio** — S3-compatible object store for evidence, API on 9000, console on 9001.

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

## Notes

- **Port 53 is not published** to the host: `systemd-resolved` owns it, and the
  gateway resolves targets itself. Samba runs DNS inside its container.
- **`SYS_ADMIN` + `apparmor:unconfined`** on the samba container are required so
  domain provisioning can set the `security.NTACL` xattr on sysvol. This is a
  dev-lab concession only and is unrelated to the gateway's `restricted-v2`
  production posture (see `docs/decisions/0001-mlock-free-credential-handling.md`).

```sh
make lab-down   # tear down (add `-v` in compose to wipe the domain)
```
