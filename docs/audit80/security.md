# Audit80 W41–W50: explicit host-local authority

Base: `82596bf8faf607e25f7366e36381a8dad58302a1`. This opt-in profile is a new
documented interpretation for the existing local action/attempt primitives;
it is not a reconstruction of the missing ADR-059. No public embed header,
grant, receipt, action or attempt wire layout changes.

`resource_device/resource_inode` identify the held private store directory.
`previous.*` describes its `config` entry. The administrator provisions the
issuer in `authority_v1`, a private 64-byte local configuration (magic,
issuer, directory identity, reserved zeros). An enabled store rejects legacy
mutation calls, including when configuration is incomplete/corrupt. There is
no downgrade API. The service UID, host process, kernel and administration
remain trusted; arbitrary same-UID writers and external guests are outside
the claim. Configuration persistence is not a second spent ledger.

Planned proof obligations: bounded prior-content snapshot; real UID/effective
UID, boot ID and boot-time clock; mandatory active epoch; immutable prepared
inputs; under-lock re-observation before spend; fresh expiration checks;
concurrency, status/recovery and injected failures. The existing action codec
requires two distinct nonzero UIDs, so the host profile must refuse ordinary
same-UID processes instead of inventing a principal. Tests use real kernel
credential changes in disposable subprocesses where authorized.

| Wave | Implemented change | Evidence | Limits |
| --- | --- | --- | --- |
| W41 | Opt-in issuer configuration bound to held directory; lifecycle and resource observation; legacy mutation guard under owner lock. | 55 checks: activation/idempotence/wrong key, missing/foreign config, retained fd after rename, legacy mutation refusal. | Owner setup is trusted; activation may remain after an I/O refusal to prevent downgrade. |

## Executed evidence

The normal build uses C99, `-Wall -Wextra -Werror -O2 -g` and
`_POSIX_C_SOURCE=200809L`. `security.sh` compiles product code and the standalone
main, with no identity hooks. The restricted execution surface reports UID 0
but refuses `setgroups` with EPERM. The narrowly authorized host execution of
the same binary succeeded with **real UID 1000 / effective UID 1001**, after
dropping supplementary groups and root credentials.

```
W41: audit80 security: 55 checks PASS (ruid=1000 euid=1001)
```
