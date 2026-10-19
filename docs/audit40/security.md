# Axial audit40 — security and evidence internals (W21–W30)

Base: `2d67522` (public launch). Changes remain in Axial. The local consumer is
a fixture profile: these tests do not claim guest/kernel enforcement, trust in
fact contents, or safety merely from signatures. Existing wire versions and
the frozen embed ABI are preserved.

Run `sh tests/audit40/security.sh`; select one wave with its name (for example
`W21`). For memory/undefined-behavior checking, set `AXI_AUDIT_BUILD` to a separate
directory and append `-fsanitize=address,undefined -fno-omit-frame-pointer` to
`AXI_AUDIT_CFLAGS`. `AXI_AUDIT_SOURCE_ROOT` can point to the pristine tree for
before/after reproductions; test sources always come from this audited tree.

| Wave | Finding and change | Regression evidence | Limit |
| --- | --- | --- | --- |
| W21 | TRS1 passed a NULL bounded-reader result to `memcmp` for 1–3-byte inputs. Require the eight-byte magic/version prefix and defend reader subtraction. | Pristine ASan/UBSan reports NULL argument and SEGV in `parse_snapshot`; fixed parser rejects all tested short prefixes (17 checks). | Bounds supplied to C APIs still describe caller-owned accessible memory. |
| W22 | A correctly linked successor could switch organization/time domain or wrap the sequence to zero. Bind both identities, reject exhausted sequences, and require a present predecessor to be nonzero. | Reproduced cross-organization acceptance before the fix. Canonical successor passes; all 472 truncations, appended data, identity swaps, skipped/wrapped sequence, and revoked-key rollback refuse. | A snapshot digest or valid transition is not authentication of the snapshot source. |
| W23 | Lease reservation iterated an unchecked caller-owned `nquota` outside fixed arrays. Validate count, sorted distinct units, limits/reservations, and unused slots before mutation. | Pristine ASan/UBSan confirms stack-buffer-overflow at `nquota=255`. Regressions cover malformed states with byte-for-byte preservation on refusal, full `UINT64_MAX` reservation without wrap, unknown unit and exhausted quotas (25 checks). | State authenticity, concurrent synchronization and persistence remain the consumer's responsibility. |
| W24 | AER1/AER2/delegation decoders wrote partial objects for correctly signed but semantically invalid bodies. Stage decoding and publish only on success; wipe expanded signing keys using the existing explicit wipe primitive. | Deterministic signing round trips, every AER1 envelope truncation, invalid enum bodies re-signed with a valid key, independent receipt verifiers, and unchanged sentinel outputs on refusal. | Existing AER1 validity rules/wire bytes remain unchanged. Wiping is best-effort memory hygiene, not a forensic guarantee. |

Further waves are recorded here with their concrete results as completed.
