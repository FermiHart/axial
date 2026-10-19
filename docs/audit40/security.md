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

Further waves are recorded here with their concrete results as completed.
