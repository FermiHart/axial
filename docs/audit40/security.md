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
| W25 | Attempt records accepted a v1 header with v2 length (and vice versa); the scanner did not bind the record's grant root to its filename. Require the version's exact length and the nonzero filename/body key match. | Reproduced acceptance of v1/168-byte records. Valid historical v1 and current v2 remain readable; crossed lengths and renamed records refuse as CORRUPT before a visitor receives the record; empty crash husks remain NOT_ATTEMPTED. | Local records are not authenticated against a malicious store owner. No record format was added. |
| W26 | Store ownership was checked before reopening the path; internal opens followed symlinks, accepted special files, and truncated temporary targets before validation. Check the actual owned dirfd and use non-following, close-on-exec, nonblocking opens; validate private regular, single-link files before truncation. | Reject store aliases, record symlinks/hardlinks/FIFOs and lock FIFOs; a temp symlink cannot overwrite its victim. Normal epoch provision/activation/read still passes (50 checks). | Intentional tightening: final-component store symlinks and nonprivate/multiply-linked files now refuse. Ancestors are resolved once; a malicious process sharing the owner's UID remains outside the guarantee. |
| W27 | I/O failure could become false evidence: rename succeeded but failing directory fsync produced FAILED/effect=0; `readdir` errors looked like complete scans; zero-progress writes looped forever. Preserve UNKNOWN/effect=1 after rename, persist the records directory entry before effect, reject incomplete scans, stop zero writes, retry trailing-read EINTR and preserve transient-error classification. | `security_faults.sh` redirects I/O names only in test objects: 109 checks for read failures, EINTR, zero writes, directory enumeration failure, pre-effect fsync failure, post-rename failure, and replay suppression. Pristine code reproduces false FAILED after rename, false successful scan, and alarm-terminated zero-write loop. | Injected failures validate control flow; this is not a real power-loss or filesystem durability certification. No production fault hooks were added. |
| W28 | Selective disclosure hashed each value twice, and overwrote aliased inputs before finishing. Delegation verification repeatedly rehashed all earlier links. Stage one leaf commitment and retain already-validated chain roots. | 44 semantic/alias/refusal checks. `security_costs.sh` measures primitive work: a 4096-byte leaf falls from 4 hashes/8444 bytes to 2/4222; a depth-32 chain from 560 hashes/309680 bytes to 32/17696, with identical leaf authority. | These are deterministic reductions in hash work (50% and 94.29%), not whole-application latency claims. Depth-32 cache adds 1024 bounded stack bytes; all attenuation and duplicate checks remain. |
| W29 | RF1 duplicate detection repeatedly rescanned the remainder of the input, with quadratic comparisons. Validate framing first and heapsort compact line offsets for adjacent duplicate checks; preserve the original bytes for hashing. | 128 varied-size accepted fixtures and their nonadjacent duplicate variants, independent digest reconstruction, 4096 records, exact 64-KiB boundary, unknown records, malformed framing, and injected failure of either allocation. On 2048 descending unique records, comparisons fall from 2,098,177 to 41,069 (98.04%). | Counts describe comparison work, not end-to-end speed. The index is bounded heap memory, freed before the pre-existing root buffer is allocated; framing validity still does not establish fact truth or authority. |
| W30 | Caller-owned coverage state could contain a terminal bit beyond its high-water mark; the next reservation then appeared already complete. Validate identity, bounds, binary active flags and zero unused slots across reserve/terminal/gap/root operations; support aliased ID initialization. | Reproduced successful reservation of a pre-completed future slot. Regressions cover every slot through 64, corrupt high-water/flags/identity, unchanged state on refusal, duplicate terminals and full-channel exhaustion. | A consistent channel proves only internal bookkeeping. It does not authenticate a restored image or establish runtime/guest coverage outside the observed consumer. |

## Remaining authority boundaries

The public `axi_local_action_v1` codec explicitly says its hashes bind data,
not the truth of caller facts. `resource_device`, `resource_inode`,
`previous.*`, `uid`, and `executor_uid` are serialized and bound into roots;
the local attempt consumer does not re-observe all of them at the effect door.
The repository references an ADR-059 that is not shipped here, and does not
specify whether the resource inode identifies the parent directory or target
object. This audit therefore does not invent a new resource authority or claim
that declaring these facts confines an external guest.

Before a production consumer relies on these fields, its owner must define
the actual held object each identity denotes, measure it at the final effect
door under the same lock, and refuse wrong-device/wrong-inode and stale
previous-content scenarios before spending a grant. UID/executor claims need
an actual authenticated caller boundary. Suggested acceptance: mint for one
resource, submit at another, and prove no spend, no write, and explicit refusal;
then mutate previous content between appraisal and commit and prove refusal.
Clock values, pinned trust roots and coverage observations are likewise
caller-supplied by design; this library does not make them true.

Fault harness: `sh tests/audit40/security_faults.sh`. It also accepts `read`,
`zero-write`, `dir-read`, `pre-effect`, or `post-rename`. Its `.inc` test unit is
compiled explicitly, keeping ordinary C test discovery free of special link
requirements. Fortify is disabled only on the two instrumented test objects
because fortified libc aliases otherwise bypass name redirection; ASan/UBSan
remain enabled when requested. In this traced container LeakSanitizer requires
`ASAN_OPTIONS=detect_leaks=0`; address and undefined-behavior checks remain active.
