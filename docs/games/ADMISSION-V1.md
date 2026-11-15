# Node host policy admission v1

`runtime/games-admission-v1.cjs` wraps unchanged portable-decision-v2.
Pass a trusted manifest of `{id,schema,version,digest}` (SHA256 of exact bytes).
`admit(id, Buffer)` validates bounded UTF8/JSON and VM structure, returning an
opaque handle or null. `evaluate(handle, factsBuffer, {fuel})` accepts bounded
JSON facts and adds trusted policy metadata to the immutable decision.
`revoke(id)` monotonically disables all handles in this loader.

Limits: 256 policies, 64 KiB policy, 4 KiB facts; no SharedArrayBuffer inputs.
No signature, persistent rollback database, key rotation or isolated process is
provided. Caller retains durable minimum versions across restart. Revocation is
not retroactive to an already committed effect. Transactions must revalidate
policy status and resource version inside their own authority boundary.
VM snapshot validation still runs per evaluation. We do not claim cached VM
admission speedup; benchmarks must account for validation and parsing.

Run: `node tools/portable-decision-build.cjs` then
`node --test tests/games-admission-v1.test.cjs`.

`createNumericAdmission` is the explicit separate loader for
`axial.portable-numeric.v1`. Its facts use canonical decimal i64 strings;
results are values, not allow decisions. Do not use JavaScript truthiness to
interpret a numeric result as permission. The original createAdmission only
admits decision-v2, and each handle remains private to its loader.
