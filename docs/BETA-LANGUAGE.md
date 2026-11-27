# Beta language/toolchain — surface declaration (L1)

**Status:** scope declaration for the language-only beta.
It approves no effect authority, no native platform, no confidential
receipts and no external relying-party validation.

## Frozen surface

- Public header: `include/axial/axi_embed_v1.h`, bytes frozen in this
  tree (SHA-256 `d51b9faa33c8bf757ca2f607282c3c97c1666b6173c29b566f6ecb9cce17e213`).
- ABI: `AXI_EMBED_V1_ABI_VERSION 1`, `amd64-sysv-lp64` profile, exactly 4
  symbols (`abi_version`, `context_create`, `context_destroy`, `eval`).
- Semantics: pure execution, CAP-free; artifacts with effects are refused
  at context creation. No receipt vocabulary, no responsible runner, no
  final port.

## Out of scope (must stay false)

- Effect authority, single syscall door, resource envelopes, universal
  mutation mediation, confidential receipts, external relying-party
  validation.
- Scope and evidence index: [CLAIMS.md](CLAIMS.md). The standalone CLI and
  opt-in host research profiles are distinct from the frozen L1 embedding surface.
- Mechanical guard: `python3 tools/check-release-scope.py` checks the header
  bytes and public scope references. `tools/check.sh` runs host goldens;
  neither automatically proves all public statements.

## Exit rules for L1

- `make gate` green in this tree.
- No byte of the header, ABI ID or symbol allowlist changed.

Campaign evidence: [scope reconciliation](assurance40/SCOPE.md). The architecture
[ADR](ADR-AXIAL-0001.md) is a revised proposal, not an expansion of L1.
