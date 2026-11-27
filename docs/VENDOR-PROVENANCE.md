# Vendored dependency provenance

The standalone build retains vendored cryptography and hashing. Do not
replace the dependency-free implementation solely for audit optics.

| File | Attribution available in source | Independently verified upstream, revision and changes |
| --- | --- | --- |
| `vendor/ed25519.c`, `vendor/ed25519.h` | The C source credits the public-domain TweetNaCl v20140427 lineage | Pending |
| `vendor/sha256_ni.h` | Retain the existing source notice | Pending |

The above records source-declared attribution, not verified upstream
provenance or a licensing determination. Before external trust use, document
the canonical upstream location, immutable revision, original file hashes,
local modifications, applicable notices, and an independent review. Keep
external conformance tools in development/test infrastructure rather than
adding an obligatory runtime dependency. Preserve the original source notices.
