# Vendor inventory — W06/W07

Source tree inspected at `a61f6d6a064996589f84ad1544a5b795f6a2d379`. The Git blob IDs below identify exact
tracked bytes (Git SHA-1 object IDs, not SHA-256 content digests).

| Path | Git blob ID | Source-declared notice |
| --- | --- | --- |
| vendor/ed25519.c | 5029a568d64336601e26bcf043fa7667f0eafe59 | TweetNaCl v20140427 public-domain lineage; SigilOS sign/verify/SHA-512 subset |
| vendor/ed25519.h | 906fc0b3a00831ce72e277ae8a14bdfe46cd7f0e | TweetNaCl/SigilOS/Beyond lineage; LicenseRef-SPL-1.0 header notice |
| vendor/sha256_ni.h | e5ec21ab169cb5a680f3d7f9e4e8dc445a41a7fd | F E R M I ∞ H A R T; Unlicense notice; BearBasm attribution in src/axi_hash.c |

Compute exact content digests from an immutable checkout:
```sh
sha256sum vendor/ed25519.c vendor/ed25519.h vendor/sha256_ni.h
```

## Upstream review

The [official TweetNaCl project](https://tweetnacl.cr.yp.to/) confirms
public-domain C distribution; [NetBSD pkgsrc](https://wwwcdn.netbsd.org/pub/pkgsrc/current/pkgsrc/security/TweetNaCl/index.html)
identifies version 20140427. This corroborates the named lineage, but not the
identity of the original upstream bytes or intermediate SigilOS/Beyond changes.
The BearBasm SHA-256 attribution is source-declared only: a pinned upstream
revision and byte-for-byte comparison remain unavailable. Keep all notices.
No licensing determination or independent review is asserted.

W07 is blocked on immutable upstream artifacts, a documented local delta and
independent review. W06's Git digests are exact source identities; SHA-256
content digests must be observed separately. No vendor bytes were modified.
