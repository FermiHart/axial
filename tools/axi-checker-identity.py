#!/usr/bin/env python3
"""Maintain the checker source commitment and guard the recorded public ABI.

No third-party modules or network. Run --write after reviewing source changes;
--check never rewrites evidence. A source commitment is not a binary attestation
or a proof that the source is correct.
"""
import argparse
import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IDENTITY = Path("src/axi_checker_identity.h")
PINNED = {
    "include/axial/axi_embed_v1.h":
        "d51b9faa33c8bf757ca2f607282c3c97c1666b6173c29b566f6ecb9cce17e213",
    "abi/axi_embed_v1-amd64-sysv-lp64.tsv":
        "f52dadb11b2803a79e10e3beeb02c8a427da3e7526b2518b8baa7bf893af37cd",
}
DOMAIN = b"AXIAL-CHECKER-SOURCE-v1\0"


def source_root():
    paths = sorted(
        path.relative_to(ROOT)
        for directory in ("src", "include", "vendor")
        for path in (ROOT / directory).rglob("*")
        if path.suffix in (".c", ".h", ".inc", ".def")
        and path.relative_to(ROOT) != IDENTITY
    )
    if not paths:
        raise ValueError("checker source set is empty")
    digest = hashlib.sha256(DOMAIN + struct.pack("<Q", len(paths)))
    for path in paths:
        full = ROOT / path
        if full.is_symlink() or not full.is_file():
            raise ValueError(f"source must be a regular, non-symlink file: {path}")
        name = path.as_posix().encode("utf-8")
        data = full.read_bytes()
        digest.update(struct.pack("<Q", len(name)))
        digest.update(name)
        digest.update(struct.pack("<Q", len(data)))
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest(), len(paths)


def header(root):
    return (
        "/* Generated identity value checked by tools/axi-checker-identity.py. */\n"
        "#ifndef AXI_CHECKER_IDENTITY_H\n#define AXI_CHECKER_IDENTITY_H\n\n"
        "#define AXI_CHECKER_SOURCE_ROOT_HEX \\\n"
        f'    "{root}"\n\n'
        "#endif /* AXI_CHECKER_IDENTITY_H */\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="refuse stale identity (default)")
    mode.add_argument("--write", action="store_true", help="write the reviewed source identity")
    args = parser.parse_args()
    try:
        for name, expected in PINNED.items():
            if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
                raise ValueError(f"recorded public v1 ABI changed: {name}")
        root, count = source_root()
        expected = header(root)
        target = ROOT / IDENTITY
        if args.write:
            target.write_text(expected, encoding="ascii")
        elif target.read_text(encoding="ascii") != expected:
            raise ValueError("checker identity is stale; review source changes, then run "
                             "python3 tools/axi-checker-identity.py --write")
        print(f"checker identity: {root} ({count} source files); public v1 ABI pins PASS")
        return 0
    except (OSError, ValueError) as error:
        print(f"checker identity: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
