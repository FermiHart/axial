#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-SPL-1.0
"""Check the frozen header commitment and required public scope references."""
from hashlib import sha256
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
HEADER = "include/axial/axi_embed_v1.h"
EXPECTED = "d51b9faa33c8bf757ca2f607282c3c97c1666b6173c29b566f6ecb9cce17e213"


def check(root):
    failures = []
    if sha256((root / HEADER).read_bytes()).hexdigest() != EXPECTED:
        failures.append("frozen public embed header digest differs")
    required = {
        "docs/BETA-LANGUAGE.md": (EXPECTED, "CLAIMS.md", "CAP-free"),
        "docs/CLAIMS.md": (EXPECTED, "CAP-free", "Not approved"),
        "README.md": ("docs/CLAIMS.md", "CAP-free"),
        "docs/OVERVIEW.md": ("CLAIMS.md",),
        "website/index.html": ("docs/CLAIMS.md", "CAP-free"),
        "SECURITY.md": ("docs/CLAIMS.md", "contact@fermihart.com"),
        "docs/RELEASE-GATE.md": ("not replace host authority qualification",),
    }
    for path, markers in required.items():
        content = (root / path).read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                failures.append(f"{path}: missing required scope marker {marker!r}")
    return failures


def main():
    try:
        failures = check(ROOT)
    except (OSError, UnicodeError) as exc:
        print(f"FAIL: scope evidence unavailable: {exc}", file=sys.stderr)
        return 1
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("PASS: header digest and public scope references (not semantic certification)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
