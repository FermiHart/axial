#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-SPL-1.0
"""Ordinary isolated regression for the documentation scope guard."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = ("include/axial/axi_embed_v1.h", "docs/BETA-LANGUAGE.md",
         "docs/CLAIMS.md", "README.md", "docs/OVERVIEW.md",
         "website/index.html", "SECURITY.md", "docs/RELEASE-GATE.md",
         "tools/check-release-scope.py")

def run(root):
    return subprocess.run([sys.executable, str(root / FILES[-1])],
                          capture_output=True, text=True, check=False)

def expect(result, code, marker):
    if result.returncode != code or marker not in result.stdout + result.stderr:
        raise AssertionError((result.returncode, result.stdout, result.stderr))

def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name in FILES:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        expect(run(root), 0, "PASS: header digest")
        readme = root / "README.md"
        original = readme.read_text(encoding="utf-8")
        readme.write_text(original.replace("docs/CLAIMS.md", "scope-index"), encoding="utf-8")
        expect(run(root), 1, "README.md: missing required scope marker")
        readme.write_text(original, encoding="utf-8")
        header = root / FILES[0]
        raw = header.read_bytes()
        header.write_bytes(raw + b"\n")
        expect(run(root), 1, "frozen public embed header digest differs")
        header.write_bytes(raw)
        (root / "docs/OVERVIEW.md").unlink()
        expect(run(root), 1, "scope evidence unavailable")
    print("PASS: four isolated scope guard cases")

if __name__ == "__main__":
    main()
