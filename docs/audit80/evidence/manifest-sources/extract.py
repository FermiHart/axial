#!/usr/bin/env python3
"""Verify and extract the exact W78 benchmark sources without Git history.

Only regular files/directories inside src/include/vendor are admitted. Both
archives and every product file must match the preserved benchmark record.
The output's before/after directories must be absent, so nothing is replaced.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
here = Path(__file__).resolve().parent
bundles = json.loads((here / "bundles.json").read_text())
record_bytes = (here / "../manifest-benchmark.json").read_bytes()
assert hashlib.sha256(record_bytes).hexdigest() == bundles["benchmark_record_sha256"]
record = json.loads(record_bytes)
destination = args.output.resolve()
for label in ("before", "after"):
    if (destination / label).exists() or (destination / label).is_symlink():
        parser.error("choose an output without existing before/after directories")

products = {}
for label in ("before", "after"):
    info = bundles["bundles"][label]
    archive_path = here / info["file"]
    assert archive_path.parent == here and not archive_path.is_symlink()
    data = archive_path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == info["sha256"]
    files = {}
    names = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for entry in tar.getmembers():
            name = PurePosixPath(entry.name)
            assert not name.is_absolute() and name.parts and ".." not in name.parts
            assert name.parts[0] in ("src", "include", "vendor")
            assert entry.name not in names and (entry.isfile() or entry.isdir())
            names.add(entry.name)
            if entry.isdir():
                continue
            total += entry.size
            assert 0 <= entry.size <= 8 * 1024 * 1024 and total <= 16 * 1024 * 1024
            with tar.extractfile(entry) as stream:
                files[entry.name] = stream.read()
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    assert hashes == record["source_sha256"][label], label
    assert len(files) == info["product_files"]
    products[label] = files

for label, files in products.items():
    root = destination / label
    root.mkdir(parents=True)
    for name, data in files.items():
        target = root / name
        target.resolve().relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    assert {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()} == record["source_sha256"][label]
print(json.dumps({"status": "PASS", "product_files_per_snapshot": {
    label: len(files) for label, files in products.items()},
    "match": "archive SHA-256 and every path/file SHA-256 match the preserved benchmark",
    "output": str(destination)}, indent=2))
