#!/usr/bin/env python3
"""Build matched full sources and measure the per-module manifest change.

Run from the repository root. Select exact snapshot directories with
--before-source/--after-source, or use the legacy --base mode against the
current checkout. --build-only compiles both products and compares --fixture
without timing. No remote access, signing, or benchmark pass threshold.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import tarfile

parser = argparse.ArgumentParser()
selection = parser.add_mutually_exclusive_group(required=True)
selection.add_argument("--base", help="legacy mode: compare this Git revision with the current checkout")
selection.add_argument("--before-source", type=Path, help="directory containing the exact baseline src/include/vendor")
parser.add_argument("--after-source", type=Path, help="directory containing the exact candidate src/include/vendor")
parser.add_argument("--build-only", action="store_true", help="compile both products and compare --fixture; do not run timings")
parser.add_argument("--build", type=Path, default=Path("build/manifest80-benchmark"))
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--compiler", default="cc")
parser.add_argument("--flags", default="-std=c99 -Wall -Wextra -Werror -O1 -D_POSIX_C_SOURCE=200809L")
parser.add_argument("--cpu", type=int, default=0)
parser.add_argument("--iterations", default="256,64,16",
                    help="iteration counts for 16,64,256 cells")
args = parser.parse_args()
if bool(args.before_source) != bool(args.after_source):
    parser.error("--before-source and --after-source must be supplied together")
counts = [int(x) for x in args.iterations.split(",")]
assert len(counts) == 3 and all(0 < n <= 100000 for n in counts)
root = Path.cwd()
build = args.build.resolve()
build.mkdir(parents=True, exist_ok=True)
if args.before_source:
    before_root = args.before_source.resolve()
    after_root = args.after_source.resolve()
    base = base_tree = candidate_revision = None
    source_selection = "snapshot directories; no Git revision inferred"
else:
    base = subprocess.check_output(["git", "rev-parse", args.base], text=True).strip()
    base_tree = subprocess.check_output(["git", "rev-parse", base + "^{tree}"], text=True).strip()
    candidate_revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    source_selection = "Git baseline and current working-directory candidate"
    archive = subprocess.check_output(["git", "archive", base, "src", "include", "vendor"])
    before_root = build / "baseline"
    after_root = root
    before_root.mkdir(exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        # A repository-created archive, limited to these three source directories.
        for member in tar.getmembers():
            assert not member.name.startswith("/") and ".." not in Path(member.name).parts
            assert member.isfile() or member.isdir(), member.name
            target = before_root / member.name
            target.resolve().relative_to(before_root.resolve())
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as stream:
                    target.write_bytes(stream.read())
driver = root / "tests/audit80/manifest_bench.c"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def product_sources(directory):
    return sorted(p for p in (directory / "src").glob("*.c")
                  if p.name not in ("axi_main.c", "axi_dossier_main.c")) + [directory / "vendor/ed25519.c"]


def identity(directory):
    hashes = {}
    for top in ("src", "include", "vendor"):
        folder = directory / top
        if folder.is_symlink() or not folder.is_dir():
            raise SystemExit("missing or linked source directory: " + str(folder))
        for p in sorted(folder.rglob("*")):
            if p.is_symlink():
                raise SystemExit("source snapshots must not contain links: " + str(p))
            if p.is_file():
                hashes[str(p.relative_to(directory))] = sha(p)
    return hashes


identities = {"before": identity(before_root), "after": identity(after_root)}
changed = sorted(p for p in identities["before"].keys() | identities["after"].keys()
                 if identities["before"].get(p) != identities["after"].get(p))
assert changed == ["src/axi_contract.c", "src/axi_iface.c", "src/axi_iface.h"], changed
binary = {}
for label, directory in (("before", before_root), ("after", after_root)):
    binary[label] = build / label
    command = [args.compiler, *shlex.split(args.flags),
               "-I" + str(directory / "src"), "-I" + str(directory / "include"),
               "-I" + str(directory / "vendor"), str(driver),
               *map(str, product_sources(directory)), "-o", str(binary[label]), "-lm"]
    with (build / (label + "-build.log")).open("w") as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
if not args.build_only:
    if not hasattr(os, "sched_setaffinity"):
        raise SystemExit("CPU affinity unavailable; describe an unpinned experiment separately")
    os.sched_setaffinity(0, {args.cpu})


def sample(label, cells, iterations):
    p = subprocess.run([str(binary[label]), str(cells), str(iterations)],
                       capture_output=True, text=True, check=True, timeout=60)
    value = json.loads(p.stdout)
    assert value["cells"] == cells and value["iterations"] == iterations
    assert value["cpu_seconds"] > 0 and value["live"] == value["fixed"] == 0
    return value


result = {
    "schema": "axi.manifest.build-verification.v1" if args.build_only else "axi.manifest.benchmark.v1",
    "benchmark_executed": not args.build_only,
    "base_revision": base,
    "base_tree": base_tree,
    "candidate_revision_before_commit": candidate_revision,
    "source_selection": source_selection,
    "candidate_identification": "exact source_sha256 file identities; checkout metadata does not identify snapshot directories",
    "source_sha256": identities,
    "changed_product_files": changed,
    "driver_sha256": sha(driver),
    "fixture_header_sha256": sha(root / "tests/audit80/manifest_fixture.h"),
    "binary_sha256": {label: sha(path) for label, path in binary.items()},
    "compiler": subprocess.check_output([args.compiler, "--version"], text=True).splitlines()[0],
    "flags_both": args.flags,
    "host": platform.platform(), "cpu": None if args.build_only else args.cpu,
    "affinity": None if args.build_only else sorted(os.sched_getaffinity(0)),
    "method": "compile both products and compare --fixture once; no timing samples" if args.build_only else
              "one warmup per binary/workload; seven alternating before/after pairs; no timing threshold",
    "timed_region": None if args.build_only else
                    "axi_codegen_contract_v1 plus full byte comparison and result release; checked AST retained",
    "outside_timing": "source generation, parse/typecheck, reference contract and SHA-256, process startup and JSON output",
    "memory_metric": "compiler invocation peak includes setup and retained reference output; requested bytes plus headers/reservations, not RSS",
    "limits": "shared host, CPU seconds not user latency, synthetic policies, no signing or runtime execution",
    "workloads": {},
}
fixtures = {}
for label in ("before", "after"):
    p = subprocess.run([str(binary[label]), "--fixture"], capture_output=True,
                       check=True, timeout=30)
    fixtures[label] = p.stdout
    (build / (label + "-fixture.axs")).write_bytes(p.stdout)
assert fixtures["before"] == fixtures["after"]
result["rich_fixture"] = {"equal_bytes": True, "text_bytes": len(fixtures["before"]),
                          "text_sha256": hashlib.sha256(fixtures["before"]).hexdigest()}
if args.build_only:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"schema": result["schema"], "benchmark_executed": False,
                      "rich_fixture": result["rich_fixture"],
                      "changed_product_files": changed}, indent=2))
    raise SystemExit(0)
for cells, iterations in zip((16, 64, 256), counts):
    warmups = {label: sample(label, cells, iterations) for label in ("before", "after")}
    expected = warmups["before"]["text_sha256"]
    assert warmups["after"]["text_sha256"] == expected
    pairs = []
    for index in range(7):
        order = ["before", "after"] if index % 2 == 0 else ["after", "before"]
        pair = {"order": order}
        for label in order:
            pair[label] = sample(label, cells, iterations)
            assert pair[label]["text_sha256"] == expected
            assert pair[label]["text_bytes"] == warmups["before"]["text_bytes"]
        pairs.append(pair)
    before = [p["before"]["cpu_seconds"] for p in pairs]
    after = [p["after"]["cpu_seconds"] for p in pairs]
    summary = {
        "before_median": statistics.median(before), "before_min": min(before), "before_max": max(before),
        "after_median": statistics.median(after), "after_min": min(after), "after_max": max(after),
        "median_change_percent": (statistics.median(after) / statistics.median(before) - 1) * 100,
    }
    result["workloads"][str(cells)] = {"warmups": warmups, "pairs": pairs, "summary": summary}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({k: v["summary"] for k, v in result["workloads"].items()}, indent=2))
