#!/usr/bin/env python3
"""Build identical audit probes against two trees and record paired measurements.

Usage: python3 tools/audit40-bench.py --baseline ../axial-baseline \
    --candidate . --output docs/audit40/benchmark.json
Only C99/POSIX, Python's standard library, and a C compiler are required.
The output contains raw samples; there are no performance pass thresholds.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import tempfile
import time

FLAGS = ["-std=c99", "-Wall", "-Wextra", "-Werror", "-O1",
         "-D_POSIX_C_SOURCE=200809L"]


def run(command, **kwargs):
    return subprocess.run([str(x) for x in command], check=True,
                          capture_output=True, **kwargs)


def build(tree, fixtures, cc):
    output = tree / "build/audit40-bench"
    output.mkdir(parents=True, exist_ok=True)
    include = ["-I" + str(tree / part) for part in ("src", "include", "vendor")]
    sources = sorted((tree / "src").glob("*.c"))
    sources = [p for p in sources if p.name not in ("axi_main.c", "axi_dossier_main.c")]
    sources += [tree / "vendor/ed25519.c"]

    def compile_one(source):
        obj = output / (source.stem + ".o")
        run([cc, *FLAGS, *include, "-c", source, "-o", obj])
        return obj

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        objects = list(pool.map(compile_one, sources))
    for name, source in [("axi", tree / "src/axi_main.c")] + [
            (name, fixtures / "tests/audit40" / (name + ".c"))
            for name in ("embed", "seal", "runtime_bench")]:
        obj = compile_one(source)
        run([cc, *FLAGS, "-o", output / name, obj, *objects, "-lm"])
    return output


def identity(tree):
    header = (tree / "src/axi_checker_identity.h").read_text()
    return {
        "revision": run(["git", "-C", tree, "rev-parse", "HEAD"], text=True).stdout.strip(),
        "checker_source_root": re.search(r'"([a-f0-9]{64})"', header).group(1),
        "public_header_sha256": hashlib.sha256(
            (tree / "include/axial/axi_embed_v1.h").read_bytes()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", default=Path("."), type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--samples", default=7, type=int)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    if not 3 <= args.samples <= 100:
        parser.error("samples must be between 3 and 100")
    trees = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    bins = {}
    for label, tree in trees.items():
        print(f"Preparing {label}: {tree}", flush=True)
        bins[label] = (tree / "build/audit40-bench" if args.skip_build else
                       build(tree, trees["candidate"], args.cc))
        for executable in ("axi", "embed", "seal", "runtime_bench"):
            (bins[label] / executable).chmod(0o755)
    if args.build_only:
        return

    # Pin only the measurement process and children, after parallel compilation.
    cpu = None
    if hasattr(os, "sched_getaffinity") and hasattr(os, "sched_setaffinity"):
        cpu = min(os.sched_getaffinity(0))
        os.sched_setaffinity(0, {cpu})
    metadata = {
        "measured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "compiler": run([args.cc, "--version"], text=True).stdout.splitlines()[0],
        "flags": FLAGS, "platform": platform.platform(), "python": platform.python_version(),
        "cpu_affinity": cpu, "warmups_per_case_and_revision": 1,
        "samples_per_revision": args.samples, "order": "alternating baseline/candidate pairs",
        "revisions": {label: identity(tree) for label, tree in trees.items()},
        "limits": ["Microbenchmarks on this host, not an application SLA.",
                   "CPU frequency and other host tenants are not controlled.",
                   "Candidate revision precedes the report commit; source root identifies product bytes.",
                   "C probes time the named operation internally; CLI samples include process startup."],
    }
    results = []
    env = dict(os.environ, LC_ALL="C")

    def measure(name, commands, expected_rc=0, metrics=None):
        samples = {label: [] for label in trees}
        reference = None
        for repetition in range(args.samples + 1):
            labels = ("baseline", "candidate") if repetition % 2 == 0 else ("candidate", "baseline")
            for label in labels:
                begin = time.perf_counter()
                proc = subprocess.run([str(x) for x in commands(label)], capture_output=True,
                                      timeout=60, env=env)
                elapsed = time.perf_counter() - begin
                if proc.returncode != expected_rc:
                    raise RuntimeError(f"{name}/{label}: rc={proc.returncode}; "
                                       f"{proc.stdout[:400]!r} {proc.stderr[:400]!r}")
                if metrics:
                    sample = json.loads(proc.stdout)
                else:
                    exact = (proc.stdout, proc.stderr)
                    if reference is None:
                        reference = exact
                    if exact != reference:
                        raise RuntimeError(f"{name}: observable output differs")
                    sample = {"seconds": elapsed}
                if repetition:
                    samples[label].append(sample)
        metrics = metrics or {"seconds": 1.0}
        for field, factor in metrics.items():
            values = {label: [sample[field] * factor for sample in rows]
                      for label, rows in samples.items()}
            medians = {label: statistics.median(rows) for label, rows in values.items()}
            result = {"case": name, "metric": field, "samples_seconds": values,
                      "median_seconds": medians,
                      "candidate_time_reduction_pct": 100 * (1 - medians["candidate"] / medians["baseline"]),
                      "speedup": medians["baseline"] / medians["candidate"], "raw": samples}
            results.append(result)
            print(f"{name}/{field}: {medians['baseline']:.6f}s -> "
                  f"{medians['candidate']:.6f}s ({result['speedup']:.3f}x)", flush=True)

    for cells in (1, 16, 256):
        measure(f"embed_{cells}_cells_200000_evaluations",
                lambda label, cells=cells: [bins[label]/"embed", "--bench", 200000, cells],
                metrics={"seconds": 1.0})
    for laws, iterations in ((1, 3000), (16, 300), (64, 50)):
        measure(f"seal_{laws}_laws_{iterations}_verifications",
                lambda label, laws=laws, iterations=iterations:
                    [bins[label]/"seal", "--bench", iterations, laws], metrics={"seconds": 1.0})
    for name, count, metrics in (("vm", 5000000, {"ns": 1e-9}),
                                  ("alloc", 8192, {"allocate_ns": 1e-9, "free_ns": 1e-9}),
                                  ("asm", 250000, {"ns": 1e-9})):
        measure(f"{name}_{count}", lambda label, name=name, count=count:
                [bins[label]/"runtime_bench", name, count], metrics=metrics)
    with tempfile.TemporaryDirectory(prefix="axial-audit40-bench-") as td:
        root = Path(td)
        invalid = root / "invalid.axi"
        invalid.write_bytes(b"@" * 65536)
        graph = root / "graph.axi"
        cells = []
        for i in range(256):
            expr = f"c{i+1}()" if i < 255 else 'fs.path_under("/x", "/")'
            cells.append(f"cell c{i} : fn() -> bool\n  fuel 10000\n  cap fs.Read\n{{\n"
                         + "  0\n" * 100 + f"  ret {expr}\n}}\n")
        graph.write_text("\n".join(cells))
        measure("cap_forward_256x100", lambda label: [bins[label]/"axi", "types", graph])
        measure("invalid_bytes_65536", lambda label: [bins[label]/"axi", "lex", invalid], 1)
        canonical = root / "canonical.axi"
        canonical.write_bytes(run([bins["candidate"]/"axi", "canon", graph]).stdout)
        measure("iface_canonical_256x100", lambda label: [bins[label]/"axi", "iface", canonical])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"metadata": metadata, "results": results}, indent=2) + "\n")
    print(f"Wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
