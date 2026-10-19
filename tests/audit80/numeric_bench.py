#!/usr/bin/env python3
"""Paired numeric microbenchmark, with raw samples and identity checks.

Compile numeric_bench.c against each source revision using identical flags.
Correctness must pass numeric.sh first. No speed threshold is a test gate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("before", type=Path)
parser.add_argument("after", type=Path)
parser.add_argument("--before-source", type=Path, required=True)
parser.add_argument("--after-source", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--compiler", default="cc")
parser.add_argument("--flags", required=True)
parser.add_argument("--cpu", type=int, default=0)
args = parser.parse_args()
if hasattr(os, "sched_setaffinity"):
    os.sched_setaffinity(0, {args.cpu})
else:
    raise SystemExit("CPU affinity is unavailable; report an explicit unpinned experiment separately")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sample(executable, mode, count):
    p = subprocess.run([str(executable.resolve()), mode, str(count)],
                       text=True, capture_output=True, check=True, timeout=30)
    value = json.loads(p.stdout)
    assert value["mode"] == mode and value["iterations"] == count
    assert value["cpu_seconds"] > 0
    return value


result = {
    "schema": "axi.numeric.microbenchmark.v1",
    "metric": "C clock() process CPU seconds; no I/O in timed region",
    "method": "one warmup per binary/workload; seven alternating before/after pairs",
    "cpu": args.cpu, "affinity": sorted(os.sched_getaffinity(0)),
    "host": platform.platform(),
    "compiler": subprocess.check_output([args.compiler, "--version"], text=True).splitlines()[0],
    "flags_both": args.flags,
    "before": {"binary_sha256": sha(args.before), "source_sha256": sha(args.before_source)},
    "after": {"binary_sha256": sha(args.after), "source_sha256": sha(args.after_source)},
    "scope": "numeric helper only; exact W65 core versus subsequent arithmetic optimizations; not legacy semantics or end-to-end compile",
    "workloads": {},
}
for mode, count in [("format", 8192), ("reader", 65536)]:
    warmups = [sample(args.before, mode, count), sample(args.after, mode, count)]
    assert warmups[0]["checksum"] == warmups[1]["checksum"]
    pairs = []
    for index in range(7):
        labels = ["before", "after"] if index % 2 == 0 else ["after", "before"]
        pair = {"order": labels}
        for label in labels:
            value = sample(getattr(args, label), mode, count)
            assert value["checksum"] == warmups[0]["checksum"]
            pair[label] = value
        pairs.append(pair)
    before = [pair["before"]["cpu_seconds"] for pair in pairs]
    after = [pair["after"]["cpu_seconds"] for pair in pairs]
    summary = {
        "before_median": statistics.median(before), "before_min": min(before), "before_max": max(before),
        "after_median": statistics.median(after), "after_min": min(after), "after_max": max(after),
        "median_change_percent": (statistics.median(after) / statistics.median(before) - 1) * 100,
    }
    result["workloads"][mode] = {"warmups": warmups, "pairs": pairs, "summary": summary}
args.output.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({name: value["summary"] for name, value in result["workloads"].items()}, indent=2))
