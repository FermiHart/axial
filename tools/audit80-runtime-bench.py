#!/usr/bin/env python3
"""Build/run isolated audit80 runtime fixtures using C99/POSIX and Python stdlib.

All output goes under this checkout's build directory, even for another source
tree. No source tree is edited. Benchmarks are synthetic, not production SLAs.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import statistics
import subprocess

ROOT = Path(__file__).resolve().parent.parent
FLAGS = "-std=c99 -O1 -g -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L"


def run(command, **kwargs):
    return subprocess.run([str(x) for x in command], check=True, **kwargs)


def build(source, output, cc, flags, names):
    output.mkdir(parents=True, exist_ok=True)
    headers = sorted(p for part in ("src", "include", "vendor")
                     for p in (source / part).rglob("*") if p.suffix in (".h", ".inc", ".def"))
    headers += sorted((ROOT / "tests/audit80").glob("runtime*.h"))
    config = hashlib.sha256((cc + "\0" + repr(flags) + str(source)).encode())
    for path in headers:
        config.update(str(path).encode()); config.update(path.read_bytes())
    includes = ["-I" + str(source / part) for part in ("src", "include", "vendor")]
    includes += ["-I" + str(ROOT / "tests/audit80")]
    key = config.hexdigest()
    sources = sorted((source / "src").glob("*.c"))
    sources = [p for p in sources if p.name not in ("axi_main.c", "axi_dossier_main.c")]
    sources += [source / "vendor/ed25519.c", ROOT / "tests/audit80/runtime_fixture.c"]

    def compile_one(path, extra_flags=(), name=None):
        obj = output / ((name or path.stem) + ".o")
        stamp = obj.with_suffix(".key")
        digest = hashlib.sha256((key + str(path) + repr(extra_flags)).encode() + path.read_bytes()).hexdigest()
        if not obj.exists() or not stamp.exists() or stamp.read_text() != digest:
            run([cc, *flags, *extra_flags, *includes, "-c", path, "-o", obj], capture_output=True)
            stamp.write_text(digest)
        return obj

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        objects = list(pool.map(compile_one, sources))
    for name in names:
        defines = {"runtime_concurrency_uncached": "-DSHA256NI_NO_CACHE=1",
                   "runtime_concurrency_software": "-DSHA256NI_FORCE_SOFTWARE=1"}
        src_name = "runtime_concurrency" if name in defines else name
        obj = compile_one(ROOT / "tests/audit80" / (src_name + ".c"),
                          [defines[name]] if name in defines else (), name)
        extra = []
        if name in ("runtime_lifecycle", "runtime_memory"):
            extra = [compile_one(ROOT / "tests/audit80/runtime_track.c"),
                     "-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free"]
        run([cc, *flags, obj, *objects, *extra, "-lm", "-pthread", "-o", output / name], capture_output=True)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "build", "context"), nargs="?", default="check")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "build/audit80-runtime")
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--cflags", default=os.environ.get("AXI_AUDIT_CFLAGS", FLAGS))
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--only", nargs="+", help="build/check only the named runtime_* fixtures")
    args = parser.parse_args()
    if not 3 <= args.samples <= 100: parser.error("samples must be between 3 and 100")
    try:
        names = ["runtime_workloads", "runtime_lifecycle", "runtime_memory", "runtime_stack", "runtime_concurrency",
                 "runtime_concurrency_uncached", "runtime_concurrency_software", "runtime_bench"]
        if args.only:
            if set(args.only) - set(names): parser.error("unknown fixture in --only")
            names = args.only
        binaries = build(args.source.resolve(), args.output.resolve(), args.cc,
                         shlex.split(args.cflags), names)
        if args.mode == "check":
            for name in names:
                if name != "runtime_bench": run([binaries / name], timeout=60)
        elif args.mode == "context":
            cpu = None
            if hasattr(os, "sched_getaffinity"):
                cpu = min(os.sched_getaffinity(0))
                os.sched_setaffinity(0, {cpu})
            results = []
            for cells, laws in ((13, 0), (64, 16), (256, 64)):
                command = [binaries / "runtime_bench", "context", cells, laws, 20]
                run(command, capture_output=True, timeout=60)  # warmup process
                samples = [json.loads(run(command, capture_output=True, text=True, timeout=60).stdout)
                           for _ in range(args.samples)]
                results.append({"cells": cells, "laws": laws, "samples": samples,
                    "median_create_ns_per_context": statistics.median(s["create_ns"] / s["iterations"] for s in samples),
                    "median_destroy_ns_per_context": statistics.median(s["destroy_ns"] / s["iterations"] for s in samples)})
            report = {"schema": "axial.audit80.context.v1", "measured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "revision": run(["git", "-C", args.source, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
                "compiler": run([args.cc, "--version"], capture_output=True, text=True).stdout.splitlines()[0],
                "flags": shlex.split(args.cflags), "cpu_affinity": cpu,
                "limits": ["Synthetic modules, no production traffic supplied.", "Pinned CPU is shared; frequency and other tenants uncontrolled.",
                           "Each context is new; process/crypto/OS caches are warmed. Parsing/signing fixture setup excluded.",
                           "Timing binary has no allocation wrappers; lifecycle allocation counts are a separate lane."], "results": results}
            data = json.dumps(report, indent=2) + "\n"
            if args.report:
                args.report.parent.mkdir(parents=True, exist_ok=True); args.report.write_text(data)
            else: print(data, end="")
    except subprocess.CalledProcessError as error:
        if error.stderr: print(error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else error.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
