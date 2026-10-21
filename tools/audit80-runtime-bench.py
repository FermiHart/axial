#!/usr/bin/env python3
"""Build/run isolated audit80 runtime fixtures using C99/POSIX and Python stdlib.

All output goes under this checkout's build directory, even for another source
tree. No source tree is edited. Benchmarks are synthetic, not production SLAs.
"""
import argparse
import concurrent.futures
import datetime
import gzip
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

ROOT = Path(__file__).resolve().parent.parent
FLAGS = "-std=c99 -O1 -g -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L"
BASELINE = "82596bf8faf607e25f7366e36381a8dad58302a1"


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
        linked_objects = objects
        if name in ("runtime_lifecycle", "runtime_memory"):
            extra = [compile_one(ROOT / "tests/audit80/runtime_track.c"),
                     "-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free"]
        if name == "runtime_context_profile":
            extra = ["-Wl,--wrap=axi_sha256,--wrap=ed25519_verify"]
        if name in ("runtime_io_faults", "runtime_recovery"):
            redirects = ["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0"]
            redirects += ["-D" + operation + "=runtime80_io_" + operation
                          for operation in ("read", "write", "fsync", "renameat")]
            wrapped = compile_one(source / "src/axi_local_attempt_v1.c", redirects, "runtime_store_attempt")
            linked_objects = [path for path in objects if path.name != "axi_local_attempt_v1.o"]
            extra = [wrapped, compile_one(ROOT / "tests/audit80/runtime_store.c"),
                     compile_one(ROOT / "tests/audit80/runtime_store_io.c")]
        run([cc, *flags, obj, *linked_objects, *extra, "-lm", "-pthread", "-o", output / name], capture_output=True)
    return output


def source_digest(source):
    digest = hashlib.sha256()
    for path in sorted(p for part in ("src", "include", "vendor")
                       for p in (source / part).rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(source)).encode() + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def baseline_snapshot(output, revision):
    revision = run(["git", "-C", ROOT, "rev-parse", "--verify", revision + "^{commit}"],
                   capture_output=True, text=True).stdout.strip()
    archive = run(["git", "-C", ROOT, "archive", revision, "src", "include", "vendor"],
                  capture_output=True).stdout
    destination = output / ("baseline-" + revision) / "source"
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
        for member in tree:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or path.parts[0] not in ("src", "include", "vendor"):
                raise ValueError("unexpected baseline archive path")
            if member.isdir():
                (destination / path).mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                (destination / path).parent.mkdir(parents=True, exist_ok=True)
                (destination / path).write_bytes(tree.extractfile(member).read())
            else:
                raise ValueError("baseline must contain only regular source files and directories")
    return destination, revision


def distribution(values):
    ordered = sorted(values)
    return {"n": len(ordered), "min": ordered[0], "max": ordered[-1],
            "mean": statistics.fmean(ordered),
            **{"p" + str(q): ordered[(len(ordered) * q + 99) // 100 - 1] for q in (50, 95, 99)}}


def timing_summary(samples):
    first = samples[0]
    if first["case"] == "mixed_latency":
        workloads = []
        for i, workload in enumerate(first["workloads"]):
            rounds = [s["workloads"][i] for s in samples]
            oracle = (workload["name"], workload["outcome"], workload["fuel"])
            if any((r["name"], r["outcome"], r["fuel"]) != oracle for r in rounds):
                raise ValueError("workload oracle changed between samples")
            workloads.append({"name": oracle[0], "outcome": oracle[1], "fuel": oracle[2],
                              "latency_ns": distribution([v for r in rounds for v in r["latency_ns"]]),
                              "round_latency_ns": [distribution(r["latency_ns"]) for r in rounds]})
        return {"workloads": workloads,
                "clock_pair_ns": distribution([v for s in samples for v in s["clock_pair_ns"]]),
                "validated_loop_ops_per_second": distribution([
                    s["validated_loop_operations"] * 1e9 / s["validated_loop_ns"] for s in samples])}
    if first["case"] == "context":
        return {key: distribution([v for s in samples for v in s[key]])
                for key in ("create_samples_ns", "destroy_samples_ns")}
    return {"validated_loop_ops_per_second": distribution([
        s["operations"] * 1e9 / s["elapsed_ns"] for s in samples])}


def measure(args, candidate):
    source = args.source.resolve()
    variants = {"candidate": candidate}
    revisions = {"candidate": run(["git", "-C", source, "rev-parse", "HEAD"],
                 capture_output=True, text=True).stdout.strip()}
    digests = {"candidate": source_digest(source)}
    if args.mode == "compare":
        baseline, revisions["baseline"] = baseline_snapshot(args.output.resolve(), args.baseline_revision)
        variants["baseline"] = build(baseline, baseline.parent / "bin", args.cc,
                                      shlex.split(args.cflags), ["runtime_bench"])
        digests["baseline"] = source_digest(baseline)
    available = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
    configurations = [("mixed", ["latency", args.iterations], 1)]
    configurations += [(f"context_{cells}_{laws}", ["context", cells, laws, args.context_iterations], 1)
                       for cells, laws in ((13, 0), (64, 16), (256, 64))]
    configurations += [(f"parallel_{workers}", ["parallel", workers, args.iterations], workers)
                       for workers in (1, 2, 4, 8)]
    raw, summaries = {}, {}
    try:
        for name, command, workers in configurations:
            affinity = available[:workers]
            if affinity: os.sched_setaffinity(0, affinity)
            raw[name] = {variant: [] for variant in variants}
            for sample in range(args.samples):
                order = list(variants) if sample % 2 == 0 else list(reversed(variants))
                for variant in order:
                    data = json.loads(run([variants[variant] / "runtime_bench", *command],
                                          capture_output=True, text=True, timeout=60).stdout)
                    data["round"] = sample; data["order"] = order; data["cpu_affinity"] = affinity
                    raw[name][variant].append(data)
            summaries[name] = {variant: timing_summary(data) for variant, data in raw[name].items()}
            if name == "mixed" and "baseline" in summaries[name]:
                oracles = [[(w["name"], w["outcome"], w["fuel"]) for w in summaries[name][v]["workloads"]]
                           for v in ("baseline", "candidate")]
                if oracles[0] != oracles[1]: raise ValueError("baseline/candidate semantic oracle differs")
            print("measured " + name, flush=True)
    finally:
        if available: os.sched_setaffinity(0, available)
    quota = Path("/sys/fs/cgroup/cpu.max")
    fixture_hash = hashlib.sha256()
    for name in ("runtime_fixture.h", "runtime_fixture.c", "runtime_bench.c"):
        fixture_hash.update(name.encode() + b"\0" + (ROOT / "tests/audit80" / name).read_bytes())
    report = {"schema": "axial.audit80.latency.v1", "measured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "revisions": revisions, "source_sha256": digests, "fixture_sha256": fixture_hash.hexdigest(),
              "compiler": run([args.cc, "--version"], capture_output=True, text=True).stdout.splitlines()[0],
              "flags": shlex.split(args.cflags), "host": platform.platform(), "available_cpus": available,
              "cpu_max": quota.read_text().strip() if quota.exists() else None,
              "rounds": args.samples, "iterations_per_workload_per_round": args.iterations,
              "contexts_per_configuration_per_round": args.context_iterations,
              "percentile_method": "nearest rank ceil(q * n), raw observations, no outlier removal",
              "limits": ["Synthetic equally weighted workloads; no production traffic or arrival process supplied.",
                         "Sequential alternating baseline/candidate processes; same compiler and fixtures, no allocation or sanitizer instrumentation.",
                         "CPU affinity is not exclusive isolation; frequency, tenants and cgroup scheduling are uncontrolled.",
                         "Eval timing excludes fixture preparation and result checks; clock overhead is reported and not subtracted.",
                         "Throughput includes each result/fuel oracle check, and parallel start/finish synchronization; it is a validated harness loop rate.",
                         "Setup and thread creation are outside timed intervals. New contexts use warmed crypto/allocator/OS caches.",
                         "Parallel readers share one immutable context and have private request/workspace/outcome storage; destruction follows all joins.",
                         "Observed tails and throughput are host evidence, not a production SLA or guaranteed scalability."],
              "results": summaries}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        raw_path = args.report.with_name(args.report.stem + ".samples.json.gz")
        raw_bytes = gzip.compress(json.dumps(raw, separators=(",", ":")).encode(), mtime=0)
        raw_path.write_bytes(raw_bytes)
        report["raw_samples"] = {"file": raw_path.name, "sha256": hashlib.sha256(raw_bytes).hexdigest()}
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    else:
        report["raw_samples"] = raw
        print(json.dumps(report, indent=2))


def context_identity(source, binaries, cc, flags):
    """GNU/ELF diagnostic evidence; generated helper never edits product source."""
    source_file = binaries / "runtime_context_identity.c"
    source_file.write_text('#include "runtime_fixture.h"\n#include <stdio.h>\n'
        'int main(void) { runtime80_fixture f; if (runtime80_fixture_init(&f,13,0)) return 1; '
        'if (fwrite(f.bytes,1,f.len,stdout)!=f.len) return 1; runtime80_fixture_free(&f); return 0; }\n')
    objects = [binaries / (path.stem + ".o") for path in sorted((source / "src").glob("*.c"))
               if path.name not in ("axi_main.c", "axi_dossier_main.c")]
    objects += [binaries / "ed25519.o", binaries / "runtime_fixture.o"]
    executable = binaries / "runtime_context_identity"
    includes = ["-I" + str(source / part) for part in ("src", "include", "vendor")]
    run([cc, *flags, *includes, "-I" + str(ROOT / "tests/audit80"), source_file,
         *objects, "-lm", "-pthread", "-o", executable], capture_output=True)
    module = run([executable], capture_output=True).stdout
    section = binaries / "ed25519.text.bin"
    run(["objcopy", "-O", "binary", "--only-section=.text", binaries / "ed25519.o", section], capture_output=True)
    addresses = {}
    for suffix in ("", "_crypto_first"):
        symbols = run(["nm", "-n", binaries / ("runtime_bench" + suffix)], capture_output=True, text=True).stdout
        addresses["crypto_first" if suffix else "original"] = next(
            line.split()[0] for line in symbols.splitlines() if line.endswith(" ed25519_verify"))
    code = section.read_bytes()
    return {"fixture": "13 cells, 0 laws, signature-valid", "signed_module_bytes": len(module),
            "signed_module_sha256": hashlib.sha256(module).hexdigest(),
            "ed25519_text_bytes": len(code), "ed25519_text_sha256": hashlib.sha256(code).hexdigest(),
            "ed25519_verify_link_address": addresses}


def context_diagnose(args, candidate):
    """Keep cryptographic work fixed while controlling compiler/link placement."""
    flags = shlex.split(args.cflags)
    release_flags = ["-O2" if flag.startswith("-O") else flag for flag in flags]
    if not any(flag.startswith("-O") for flag in flags): release_flags.append("-O2")
    base, revision = baseline_snapshot(args.output.resolve(), args.baseline_revision)
    baseline = build(base, base.parent / "bin", args.cc, flags,
                     ["runtime_bench", "runtime_context_profile"])
    variants = {}
    for label, source, binaries in (("baseline", base, baseline),
                                    ("candidate", args.source.resolve(), candidate)):
        variants[label + "_selected"] = (binaries / "runtime_bench", binaries / "runtime_context_profile")
        core = [binaries / (path.stem + ".o") for path in sorted((source / "src").glob("*.c"))
                if path.name not in ("axi_main.c", "axi_dossier_main.c")]
        objects = [binaries / "ed25519.o", *core, binaries / "runtime_fixture.o"]
        fixed = []
        for name in ("runtime_bench", "runtime_context_profile"):
            binary = binaries / (name + "_crypto_first")
            extra = ["-Wl,--wrap=axi_sha256,--wrap=ed25519_verify"] if name == "runtime_context_profile" else []
            run([args.cc, *flags, binaries / (name + ".o"), *objects, *extra, "-lm", "-pthread", "-o", binary],
                capture_output=True)
            fixed.append(binary)
        variants[label + "_crypto_first"] = tuple(fixed)
        release_output = (base.parent / "bin-o2" if label == "baseline" else
                          args.output.resolve().with_name(args.output.name + "-o2"))
        release = build(source, release_output, args.cc, release_flags,
                        ["runtime_bench", "runtime_context_profile"])
        variants[label + "_release"] = (release / "runtime_bench", release / "runtime_context_profile")
    available = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
    raw, summary = {}, {}
    try:
        if available: os.sched_setaffinity(0, {available[0]})
        for cells, laws in ((13, 0), (64, 16), (256, 64)):
            key = f"context_{cells}_{laws}"
            raw[key] = {name: [] for name in variants}
            for sample in range(args.samples):
                order = list(variants) if sample % 2 == 0 else list(reversed(variants))
                for name in order:
                    data = json.loads(run([variants[name][0], "context", cells, laws, args.context_iterations],
                                          capture_output=True, text=True, timeout=60).stdout)
                    data["round"] = sample; data["order"] = order
                    raw[key][name].append(data)
            summary[key] = {name: timing_summary(data) for name, data in raw[key].items()}
            print("diagnosed " + key, flush=True)
        raw["phase_13_0"] = {name: [] for name in variants}
        for sample in range(args.samples):
            order = list(variants) if sample % 2 == 0 else list(reversed(variants))
            for name in order:
                data = json.loads(run([variants[name][1], 13, 0, 20], capture_output=True,
                                      text=True, timeout=60).stdout)
                data["round"] = sample; data["order"] = order
                raw["phase_13_0"][name].append(data)
        summary["phase_13_0"] = {
            name: {key + "_per_context": distribution([s[key] / s["iterations"] for s in samples])
                   for key in ("total_ns", "sha256_ns", "sha256_calls", "ed25519_verify_ns", "ed25519_verify_calls")}
            for name, samples in raw["phase_13_0"].items()}
    finally:
        if available: os.sched_setaffinity(0, available)
    report = {"schema": "axial.audit80.context-diagnosis.v1",
              "measured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "baseline_revision": revision,
              "candidate_revision": run(["git", "-C", args.source, "rev-parse", "HEAD"],
                                         capture_output=True, text=True).stdout.strip(),
              "source_sha256": {"baseline": source_digest(base), "candidate": source_digest(args.source.resolve())},
              "selected_flags": flags, "release_flags": release_flags,
              "compiler": run([args.cc, "--version"], capture_output=True, text=True).stdout.splitlines()[0],
              "cpu_affinity": available[:1], "rounds": args.samples,
              "contexts_per_configuration_per_round": args.context_iterations,
              "limits": ["Creation only; no production arrival process or SLA.",
                         "Selected and release binaries have no timing instrumentation; phase binaries wrap only SHA-256 and Ed25519 verify.",
                         "Crypto-first binaries relink the same existing objects; source, signatures and verification policy are unchanged.",
                         "Phase times include probe clock overhead and are diagnostic, not absolute performance numbers.",
                         "The CPU is pinned but shared, with uncontrolled frequency and other tenants. No outlier removal."],
              "results": summary, "raw_samples": raw}
    report["artifact_identity"] = {
        "baseline": context_identity(base, baseline, args.cc, flags),
        "candidate": context_identity(args.source.resolve(), candidate, args.cc, flags)}
    data = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True); args.report.write_text(data)
    else: print(data, end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "build", "context", "latency", "compare", "diagnose-context"), nargs="?", default="check")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "build/audit80-runtime")
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--cflags", default=os.environ.get("AXI_AUDIT_CFLAGS", FLAGS))
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--context-iterations", type=int, default=100)
    parser.add_argument("--baseline-revision", default=BASELINE)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--only", nargs="+", help="build/check only the named runtime_* fixtures")
    args = parser.parse_args()
    if not 3 <= args.samples <= 100: parser.error("samples must be between 3 and 100")
    if not 100 <= args.iterations <= 100000: parser.error("iterations must be between 100 and 100000")
    if not 10 <= args.context_iterations <= 10000: parser.error("context-iterations must be between 10 and 10000")
    try:
        names = ["runtime_workloads", "runtime_lifecycle", "runtime_memory", "runtime_stack", "runtime_concurrency",
                 "runtime_concurrency_uncached", "runtime_concurrency_software", "runtime_io_faults", "runtime_recovery",
                 "runtime_bench", "runtime_context_profile"]
        if args.only:
            if set(args.only) - set(names): parser.error("unknown fixture in --only")
            names = args.only
        if args.mode in ("context", "latency", "compare"): names = ["runtime_bench"]
        if args.mode == "diagnose-context": names = ["runtime_bench", "runtime_context_profile"]
        binaries = build(args.source.resolve(), args.output.resolve(), args.cc,
                         shlex.split(args.cflags), names)
        if args.mode == "check":
            for name in names:
                if name not in ("runtime_bench", "runtime_context_profile"): run([binaries / name], timeout=60)
        elif args.mode == "diagnose-context":
            context_diagnose(args, binaries)
        elif args.mode in ("latency", "compare"):
            measure(args, binaries)
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
