#!/usr/bin/env python3
"""Build/run isolated audit80 runtime fixtures using C99/POSIX and Python stdlib.

All output goes under this checkout's build directory, even for another source
tree. No source tree is edited. Benchmarks are synthetic, not production SLAs.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parent.parent
FLAGS = "-std=c99 -O1 -g -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L"


def run(command, **kwargs):
    return subprocess.run([str(x) for x in command], check=True, **kwargs)


def build(source, output, cc, flags, names):
    output.mkdir(parents=True, exist_ok=True)
    headers = sorted(p for part in ("src", "include", "vendor")
                     for p in (source / part).rglob("*") if p.suffix in (".h", ".inc", ".def"))
    config = hashlib.sha256((cc + "\0" + repr(flags) + str(source)).encode())
    for path in headers:
        config.update(str(path.relative_to(source)).encode()); config.update(path.read_bytes())
    includes = ["-I" + str(source / part) for part in ("src", "include", "vendor")]
    includes += ["-I" + str(ROOT / "tests/audit80")]
    key = config.hexdigest()
    sources = sorted((source / "src").glob("*.c"))
    sources = [p for p in sources if p.name not in ("axi_main.c", "axi_dossier_main.c")]
    sources += [source / "vendor/ed25519.c", ROOT / "tests/audit80/runtime_fixture.c"]

    def compile_one(path):
        obj = output / (path.stem + ".o")
        stamp = obj.with_suffix(".key")
        digest = hashlib.sha256((key + str(path)).encode() + path.read_bytes()).hexdigest()
        if not obj.exists() or not stamp.exists() or stamp.read_text() != digest:
            run([cc, *flags, *includes, "-c", path, "-o", obj], capture_output=True)
            stamp.write_text(digest)
        return obj

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        objects = list(pool.map(compile_one, sources))
    for name in names:
        obj = compile_one(ROOT / "tests/audit80" / (name + ".c"))
        run([cc, *flags, obj, *objects, "-lm", "-pthread", "-o", output / name], capture_output=True)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "build"), nargs="?", default="check")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "build/audit80-runtime")
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--cflags", default=os.environ.get("AXI_AUDIT_CFLAGS", FLAGS))
    args = parser.parse_args()
    try:
        names = ["runtime_workloads"]
        binaries = build(args.source.resolve(), args.output.resolve(), args.cc,
                         shlex.split(args.cflags), names)
        if args.mode == "check":
            for name in names: run([binaries / name], timeout=60)
    except subprocess.CalledProcessError as error:
        if error.stderr: print(error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else error.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
