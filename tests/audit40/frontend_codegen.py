#!/usr/bin/env python3
"""Audit40 source -> signed AXB -> real VM regressions; fixed test identity."""
import pathlib
import subprocess
import sys
import tempfile

AXI = pathlib.Path(sys.argv[1]).resolve()
GROUP = sys.argv[2] if len(sys.argv) > 2 else "all"


def invoke(*args, timeout=20):
    return subprocess.run([str(AXI), *map(str, args)], text=True,
                          capture_output=True, timeout=timeout)


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


with tempfile.TemporaryDirectory(prefix="axi-frontend-") as td:
    tmp = pathlib.Path(td)
    seed = tmp / "test.seed"
    pub = tmp / "test.pk"
    seed.write_bytes(bytes(range(32)))
    pub.write_bytes(bytes.fromhex(
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"))

    def compile_source(name, source):
        src = tmp / (name + ".axi")
        artifact = tmp / (name + ".axb")
        src.write_text(source)
        result = invoke("compile", src, "-o", artifact, "--signing-key", seed)
        check(result.returncode == 0, f"{name}: compile refused: {result.stderr}")
        return artifact

    def expect_value(artifact, cell, args, value):
        result = invoke("run", artifact, cell, *args, "--trusted-key", pub)
        check(result.returncode == 0 and result.stdout.strip() == value,
              f"{cell}{args}: expected {value!r}, got rc={result.returncode} "
              f"{result.stdout!r} {result.stderr!r}")

    if GROUP in ("all", "branches"):
        # Both branches fall through. A stale byte offset after widening jf
        # makes the then-path jmp skip the following ret's ldk instruction.
        for statements in (3, 9, 20, 70, 1001):
            body = "    0\n" * statements + "    if flag {}\n"
            source = ("cell branch : fn(flag: bool) -> u64\n  fuel 10000\n{\n"
                      f"  if flag {{\n{body}  }} else {{\n{body}  }}\n"
                      "  ret 77\n}\n")
            artifact = compile_source("branches" + str(statements), source)
            expect_value(artifact, "branch", ["true"], "u64 77")
            expect_value(artifact, "branch", ["false"], "u64 77")
        nested = """cell branch : fn(a: bool, b: bool) -> u64
  fuel 10000
{
  if a {
    if b { 1 2 3 4 5 6 7 8 9 } else { 10 11 12 13 14 15 16 }
    20 21 22 23 24 25 26
  } else { 30 31 32 33 34 35 36 37 38 }
  ret 77
}
"""
        artifact = compile_source("nested_branches", nested)
        for a in ("false", "true"):
            for b in ("false", "true"):
                expect_value(artifact, "branch", [a, b], "u64 77")
        print("frontend W02: PASS (branch relocation widths and nested paths)")
