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

    if GROUP in ("all", "calls"):
        source = """cell add : fn(a: u64, b: u64) -> u64
  fuel 1000
  pure
{ ret a + b }
cell retain : fn() -> u64
  fuel 10000
  pure
{
  let keep = 99
  add(1, 2)
  ret keep
}
cell builtin_retain : fn() -> u64
  fuel 10000
  pure
{
  let keep = 99
  math.add_checked(1, 2)
  ret keep
}
cell nested : fn() -> u64
  fuel 10000
  pure
{
  let keep = 100
  ret add(add(1, 2), add(3, 4)) + keep
}
cell noargs : fn() -> u64
  fuel 1000
  pure
{ ret 7 }
cell twice : fn() -> u64
  fuel 10000
  pure
{ ret noargs() + noargs() }
"""
        artifact = compile_source("call_windows", source)
        for cell, value in (("retain", 99), ("builtin_retain", 99),
                            ("nested", 110), ("twice", 14)):
            expect_value(artifact, cell, [], "u64 " + str(value))
        repeated = ("cell repeat : fn() -> u64\n  fuel 100000\n  pure\n{\n"
                    "  let keep = 99\n" + "  math.add_checked(1, 2)\n" * 100
                    + "  ret keep\n}\n")
        artifact = compile_source("temporary_lifetime", repeated)
        expect_value(artifact, "repeat", [], "u64 99")
        # Sixteen live arguments must be copied into a genuinely free window.
        params = ", ".join(f"a{i}: u64" for i in range(16))
        source = (f"cell wide : fn({params}) -> u64\n  fuel 1000\n  pure\n"
                  "{ ret a0 + a15 }\ncell test : fn() -> u64\n"
                  "  fuel 10000\n  pure\n{\n  let keep = 99\n"
                  "  let sum = wide(" + ", ".join(str(i) for i in range(16))
                  + ")\n  ret keep + sum\n}\n")
        artifact = compile_source("sixteen_arguments", source)
        expect_value(artifact, "test", [], "u64 114")
        print("frontend W03: PASS (live bindings, nesting, zero/16 args, reuse)")
