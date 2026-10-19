#!/usr/bin/env python3
"""Source -> signed v7 -> real VM regressions, deterministic public test key."""
import pathlib
import subprocess
import sys
import tempfile

AXI = pathlib.Path(sys.argv[1]).resolve()
GROUP = sys.argv[2] if len(sys.argv) > 2 else "all"


def call(*args):
    return subprocess.run([str(AXI), *map(str, args)], capture_output=True,
                          text=True, timeout=30)


def require(ok, detail):
    if not ok:
        raise AssertionError(detail)


with tempfile.TemporaryDirectory(prefix="axial-audit80-frontend-") as td:
    root = pathlib.Path(td)
    seed, pk = root / "test.seed", root / "test.pk"
    seed.write_bytes(bytes(range(32)))
    pk.write_bytes(bytes.fromhex(
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"))

    def compile_source(name, text):
        source, artifact = root / (name + ".axi"), root / (name + ".axb")
        source.write_text(text)
        p = call("compile", source, "-o", artifact, "--signing-key", seed)
        require(p.returncode == 0, (name, p.returncode, p.stderr))
        return artifact

    def value(artifact, cell, args, expected):
        p = call("run", artifact, cell, *args, "--trusted-key", pk)
        require(p.returncode == 0 and p.stdout.rstrip() == expected,
                (cell, args, expected, p.returncode, p.stdout, p.stderr))

    def refused(name, text, diagnostic):
        source, artifact = root / (name + ".axi"), root / (name + ".axb")
        source.write_text(text)
        p = call("compile", source, "-o", artifact, "--signing-key", seed)
        require(p.returncode != 0 and diagnostic in p.stderr and not artifact.exists(),
                (name, p.returncode, p.stdout, p.stderr))

    def error(atom):
        return "err %d %s 0" % (len(atom), atom.encode().hex())

    if GROUP in ("all", "errors"):
        artifact = compile_source("errors", '''cell direct : fn() -> err.Io
  fuel 100
  pure
{ ret err.Io }
cell bound : fn() -> str | err.Io
  fuel 100
  pure
{ let literal = "Io" let failure = err.Io ret failure }
cell branch : fn(fail: bool) -> str | err.fs.Missing
  fuel 100
  pure
{ if fail { ret err.fs.Missing } ret "fs.Missing" }
cell text : fn() -> str
  fuel 100
  pure
{ let ignored = err.Io ret "Io" }
''')
        value(artifact, "direct", [], error("Io"))
        value(artifact, "bound", [], error("Io"))
        value(artifact, "branch", ["true"], error("fs.Missing"))
        value(artifact, "branch", ["false"], "str 10 66732e4d697373696e67")
        value(artifact, "text", [], "str 2 496f")
        refused("undeclared", "cell f : fn() -> ok fuel 100 { ret err.Io }", "AXI-T018")
        refused("bad_atom", "cell f : fn() -> ok fuel 100 { err." + "a" * 64 + " ret ok }", "AXI-T002")
        print("frontend W51: PASS (error atoms, bindings, branches and string namespace)")

    if GROUP in ("all", "returns"):
        cases = [("u64", "7", "u64 7"), ("i64", "-7", "i64 -7"),
                 ("f64", "0.5", "f64 3fe0000000000000"),
                 ("bool", "false", "bool false"),
                 ("decision", "true", "decision true"),
                 ("str", '"x"', "str 1 78")]
        for ty, literal, expected in cases:
            for reversed_order in (False, True):
                returns = "ok | " + ty if reversed_order else ty + " | ok"
                artifact = compile_source("returns_" + ty + str(reversed_order),
                    "cell choose : fn(none: bool) -> " + returns + " | err.Io\n"
                    "  fuel 100\n  pure\n{ if none { ret } let p = " + literal + " ret p }\n")
                value(artifact, "choose", ["false"], "union 0 " + expected)
                value(artifact, "choose", ["true"], "union 1 ok")
        artifact = compile_source("return_json", '''cell choose : fn(p: json, none: bool) -> json | ok
  fuel 100
  pure
{ if none { ret ok } ret p }
''')
        value(artifact, "choose", ["{}", "false"], "union 0 json 2 7b7d")
        value(artifact, "choose", ["{}", "true"], "union 1 ok")
        print("frontend W52: PASS (all admitted option payloads and canonical manifest tags)")

    if GROUP in ("all", "result"):
        artifact = compile_source("result", '''cell risky : fn(n: u64) -> u64 | err.One | err.Two
  fuel 1000
  pure
{ if n == 1 { ret err.One } if n == 2 { ret err.Two } ret n }
cell middle : fn(n: u64) -> u64 | err.Two | err.One
  fuel 1000
  pure
{ let value = risky(n)? ret value + 1 }
cell outer : fn(a: u64, b: u64) -> u64 | err.One | err.Two
  fuel 1000
  pure
{ ret middle(a)? + middle(b)? }
cell before_trap : fn(a: u64) -> u64 | err.One | err.Two
  fuel 1000
  pure
{ ret risky(a)? + 1 / 0 }
cell always : fn() -> err.One
  fuel 1000
  pure
{ ret err.One }
cell only_errors : fn() -> ok | err.One
  fuel 1000
  pure
{ always()? ret ok }
''')
        value(artifact, "outer", ["4", "5"], "u64 11")
        value(artifact, "outer", ["1", "0"], error("One"))
        value(artifact, "outer", ["0", "2"], error("Two"))
        value(artifact, "before_trap", ["1"], error("One"))
        value(artifact, "only_errors", [], error("One"))
        prefix = "cell r : fn() -> u64 | err.X fuel 100 { ret err.X }\n"
        refused("missing_error", prefix + "cell f : fn() -> u64 fuel 100 { ret r()? }", "AXI-T015")
        refused("leaked_result", prefix + "cell f : fn() -> u64 | err.X fuel 100 { ret r() }", "AXI-T013")
        refused("try_scalar", "cell f : fn() -> u64 fuel 100 { ret 1? }", "AXI-T014")
        print("frontend W53: PASS (named-error propagation, nested calls, short circuit and refusals)")

    if GROUP in ("all", "options"):
        artifact = compile_source("options", '''cell option : fn(n: u64) -> u64 | ok | err.Bad
  fuel 1000
  pure
{ if n == 0 { ret ok } if n == 1 { ret err.Bad } ret n }
cell middle : fn(n: u64) -> str | ok | err.Bad
  fuel 1000
  pure
{ let ignored = option(n)? ret "value" }
cell discard : fn(n: u64) -> ok | err.Bad
  fuel 1000
  pure
{ option(n)? ret ok }
cell bool_option : fn(none: bool) -> bool | ok
  fuel 1000
  pure
{ if none { ret ok } ret false }
cell condition : fn(none: bool) -> u64 | ok
  fuel 1000
  pure
{ if bool_option(none)? { ret 1 } ret 2 }
cell add : fn(a: u64, b: u64) -> u64
  fuel 1000
  pure
{ ret a + b }
cell call_args : fn(n: u64) -> u64 | ok | err.Bad
  fuel 1000
  pure
{ let keep = 99 ret add(option(n)?, option(4)?) + keep }
cell recursive : fn(n: u64) -> u64 | ok | err.Bad
  fuel 1000
  pure
{ if n > 2 { ret recursive(n - 1)? + 1 } ret option(n)? }
cell short : fn(n: u64) -> u64 | ok | err.Bad
  fuel 1000
  pure
{ ret option(n)? + 1 / 0 }
''')
        for cell in ("middle", "discard", "call_args", "recursive", "short"):
            value(artifact, cell, ["1"], error("Bad"))
            value(artifact, cell, ["0"], "ok" if cell == "discard" else "union 1 ok")
        value(artifact, "middle", ["3"], "union 0 str 5 76616c7565")
        value(artifact, "call_args", ["3"], "union 0 u64 106")
        value(artifact, "recursive", ["8"], "union 0 u64 8")
        value(artifact, "condition", ["true"], "union 1 ok")
        value(artifact, "condition", ["false"], "union 0 u64 2")
        prefix = "cell choice : fn() -> u64 | ok fuel 100 { ret ok }\n"
        refused("missing_none", prefix + "cell f : fn() -> u64 fuel 100 { ret choice()? }", "AXI-T015")
        print("frontend W54: PASS (option remapping, nested arguments, recursion, false and early propagation)")
