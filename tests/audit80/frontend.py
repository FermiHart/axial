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
