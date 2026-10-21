#!/usr/bin/env python3
"""Decimal profile v1 through canonical source, signed v7 and the real VM."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from numeric import INF, boundary_text, canonical_expected, dyadic_text, expected

AXI = Path(sys.argv[1]).resolve()
SIGN = 1 << 63


def call(*args):
    return subprocess.run([str(AXI), *map(str, args)], text=True,
                          capture_output=True, timeout=30)


def ok(result):
    assert result.returncode == 0, (result.args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def exact_literal(bits):
    field, fraction = bits >> 52, bits & ((1 << 52) - 1)
    return dyadic_text(fraction | ((1 << 52) if field else 0),
                       field - 1075 if field else -1074)


def vm_bits(bits):
    magnitude = bits & (SIGN - 1)
    if magnitude > INF:
        return 0x7FF8000000000000
    return 0 if not magnitude else bits


def alias(text):
    sign = "-" if text.startswith("-") else ""
    text = text.removeprefix("-")
    return sign + "00" + text.replace(".", "_.") + "000___"


with tempfile.TemporaryDirectory(prefix="axial-audit80-numeric-") as td:
    root = Path(td)
    seed, key = root / "test.seed", root / "test.pk"
    seed.write_bytes(bytes(range(32)))
    key.write_bytes(bytes.fromhex(
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"))
    patterns = [0, 1, 2, 3, 0x000FFFFFFFFFFFFE, 0x000FFFFFFFFFFFFF,
                0x0010000000000000, 0x0010000000000001,
                0x3FB999999999999A, 0x3FD3333333333333, 0x3FD3333333333334,
                0x3FE6666666666666, 0x3FEFFFFFFFFFFFFF, 0x3FF0000000000000,
                0x3FF0000000000001, 0x4340000000000000,
                0x43F0000000000000, 0x7FEFFFFFFFFFFFFE, 0x7FEFFFFFFFFFFFFF]
    cases = []
    for bits in patterns:
        exact = exact_literal(bits)
        cases += [(exact, bits), ("-" + exact, bits | SIGN)]
    for source in ["0.3", "0.7", "9007199254740993.0", "18446744073709551616.0",
                   "0." + "0" * 1500 + "1", boundary_text(0), boundary_text(1),
                   boundary_text(0x3FF0000000000000) + "0" * 900 + "1"]:
        status, bits = expected(source)
        assert status == 0
        cases.append((source, bits))

    def unit(use_alias):
        return "\n".join(
            f"cell f{i} : fn() -> f64 fuel 100 pure {{ ret {alias(source) if use_alias else source} }}"
            for i, (source, _) in enumerate(cases)) + "\n"

    source = root / "numeric.axi"
    source.write_text(unit(False))
    canonical = ok(call("canon", source))
    source.write_text(unit(True))
    assert ok(call("canon", source)) == canonical, "decimal aliases differ in canonical source"
    source.write_text(canonical)
    assert ok(call("canon", source)) == canonical, "canonical form is not a fixed point"
    ok(call("check", source))
    for i, (_, bits) in enumerate(cases):
        wanted = canonical_expected(bits)[1]
        body = canonical.split(f"cell f{i} :", 1)[1].split("}", 1)[0]
        assert f"ret {wanted}\n" in body, (i, bits, body, wanted)
    artifact = root / "numeric.axb"
    ok(call("compile", source, "-o", artifact, "--signing-key", seed))
    for i, (_, bits) in enumerate(cases):
        result = ok(call("run", artifact, f"f{i}", "--trusted-key", key))
        assert result == f"f64 {vm_bits(bits):016x}\n", (i, bits, result)
    assembly = ok(call("dis", artifact, "--trusted-key", key))
    for i, (_, bits) in enumerate(cases):
        body = assembly.split(f"cell f{i} ", 1)[1].split("\nend", 1)[0]
        constants = [int(value, 16) for value in re.findall(r"\bk\d+ f64 ([0-9a-f]+)", body)]
        assert bits in constants, (i, bits, constants)
        if bits & SIGN:
            assert "\n  sub " not in body and len(re.findall(r"\n  ldk ", body)) == 1, body
    # Pool retains -0; the frozen runtime normalizes it to +0. Direct negative
    # literals now need exactly LDK + RET (2 fuel), with no discarded load.
    result = ok(call("run", artifact, "f1", "--trusted-key", key, "--fuel", "2", "--fuel-report"))
    assert result == "f64 0000000000000000\nfuel 2\n", result
    text = root / "numeric.axs"
    rebuilt = root / "numeric-rebuilt.axb"
    text.write_text(assembly)
    ok(call("asm", text, "-o", rebuilt, "--signing-key", seed))
    for i in [1, 2, 3, len(cases) - 1]:
        result = ok(call("run", rebuilt, f"f{i}", "--trusted-key", key))
        assert result == f"f64 {vm_bits(cases[i][1]):016x}\n", (i, result)

    source.write_text("cell neg : fn(x: f64) -> f64 fuel 100 pure { ret -x }\n"
                      "cell twice : fn(x: f64) -> f64 fuel 100 pure { ret --x }\n")
    ok(call("compile", source, "-o", artifact, "--signing-key", seed))
    for bits in [0, SIGN, 1, SIGN | 1, 0x3FD3333333333333, INF, SIGN | INF,
                 0x7FF8000000000001]:
        result = ok(call("run", artifact, "neg", f"{bits:016x}", "--trusted-key", key))
        assert result == f"f64 {vm_bits(vm_bits(bits) ^ SIGN):016x}\n", (bits, result)
        result = ok(call("run", artifact, "twice", f"{bits:016x}", "--trusted-key", key))
        assert result == f"f64 {vm_bits(bits):016x}\n", (bits, result)

    bad_values = [(boundary_text(INF - 1), "AXI-L006"), ("9" * 8000 + ".0", "AXI-L006"),
                  ("18446744073709551616", "AXI-L005"), ("1.0e1", "AXI-L004")]
    for literal, diagnostic in bad_values:
        source.write_text(f"cell bad : fn() -> f64 fuel 100 {{ ret {literal} }}\n")
        artifact.write_bytes(b"existing-output-must-survive")
        result = call("compile", source, "-o", artifact, "--signing-key", seed)
        assert result.returncode != 0 and diagnostic in result.stderr, result.stderr
        assert artifact.read_bytes() == b"existing-output-must-survive"
        artifact.unlink()
        result = call("compile", source, "-o", artifact, "--signing-key", seed)
        assert result.returncode != 0 and not artifact.exists(), result.stderr

    print(f"numeric W66: PASS ({len(cases)} signed literal cases, aliases, fixed points, raw pools, VM zero contract and refusals)")
