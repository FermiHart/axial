#!/usr/bin/env python3
"""Budget thresholds, ownership cleanup and deterministic whole-CLI OOM sweep."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

axi = str(pathlib.Path(sys.argv[1]).resolve())
fail_axi = str(pathlib.Path(sys.argv[2]).resolve()) if len(sys.argv) > 2 else None
checks = 0


def run(binary, args, env=None, cwd=None):
    global checks
    p = subprocess.run([binary, *map(str, args), "--compile-mem-report"],
                       capture_output=True, text=True, env=env, cwd=cwd)
    reports = [json.loads(line) for line in p.stderr.splitlines()
               if line.startswith('{"schema":"axi.compiler-memory.v1"')]
    assert p.returncode >= 0, (args, p.returncode, p.stderr)
    assert len(reports) == 1, (args, p.returncode, p.stdout, p.stderr)
    m = reports[0]
    assert m["live"] == m["fixed"] == m["allocations"] == 0, (args, m, p.stderr)
    assert m["peak"] <= m["limit"], (args, m)
    assert "AXI-C006" not in p.stderr + p.stdout or m["failure"] == "AXI-M000"
    checks += 5
    return p, m


with tempfile.TemporaryDirectory(prefix="axi80-compiler-") as directory:
    d = pathlib.Path(directory)
    seed, pk = d / "test.seed", d / "test.pk"
    seed.write_bytes(bytes(range(32)))
    pk.write_bytes(bytes.fromhex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"))
    source, changed, unformatted = d / "source.axi", d / "changed.axi", d / "form.axi"
    source.write_text(pathlib.Path("tests/hello.axi").read_text() +
                      '\ncell fail : fn() -> u64 | err.No\n  fuel 100\n  pure\n{\n  ret err.No\n}\n')
    canonical = subprocess.run([axi, "canon", str(source)], capture_output=True, check=True).stdout
    source.write_bytes(canonical)
    changed.write_bytes(canonical.replace(b"10_000", b"20_000"))
    unformatted.write_bytes(canonical.replace(b"  ret", b" ret"))
    target, axs = d / "output.axb", d / "input.axs"
    subprocess.run([axi, "compile", str(source), "-o", str(target), "--signing-key", str(seed)],
                   capture_output=True, check=True)
    axs.write_bytes(subprocess.run([axi, "dis", str(target), "--trusted-key", str(pk)],
                                  capture_output=True, check=True).stdout)
    reference = target.read_bytes()
    echo_source, echo_module = d / "echo.axi", d / "echo.axb"
    echo_source.write_text('cell echo : fn(s: str) -> str\n  fuel 100\n  pure\n{\n  ret s\n}\n')
    subprocess.run([axi, "compile", str(echo_source), "-o", str(echo_module),
                    "--signing-key", str(seed)], capture_output=True, check=True)
    source_options, seed_options = d / "source-options", d / "seed-options"
    public_options, output_options = d / "public-options", d / "output-options"
    for directory in (source_options, seed_options, public_options, output_options):
        directory.mkdir()
    # Names are data in the required FILE positions and in option values.
    # Only subsequent compiler option positions may select the budget.
    for name in ("--compile-mem", "--compile-mem-report"):
        (source_options / name).write_bytes(canonical)
        (seed_options / name).write_bytes(seed.read_bytes())
        (public_options / name).write_bytes(pk.read_bytes())
        p, m = run(axi, ["parse", name, "--json"], cwd=source_options)
        assert p.returncode == 0 and m["failure"] == "AXI-M000", (name, p.stderr)
        json.loads(p.stdout)
        p, m = run(axi, ["iface-diff", name, name, "--json"], cwd=source_options)
        assert p.returncode == 0 and json.loads(p.stdout)["verdict"] == "identical"
        p, m = run(axi, ["compile", source, "-o", name, "--signing-key", seed],
                   cwd=output_options)
        assert p.returncode == 0 and (output_options / name).read_bytes() == reference
        p, m = run(axi, ["compile", source, "-o", target, "--signing-key", name],
                   cwd=seed_options)
        assert p.returncode == 0 and target.read_bytes() == reference
        p = subprocess.run([axi, "run", str(echo_module), "echo", "--trusted-key",
                            str(pk), "--", name], capture_output=True, text=True)
        expected = "str %d %s\n" % (len(name), name.encode().hex())
        assert p.returncode == 0 and p.stdout == expected and not p.stderr, (name, p)
        p = subprocess.run([axi, "run", str(echo_module), "echo", "plain",
                            "--trusted-key", name], cwd=public_options,
                           capture_output=True, text=True)
        assert p.returncode == 0 and p.stdout == "str 5 706c61696e\n" and not p.stderr
        checks += 7
    commands = [[name, source] for name in
                ("lex", "parse", "canon", "form", "types", "check", "iface", "lint-safe")]
    commands += [["iface-diff", source, source],
                 ["compile", source, "-o", target, "--signing-key", seed],
                 ["asm", axs, "-o", target, "--signing-key", seed]]
    for args in commands:
        p, m = run(axi, args)
        assert p.returncode == 0 and m["failure"] == "AXI-M000", (args, p.stderr)
        peak = m["peak"]
        for limit in (0, 1024, peak - 1, peak):
            if args[0] in ("compile", "asm"):
                target.write_bytes(b"previous artifact")
            p, m = run(axi, [*args, "--compile-mem", limit])
            if limit < peak:
                assert p.returncode == 2 and m["failure"] == "AXI-M001", (args, limit, p.stderr)
                if args[0] in ("compile", "asm"):
                    assert target.read_bytes() == b"previous artifact"
            else:
                assert p.returncode == 0 and m["failure"] == "AXI-M000", (args, p.stderr)
            checks += 2
    for name in ("lex", "parse", "form", "types", "check", "iface", "lint-safe"):
        p, m = run(axi, [name, source, "--json", "--compile-mem", 0])
        assert p.returncode == 2 and "AXI-M001" in p.stdout
        json.loads(p.stdout)
        checks += 2
    for options in (["--compile-mem", "-1"], ["--compile-mem", "1x"],
                    ["--compile-mem", ""], ["--compile-mem", "184467440737095516160"],
                    ["--compile-mem", "1000", "--compile-mem", "2000"],
                    ["--compile-mem-report", "--compile-mem-report"], ["--compile-mem"]):
        p = subprocess.run([axi, "parse", str(source), *options], capture_output=True, text=True)
        assert p.returncode == 2 and "AXI-X005" in p.stderr
        checks += 1
    p = subprocess.run([axi, "version", "--compile-mem", "1"], capture_output=True, text=True)
    assert p.returncode == 2 and "usage:" in p.stderr
    checks += 1

    sweeps = {}
    if fail_axi:
        fail_commands = [["compile", source, "-o", target, "--signing-key", seed],
                         ["asm", axs, "-o", target, "--signing-key", seed],
                         ["iface-diff", source, changed, "--json"],
                         ["form", unformatted, "--json"]]
        for args in fail_commands:
            for fail_at in range(1, 4097):
                env = dict(os.environ, AXI_ALLOC_FAIL_AT=str(fail_at))
                target.write_bytes(b"previous artifact")
                p, m = run(fail_axi, args, env)
                if "AXI-FP001" not in p.stderr:
                    assert m["failure"] == "AXI-M000" and p.returncode in (0, 1), (args, p.stderr)
                    sweeps[args[0]] = fail_at - 1
                    break
                assert p.returncode == 2 and m["failure"] == "AXI-M002", (args, fail_at, p.stderr, p.stdout)
                if args[0] in ("compile", "asm"):
                    assert target.read_bytes() == b"previous artifact", (args, fail_at)
                if args[-1] == "--json" and p.stdout:
                    json.loads(p.stdout)
                checks += 2
            else:
                raise AssertionError((args, "failpoint sweep did not reach the end"))
    print(json.dumps({"suite": "compiler-cli", "checks": checks,
                      "host_oom_sites": sweeps, "status": "PASS"}, sort_keys=True))
