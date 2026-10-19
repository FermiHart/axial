#!/usr/bin/env python3
"""Matched-build frontend timings; no threshold or unsupported speed claim."""
import json
import pathlib
import statistics
import subprocess
import sys
import tempfile
import time

axi = pathlib.Path(sys.argv[1]).resolve()
repetitions = int(sys.argv[2]) if len(sys.argv) > 2 else 7
assert 1 <= repetitions <= 100
with tempfile.TemporaryDirectory(prefix="axi-frontend-bench-") as td:
    root = pathlib.Path(td)
    graph = root / "graph.axi"
    cells = []
    for i in range(256):
        expr = f"c{i + 1}()" if i < 255 else 'fs.path_under("/x", "/")'
        cells.append(f"cell c{i} : fn() -> bool\n  fuel 10000\n  cap fs.Read\n{{\n"
                     + "  0\n" * 100 + "  ret " + expr + "\n}\n")
    graph.write_text("\n".join(cells))
    invalid = root / "invalid.axi"
    invalid.write_bytes(b"@" * 65536)
    results = []
    for name, verb, source, rc in (("cap_forward_256x100", "types", graph, 0),
                                   ("invalid_bytes_65536", "lex", invalid, 1)):
        samples = []
        for _ in range(repetitions + 1):
            begin = time.perf_counter()
            run = subprocess.run([str(axi), verb, str(source)],
                                 capture_output=True, timeout=30)
            elapsed = time.perf_counter() - begin
            if run.returncode != rc:
                raise RuntimeError(f"{name}: rc={run.returncode}, {run.stderr[:400]!r}")
            samples.append(elapsed)
        results.append({"case": name, "input_bytes": source.stat().st_size,
                        "samples_seconds": samples[1:],
                        "median_seconds": statistics.median(samples[1:])})
    print(json.dumps({"axi": str(axi), "warmups": 1,
                      "repetitions": repetitions, "results": results}, indent=2))
