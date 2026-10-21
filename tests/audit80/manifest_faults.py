#!/usr/bin/env python3
"""Fail every real allocation in the four-cell source-to-contract path."""
import json
import os
from pathlib import Path
import subprocess
import sys

binary = str(Path(sys.argv[1]).resolve())
checks = 0
for fail_at in range(1, 16385):
    p = subprocess.run([binary, "--failpoint"], capture_output=True, text=True,
                       env=dict(os.environ, AXI_ALLOC_FAIL_AT=str(fail_at)), timeout=30)
    assert p.returncode == 0, (fail_at, p.returncode, p.stdout, p.stderr)
    result = json.loads(p.stdout)
    assert result["live"] == result["fixed"] == 0, (fail_at, result)
    checks += result["checks"]
    if "AXI-FP001" not in p.stderr:
        assert result["failure"] == "AXI-M000", (fail_at, result)
        print(json.dumps({"suite": "manifest-faults", "host_oom_sites": fail_at - 1,
                          "checks": checks, "status": "PASS"}, sort_keys=True))
        break
    assert result["failure"] == "AXI-M002", (fail_at, result, p.stderr)
else:
    raise AssertionError("failpoint sweep did not reach the end")
