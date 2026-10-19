#!/usr/bin/env python3
"""Sweep every parser-node allocation, including malformed and empty input."""
import os
import pathlib
import re
import subprocess
import sys

test = pathlib.Path(sys.argv[1]).resolve()
total = 0
for case in range(3):
    env = dict(os.environ)
    env.pop("AXI_ALLOC_FAIL_AT", None)
    env.pop("AXI_ALLOC_FAIL_KIND", None)
    original = subprocess.run([str(test), str(case)], capture_output=True,
                              text=True, env=env, timeout=10)
    match = re.search(r"parse=ok nodes=(\d+)", original.stdout)
    assert original.returncode == 0 and match, original.stdout + original.stderr
    nodes = int(match.group(1))
    for fail_at in range(1, nodes + 1):
        env["AXI_ALLOC_FAIL_AT"] = str(fail_at)
        env["AXI_ALLOC_FAIL_KIND"] = "calloc"
        refused = subprocess.run([str(test), str(case)], capture_output=True,
                                 text=True, env=env, timeout=10)
        assert refused.returncode == 0 and "parse=refused" in refused.stdout, (
            case, fail_at, refused.returncode, refused.stdout, refused.stderr)
        assert "AXI-FP001" in refused.stderr, "failpoint did not fire"
        total += 1
print(f"frontend W10: PASS ({total} allocation refusals, 3 inputs, host recovery)")
