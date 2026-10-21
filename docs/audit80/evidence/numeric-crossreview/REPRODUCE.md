# Independent numeric cross-review evidence

These temporary probes were run against byte-identical snapshots of the
frontend agent's `axi_numeric.c` and `.h`. No existing worktree was edited.
The source hashes were rechecked after execution and remained equal.
`review-output.txt` and `bounds-output.txt` preserve the outputs captured
from the executed tool calls; they are not claims of new executions.

The probe and Python checker have a fixed temporary path. To reproduce from
a saved copy, copy the four source files (`probe.c`, `check.py`,
`axi_numeric.c`, `axi_numeric.h`) to `/tmp/axial-numeric-crossreview/`, then:

```sh
cc -std=c99 -Wall -Wextra -Werror -Wpedantic -O1 -g \
  -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie \
  /tmp/axial-numeric-crossreview/probe.c \
  /tmp/axial-numeric-crossreview/axi_numeric.c \
  -lm -o /tmp/axial-numeric-crossreview/probe
python3 /tmp/axial-numeric-crossreview/check.py
```

The Python runner sets ASan/UBSan halt-on-error options and disables
LeakSanitizer. It does not import the product's `numeric.py` oracle.

## Precise scope

- Reader: 33 selected exact adjacent-binary64 midpoints, biased toward the
  smallest normal binade and subnormals, including the actual 768-significant-
  digit maximum and the overflow boundary. At each midpoint, 15 variants
  cover below/tie/above at positions 799/800/801/1025/2048, including inserted
  underscores and long zero suffixes. Expected neighbors follow from exact
  Python `as_integer_ratio` midpoint arithmetic and parity; the chosen
  decimal perturbation is separately proved smaller than one quarter of
  the adjacent binary gap. CPython `float` is an additional conversion oracle.
- Formatter: 3,178 distinct bit patterns concentrated at the five nearest
  binary64 values around each decimal decade from 10^-323 through 10^308,
  plus signed samples and endpoints. The complete produced string is
  compared to CPython `repr`, expanded without an exponent using Decimal.
  This compares the **selected output**, not every candidate decimal
  coefficient or grid. No separate exhaustive shortest/closest/even oracle
  was implemented in this cross-review; those choices also received manual
  mathematical/source review. No formatter-to-reader round-trip was added
  here; that is part of the existing frontend suite.
- Every case executes under all four standard fenv rounding modes with all
  standard preexisting exception flags raised. The probe checks that the
  flags/mode remain unchanged and checks canaries directly around the
  2,372-byte workspace. All probe/core code was compiled under ASan/UBSan.
- Bounds were independently evaluated with unbounded Python integers:
  `(10**800-1).bit_length() == 2658`,
  `(5**1123*((1<<54)-1)).bit_length() == 2662`, and
  `len(str(((1<<54)-1)*5**1075)) == 768`.

The results establish no exhaustive enumeration of the binary64 space, no
machine-checked proof, no alternative-ABI or big-endian execution, and no
LeakSanitizer result. No counterexample was found in the reviewed scope.
