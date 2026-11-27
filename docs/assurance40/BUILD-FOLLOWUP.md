# Observed W26–W30 follow-up

[Build job 140571091454](https://github.com/FermiHart/axial/actions/runs/46018316942/job/140571091454)
and [compiler run 46018316941](https://github.com/FermiHart/axial/actions/runs/46018316941)
on PR head de9d5836f9515073ee4376e0862524518c4fa872. Exact observed manifest: [BUILD-OBSERVED.json](BUILD-OBSERVED.json).
Both fresh build directories on the same runner yielded axi SHA-256
e039bf5f713773d9e1281ff77a698aad75cad641456d57b447537af82e6a3ec2. No independent host reproduction claimed.
GCC 13.3.0 and Clang 18.1.3 passed ordinary O1/O2 jobs; immutable toolchain
pin unavailable. Informational diagnostics:

| Compiler | -Wformat-nonliteral | -Wshadow | Total |
| --- | ---: | ---: | ---: |
| GCC | 0 | 1 | 1 |
| Clang | 4 | 1 | 5 |

Jobs 140571092150 and 140571091711. Counts are diagnostics, not unique
source locations. No zero-warning or source-fix claim.
