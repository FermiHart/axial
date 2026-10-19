# Driver, integration and evidence — W31–W40

Baseline: `2d6752255ffcc92e0b103c97609daf205a5a39de`, public tree of
2026-10-19. This campaign is confined to Axial. The public embed-v1 header
and its ABI are preserved. Host results do not establish native/guest
enforcement or a production trusted runner.

## W31 — Incremental, dependency-aware builds

The original Makefile compiled all translation units in one command for
both executables, did not track headers and ignored `LDFLAGS`. It now shares
objects, emits compiler dependencies and uses a content-stable compiler/flag
stamp. `BUILD` can isolate toolchain configurations; link flags and libraries
are honored. The default optimization remains `-O1` for comparable baselines.

Validation: clean build, unchanged no-op build, header-triggered dependent
rebuild, and demo reuse of core objects. No public API or artifact format
changes. Evidence commands: `make -j4 dev`, `make dev`,
`touch src/axi_hash.h && make -j4 dev`, `make demo`.
