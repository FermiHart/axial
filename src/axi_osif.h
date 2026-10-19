/* axial — the agent-first, capability-native, attested language.
 * Bear Core. SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  AXI-INV-064 — sovereign build shim (inherits bear's INV-021).
 *
 *  When the compiler is bear (it predefines __bear_selfhost__), the standard
 *  stream handles cannot be referenced as data: on macOS libc exports them
 *  only from a dylib (___stdinp/___stdoutp/___stderrp), and a direct
 *  RIP-relative data reloc cannot reach a dylib symbol — it needs the GOT.
 *  Bear solved this for itself by routing the handles through accessor
 *  FUNCTIONS (a plain call is a BRANCH reloc, which links).  axial inherits
 *  the same door instead of inventing a second one: axi_osif.c (platform
 *  glue, compiled by the host cc with the real <stdio.h>) owns the three
 *  accessors, and every TU that needs a stream includes THIS header.
 *
 *  A normal cc build never sees the shim and uses real <stdio.h>.
 *  Gate: tools/axi-sovereign.sh (bear-built axi must produce byte-identical
 *  artifacts to the cc-built axi across the whole corpus).
 *
 *  The handles are reached through names axial OWNS (AXI_IN/AXI_OUT/AXI_ERR),
 *  not by redefining `stderr`.  A macro named `stderr` loses to whichever
 *  <stdio.h> is included after it — include order would silently decide
 *  whether the sovereign build works.  A name of our own cannot be clobbered
 *  by a system header, so the door does not move.  Enforced: the bare
 *  identifiers are banned from axial sources (gate: tools/axi-sovereign.sh).
 *
 *  One header, one door: every TU that prints goes through here.  Do not
 *  re-declare the accessors anywhere else.
 * ═════════════════════════════════════════════════════════════════════════ */

#ifndef AXI_OSIF_H
#define AXI_OSIF_H

#ifdef __bear_selfhost__
extern void *axi_osif_stdin(void);
extern void *axi_osif_stdout(void);
extern void *axi_osif_stderr(void);
# define AXI_IN  axi_osif_stdin()
# define AXI_OUT axi_osif_stdout()
# define AXI_ERR axi_osif_stderr()
#else
# define AXI_IN  stdin
# define AXI_OUT stdout
# define AXI_ERR stderr
#endif

#endif /* AXI_OSIF_H */
