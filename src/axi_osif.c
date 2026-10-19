/* axial — platform glue for the sovereign build.  Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * AXI-INV-064.  This is the ONLY axial translation unit that is not compiled
 * by bear in the sovereign build.  It exists for exactly one reason: the C
 * standard stream handles are dylib data symbols on macOS, and a compiler
 * that emits direct data relocs cannot reach them (bear's INV-021).  The fix
 * is to expose them as functions — a call is a branch reloc, which links.
 *
 * It must stay this small and this dumb.  Nothing that has an opinion about
 * axial's semantics may live here, because this file is the one place the
 * sovereign chain does not cover; anything with meaning inside it would be
 * meaning the chain cannot vouch for.  Three returns, no logic, no state.
 *
 * Compiled by the host cc with the real <stdio.h>, exactly once, constant.
 */
#include <stdio.h>

void *axi_osif_stdin(void)  { return (void *)stdin;  }
void *axi_osif_stdout(void) { return (void *)stdout; }
void *axi_osif_stderr(void) { return (void *)stderr; }
