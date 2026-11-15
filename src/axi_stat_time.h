/* Host stat timestamp field spelling, preserving nanosecond precision.
 * Private portability shim, not an installed ABI.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#ifndef AXI_STAT_TIME_H
#define AXI_STAT_TIME_H

#include <sys/stat.h>

#if defined(__APPLE__) && defined(__MACH__)
#define AXI_STAT_MTIME(st) ((st)->st_mtimespec)
#define AXI_STAT_CTIME(st) ((st)->st_ctimespec)
#else
#define AXI_STAT_MTIME(st) ((st)->st_mtim)
#define AXI_STAT_CTIME(st) ((st)->st_ctim)
#endif

#endif
