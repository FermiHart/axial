/* Private C99 best-effort compiler-visible secret wipe; not a forensic proof. */
#ifndef AXI_PRIVATE_WIPE_H
#define AXI_PRIVATE_WIPE_H
#include <stddef.h>
static inline void axi_private_wipe(void *bytes, size_t n)
{
    volatile unsigned char *p=(volatile unsigned char *)bytes;
    while(n--) *p++=0;
}
#endif
