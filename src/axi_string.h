/* Source/AXS text-string contract v1: five exact escapes, no locale.
 * Internal helpers only; no public embed-v1 ABI change. */
#ifndef AXI_STRING_H
#define AXI_STRING_H

static inline int axi_string_unescape_byte(unsigned char escaped, unsigned char *out)
{
    switch (escaped) {
    case 'n': *out = '\n'; return 1;
    case 't': *out = '\t'; return 1;
    case '0': *out = '\0'; return 1;
    case '\\': *out = '\\'; return 1;
    case '"': *out = '"'; return 1;
    default: return 0;
    }
}

/* Return encoded length, or zero when the text grammar has no spelling. */
static inline int axi_string_escape_byte(unsigned char byte, char out[2])
{
    char escaped;
    switch (byte) {
    case '\n': escaped = 'n'; break;
    case '\t': escaped = 't'; break;
    case '\0': escaped = '0'; break;
    case '\\': escaped = '\\'; break;
    case '"': escaped = '"'; break;
    default:
        if (byte < 0x20 || byte == 0x7f) return 0;
        out[0] = (char)byte; return 1;
    }
    out[0] = '\\'; out[1] = escaped; return 2;
}

#endif
