/* axial — bounded JSON parser (CA12). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * INV-323 / AXI-INV-105: one parser, one meaning. Duplicate keys are a
 * refused ambiguity, and nothing is extracted before the whole document parses.
 * AX30: recursive descent has an explicit depth and shared work bound;
 * duplicate probes skip already validated values without recursively probing
 * siblings again. Strings are validated even when no path selects them.
 */
#include "axi_json.h"

#include <stdint.h>
#include <string.h>

#define JSON_MAX_DEPTH 64u

typedef struct {
    const char *p;
    size_t      len;
    size_t      pos;
    size_t     *work;
    int         check_keys;
} jcur;

static int jcharge(jcur *c, size_t n)
{
    if (!c->work || n > AXI_JSON_WORK_LIMIT - *c->work) return -1;
    *c->work += n;
    return 0;
}


static size_t utf8_valid_prefix(const unsigned char *s, size_t n)
{
    unsigned char c;
    if (n == 0) return 0;
    c = s[0];
    if (c < 0x80) return 1;
    if (c >= 0xc2 && c <= 0xdf && n >= 2
            && s[1] >= 0x80 && s[1] <= 0xbf) return 2;
    if (c == 0xe0 && n >= 3 && s[1] >= 0xa0 && s[1] <= 0xbf
            && s[2] >= 0x80 && s[2] <= 0xbf) return 3;
    if (((c >= 0xe1 && c <= 0xec) || (c >= 0xee && c <= 0xef)) && n >= 3
            && s[1] >= 0x80 && s[1] <= 0xbf
            && s[2] >= 0x80 && s[2] <= 0xbf) return 3;
    if (c == 0xed && n >= 3 && s[1] >= 0x80 && s[1] <= 0x9f
            && s[2] >= 0x80 && s[2] <= 0xbf) return 3;
    if (c == 0xf0 && n >= 4 && s[1] >= 0x90 && s[1] <= 0xbf
            && s[2] >= 0x80 && s[2] <= 0xbf
            && s[3] >= 0x80 && s[3] <= 0xbf) return 4;
    if (c >= 0xf1 && c <= 0xf3 && n >= 4
            && s[1] >= 0x80 && s[1] <= 0xbf
            && s[2] >= 0x80 && s[2] <= 0xbf
            && s[3] >= 0x80 && s[3] <= 0xbf) return 4;
    if (c == 0xf4 && n >= 4 && s[1] >= 0x80 && s[1] <= 0x8f
            && s[2] >= 0x80 && s[2] <= 0xbf
            && s[3] >= 0x80 && s[3] <= 0xbf) return 4;
    return 0;
}

int axi_json_escape(const char *bytes, size_t len,
                    axi_json_sink sink, void *ctx)
{
    static const char HEX[] = "0123456789abcdef";
    size_t i = 0;
    if ((!bytes && len != 0) || !sink) return -1;
    while (i < len) {
        unsigned char c = (unsigned char)bytes[i];
        const char *escaped = NULL;
        size_t escaped_len = 0, un;
        char one[6];
        switch (c) {
        case '"':  escaped = "\\\""; escaped_len = 2; break;
        case '\\': escaped = "\\\\"; escaped_len = 2; break;
        case '\b': escaped = "\\b";  escaped_len = 2; break;
        case '\f': escaped = "\\f";  escaped_len = 2; break;
        case '\n': escaped = "\\n";  escaped_len = 2; break;
        case '\r': escaped = "\\r";  escaped_len = 2; break;
        case '\t': escaped = "\\t";  escaped_len = 2; break;
        default: break;
        }
        if (escaped) {
            if (sink(ctx, escaped, escaped_len) != 0) return -1;
            i++;
        } else if (c < 0x20) {
            one[0] = '\\'; one[1] = 'u'; one[2] = '0'; one[3] = '0';
            one[4] = HEX[c >> 4]; one[5] = HEX[c & 15];
            if (sink(ctx, one, sizeof one) != 0) return -1;
            i++;
        } else if (c < 0x80) {
            if (sink(ctx, bytes + i, 1) != 0) return -1;
            i++;
        } else if ((un = utf8_valid_prefix(
                        (const unsigned char *)bytes + i, len - i)) != 0) {
            if (sink(ctx, bytes + i, un) != 0) return -1;
            i += un;
        } else {
            one[0] = '\\'; one[1] = 'u'; one[2] = '0'; one[3] = '0';
            one[4] = HEX[c >> 4]; one[5] = HEX[c & 15];
            if (sink(ctx, one, sizeof one) != 0) return -1;
            i++;
        }
    }
    return 0;
}

static int jspace(unsigned char c)
{
    /* INV-286 / AXI-INV-081: JSON's grammar is ASCII, independent of the
     * process locale — this parser never calls ctype/locale functions. */
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static void jskip_ws(jcur *c)
{
    size_t before = c->pos;
    while (c->pos < c->len && jspace((unsigned char)c->p[c->pos])) c->pos++;
    if (jcharge(c, c->pos - before) != 0) *c->work = AXI_JSON_WORK_LIMIT;
}

static int jexpect(jcur *c, char want)
{
    if (c->pos >= c->len || c->p[c->pos] != want) return -1;
    c->pos++;
    return 0;
}

/* Read one Unicode scalar from a JSON string body, without allocation.
 * Escaped and literal spellings produce the same scalar for duplicate keys. */
static int jhex4(const char *s, size_t n, uint32_t *v)
{
    uint32_t out = 0;
    if (n < 4) return -1;
    for (size_t i = 0; i < 4; i++) {
        unsigned char c = (unsigned char)s[i];
        unsigned digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return -1;
        out = out * 16 + digit;
    }
    *v = out;
    return 0;
}

static int jscalar(const char *s, size_t n, size_t *pos, uint32_t *out)
{
    size_t i = *pos, width;
    uint32_t cp;
    unsigned char c;
    if (i >= n) return -1;
    c = (unsigned char)s[i++];
    if (c < 0x20) return -1;
    if (c == '\\') {
        if (i >= n) return -1;
        c = (unsigned char)s[i++];
        switch (c) {
        case '"': cp = '"'; break;
        case '\\': cp = '\\'; break;
        case '/': cp = '/'; break;
        case 'b': cp = '\b'; break;
        case 'f': cp = '\f'; break;
        case 'n': cp = '\n'; break;
        case 'r': cp = '\r'; break;
        case 't': cp = '\t'; break;
        case 'u':
            if (jhex4(s + i, n - i, &cp) != 0) return -1;
            i += 4;
            if (cp >= 0xd800 && cp <= 0xdbff) {
                uint32_t lo;
                if (n - i < 6 || s[i] != '\\' || s[i+1] != 'u' ||
                    jhex4(s + i + 2, n - i - 2, &lo) != 0 ||
                    lo < 0xdc00 || lo > 0xdfff) return -1;
                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                i += 6;
            } else if (cp >= 0xdc00 && cp <= 0xdfff) return -1;
            break;
        default: return -1;
        }
    } else if (c < 0x80) {
        cp = c;
    } else {
        width = utf8_valid_prefix((const unsigned char *)s + i - 1, n - i + 1);
        if (!width) return -1;
        cp = c & (width == 2 ? 0x1f : width == 3 ? 0x0f : 0x07);
        for (size_t j = 1; j < width; j++)
            cp = (cp << 6) | ((unsigned char)s[i++] & 0x3f);
    }
    *pos = i; *out = cp;
    return 0;
}

static size_t jencode(uint32_t cp, char b[4])
{
    if (cp < 0x80) { b[0] = (char)cp; return 1; }
    if (cp < 0x800) { b[0] = (char)(0xc0 | (cp >> 6));
        b[1] = (char)(0x80 | (cp & 63)); return 2; }
    if (cp < 0x10000) { b[0] = (char)(0xe0 | (cp >> 12));
        b[1] = (char)(0x80 | ((cp >> 6) & 63));
        b[2] = (char)(0x80 | (cp & 63)); return 3; }
    b[0] = (char)(0xf0 | (cp >> 18));
    b[1] = (char)(0x80 | ((cp >> 12) & 63));
    b[2] = (char)(0x80 | ((cp >> 6) & 63));
    b[3] = (char)(0x80 | (cp & 63)); return 4;
}

static long jstring_decode(const char *raw, size_t rawlen, char *scratch,
                           size_t scratch_cap, int unicode_escapes)
{
    size_t i = 0, n = 0;
    while (i < rawlen) {
        size_t before = i, width;
        uint32_t cp;
        char buf[4];
        if (jscalar(raw, rawlen, &i, &cp) != 0) return -1;
        /* Preserve json.get's documented v0 limitation. Typed extraction is
         * opt-in and supports valid surrogate pairs and non-ASCII escapes. */
        if (!unicode_escapes && raw[before] == '\\' && cp > 0x7f) return -1;
        width = jencode(cp, buf);
        if (width > scratch_cap - n) return -1;
        memcpy(scratch + n, buf, width); n += width;
    }
    return (long)n;
}

static int jkey_equal(const char *a, size_t an, const char *b, size_t bn)
{
    size_t ai = 0, bi = 0;
    if (an == bn && memcmp(a, b, an) == 0) return 1;
    while (ai < an && bi < bn) {
        uint32_t ac, bc;
        if (jscalar(a, an, &ai, &ac) || jscalar(b, bn, &bi, &bc) || ac != bc)
            return 0;
    }
    return ai == an && bi == bn;
}

static uint64_t jkey_hash(const char *s, size_t n)
{
    size_t i = 0;
    uint32_t cp;
    uint64_t h = UINT64_C(14695981039346656037);
    while (i < n) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c < 0x80 && c != '\\') { cp = c; i++; }
        else if (jscalar(s, n, &i, &cp) != 0) return 0;
        h = (h ^ cp) * UINT64_C(1099511628211);
    }
    return h;
}

/* Forward: parse one value, recursing through an explicit depth budget. */
static int jvalue(jcur *c, unsigned depth);

static int jstring_raw(jcur *c, size_t *raw_off, size_t *raw_len)
{
    size_t start;
    if (jexpect(c, '"') != 0) return -1;
    start = c->pos;
    while (c->pos < c->len && c->p[c->pos] != '"') {
        size_t before = c->pos;
        uint32_t cp;
        /* Contiguous ordinary ASCII is validated and charged in a single run.
         * Escapes, controls and UTF-8 still traverse the strict scalar decoder. */
        while (c->pos < c->len) {
            unsigned char ch = (unsigned char)c->p[c->pos];
            if (ch < 0x20 || ch >= 0x80 || ch == '"' || ch == '\\') break;
            c->pos++;
        }
        if (c->pos != before) {
            if (jcharge(c, c->pos - before) != 0) return -1;
            continue;
        }
        if (jscalar(c->p, c->len, &c->pos, &cp) != 0 ||
            jcharge(c, c->pos - before) != 0) return -1;
    }
    if (c->pos >= c->len) return -1;
    *raw_off = start; *raw_len = c->pos - start; c->pos++;
    return 0;
}

static int jnumber(jcur *c)
{
    size_t start = c->pos;
    if (c->pos < c->len && c->p[c->pos] == '-') c->pos++;
    if (c->pos >= c->len) return -1;
    if (c->p[c->pos] == '0') {
        c->pos++;
        if (c->pos < c->len && c->p[c->pos] >= '0' && c->p[c->pos] <= '9')
            return -1;                            /* leading zero */
    } else if (c->p[c->pos] >= '1' && c->p[c->pos] <= '9') {
        while (c->pos < c->len && c->p[c->pos] >= '0' && c->p[c->pos] <= '9')
            c->pos++;
    } else {
        return -1;
    }
    if (c->pos < c->len && c->p[c->pos] == '.') {
        c->pos++;
        if (c->pos >= c->len || c->p[c->pos] < '0' || c->p[c->pos] > '9')
            return -1;                            /* bare dot */
        while (c->pos < c->len && c->p[c->pos] >= '0' && c->p[c->pos] <= '9')
            c->pos++;
    }
    if (c->pos < c->len && (c->p[c->pos] == 'e' || c->p[c->pos] == 'E')) {
        c->pos++;
        if (c->pos < c->len && (c->p[c->pos] == '+' || c->p[c->pos] == '-'))
            c->pos++;
        if (c->pos >= c->len || c->p[c->pos] < '0' || c->p[c->pos] > '9')
            return -1;                            /* bare exponent */
        while (c->pos < c->len && c->p[c->pos] >= '0' && c->p[c->pos] <= '9')
            c->pos++;
    }
    return c->pos > start ? jcharge(c, c->pos - start) : -1;
}

static int jliteral(jcur *c, const char *word)
{
    size_t n = strlen(word);
    if (c->pos + n > c->len || memcmp(c->p + c->pos, word, n) != 0) return -1;
    c->pos += n;
    return 0;
}

static int jarray(jcur *c, unsigned depth)
{
    if (jexpect(c, '[') != 0) return -1;
    jskip_ws(c);
    if (c->pos < c->len && c->p[c->pos] == ']') { c->pos++; return 0; }
    for (;;) {
        jskip_ws(c);
        if (jvalue(c, depth) != 0) return -1;
        jskip_ws(c);
        if (jexpect(c, ',') == 0) continue;
        return jexpect(c, ']');
    }
}

static int jobject(jcur *c, unsigned depth)
{
    size_t fields;
    uint64_t seen = 0;
    if (jexpect(c, '{') != 0) return -1;
    fields = c->pos;
    jskip_ws(c);
    if (c->pos < c->len && c->p[c->pos] == '}') { c->pos++; return 0; }
    for (;;) {
        size_t koff, klen, key_start;
        uint64_t hash, bit;
        jskip_ws(c); key_start = c->pos;
        if (jstring_raw(c, &koff, &klen) != 0) return -1;
        hash = jkey_hash(c->p + koff, klen);
        bit = UINT64_C(1) << (hash & 63);
        /* Bloom filter is an optimization only. Collisions always fall back
         * to exact decoded equality. Probe only prior validated siblings;
         * suppress duplicate recursion while skipping their values. */
        if (c->check_keys && (seen & bit)) {
            jcur probe = *c;
            probe.pos = fields; probe.check_keys = 0;
            for (;;) {
                size_t other, olen;
                jskip_ws(&probe);
                if (probe.pos >= key_start) break;
                if (jstring_raw(&probe, &other, &olen) != 0) return -1;
                if (jkey_hash(probe.p + other, olen) == hash &&
                    jkey_equal(probe.p + other, olen, c->p + koff, klen)) return -1;
                jskip_ws(&probe);
                if (jexpect(&probe, ':') != 0) return -1;
                jskip_ws(&probe);
                if (jvalue(&probe, depth) != 0) return -1;
                jskip_ws(&probe);
                if (jexpect(&probe, ',') != 0) return -1;
            }
        }
        seen |= bit;
        jskip_ws(c);
        if (jexpect(c, ':') != 0) return -1;
        jskip_ws(c);
        if (jvalue(c, depth) != 0) return -1;
        jskip_ws(c);
        if (jexpect(c, ',') == 0) continue;
        return jexpect(c, '}');
    }
}

static int jvalue(jcur *c, unsigned depth)
{
    if (depth > JSON_MAX_DEPTH || jcharge(c, 1) != 0) return -1;
    if (c->pos >= c->len) return -1;
    switch (c->p[c->pos]) {
    case '{': return jobject(c, depth + 1);
    case '[': return jarray(c, depth + 1);
    case '"': {
        size_t off, len;
        return jstring_raw(c, &off, &len);
    }
    case 't': return jliteral(c, "true");
    case 'f': return jliteral(c, "false");
    case 'n': return jliteral(c, "null");
    default:  return jnumber(c);
    }
}

int axi_json_validate(const char *doc, size_t len)
{
    if (!doc || len == 0 || len > AXI_JSON_SCRATCH_SIZE) return -1;
    size_t work = 0;
    jcur c = { doc, len, 0, &work, 1 };
    jskip_ws(&c);
    if (jvalue(&c, 1) != 0) return -1;
    jskip_ws(&c);
    return c.pos == c.len && work < AXI_JSON_WORK_LIMIT ? 0 : -1;   /* trailing garbage is refusal */
}

/* ---- path extraction over a validated document --------------------------- */

/* Extract the raw slice of the value at cursor; strings keep their quotes so
 * the slice is itself a valid JSON value. */
static int jvalue_slice(jcur *c, unsigned depth, size_t *off, size_t *len)
{
    size_t start = c->pos;
    if (jvalue(c, depth) != 0) return -1;
    *off = start;
    *len = c->pos - start;
    return 0;
}

/* A path key is literal UTF-8; backslash has no JSON escape meaning there. */
static int jkey_matches_path(const char *raw, size_t n, const char *key, size_t kn)
{
    size_t i = 0, j = 0;
    /* A path key is literal, not a JSON-escaped string. Raw equality is
     * sufficient only if the validated key has no escapes. */
    if (n == kn && !memchr(raw, '\\', n) && memcmp(raw, key, n) == 0) return 1;
    while (i < n) {
        uint32_t cp; char b[4]; size_t width;
        if (jscalar(raw, n, &i, &cp) != 0) return 0;
        width = jencode(cp, b);
        if (width > kn - j || memcmp(key + j, b, width) != 0) return 0;
        j += width;
    }
    return j == kn;
}

static int jobject_find(jcur *c, unsigned depth, const char *key, size_t klen,
                        size_t *off, size_t *len)
{
    if (jexpect(c, '{') != 0) return -1;
    jskip_ws(c);
    if (c->pos < c->len && c->p[c->pos] == '}') return -1;
    for (;;) {
        size_t koff, klen2;
        jskip_ws(c);
        if (jstring_raw(c, &koff, &klen2) != 0) return -1;
        jskip_ws(c);
        if (jexpect(c, ':') != 0) return -1;
        jskip_ws(c);
        if (jkey_matches_path(c->p + koff, klen2, key, klen))
            return jvalue_slice(c, depth, off, len);
        if (jvalue(c, depth) != 0) return -1;
        jskip_ws(c);
        if (jexpect(c, ',') == 0) continue;
        return -1;
    }
}

static int jarray_index(jcur *c, unsigned depth, unsigned long idx,
                        size_t *off, size_t *len)
{
    if (jexpect(c, '[') != 0) return -1;
    jskip_ws(c);
    if (c->pos < c->len && c->p[c->pos] == ']') return -1;
    unsigned long i = 0;
    for (;;) {
        jskip_ws(c);
        if (i == idx)
            return jvalue_slice(c, depth, off, len);
        if (jvalue(c, depth) != 0) return -1;
        i++;
        jskip_ws(c);
        if (jexpect(c, ',') == 0) continue;
        return -1;
    }
}

/* INV-704: the scratch is caller-owned memory, never thread-local storage —
 * concurrent embed contexts and the Bear target have no TLS; a static shared
 * scratch would race. A decoded string that does not fit is a typed refusal. */
static int jpath_valid(const char *p, size_t n)
{
    size_t i = 1, depth = 0;
    if (!p || n < 3 || n > AXI_JSON_SCRATCH_SIZE || p[0] != '$' || p[1] != '.') return 0;
    while (i < n) {
        if (++depth > 64) return 0;
        if (p[i] == '.') {
            size_t begin = ++i;
            while (i < n && p[i] != '.' && p[i] != '[') i++;
            if (i == begin) return 0;
        } else if (p[i] == '[') {
            unsigned long index = 0;
            size_t begin = ++i;
            while (i < n && p[i] >= '0' && p[i] <= '9') {
                unsigned d = (unsigned)(p[i++] - '0');
                if (index > (1000000ul - d) / 10) return 0;
                index = index * 10 + d;
            }
            if (i == begin || i == n || p[i++] != ']') return 0;
        } else return 0;
    }
    return 1;
}

static int json_lookup(const char *doc, size_t len, const char *path, size_t plen,
                       char *scratch, size_t scratch_cap, axi_json_value *value,
                       int unicode_escapes)
{
    if (!doc || !path || !value || !scratch
            || scratch_cap == 0 || scratch_cap > AXI_JSON_SCRATCH_SIZE)
        return -1;
    if (axi_json_validate(doc, len) != 0) return -1;
    if (!jpath_valid(path, plen)) return AXI_JSON_INVALID;

    /* The finder reports slice-relative offsets; the slice origin is
     * (c.p - c.pos), so the absolute position is a single addition. */
    size_t work = 0;
    jcur c = { doc, len, 0, &work, 0 };
    jskip_ws(&c);
    const char *p = path + 1;   /* "$" consumed; every segment starts at ./[ */
    const char *pend = path + plen;
    size_t off = 0, vlen = len;

    while (p < pend) {
        size_t rel_off = 0, rel_len = 0;
        if (*p == '.') {
            /* segment separator: $.a.b — consume the dot, read the key */
            p++;
            const char *key = p;
            size_t klen = 0;
            while (p < pend && *p != '.' && *p != '[') { p++; klen++; }
            if (klen == 0) return -1;
            if (jobject_find(&c, 1, key, klen, &rel_off, &rel_len) != 0)
                return work >= AXI_JSON_WORK_LIMIT ? AXI_JSON_INVALID : AXI_JSON_MISSING;
        } else if (*p == '[') {
            p++;
            if (p >= pend || *p < '0' || *p > '9') return -1;
            unsigned long idx = 0;
            while (p < pend && *p >= '0' && *p <= '9') {
                if (idx > 1000000ul) return -1;   /* index bomb */
                idx = idx * 10 + (unsigned long)(*p - '0');
                p++;
            }
            if (p >= pend || *p != ']') return -1;
            p++;
            if (jarray_index(&c, 1, idx, &rel_off, &rel_len) != 0)
                return work >= AXI_JSON_WORK_LIMIT ? AXI_JSON_INVALID : AXI_JSON_MISSING;
        } else {
            return -1;
        }
        /* descend: the found slice becomes the new base, in doc coords */
        {
            const char *slice_start = c.p;              /* current slice origin */
            const char *found = slice_start + rel_off;  /* absolute in doc */
            off = (size_t)(found - doc);
            vlen = rel_len;
            c.p = found;
            c.len = rel_len;
            c.pos = 0;
            jskip_ws(&c);
        }
    }

    /* Do not expose a partial value on refusal. Scratch is temporary and can
     * be modified, but the result structure is published only after success. */
    axi_json_value result;
    memset(&result, 0, sizeof result);
    result.bytes = doc + off; result.length = vlen;
    switch (doc[off]) {
    case '"': {
        result.kind = AXI_JSON_STRING;
        if (!memchr(doc + off + 1, '\\', vlen - 2)) {
            result.bytes = doc + off + 1; result.length = vlen - 2;
            break;
        }
        long n = jstring_decode(doc + off + 1, vlen - 2, scratch,
                                scratch_cap, unicode_escapes);
        if (n < 0) return AXI_JSON_INVALID;
        result.kind = AXI_JSON_STRING; result.bytes = scratch;
        result.length = (size_t)n;
        break;
    }
    case 't': case 'f': result.kind = AXI_JSON_BOOLEAN; break;
    case 'n': result.kind = AXI_JSON_NULL; break;
    case '{': result.kind = AXI_JSON_OBJECT; break;
    case '[': result.kind = AXI_JSON_ARRAY; break;
    default: result.kind = AXI_JSON_NUMBER; break;
    }
    if (work >= AXI_JSON_WORK_LIMIT) return AXI_JSON_INVALID;
    *value = result;
    return AXI_JSON_FOUND;
}

int axi_json_get_typed(const char *doc, size_t len, const char *path, size_t plen,
                       char *scratch, size_t scratch_cap, axi_json_value *out)
{
    return json_lookup(doc, len, path, plen, scratch, scratch_cap, out, 1);
}

int axi_json_get(const char *doc, size_t len, const char *path, size_t plen,
                 char *scratch, size_t scratch_cap,
                 const char **out, size_t *outlen)
{
    axi_json_value value;
    if (!out || !outlen) return -1;
    if (json_lookup(doc, len, path, plen, scratch, scratch_cap, &value, 0) != 0)
        return -1;
    *out = value.bytes; *outlen = value.length;
    return 0;
}
