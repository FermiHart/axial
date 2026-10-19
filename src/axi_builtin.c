/* axial — policy builtins runtime (M3). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 */
#include "axi_builtin.h"
#include "axi_cap_table.h"
#include "axi_json.h"
#include "axi_u64.h"
#include "axi_builtin_registry.h"
#include <string.h>
#include <limits.h>

/* ---- builtin table -------------------------------------------------------- */

#define RUNTIME_ROW(name, arity, p0, p1, p2, ret, cap, capstr, impure) \
    { name, arity, cap, capstr },
static const axi_builtin_info BUILTINS[] = {
    AXI_BUILTIN_REGISTRY(RUNTIME_ROW)
    { NULL, 0, CAP_NONE, NULL }
};
#undef RUNTIME_ROW
#define LENGTH_ROW(name, arity, p0, p1, p2, ret, cap, capstr, impure) sizeof(name)-1,
static const size_t BUILTIN_LENGTHS[] = { AXI_BUILTIN_REGISTRY(LENGTH_ROW) };
#undef LENGTH_ROW

typedef char axi_path_buffer[PATH_MAX];

const axi_builtin_info *axi_builtin_lookup(const char *name, size_t len)
{
    if (!name) return NULL;
    for (int i = 0; BUILTINS[i].name; i++) {
        if (BUILTIN_LENGTHS[i] == len &&
            memcmp(BUILTINS[i].name, name, len) == 0)
            return &BUILTINS[i];
    }
    return NULL;
}

int axi_builtin_scratch_bytes(const char *name, size_t len, size_t *bytes)
{
    size_t one = sizeof(axi_path_buffer);
    if (!name || !bytes) return -1;
    *bytes = 0;
    if (len != sizeof("fs.path_under") - 1
            || memcmp(name, "fs.path_under", len) != 0) return 0;
    if (one > (size_t)-1 - one) return -1;
    *bytes = one + one;
    return 0;
}

/* ---- helpers -------------------------------------------------------------- */

static int v_is_str(const axi_vval *v)
{
    return v && (v->kind == VB_STR || v->kind == VB_BYTES);
}

static void v_set_bool(axi_vval *out, int v)
{
    out->kind = VB_BOOL;
    out->bits = v ? 1 : 0;
    out->s = NULL;
    out->slen = 0;
}

static void v_set_str(axi_vval *out, const char *s, uint32_t len)
{
    out->kind = VB_STR;
    out->bits = 0;
    out->s = s;
    out->slen = len;
}


/* Simple canonicalisation: remove redundant slashes and . / .. components.
 * Writes into dst (size dsize) and returns dst, or NULL on overflow. */
static char *canon_path(const char *src, size_t slen, char *dst, size_t dsize)
{
    char *out = dst;
    size_t n = 0;
    const char *end = src + slen;
    /* INV-296 / AXI-INV-091: lexical bytes cannot alias through C-string NUL. */
    if (memchr(src, '\0', slen)) return NULL;
    int absolute = (slen > 0 && src[0] == '/');
    if (absolute) {
        if (n + 1 >= dsize) return NULL;
        out[n++] = '/';
    }
    const char *p = src;
    while (p < end) {
        while (p < end && *p == '/') p++;
        if (p == end) break;
        const char *seg = p;
        while (p < end && *p != '/') p++;
        size_t len = (size_t)(p - seg);
        if (len == 1 && seg[0] == '.') {
            continue;
        } else if (len == 2 && seg[0] == '.' && seg[1] == '.') {
            size_t base = absolute ? 1u : 0u;
            /* Preserve unresolved relative ..; dropping it changes authority.
             * INV-285 / AXI-INV-080. */
            if (n > base) {
                size_t j = n;
                while (j > 0 && out[j - 1] != '/') j--;
                if (n - j != 2 || out[j] != '.' || out[j + 1] != '.') {
                    n = j > base ? j - 1 : base;
                    continue;
                }
            }
            if (absolute) continue;
        }
        if (n > 0 && out[n - 1] != '/') {
            if (n + 1 >= dsize) return NULL;
            out[n++] = '/';
        }
        if (n + len >= dsize) return NULL;
        memcpy(out + n, seg, len);
        n += len;
    }
    if (n == 0) {
        if (n + 1 >= dsize) return NULL;
        out[n++] = '.';
    }
    out[n] = '\0';
    return dst;
}

/* Lexical predicate only: symlink/resource containment belongs to the effect
 * door and its root-bearing kernel cap. INV-293 / AXI-INV-088. */
static int path_under(const char *child, size_t child_len,
                      const char *root, size_t root_len)
{
    axi_path_buffer c, r;
    if (!child || !root) return 0;
    if (!canon_path(child, child_len, c, sizeof c)) return 0;
    if (!canon_path(root, root_len, r, sizeof r)) return 0;
    size_t rl = strlen(r);
    size_t cl = strlen(c);
    if (rl == 0) return 1;
    if (rl == 1 && r[0] == '/') {
        /* root = "/" : child is under if absolute */
        return cl > 0 && c[0] == '/';
    }
    if (cl < rl) return 0;
    if (memcmp(c, r, rl) != 0) return 0;
    /* boundary: either exact match, or next char is / */
    if (cl == rl || c[rl] == '/') return 1;
    return 0;
}


static const char *const JSON_KINDS[] = {
    "invalid", "string", "number", "bool", "null", "array", "object"
};

/* ---- implementations ------------------------------------------------------ */

int axi_builtin_exec(const char *name, const axi_vval *args, int arity,
                     axi_vval *out, const char **errmsg,
                     char *json_scratch, size_t json_scratch_cap)
{
    const axi_builtin_info *bi;
    if (!errmsg) return -1;
    if (!name || !args || !out) { *errmsg = "invalid builtin arguments"; return -1; }
    bi = axi_builtin_lookup(name, strlen(name));
    if (!bi) { *errmsg = "builtin not found"; return -1; }
    if (arity != bi->arity) { *errmsg = "wrong arity"; return -1; }

    if (strcmp(name, "fs.path_under") == 0) {
        if (!v_is_str(&args[0]) || !v_is_str(&args[1]))
            { *errmsg = "fs.path_under wants two strings"; return -1; }
        v_set_bool(out, path_under(args[0].s, args[0].slen,
                                   args[1].s, args[1].slen));
        return 0;
    }
    if (strncmp(name, "json.", 5) == 0) {
        axi_json_value value;
        int rc;
        if (!v_is_str(&args[0]) || !v_is_str(&args[1]))
            { *errmsg = "json getter wants JSON and path strings"; return -1; }
        if (strcmp(name, "json.get") == 0) {
            /* Legacy textual conversion stays explicit. Its implementation
             * validates once; malformed documents never expose a prefix. */
            const char *res; size_t n;
            if (axi_json_get(args[0].s, args[0].slen, args[1].s, args[1].slen,
                             json_scratch, json_scratch_cap, &res, &n) != 0)
                { *errmsg = "invalid JSON document or path not found"; return -1; }
            v_set_str(out, res, (uint32_t)n); return 0;
        }
        rc = axi_json_get_typed(args[0].s, args[0].slen, args[1].s, args[1].slen,
                                json_scratch, json_scratch_cap, &value);
        if (strcmp(name, "json.kind") == 0 && rc == AXI_JSON_MISSING) {
            v_set_str(out, "missing", 7); return 0;
        }
        if (rc != AXI_JSON_FOUND) {
            *errmsg = rc == AXI_JSON_MISSING ? "JSON field missing" : "invalid JSON document or path";
            return -1;
        }
        if (strcmp(name, "json.kind") == 0) {
            const char *kind = JSON_KINDS[value.kind];
            v_set_str(out, kind, (uint32_t)strlen(kind)); return 0;
        }
        if (strcmp(name, "json.bool") == 0) {
            if (value.kind != AXI_JSON_BOOLEAN)
                { *errmsg = "JSON field is not bool"; return -1; }
            v_set_bool(out, value.length == 4); return 0;
        }
        if (strcmp(name, "json.string") == 0) {
            if (value.kind != AXI_JSON_STRING)
                { *errmsg = "JSON field is not string"; return -1; }
            v_set_str(out, value.bytes, (uint32_t)value.length); return 0;
        }
        if (strcmp(name, "json.u64") == 0 || strcmp(name, "json.i64") == 0) {
            uint64_t bits;
            const char *digits = value.bytes; size_t n = value.length;
            int is_signed = strcmp(name, "json.i64") == 0;
            int negative = is_signed && n && digits[0] == '-';
            if (negative) { digits++; n--; }
            if (value.kind != AXI_JSON_NUMBER ||
                axi_u64_parse(digits, n, AXI_U64_ZERO_PERMITTED, &bits) != AXI_U64_OK ||
                (is_signed && bits > (negative ? UINT64_C(1)<<63 : INT64_MAX))) {
                *errmsg = "JSON field is not an exact in-range integer"; return -1;
            }
            out->kind = is_signed ? VB_I64 : VB_U64;
            out->bits = negative ? UINT64_C(0) - bits : bits;
            out->s = NULL; out->slen = 0; return 0;
        }
    }
    if (strncmp(name, "math.", 5) == 0 || strncmp(name, "budget.", 7) == 0) {
        uint64_t value = 0;
        axi_arith_status status = AXI_ARITH_INVALID;
        for (int i = 0; i < arity; i++) if (args[i].kind != VB_U64) {
            *errmsg = "checked arithmetic requires u64 arguments"; return -1;
        }
        if (strcmp(name, "budget.fits") == 0) {
            v_set_bool(out, axi_u64_budget_fits(args[0].bits, args[1].bits, args[2].bits)); return 0;
        }
        if (strcmp(name, "budget.fits_product") == 0) {
            v_set_bool(out, axi_u64_product_fits(args[0].bits, args[1].bits, args[2].bits)); return 0;
        }
        if (strcmp(name, "math.add_checked") == 0)
            status = axi_u64_add_checked(args[0].bits, args[1].bits, &value);
        else if (strcmp(name, "math.sub_checked") == 0)
            status = axi_u64_sub_checked(args[0].bits, args[1].bits, &value);
        else if (strcmp(name, "math.mul_checked") == 0)
            status = axi_u64_mul_checked(args[0].bits, args[1].bits, &value);
        else if (strcmp(name, "math.div_checked") == 0)
            status = axi_u64_div_checked(args[0].bits, args[1].bits, &value);
        else if (strcmp(name, "math.mod_checked") == 0)
            status = axi_u64_mod_checked(args[0].bits, args[1].bits, &value);
        if (status != AXI_ARITH_OK) {
            *errmsg = status == AXI_ARITH_OVERFLOW ? "u64 overflow" :
                      status == AXI_ARITH_UNDERFLOW ? "u64 underflow" :
                      status == AXI_ARITH_DIVZERO ? "u64 division by zero" : "invalid arithmetic";
            return -1;
        }
        out->kind = VB_U64; out->bits = value; out->s = NULL; out->slen = 0; return 0;
    }
    *errmsg = "builtin not implemented";
    return -1;
}
