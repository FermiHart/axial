/* ADR-059 / AXI-INV-184: one bounded data identity; no authority/effect door. */
#include "axi_local_action_v1.h"
#include "axi_ast.h"
#include "axi_hash.h"
#include "axi_json.h"
#include "axi_u64.h"
#include <string.h>

typedef struct {
    uint8_t bytes[AXI_LOCAL_ACTION_V1_MAX_BYTES + 32u];
    size_t used;
    int bad;
} writer;

typedef struct {
    const char *bytes;
    size_t len, pos;
    int bad;
} reader;

static int zero32(const uint8_t bytes[32])
{
    unsigned i;
    uint8_t any = 0;
    for (i = 0; i < 32; i++) any |= bytes[i];
    return any == 0;
}

static int valid(const axi_local_action_v1 *a)
{
    if (!a || !a->uid || !a->executor_uid || a->uid == UINT32_MAX ||
            a->executor_uid == UINT32_MAX || a->uid == a->executor_uid ||
            a->has_previous > 1 || a->payload_size > 4096 || a->fuel > 1000000 ||
            a->workspace > 1048576 || a->ttl_ns < UINT64_C(1000000000) ||
            a->ttl_ns > UINT64_C(300000000000) || a->not_after <= a->not_before ||
            a->not_after - a->not_before != a->ttl_ns) return 0;
    if (a->has_previous) return a->previous.size <= 4096;
    return !a->previous.device && !a->previous.inode && !a->previous.size &&
           !a->previous.mtime_ns && zero32(a->previous.sha256);
}

static void put(writer *w, const void *bytes, size_t n)
{
    if (w->bad) return;
    if (n > sizeof w->bytes - w->used) { w->bad = 1; return; }
    memcpy(w->bytes + w->used, bytes, n);
    w->used += n;
}

static void text(writer *w, const char *s) { put(w, s, strlen(s)); }

static void decimal(writer *w, uint64_t value)
{
    char bytes[32] = {0};
    /* AXI-INV-025: JSON digits come from the existing canonical mint. */
    axi_canon_int_json(value, bytes, sizeof bytes);
    if (!bytes[0]) { w->bad = 1; return; }
    text(w, bytes);
}

static void hex(writer *w, const uint8_t *bytes, size_t n, int uuid)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    text(w, "\"");
    for (i = 0; i < n; i++) {
        char pair[2];
        if (uuid && (i == 4 || i == 6 || i == 8 || i == 10)) text(w, "-");
        pair[0] = digits[bytes[i] >> 4]; pair[1] = digits[bytes[i] & 15];
        put(w, pair, 2);
    }
    text(w, "\"");
}

static void clock_json(writer *w, const axi_local_action_v1 *a)
{
    text(w, "{\"boot\":"); hex(w, a->boot, 16, 1);
    text(w, ",\"not_after\":"); decimal(w, a->not_after);
    text(w, ",\"not_before\":"); decimal(w, a->not_before);
    text(w, ",\"source\":\"linux.CLOCK_BOOTTIME.ns\"}");
}

static void limits_json(writer *w, const axi_local_action_v1 *a)
{
    text(w, "{\"fuel\":"); decimal(w, a->fuel);
    text(w, ",\"max_content\":4096,\"ttl_ns\":"); decimal(w, a->ttl_ns);
    text(w, ",\"workspace\":"); decimal(w, a->workspace); text(w, "}");
}

static void policy_json(writer *w, const axi_local_action_v1 *a)
{
    text(w, "{\"binary\":"); hex(w, a->policy_binary, 32, 0);
    text(w, ",\"cell\":\"decide\",\"iface\":"); hex(w, a->policy_iface, 32, 0);
    text(w, ",\"module\":"); hex(w, a->policy_module, 32, 0);
    text(w, ",\"producer\":"); hex(w, a->policy_producer, 32, 0); text(w, "}");
}

static void previous_json(writer *w, const axi_local_action_v1 *a)
{
    const axi_local_previous_v1 *p = &a->previous;
    if (!a->has_previous) { text(w, "null"); return; }
    text(w, "{\"device\":"); decimal(w, p->device);
    text(w, ",\"inode\":"); decimal(w, p->inode);
    text(w, ",\"mtime_ns\":"); decimal(w, p->mtime_ns);
    text(w, ",\"sha256\":"); hex(w, p->sha256, 32, 0);
    text(w, ",\"size\":"); decimal(w, p->size); text(w, "}");
}

static void principal_json(writer *w, const axi_local_action_v1 *a)
{
    text(w, "{\"executor_uid\":"); decimal(w, a->executor_uid);
    text(w, ",\"uid\":"); decimal(w, a->uid); text(w, "}");
}

static void resource_json(writer *w, const axi_local_action_v1 *a)
{
    text(w, "{\"device\":"); decimal(w, a->resource_device);
    text(w, ",\"inode\":"); decimal(w, a->resource_inode);
    text(w, ",\"name\":\"config\"}");
}

static void action_json(writer *w, const axi_local_action_v1 *a)
{
    text(w, "{\"clock\":"); clock_json(w, a);
    text(w, ",\"deployment\":"); hex(w, a->deployment, 16, 0);
    text(w, ",\"limits\":"); limits_json(w, a);
    text(w, ",\"operation\":\"publish_config\",\"payload\":{\"sha256\":");
    hex(w, a->payload_sha256, 32, 0);
    text(w, ",\"size\":"); decimal(w, a->payload_size);
    text(w, "},\"policy\":"); policy_json(w, a);
    text(w, ",\"previous\":"); previous_json(w, a);
    text(w, ",\"principal\":"); principal_json(w, a);
    text(w, ",\"resource\":"); resource_json(w, a);
    text(w, ",\"schema\":\"" AXI_LOCAL_ACTION_V1_SCHEMA "\",\"trust_snapshot_root\":");
    hex(w, a->trust_snapshot_root, 32, 0); text(w, "}");
}

int axi_local_action_v1_encode(const axi_local_action_v1 *a, void *out, size_t capacity)
{
    writer w;
    if (!out || !valid(a)) return AXI_LOCAL_ACTION_V1_INVALID;
    w.used = 0; w.bad = 0;
    action_json(&w, a);
    if (w.bad || w.used > AXI_LOCAL_ACTION_V1_MAX_BYTES) return AXI_LOCAL_ACTION_V1_INVALID;
    if (w.used > capacity) return AXI_LOCAL_ACTION_V1_CAPACITY;
    memcpy(out, w.bytes, w.used); /* AXI-INV-184: commit complete bytes once. */
    return (int)w.used;
}

static void literal(reader *r, const char *s)
{
    size_t n = strlen(s);
    if (r->bad) return;
    if (n > r->len - r->pos || memcmp(r->bytes + r->pos, s, n)) { r->bad = 1; return; }
    r->pos += n;
}

static uint64_t number(reader *r)
{
    size_t start = r->pos;
    uint64_t value = 0;
    if (r->bad) return 0;
    while (r->pos < r->len && r->bytes[r->pos] >= '0' && r->bytes[r->pos] <= '9') r->pos++;
    if (axi_u64_parse(r->bytes + start, r->pos - start, AXI_U64_ZERO_PERMITTED, &value) != AXI_U64_OK) r->bad = 1;
    return value;
}

static int digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static void read_hex(reader *r, uint8_t *out, size_t n, int uuid)
{
    size_t i;
    literal(r, "\"");
    for (i = 0; i < n; i++) {
        int high, low;
        if (uuid && (i == 4 || i == 6 || i == 8 || i == 10)) literal(r, "-");
        if (r->bad) return;
        if (r->len - r->pos < 2) { r->bad = 1; return; }
        high = digit(r->bytes[r->pos]); low = digit(r->bytes[r->pos + 1]);
        if (high < 0 || low < 0) { r->bad = 1; return; }
        out[i] = (uint8_t)((high << 4) | low); r->pos += 2;
    }
    literal(r, "\"");
}

int axi_local_action_v1_decode(axi_local_action_v1 *out, const void *bytes, size_t len)
{
    axi_local_action_v1 a;
    reader r;
    uint64_t uid, executor_uid;
    /* The common JSON door checks the complete document before this fixed,
     * canonical-schema reader extracts any value. No second general parser. */
    if (!out || !bytes || !len || len > AXI_LOCAL_ACTION_V1_MAX_BYTES ||
            axi_json_validate(bytes, len) != 0) return AXI_LOCAL_ACTION_V1_INVALID;
    memset(&a, 0, sizeof a);
    r.bytes = bytes; r.len = len; r.pos = 0; r.bad = 0;
    literal(&r, "{\"clock\":{\"boot\":"); read_hex(&r, a.boot, 16, 1);
    literal(&r, ",\"not_after\":"); a.not_after = number(&r);
    literal(&r, ",\"not_before\":"); a.not_before = number(&r);
    literal(&r, ",\"source\":\"linux.CLOCK_BOOTTIME.ns\"},\"deployment\":"); read_hex(&r, a.deployment, 16, 0);
    literal(&r, ",\"limits\":{\"fuel\":"); a.fuel = number(&r);
    literal(&r, ",\"max_content\":4096,\"ttl_ns\":"); a.ttl_ns = number(&r);
    literal(&r, ",\"workspace\":"); a.workspace = number(&r);
    literal(&r, "},\"operation\":\"publish_config\",\"payload\":{\"sha256\":"); read_hex(&r, a.payload_sha256, 32, 0);
    literal(&r, ",\"size\":"); a.payload_size = number(&r);
    literal(&r, "},\"policy\":{\"binary\":"); read_hex(&r, a.policy_binary, 32, 0);
    literal(&r, ",\"cell\":\"decide\",\"iface\":"); read_hex(&r, a.policy_iface, 32, 0);
    literal(&r, ",\"module\":"); read_hex(&r, a.policy_module, 32, 0);
    literal(&r, ",\"producer\":"); read_hex(&r, a.policy_producer, 32, 0);
    literal(&r, "},\"previous\":");
    if (!r.bad && r.pos < r.len && r.bytes[r.pos] == 'n') literal(&r, "null");
    else {
        a.has_previous = 1;
        literal(&r, "{\"device\":"); a.previous.device = number(&r);
        literal(&r, ",\"inode\":"); a.previous.inode = number(&r);
        literal(&r, ",\"mtime_ns\":"); a.previous.mtime_ns = number(&r);
        literal(&r, ",\"sha256\":"); read_hex(&r, a.previous.sha256, 32, 0);
        literal(&r, ",\"size\":"); a.previous.size = number(&r); literal(&r, "}");
    }
    literal(&r, ",\"principal\":{\"executor_uid\":"); executor_uid = number(&r);
    literal(&r, ",\"uid\":"); uid = number(&r);
    if (uid >= UINT32_MAX || executor_uid >= UINT32_MAX) r.bad = 1;
    else { a.uid = (uint32_t)uid; a.executor_uid = (uint32_t)executor_uid; }
    literal(&r, "},\"resource\":{\"device\":"); a.resource_device = number(&r);
    literal(&r, ",\"inode\":"); a.resource_inode = number(&r);
    literal(&r, ",\"name\":\"config\"},\"schema\":\"" AXI_LOCAL_ACTION_V1_SCHEMA "\",\"trust_snapshot_root\":");
    read_hex(&r, a.trust_snapshot_root, 32, 0); literal(&r, "}");
    if (r.bad || r.pos != r.len || !valid(&a)) return AXI_LOCAL_ACTION_V1_INVALID;
    memcpy(out, &a, sizeof a); /* AXI-INV-184: no partial decoded object. */
    return 0;
}

static void domain(writer *w, const char *s)
{
    w->used = 0; w->bad = 0;
    put(w, s, strlen(s) + 1); /* Exactly one NUL is part of each domain. */
}

static int finish(writer *w, uint8_t out[32])
{
    if (w->bad) return -1;
    axi_sha256(w->bytes, w->used, out);
    return 0;
}

int axi_local_action_v1_roots(const axi_local_action_v1 *a, axi_local_action_roots_v1 *out)
{
    writer w;
    axi_local_action_roots_v1 result;
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)out;
    if (!out || !valid(a)) return AXI_LOCAL_ACTION_V1_INVALID;
    if (x <= y ? y - x < sizeof *a : x - y < sizeof *out) return AXI_LOCAL_ACTION_V1_INVALID;
    domain(&w, "AXV2-ACTION-v1"); action_json(&w, a);
    if (w.used > AXI_LOCAL_ACTION_V1_MAX_BYTES + sizeof("AXV2-ACTION-v1") ||
            finish(&w, result.action)) return AXI_LOCAL_ACTION_V1_INVALID;
    domain(&w, "AXV2-PRINCIPAL-v1");
    text(&w, "{\"deployment\":"); hex(&w, a->deployment, 16, 0);
    text(&w, ",\"principal\":"); principal_json(&w, a); text(&w, "}");
    if (finish(&w, result.principal)) return AXI_LOCAL_ACTION_V1_INVALID;
    domain(&w, "AXV2-POLICY-v1"); policy_json(&w, a);
    if (finish(&w, result.policy)) return AXI_LOCAL_ACTION_V1_INVALID;
    domain(&w, "AXV2-RESOURCE-v1");
    text(&w, "{\"previous\":"); previous_json(&w, a);
    text(&w, ",\"resource\":"); resource_json(&w, a); text(&w, "}");
    if (finish(&w, result.resource)) return AXI_LOCAL_ACTION_V1_INVALID;
    domain(&w, "AXV2-BUDGET-v1");
    text(&w, "{\"clock\":"); clock_json(&w, a);
    text(&w, ",\"limits\":"); limits_json(&w, a); text(&w, "}");
    if (finish(&w, result.budget)) return AXI_LOCAL_ACTION_V1_INVALID;
    memcpy(out, &result, sizeof result);
    return 0;
}
