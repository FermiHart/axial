/* ADR-020 Phase B production implementation. */
#include <axial/axi_embed_v1.h>

#include "axi_alloc.h"
#include "axi_builtin.h"
#include "axi_contract.h"
#include "axi_diag.h"
#include "axi_sign.h"
#include "axi_vm.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct axi_embed_v1_context {
    axb_contract_mod model;
    uint32_t admission_profile;
};

typedef struct {
    uintptr_t begin;
    uintptr_t end;
} memory_range;

enum range_check {
    RANGE_CHECK_INVALID = 0,
    RANGE_CHECK_DISJOINT = 1,
    RANGE_CHECK_OVERLAP = -1
};

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
} record_prefix;

static int record_prefix_valid(const void *record, size_t expected_size)
{
    record_prefix prefix;
    if (!record) return 0;
    memcpy(&prefix, record, sizeof prefix);
    return prefix.abi_version == AXI_EMBED_V1_ABI_VERSION
        && prefix.struct_size >= expected_size;
}

static int range_make(const void *pointer, uint64_t length, memory_range *out)
{
    uintptr_t begin;
    if (!out || length > SIZE_MAX || (length != 0 && !pointer)) return 0;
    begin = (uintptr_t)pointer;
    if (length > UINTPTR_MAX - begin) return 0;
    out->begin = begin;
    out->end = begin + (uintptr_t)length;
    return 1;
}

static int range_array(const void *pointer, uint64_t count, size_t stride,
                       memory_range *out)
{
    if (stride != 0 && count > SIZE_MAX / stride) return 0;
    return range_make(pointer, count * stride, out);
}

static int range_overlaps(memory_range left, memory_range right)
{
    return left.begin != left.end && right.begin != right.end
        && left.begin < right.end && right.begin < left.end;
}

static int ranges_finish(const memory_range *writable, size_t nw,
                         const memory_range *input, size_t ni, int valid)
{
    size_t i, j;
    for (i = 0; i < nw; i++) {
        for (j = i + 1; j < nw; j++)
            if (range_overlaps(writable[i], writable[j]))
                return RANGE_CHECK_OVERLAP;
        for (j = 0; j < ni; j++)
            if (range_overlaps(writable[i], input[j]))
                return RANGE_CHECK_OVERLAP;
    }
    return valid ? RANGE_CHECK_DISJOINT : RANGE_CHECK_INVALID;
}

static int reserved_zero(const uint64_t *reserved, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        if (reserved[i] != 0) return 0;
    return 1;
}

static int diag_prepare(axi_embed_v1_diag_buffer *diags)
{
    if (!diags) return 1;
    if (diags->abi_version != AXI_EMBED_V1_ABI_VERSION
            || diags->struct_size < sizeof *diags
            || (diags->capacity != 0 && !diags->entries)
            || diags->capacity > SIZE_MAX / sizeof *diags->entries
            || !reserved_zero(diags->reserved,
                              sizeof diags->reserved / sizeof diags->reserved[0]))
        return 0;
    diags->count = 0;
    diags->dropped = 0;
    return 1;
}

static int create_ranges_disjoint(const axi_embed_v1_context_options *options,
                                  int options_prefix_valid,
                                  axi_embed_v1_context **out,
                                  const axi_embed_v1_diag_buffer *diags,
                                  int diags_prefix_valid)
{
    memory_range writable[3] = {{0}}, input[3] = {{0}};
    memory_range range;
    size_t nw = 0, ni = 0;
    int valid = 1;
    if (out) {
        if (!range_make(out, sizeof *out, &range)) valid = 0;
        else writable[nw++] = range;
    }
    if (diags) {
        if (!range_make(diags, diags_prefix_valid ? sizeof *diags
                                                  : sizeof(record_prefix),
                        &range)) valid = 0;
        else if (diags_prefix_valid) writable[nw++] = range;
        else input[ni++] = range;
        if (diags_prefix_valid) {
            if (!range_array(diags->entries, diags->capacity,
                             sizeof *diags->entries, &range)) valid = 0;
            else writable[nw++] = range;
        }
    }
    if (options) {
        if (!range_make(options, options_prefix_valid ? sizeof *options
                                                      : sizeof(record_prefix),
                        &range)) valid = 0;
        else input[ni++] = range;
        if (options_prefix_valid) {
            if (!range_make(options->module.data, options->module.len, &range))
                valid = 0;
            else input[ni++] = range;
        }
    }
    return ranges_finish(writable, nw, input, ni, valid);
}

static int eval_ranges_disjoint(const axi_embed_v1_context *context,
                                 const axi_embed_v1_eval_request *request,
                                 int request_prefix_valid,
                                 axi_embed_v1_outcome *outcome,
                                 int outcome_prefix_valid,
                                 const axi_embed_v1_diag_buffer *diags,
                                 int diags_prefix_valid)
{
    memory_range writable[4], input[38], args_range;
    memory_range range;
    size_t nw = 0, ni = 0, i;
    int args_valid = 1, valid = 1;
    if (outcome) {
        if (!range_make(outcome, outcome_prefix_valid ? sizeof *outcome
                                                      : sizeof(record_prefix),
                        &range)) valid = 0;
        else if (outcome_prefix_valid) writable[nw++] = range;
        else input[ni++] = range;
    }
    if (diags) {
        if (!range_make(diags, diags_prefix_valid ? sizeof *diags
                                                  : sizeof(record_prefix),
                        &range)) valid = 0;
        else if (diags_prefix_valid) writable[nw++] = range;
        else input[ni++] = range;
        if (diags_prefix_valid) {
            if (!range_array(diags->entries, diags->capacity,
                             sizeof *diags->entries, &range)) valid = 0;
            else writable[nw++] = range;
        }
    }
    if (request) {
        if (!range_make(request, request_prefix_valid ? sizeof *request
                                                      : sizeof(record_prefix),
                        &range)) valid = 0;
        else input[ni++] = range;
        if (request_prefix_valid) {
            if (!range_make(request->cell.data, request->cell.len, &range))
                valid = 0;
            else input[ni++] = range;
            if (request->argc > 16) {
                valid = 0;
                args_valid = 0;
            } else if (!range_array(request->args, request->argc,
                                    sizeof *request->args, &args_range)) {
                valid = 0;
                args_valid = 0;
            } else input[ni++] = args_range;
            if (!range_make(request->workspace.data,
                            request->workspace.capacity, &range)) valid = 0;
            else writable[nw++] = range;
            if (args_valid) for (i = 0; i < request->argc; i++) {
                if (!range_make(request->args[i].payload.data,
                                request->args[i].payload.len, &range)) valid = 0;
                else input[ni++] = range;
                if (!range_make(request->args[i].atom.data,
                                request->args[i].atom.len, &range)) valid = 0;
                else input[ni++] = range;
            }
        }
    }
    if (context) {
        if (!range_make(context, sizeof *context, &range)) valid = 0;
        else input[ni++] = range;
    }
    return ranges_finish(writable, nw, input, ni, valid);
}

static void diag_emit(axi_embed_v1_diag_buffer *diags, const char *code,
                      uint32_t phase, const char *message, const char *repair)
{
    axi_embed_v1_diag *entry;
    size_t code_len, message_len, repair_len;
    if (!diags) return;
    if (diags->capacity == 0) { diags->dropped = 1; return; }
    entry = &diags->entries[0];
    memset(entry, 0, sizeof *entry);
    entry->schema_version = AXI_EMBED_V1_DIAG_SCHEMA_VERSION;
    entry->phase = phase;
    entry->offset = AXI_EMBED_V1_NO_OFFSET;
    code_len = strlen(code);
    message_len = strlen(message);
    repair_len = strlen(repair);
    if (code_len >= sizeof entry->code) code_len = sizeof entry->code - 1;
    if (message_len >= sizeof entry->message)
        message_len = sizeof entry->message - 1;
    if (repair_len >= sizeof entry->repair)
        repair_len = sizeof entry->repair - 1;
    memcpy(entry->code, code, code_len);
    memcpy(entry->message, message, message_len);
    memcpy(entry->repair, repair, repair_len);
    diags->count = 1;
}

static axi_embed_v1_status refuse(axi_embed_v1_diag_buffer *diags,
                                  axi_embed_v1_status status,
                                  const char *code, uint32_t phase,
                                  const char *message, const char *repair)
{
    diag_emit(diags, code, phase, message, repair);
    return status;
}

static int leaf_type_has_cap(const axb_mtype *type)
{
    return type->tag == AXB_MT_CAP;
}

static int model_is_pure_cap_free(const axb_contract_mod *model)
{
    uint32_t i, j;
    if (model->body.neff != 0) return 0;
    for (i = 0; i < model->nmanifest; i++) {
        const axb_manifest *manifest = &model->manifest[i];
        if (!(manifest->flags
              & (AXB_MANIFEST_FLAG_PURE | AXB_MANIFEST_FLAG_POLICY))
                || manifest->ncaps != 0) return 0;
        for (j = 0; j < manifest->nparams; j++)
            if (leaf_type_has_cap(&manifest->params[j].type)) return 0;
        for (j = 0; j < manifest->nreturns; j++)
            if (leaf_type_has_cap(&manifest->returns[j])) return 0;
    }
    return 1;
}

static int bytes_valid(axi_embed_v1_bytes bytes)
{
    return bytes.len <= UINT32_MAX && (bytes.len == 0 || bytes.data != NULL);
}

static int public_value_to_vm(const axi_embed_v1_value *value, axi_vval *out)
{
    if (!value || !out || value->flags != 0 || value->tag != 0
            || !reserved_zero(value->reserved,
                              sizeof value->reserved / sizeof value->reserved[0])
            || !bytes_valid(value->payload) || !bytes_valid(value->atom))
        return 0;
    memset(out, 0, sizeof *out);
    switch (value->kind) {
    case AXI_EMBED_V1_VALUE_UNIT:
        if (value->payload_kind != 0 || value->bits != 0
                || value->payload.len != 0 || value->atom.len != 0) return 0;
        out->kind = VB_UNIT;
        return 1;
    case AXI_EMBED_V1_VALUE_U64:
        out->kind = VB_U64;
        break;
    case AXI_EMBED_V1_VALUE_I64:
        out->kind = VB_I64;
        break;
    case AXI_EMBED_V1_VALUE_F64:
        out->kind = VB_F64;
        break;
    case AXI_EMBED_V1_VALUE_BOOL:
        if (value->bits > 1) return 0;
        out->kind = VB_BOOL;
        break;
    case AXI_EMBED_V1_VALUE_STR:
        out->kind = VB_STR;
        break;
    case AXI_EMBED_V1_VALUE_BYTES:
        out->kind = VB_BYTES;
        break;
    case AXI_EMBED_V1_VALUE_ERROR:
        if (value->atom.len == 0) return 0;
        out->kind = VB_ERR;
        break;
    default:
        return 0;
    }
    if (value->payload_kind != 0) return 0;
    if (value->kind != AXI_EMBED_V1_VALUE_STR
            && value->kind != AXI_EMBED_V1_VALUE_BYTES
            && value->kind != AXI_EMBED_V1_VALUE_ERROR) {
        if (value->payload.len != 0 || value->atom.len != 0) return 0;
    } else if (value->kind != AXI_EMBED_V1_VALUE_ERROR
               && (value->bits != 0 || value->atom.len != 0)) return 0;
    out->bits = value->bits;
    out->s = (const char *)value->payload.data;
    out->slen = (uint32_t)value->payload.len;
    out->atom = (const char *)value->atom.data;
    out->atom_len = (uint32_t)value->atom.len;
    return 1;
}

static uint32_t public_kind(axi_vkind kind)
{
    switch (kind) {
    case VB_UNIT: return AXI_EMBED_V1_VALUE_UNIT;
    case VB_U64: return AXI_EMBED_V1_VALUE_U64;
    case VB_I64: return AXI_EMBED_V1_VALUE_I64;
    case VB_F64: return AXI_EMBED_V1_VALUE_F64;
    case VB_BOOL: return AXI_EMBED_V1_VALUE_BOOL;
    case VB_STR: return AXI_EMBED_V1_VALUE_STR;
    case VB_BYTES: return AXI_EMBED_V1_VALUE_BYTES;
    case VB_ERR: return AXI_EMBED_V1_VALUE_ERROR;
    default: return 0;
    }
}

static int vm_value_shape(const axi_vval *value,
                          axi_embed_v1_value *out, uint64_t *required)
{
    uint32_t kind;
    memset(out, 0, sizeof *out);
    *required = 0;
    if (value->kind == VB_UNION) {
        kind = public_kind(value->payload_kind);
        if (!kind || kind == AXI_EMBED_V1_VALUE_UNION) return 0;
        out->kind = AXI_EMBED_V1_VALUE_UNION;
        out->payload_kind = kind;
        out->tag = value->tag;
    } else {
        kind = public_kind(value->kind);
        if (!kind) return 0;
        out->kind = kind;
    }
    out->bits = value->bits;
    if (kind == AXI_EMBED_V1_VALUE_STR
            || kind == AXI_EMBED_V1_VALUE_BYTES
            || kind == AXI_EMBED_V1_VALUE_ERROR) {
        out->payload.len = value->slen;
        *required = value->slen;
    }
    if (kind == AXI_EMBED_V1_VALUE_ERROR) {
        out->atom.len = value->atom_len;
        *required += value->atom_len;
    }
    return 1;
}

static void vm_value_copy(const axi_vval *value, axi_embed_v1_value *out,
                          uint8_t *workspace)
{
    uint32_t kind = out->kind == AXI_EMBED_V1_VALUE_UNION
                  ? out->payload_kind : out->kind;
    uint64_t offset = 0;
    if (kind == AXI_EMBED_V1_VALUE_ERROR && value->atom_len != 0) {
        memcpy(workspace, value->atom, value->atom_len);
        out->atom.data = workspace;
        offset = value->atom_len;
    }
    if ((kind == AXI_EMBED_V1_VALUE_STR
            || kind == AXI_EMBED_V1_VALUE_BYTES
            || kind == AXI_EMBED_V1_VALUE_ERROR) && value->slen != 0) {
        memcpy(workspace + offset, value->s, value->slen);
        out->payload.data = workspace + offset;
    }
}

static void diag_publish_internal(axi_embed_v1_diag_buffer *public_diags,
                                  const axi_diags *internal,
                                  uint32_t phase)
{
    uint64_t available, count, i;
    if (!public_diags) return;
    available = internal->n < 0 ? 0 : (uint64_t)internal->n;
    count = available < public_diags->capacity
          ? available : public_diags->capacity;
    for (i = 0; i < count; i++) {
        const axi_diag *source = &internal->d[i];
        axi_embed_v1_diag *target = &public_diags->entries[i];
        memset(target, 0, sizeof *target);
        target->schema_version = AXI_EMBED_V1_DIAG_SCHEMA_VERSION;
        target->phase = phase;
        target->offset = source->off == AXI_NO_OFF
                       ? AXI_EMBED_V1_NO_OFFSET : source->off;
        memcpy(target->code, source->code, sizeof target->code);
        memcpy(target->message, source->msg, sizeof target->message);
        memcpy(target->repair, source->fix, sizeof target->repair);
    }
    public_diags->count = count;
    public_diags->dropped = available - count
                          + (internal->dropped > 0
                             ? (uint64_t)internal->dropped : 0);
}

static int find_cell(const axb_contract_mod *model, axi_embed_v1_bytes name,
                     uint32_t *index)
{
    uint32_t i;
    for (i = 0; i < model->body.n; i++) {
        size_t len = strlen(model->body.cells[i].name);
        if (name.len == len
                && memcmp(name.data, model->body.cells[i].name, len) == 0) {
            *index = i;
            return 1;
        }
    }
    return 0;
}

uint32_t axi_embed_v1_abi_version(void)
{
    return AXI_EMBED_V1_ABI_VERSION;
}

axi_embed_v1_status axi_embed_v1_context_create(
    const axi_embed_v1_context_options *options,
    axi_embed_v1_context **out,
    axi_embed_v1_diag_buffer *diags)
{
    axi_embed_v1_context *context;
    int diags_prefix, options_prefix, ranges;
    int decode_rc;
    options_prefix = record_prefix_valid(options, sizeof *options);
    diags_prefix = !diags || record_prefix_valid(diags, sizeof *diags);
    ranges = create_ranges_disjoint(options, options_prefix, out, diags,
                                    diags_prefix);
    if (ranges == RANGE_CHECK_OVERLAP)
        return AXI_EMBED_V1_STATUS_INVALID_ARGUMENT;
    /* AXI-INV-151: valid outputs precede every non-overlap refusal. */
    if (out) *out = NULL;
    if (!diags_prefix) return AXI_EMBED_V1_STATUS_INVALID_ARGUMENT;
    if (!diag_prepare(diags)) return AXI_EMBED_V1_STATUS_INVALID_ARGUMENT;
    if (!options || !out)
        return refuse(diags, AXI_EMBED_V1_STATUS_INVALID_ARGUMENT,
                      "AXI-EV101", AXI_EMBED_V1_PHASE_ARGUMENT,
                      "context creation requires options and output storage",
                      "provide non-NULL, disjoint options and output pointers");
    if (!options_prefix)
        return refuse(diags, AXI_EMBED_V1_STATUS_ABI_MISMATCH,
                      "AXI-EV102", AXI_EMBED_V1_PHASE_ARGUMENT,
                      "context options use an unsupported ABI prefix",
                      "set abi_version and struct_size for embed API v1");
    if (ranges == RANGE_CHECK_INVALID)
        return AXI_EMBED_V1_STATUS_INVALID_ARGUMENT;
    if (options->flags != 0
            || !reserved_zero(options->reserved,
                              sizeof options->reserved
                                  / sizeof options->reserved[0])
            || (options->admission_profile != AXI_EMBED_V1_ADMIT_SIGNATURE_VALID
                && options->admission_profile != AXI_EMBED_V1_ADMIT_CHECKED)
            || !options->module.data || options->module.len == 0
            || options->module.len > SIZE_MAX
            || options->module.len > AXB_CONTRACT_MAX_BYTES + AXBS_TRAILER)
        return refuse(diags, AXI_EMBED_V1_STATUS_INVALID_ARGUMENT,
                      "AXI-EV101", AXI_EMBED_V1_PHASE_ARGUMENT,
                      "context options contain an invalid field",
                      "use one admission profile and canonical bounded inputs");

    errno = 0;
    context = axi_calloc(1, sizeof *context);
    if (!context)
        return refuse(diags, AXI_EMBED_V1_STATUS_OUT_OF_MEMORY,
                      "AXI-EV104", AXI_EMBED_V1_PHASE_ADMISSION,
                      "context allocation failed", "release memory and retry");
    errno = 0;
    decode_rc = axb_contract_v7_decode_trusted(&context->model,
                                               options->module.data,
                                               (size_t)options->module.len,
                                               options->trusted_producer_pk);
    if (decode_rc != 0) {
        int oom = errno == ENOMEM;
        free(context);
        return refuse(diags,
                      oom ? AXI_EMBED_V1_STATUS_OUT_OF_MEMORY
                          : AXI_EMBED_V1_STATUS_ADMISSION_REFUSED,
                      oom ? "AXI-EV104" : "AXI-EV103",
                      AXI_EMBED_V1_PHASE_ADMISSION,
                      oom ? "module admission allocation failed"
                          : "module signature or v7 framing was refused",
                      oom ? "release memory and retry"
                          : "provide one exact trusted signed-v7 artifact");
    }
    if (!model_is_pure_cap_free(&context->model)
            || (options->admission_profile == AXI_EMBED_V1_ADMIT_CHECKED
                && (!context->model.seal.present
                    || axb_contract_seal_verify(&context->model, 1) != 0))) {
        axb_contract_mod_free(&context->model);
        free(context);
        return refuse(diags, AXI_EMBED_V1_STATUS_ADMISSION_REFUSED,
                      "AXI-EV103", AXI_EMBED_V1_PHASE_ADMISSION,
                      "artifact does not satisfy the selected pure profile",
                      "remove authority or provide a valid checked certificate");
    }
    context->admission_profile = options->admission_profile;
    *out = context;
    return AXI_EMBED_V1_STATUS_OK;
}

void axi_embed_v1_context_destroy(axi_embed_v1_context *context)
{
    if (!context) return;
    axb_contract_mod_free(&context->model);
    memset(context, 0, sizeof *context);
    free(context);
}

axi_embed_v1_status axi_embed_v1_eval(
    const axi_embed_v1_context *context,
    const axi_embed_v1_eval_request *request,
    axi_embed_v1_outcome *outcome,
    axi_embed_v1_diag_buffer *diags)
{
    axi_vval args[16], result;
    axi_vm_output_storage storage = {0};
    axi_diags internal_diags;
    uint32_t cell_index, i;
    uint64_t fuel_used = 0, required = 0;
    int diags_prefix, ok, outcome_prefix, outcome_valid, ranges;
    int request_prefix, fuel_exhausted = 0;
    outcome_prefix = record_prefix_valid(outcome, sizeof *outcome);
    outcome_valid = outcome_prefix
        && reserved_zero(outcome->reserved,
                         sizeof outcome->reserved / sizeof outcome->reserved[0]);
    request_prefix = record_prefix_valid(request, sizeof *request);
    diags_prefix = !diags || record_prefix_valid(diags, sizeof *diags);
    ranges = eval_ranges_disjoint(context, request, request_prefix,
                                  outcome, outcome_valid, diags, diags_prefix);
    if (ranges == RANGE_CHECK_OVERLAP)
        return AXI_EMBED_V1_STATUS_INVALID_ARGUMENT;
    /* AXI-INV-151: valid outputs precede every non-overlap refusal. */
    if (outcome_valid) {
        memset(outcome, 0, sizeof *outcome);
        outcome->abi_version = AXI_EMBED_V1_ABI_VERSION;
        outcome->struct_size = sizeof *outcome;
        outcome->kind = AXI_EMBED_V1_OUTCOME_REFUSED;
    }
    if (!diags_prefix) return AXI_EMBED_V1_STATUS_INVALID_ARGUMENT;
    if (!diag_prepare(diags)) return AXI_EMBED_V1_STATUS_INVALID_ARGUMENT;
    if (!outcome) return AXI_EMBED_V1_STATUS_INVALID_ARGUMENT;
    if (!outcome_valid) return AXI_EMBED_V1_STATUS_ABI_MISMATCH;
    if (!context || !request)
        return refuse(diags, AXI_EMBED_V1_STATUS_INVALID_ARGUMENT,
                      "AXI-EV101", AXI_EMBED_V1_PHASE_ARGUMENT,
                      "evaluation requires context, request and outcome",
                      "provide non-NULL disjoint call records");
    if (!request_prefix)
        return refuse(diags, AXI_EMBED_V1_STATUS_ABI_MISMATCH,
                      "AXI-EV102", AXI_EMBED_V1_PHASE_ARGUMENT,
                      "eval request uses an unsupported ABI prefix",
                      "set abi_version and struct_size for embed API v1");
    if (ranges == RANGE_CHECK_INVALID)
        return AXI_EMBED_V1_STATUS_INVALID_ARGUMENT;
    outcome->fuel_requested = request->fuel_limit;
    if (!reserved_zero(request->reserved,
                       sizeof request->reserved / sizeof request->reserved[0])
            || !bytes_valid(request->cell) || request->cell.len == 0
            || request->argc > 16
            || (request->argc != 0 && !request->args)
            || (request->workspace.capacity != 0 && !request->workspace.data)
            || request->workspace.capacity > SIZE_MAX)
        return refuse(diags, AXI_EMBED_V1_STATUS_INVALID_ARGUMENT,
                      "AXI-EV101", AXI_EMBED_V1_PHASE_ARGUMENT,
                      "eval request contains an invalid field",
                      "use bounded canonical values and caller workspace");
    for (i = 0; i < request->argc; i++)
        if (!public_value_to_vm(&request->args[i], &args[i])) {
            refuse(diags, AXI_EMBED_V1_STATUS_OK,
                   "AXI-EV105", AXI_EMBED_V1_PHASE_PREFLIGHT,
                   "argument value is not canonical or exceeds v1 bounds",
                   "provide the exact closed value shape declared by the cell");
            return AXI_EMBED_V1_STATUS_OK;
        }
    if (!find_cell(&context->model, request->cell, &cell_index)) {
        refuse(diags, AXI_EMBED_V1_STATUS_OK,
               "AXI-EV106", AXI_EMBED_V1_PHASE_PREFLIGHT,
               "requested cell is not present in the admitted context",
               "request one exact admitted cell name");
        return AXI_EMBED_V1_STATUS_OK;
    }
    if (memcmp(request->expected_iface_hash,
               context->model.manifest[cell_index].iface_hash, 32) != 0) {
        refuse(diags, AXI_EMBED_V1_STATUS_OK,
               "AXI-EV107", AXI_EMBED_V1_PHASE_PREFLIGHT,
               "expected interface hash does not match the admitted cell",
               "bind the request to the exact manifest interface hash");
        return AXI_EMBED_V1_STATUS_OK;
    }
    outcome->fuel_effective = request->fuel_limit;
    if (outcome->fuel_effective
            > context->model.manifest[cell_index].fuel_max)
        outcome->fuel_effective = context->model.manifest[cell_index].fuel_max;
    axi_diags_init(&internal_diags);
    memset(&result, 0, sizeof result);
    ok = axi_vm_run_contract_cell_preverified_pure_scoped_diag(
        &context->model, cell_index, args, (uint8_t)request->argc, &result,
        outcome->fuel_effective, &fuel_used, &fuel_exhausted, &internal_diags,
        &storage);
    outcome->fuel_used = fuel_used;
    if (!ok) {
        axi_vm_output_storage_release(&storage);
        outcome->kind = AXI_EMBED_V1_OUTCOME_TRAP;
        if (fuel_exhausted)
            outcome->flags |= AXI_EMBED_V1_OUTCOME_F_FUEL_EXHAUSTED;
        diag_publish_internal(diags, &internal_diags,
                              AXI_EMBED_V1_PHASE_EXECUTION);
        return AXI_EMBED_V1_STATUS_OK;
    }
    if (!vm_value_shape(&result, &outcome->value, &required)) {
        axi_vm_output_storage_release(&storage);
        outcome->kind = AXI_EMBED_V1_OUTCOME_TRAP;
        return refuse(diags, AXI_EMBED_V1_STATUS_OK,
                      "AXI-EV108", AXI_EMBED_V1_PHASE_OUTPUT,
                      "runtime result has no v1 value representation",
                      "return one closed manifest scalar or tagged arm");
    }
    outcome->workspace_required = required;
    if (required > request->workspace.capacity) {
        axi_vm_output_storage_release(&storage);
        memset(&outcome->value, 0, sizeof outcome->value);
        outcome->kind = AXI_EMBED_V1_OUTCOME_BUFFER_TOO_SMALL;
        return AXI_EMBED_V1_STATUS_OK;
    }
    vm_value_copy(&result, &outcome->value, request->workspace.data);
    axi_vm_output_storage_release(&storage);
    outcome->workspace_used = required;
    if (context->model.manifest[cell_index].flags & AXB_MANIFEST_FLAG_POLICY) {
        if (outcome->value.kind != AXI_EMBED_V1_VALUE_BOOL
                || outcome->value.bits > 1) {
            memset(&outcome->value, 0, sizeof outcome->value);
            outcome->kind = AXI_EMBED_V1_OUTCOME_REFUSED;
            return refuse(diags, AXI_EMBED_V1_STATUS_OK,
                          "AXI-EV109", AXI_EMBED_V1_PHASE_OUTPUT,
                          "policy result is not canonical boolean",
                          "return exactly false or true from a policy cell");
        }
        outcome->kind = outcome->value.bits ? AXI_EMBED_V1_OUTCOME_ALLOW
                                             : AXI_EMBED_V1_OUTCOME_DENY;
    } else {
        outcome->kind = AXI_EMBED_V1_OUTCOME_VALUE;
    }
    return AXI_EMBED_V1_STATUS_OK;
}
