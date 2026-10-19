/* Guard the existing amd64 SysV LP64 profile, independently of implementation. */
#include <axial/axi_embed_v1.h>
#include <stddef.h>
#include <stdio.h>

#define ALIGNOF(t) offsetof(struct { char prefix; t value; }, value)
#define ASSERT_ABI(name, expr) typedef char name[(expr) ? 1 : -1]
ASSERT_ABI(pointer_bits, sizeof(void *) == 8);
ASSERT_ABI(long_bits, sizeof(long) == 8);
ASSERT_ABI(size_axi_embed_v1_bytes, sizeof(axi_embed_v1_bytes) == 16);
ASSERT_ABI(align_axi_embed_v1_bytes, ALIGNOF(axi_embed_v1_bytes) == 8);
ASSERT_ABI(size_axi_embed_v1_buffer, sizeof(axi_embed_v1_buffer) == 16);
ASSERT_ABI(align_axi_embed_v1_buffer, ALIGNOF(axi_embed_v1_buffer) == 8);
ASSERT_ABI(size_axi_embed_v1_value, sizeof(axi_embed_v1_value) == 72);
ASSERT_ABI(align_axi_embed_v1_value, ALIGNOF(axi_embed_v1_value) == 8);
ASSERT_ABI(size_axi_embed_v1_diag, sizeof(axi_embed_v1_diag) == 368);
ASSERT_ABI(align_axi_embed_v1_diag, ALIGNOF(axi_embed_v1_diag) == 8);
ASSERT_ABI(size_axi_embed_v1_diag_buffer, sizeof(axi_embed_v1_diag_buffer) == 56);
ASSERT_ABI(align_axi_embed_v1_diag_buffer, ALIGNOF(axi_embed_v1_diag_buffer) == 8);
ASSERT_ABI(size_axi_embed_v1_context_options, sizeof(axi_embed_v1_context_options) == 80);
ASSERT_ABI(align_axi_embed_v1_context_options, ALIGNOF(axi_embed_v1_context_options) == 8);
ASSERT_ABI(size_axi_embed_v1_eval_request, sizeof(axi_embed_v1_eval_request) == 112);
ASSERT_ABI(align_axi_embed_v1_eval_request, ALIGNOF(axi_embed_v1_eval_request) == 8);
ASSERT_ABI(size_axi_embed_v1_outcome, sizeof(axi_embed_v1_outcome) == 144);
ASSERT_ABI(align_axi_embed_v1_outcome, ALIGNOF(axi_embed_v1_outcome) == 8);
ASSERT_ABI(offset_axi_embed_v1_bytes_data, offsetof(axi_embed_v1_bytes, data) == 0);
ASSERT_ABI(offset_axi_embed_v1_bytes_len, offsetof(axi_embed_v1_bytes, len) == 8);
ASSERT_ABI(offset_axi_embed_v1_buffer_data, offsetof(axi_embed_v1_buffer, data) == 0);
ASSERT_ABI(offset_axi_embed_v1_buffer_capacity, offsetof(axi_embed_v1_buffer, capacity) == 8);
ASSERT_ABI(offset_axi_embed_v1_value_kind, offsetof(axi_embed_v1_value, kind) == 0);
ASSERT_ABI(offset_axi_embed_v1_value_payload_kind, offsetof(axi_embed_v1_value, payload_kind) == 4);
ASSERT_ABI(offset_axi_embed_v1_value_tag, offsetof(axi_embed_v1_value, tag) == 8);
ASSERT_ABI(offset_axi_embed_v1_value_flags, offsetof(axi_embed_v1_value, flags) == 12);
ASSERT_ABI(offset_axi_embed_v1_value_bits, offsetof(axi_embed_v1_value, bits) == 16);
ASSERT_ABI(offset_axi_embed_v1_value_payload, offsetof(axi_embed_v1_value, payload) == 24);
ASSERT_ABI(offset_axi_embed_v1_value_atom, offsetof(axi_embed_v1_value, atom) == 40);
ASSERT_ABI(offset_axi_embed_v1_value_reserved, offsetof(axi_embed_v1_value, reserved) == 56);
ASSERT_ABI(offset_axi_embed_v1_diag_schema_version, offsetof(axi_embed_v1_diag, schema_version) == 0);
ASSERT_ABI(offset_axi_embed_v1_diag_code, offsetof(axi_embed_v1_diag, code) == 4);
ASSERT_ABI(offset_axi_embed_v1_diag_phase, offsetof(axi_embed_v1_diag, phase) == 16);
ASSERT_ABI(offset_axi_embed_v1_diag_reserved0, offsetof(axi_embed_v1_diag, reserved0) == 20);
ASSERT_ABI(offset_axi_embed_v1_diag_offset, offsetof(axi_embed_v1_diag, offset) == 24);
ASSERT_ABI(offset_axi_embed_v1_diag_message, offsetof(axi_embed_v1_diag, message) == 32);
ASSERT_ABI(offset_axi_embed_v1_diag_repair, offsetof(axi_embed_v1_diag, repair) == 192);
ASSERT_ABI(offset_axi_embed_v1_diag_reserved, offsetof(axi_embed_v1_diag, reserved) == 352);
ASSERT_ABI(offset_axi_embed_v1_diag_buffer_abi_version, offsetof(axi_embed_v1_diag_buffer, abi_version) == 0);
ASSERT_ABI(offset_axi_embed_v1_diag_buffer_struct_size, offsetof(axi_embed_v1_diag_buffer, struct_size) == 4);
ASSERT_ABI(offset_axi_embed_v1_diag_buffer_entries, offsetof(axi_embed_v1_diag_buffer, entries) == 8);
ASSERT_ABI(offset_axi_embed_v1_diag_buffer_capacity, offsetof(axi_embed_v1_diag_buffer, capacity) == 16);
ASSERT_ABI(offset_axi_embed_v1_diag_buffer_count, offsetof(axi_embed_v1_diag_buffer, count) == 24);
ASSERT_ABI(offset_axi_embed_v1_diag_buffer_dropped, offsetof(axi_embed_v1_diag_buffer, dropped) == 32);
ASSERT_ABI(offset_axi_embed_v1_diag_buffer_reserved, offsetof(axi_embed_v1_diag_buffer, reserved) == 40);
ASSERT_ABI(offset_axi_embed_v1_context_options_abi_version, offsetof(axi_embed_v1_context_options, abi_version) == 0);
ASSERT_ABI(offset_axi_embed_v1_context_options_struct_size, offsetof(axi_embed_v1_context_options, struct_size) == 4);
ASSERT_ABI(offset_axi_embed_v1_context_options_admission_profile, offsetof(axi_embed_v1_context_options, admission_profile) == 8);
ASSERT_ABI(offset_axi_embed_v1_context_options_flags, offsetof(axi_embed_v1_context_options, flags) == 12);
ASSERT_ABI(offset_axi_embed_v1_context_options_module, offsetof(axi_embed_v1_context_options, module) == 16);
ASSERT_ABI(offset_axi_embed_v1_context_options_trusted_producer_pk, offsetof(axi_embed_v1_context_options, trusted_producer_pk) == 32);
ASSERT_ABI(offset_axi_embed_v1_context_options_reserved, offsetof(axi_embed_v1_context_options, reserved) == 64);
ASSERT_ABI(offset_axi_embed_v1_eval_request_abi_version, offsetof(axi_embed_v1_eval_request, abi_version) == 0);
ASSERT_ABI(offset_axi_embed_v1_eval_request_struct_size, offsetof(axi_embed_v1_eval_request, struct_size) == 4);
ASSERT_ABI(offset_axi_embed_v1_eval_request_cell, offsetof(axi_embed_v1_eval_request, cell) == 8);
ASSERT_ABI(offset_axi_embed_v1_eval_request_expected_iface_hash, offsetof(axi_embed_v1_eval_request, expected_iface_hash) == 24);
ASSERT_ABI(offset_axi_embed_v1_eval_request_args, offsetof(axi_embed_v1_eval_request, args) == 56);
ASSERT_ABI(offset_axi_embed_v1_eval_request_argc, offsetof(axi_embed_v1_eval_request, argc) == 64);
ASSERT_ABI(offset_axi_embed_v1_eval_request_fuel_limit, offsetof(axi_embed_v1_eval_request, fuel_limit) == 72);
ASSERT_ABI(offset_axi_embed_v1_eval_request_workspace, offsetof(axi_embed_v1_eval_request, workspace) == 80);
ASSERT_ABI(offset_axi_embed_v1_eval_request_reserved, offsetof(axi_embed_v1_eval_request, reserved) == 96);
ASSERT_ABI(offset_axi_embed_v1_outcome_abi_version, offsetof(axi_embed_v1_outcome, abi_version) == 0);
ASSERT_ABI(offset_axi_embed_v1_outcome_struct_size, offsetof(axi_embed_v1_outcome, struct_size) == 4);
ASSERT_ABI(offset_axi_embed_v1_outcome_kind, offsetof(axi_embed_v1_outcome, kind) == 8);
ASSERT_ABI(offset_axi_embed_v1_outcome_flags, offsetof(axi_embed_v1_outcome, flags) == 12);
ASSERT_ABI(offset_axi_embed_v1_outcome_value, offsetof(axi_embed_v1_outcome, value) == 16);
ASSERT_ABI(offset_axi_embed_v1_outcome_fuel_requested, offsetof(axi_embed_v1_outcome, fuel_requested) == 88);
ASSERT_ABI(offset_axi_embed_v1_outcome_fuel_effective, offsetof(axi_embed_v1_outcome, fuel_effective) == 96);
ASSERT_ABI(offset_axi_embed_v1_outcome_fuel_used, offsetof(axi_embed_v1_outcome, fuel_used) == 104);
ASSERT_ABI(offset_axi_embed_v1_outcome_workspace_used, offsetof(axi_embed_v1_outcome, workspace_used) == 112);
ASSERT_ABI(offset_axi_embed_v1_outcome_workspace_required, offsetof(axi_embed_v1_outcome, workspace_required) == 120);
ASSERT_ABI(offset_axi_embed_v1_outcome_reserved, offsetof(axi_embed_v1_outcome, reserved) == 128);

int main(void)
{
    const unsigned value = 1;
    if (*(const unsigned char *)&value != 1 || axi_embed_v1_abi_version() != 1) {
        fputs("audit ABI: expected amd64 SysV LP64 little-endian v1 profile\n", stderr);
        return 1;
    }
    puts("audit ABI: 72 compile-time layout checks + endian/version PASS");
    return 0;
}
