/* Deliberately bounded test-thread stacks. A crashing baseline is isolated in
 * a child process; no product hook and no claim about arbitrary host stacks. */
#include "runtime_fixture.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    axi_embed_v1_context *context;
    axi_embed_v1_eval_request request;
    axi_embed_v1_outcome outcome;
    axi_embed_v1_value arg;
    uint64_t expected_fuel;
    int ok;
} probe;

static void *evaluate(void *raw)
{
    probe *p = raw;
    p->ok = axi_embed_v1_eval(p->context, &p->request, &p->outcome, NULL) == 0
        && p->outcome.kind == AXI_EMBED_V1_OUTCOME_VALUE
        && p->outcome.value.kind == AXI_EMBED_V1_VALUE_U64
        && p->outcome.value.bits == 77 && p->outcome.fuel_used == p->expected_fuel;
    return NULL;
}

static int chain_probe(unsigned depth, unsigned registers, size_t stack)
{
    runtime80_fixture fixture;
    probe p;
    pid_t child;
    int status;
    memset(&p, 0, sizeof p);
    if (runtime80_chain_init(&fixture, depth, registers)
            || runtime80_context(&fixture, AXI_EMBED_V1_ADMIT_SIGNATURE_VALID, &p.context)) return 1;
    p.request.abi_version = p.outcome.abi_version = AXI_EMBED_V1_ABI_VERSION;
    p.request.struct_size = sizeof p.request; p.outcome.struct_size = sizeof p.outcome;
    p.request.cell.data = (const uint8_t *)"frame000"; p.request.cell.len = 8;
    memcpy(p.request.expected_iface_hash, fixture.model.manifest[0].iface_hash, 32);
    p.arg.kind = AXI_EMBED_V1_VALUE_U64; p.arg.bits = 77;
    p.request.args = &p.arg; p.request.argc = 1;
    p.expected_fuel = (uint64_t)(depth - 1) * 5 + 1; p.request.fuel_limit = p.expected_fuel;
    child = fork();
    if (child == 0) {
        pthread_attr_t attr;
        pthread_t thread;
        struct rlimit core = {0, 0};
        (void)setrlimit(RLIMIT_CORE, &core);
        if (pthread_attr_init(&attr) || pthread_attr_setstacksize(&attr, stack)
                || pthread_create(&thread, &attr, evaluate, &p)) _exit(2);
        pthread_attr_destroy(&attr);
        if (pthread_join(thread, NULL)) _exit(2);
        _exit(p.ok ? 0 : 1);
    }
    if (child < 0 || waitpid(child, &status, 0) != child) return 1;
    axi_embed_v1_context_destroy(p.context); runtime80_fixture_free(&fixture);
    printf("{\"case\":\"stack\",\"depth\":%u,\"registers\":%u,\"stack_bytes\":%zu,"
           "\"fuel\":%llu,\"signal\":%d,\"ok\":%s}\n", depth, registers, stack,
           (unsigned long long)p.expected_fuel, WIFSIGNALED(status) ? WTERMSIG(status) : 0,
           WIFEXITED(status) && WEXITSTATUS(status) == 0 ? "true" : "false");
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

int main(void)
{
    int failed = 0;
    failed |= chain_probe(8, 256, 4u * 1024u * 1024u);
    failed |= chain_probe(64, 1, 512u * 1024u);
    failed |= chain_probe(256, 1, 2u * 1024u * 1024u);
    return failed;
}
