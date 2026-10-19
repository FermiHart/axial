/* Audit40 W10: parser refusal must reclaim ownership and leave its host alive. */
#include "axi_ast.h"
#include "axi_cap_table.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef AXI_TEST_ALLOCATION_TRACKING
/* LeakSanitizer cannot inspect threads in some restricted hosts. Count the
 * actual product calloc/free ownership as an independent cleanup check. */
static void *live[512];
static size_t live_count;
void *__real_calloc(size_t count, size_t size);
void __real_free(void *ptr);
void *__wrap_calloc(size_t count, size_t size)
{
    void *ptr = __real_calloc(count, size);
    if (ptr) {
        size_t i;
        for (i = 0; i < sizeof live / sizeof live[0] && live[i]; i++) {}
        assert(i < sizeof live / sizeof live[0]);
        live[i] = ptr;
        live_count++;
    }
    return ptr;
}
void __wrap_free(void *ptr)
{
    if (ptr) for (size_t i = 0; i < sizeof live / sizeof live[0]; i++) {
        if (live[i] == ptr) { live[i] = NULL; live_count--; break; }
    }
    __real_free(ptr);
}
#endif

static const char *const cases[] = {
    ".eff io.Write\n"
    "cell calc : fn(a: i64, out: cap io.Write) -> i64 | err.Fail\n"
    "  fuel 1000 cap io.Write uses io.Write\n"
    "{ let xs = [1, 2, 3] let f = 1.25 let neg = -2\n"
    "  if !false { out.write(\"hi\") } else { let x = xs[0] }\n"
    "  ret calc(a + neg, out)? }\n"
    "policy gate : fn(doc: json) -> decision cap fs.Read\n"
    "{ let v = json.bool(doc, \"$.v\") if v { ret \"/x\" under \"/\" } ret false }\n"
    "proof { true 1 + 2 == 3 }\n",
    "cell broken fn(, x: cap ) fuel pure { let = [1,,2] if ) { ret } }\n"
    "policy p : fn() -> bool {ret true} proof{let a=0}\n",
    "",
};

static size_t count_nodes(const axi_node *node)
{
    size_t count = 0;
    for (; node; node = node->next)
        count += 1 + count_nodes(node->a) + count_nodes(node->b)
            + count_nodes(node->c) + count_nodes(node->list);
    return count;
}

static int oom_diag(const axi_diags *ds)
{
    for (int i = 0; i < ds->n; i++)
        if (strcmp(ds->d[i].code, "AXI-D999") == 0) return 1;
    return 0;
}

int main(int argc, char **argv)
{
    int index = argc > 1 ? atoi(argv[1]) : 0;
    const char *source;
    axi_node *unit;
    axi_diags ds;
    assert(index >= 0 && (size_t)index < sizeof cases / sizeof cases[0]);
    assert(!axi_cap_info_by_kind((axi_cap_kind)-1));
    assert(!axi_cap_info_by_kind((axi_cap_kind)CAP__COUNT));
    assert(axi_cap_info_by_kind(CAP_NONE));
    assert(axi_cap_info_by_kind(CAP_IO_WRITE));
    assert(strcmp(axi_tok_name((axi_tok_kind)-1), "?") == 0);
    assert(strcmp(axi_tok_name((axi_tok_kind)T_COUNT), "?") == 0);
    source = cases[index];
    axi_diags_init(&ds);
    unit = axi_parse_unit(source, strlen(source), "audit40", &ds);
    if (!unit) {
        assert(oom_diag(&ds));
        puts("parse=refused");
        /* The failpoint is one-shot; a new invocation in this same process
         * must work normally, proving allocation failure did not poison it. */
        axi_diags_init(&ds);
        unit = axi_parse_unit(source, strlen(source), "audit40", &ds);
        assert(unit && !oom_diag(&ds));
    } else {
        assert(!oom_diag(&ds));
        if (index != 1) assert(ds.n == 0 && ds.dropped == 0);
        printf("parse=ok nodes=%lu\n", (unsigned long)count_nodes(unit));
    }
    axi_ast_free(unit);
#ifdef AXI_TEST_ALLOCATION_TRACKING
    assert(live_count == 0);
#endif
    return 0;
}
