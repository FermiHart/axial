# W57–W62 — orçamento por invocação do compilador

## W57 — propriedade e cota explícitas

`axi_compile_budget` é um contexto interno pertencente ao chamador. Uma cota
limita a soma dos buffers, cabeçalhos de alocação e reservas explícitas de
workspace da invocação. Contextos distintos não compartilham contador, cache
mutável ou estado global. O mesmo contexto exige serialização pelo chamador.

A causa da primeira recusa permanece até a reinicialização: `AXI-M001` para
cota, `AXI-M002` para OOM do host, `AXI-M003` para overflow e `AXI-M004` para
erro interno de propriedade. Liberação continua disponível após a recusa.
Uma falha de realloc preserva o ponteiro e seu conteúdo anteriores.

O alocador privado do frontend mantém propriedade em tempo constante; ele
recebe somente bases de alocações válidas, como `free` da linguagem C. Não
substitui o protocolo defensivo de ponteiros do runtime. Contas do backend
usam o protocolo existente e encaminham tanto heap quanto reservas fixas ao
mesmo orçamento do compilador. Os novos hooks são opcionais e nulos nas contas
anteriores.

O valor contabilizado é uma cota do trabalho pertencente à compilação. Não é
uma medida de RSS, do cache de páginas do kernel ou dos metadados privados da
libc; não oferece isolamento de um chamador malicioso que altera o próprio
contexto. Fontes e resultados do perfil com orçamento devem viver até serem
liberados pelo mesmo contexto. O caminho legado com orçamento `NULL` conserva
ponteiros compatíveis com `free`.

Validação W57: `tests/audit80/compiler_budget.c` cobre concorrência por cota
entre buffers e reservas do backend, fronteira exata, overflow, manutenção do
conteúdo em realloc recusado, independência de dois contextos e causa de OOM
injetada. Contagens efetivas e a matriz integrada serão consolidadas em W62.

## W58 — AST pertencente à invocação

`axi_parse_unit_budget` associa cada nó à cota explícita, incluindo o link
privado de cleanup e o cabeçalho de alocação. O parser reserva seu workspace
fixo e libera todos os nós parciais quando a cota termina. O proprietário
permanece no nó; `axi_ast_free` libera pela mesma conta. A API antiga mantém
seu caminho `NULL` compatível com `free`. O chamador deve manter a fonte viva;
a CLI usa uma cópia contabilizada no mesmo orçamento.

Validação: teste de parser na fronteira exata e com um byte a menos, origem
contabilizada junto da AST, recuperação de sintaxe e cleanup da invocação.
O fixture passou 17 checks; o pico desta revisão intermediária é 3.297 bytes
com 18 alocações vivas. Alterações posteriores de metadados de AST podem
mudar esse pico; os testes derivam a fronteira da construção real.

## W59 — análise e renderização recuperáveis

O workspace principal do typechecker, suas arestas de chamada, as strings de
leis canônicas, os buffers de formatação e as edições de diagnóstico recebem
a mesma cota explícita. O canonicalizador também reserva o workspace de
trivia. As variantes antes terminantes do renderer agora retornam `NULL`;
a falta de memória deixa de chamar `exit(2)` no hospedeiro.

Validação: 28 checks de sucesso e recusa em cada fase, árvore mantida válida
após recusa e saldo zero após cleanup. Os 67 goldens originais e todo o gate
de frontend W01–W10 passaram, incluindo as duas varreduras de 99 falhas de
alocação e o caso de 40.000 statements sob stack de 2 MiB.

## W60 — geração de texto e projeções

Constantes de erro e string, nomes de builtins, buffers de emissão, modelo
da interface, listas, leis e diff usam o orçamento da AST. O decoder de
strings tem uma wrapper de orçamento sobre a implementação sem alocação
W55; não há um segundo significado de escapes. A recusa preserva a AST e
limpa os temporários antes de retornar. A coleta de diferenças deixou de
encerrar o processo em OOM e recusa antes de publicar um veredito parcial.

Validação: 35 checks cobrindo strings com LF/NUL semântico, constantes de
erro em namespace próprio, geração de código, interface textual/JSON e
cotas insuficientes. Fonte e AST permanecem contabilizadas enquanto cada
projeção ocorre; o saldo volta a zero no encerramento.

## W61 — one budget through assembly and signing

Contract generation, AXS parsing, manifest storage, disassembly, hashing, verification, signature scratch, signed framing and atomic publication now have explicit accounted paths. Builder models retain their owning backend account; destruction frees every partially assembled object through that owner. Existing APIs remain malloc/free compatible. Source generation copies its final text to the invocation owner before its temporary backend account leaves scope, and releases the intermediate legacy AXS immediately after assembly.

Validation: `compiler_backend.c` passes 71 assertions. The full budgeted path produces byte-identical signed artifacts to the legacy path for the same source and disposable test seed, and the trusted decoder accepts them. Separate codegen, assembly, signing and publication quota refusals restore the retained-source baseline. A publication refused for quota leaves an existing target byte-for-byte intact. Cleanup restores zero live bytes, allocations and fixed reservations.

## W62 — default compiler cap, CLI diagnostics and whole-path failure sweep

The source commands `lex`, `parse`, `canon`, `form`, `types`, `check`, `compile`, `iface`, `iface-diff`, `lint-safe`, and contract `asm` create one explicit invocation budget. The default is 268,435,456 charged bytes (256 MiB). `--compile-mem BYTES` accepts a decimal byte count, including zero for a deterministic refusal probe. Place compiler memory options after the required FILE argument, or after both OLD and NEW for `iface-diff`. Duplicate, malformed or overflowed compiler memory options fail with `AXI-X005`. Required file names and the values of `-o` and `--signing-key` remain data even when their names equal these options. Commands outside this compiler set receive their original arguments unchanged and apply their existing option rules, including the runtime `--` boundary. The existing 64 MiB regular-source snapshot ceiling remains an independent input limit. `--mem` on runtime commands keeps its existing runtime meaning.

Example (the signing seed must be the operator's own explicit file):

```sh
build/axi compile policy.axi -o policy.axb --signing-key operator.seed \
  --compile-mem 134217728 --compile-mem-report
```

The optional stderr JSON record has schema `axi.compiler-memory.v1` and fields `limit`, `peak`, `live`, `allocations`, `fixed`, and `failure`. `allocations` is the number of allocations still live at exit, not a lifetime allocation counter. Clean success and all exercised refusals have zero live storage, allocations and reservations. Reporting precedes the final defensive budget destruction, so cleanup defects cannot be hidden by the destructor. `AXI-M001` is quota, `AXI-M002` host OOM, `AXI-M003` size overflow and `AXI-M004` ownership. Memory failure returns status 2; JSON-capable source commands retain typed diagnostic output. A failed canonical allocation is no longer mislabeled as the comment ceiling.

The invocation accounts source snapshots, AST allocation headers and nodes, type-checking state and call graphs, canonical/interface/codegen buffers, assembler ownership, manifests/arenas and backend/signature workspace. The CLI reserves its bounded diagnostic/lexical workspace explicitly. Form comparison arrays moved out of mutable static storage into invocation-owned memory. This is a requested-storage contract, not a process RSS cap: libc private metadata/stdio internals, general C stack, OS pages and page cache are outside its definition. The default does not promise that every file under the input-byte ceiling fits after AST expansion.

`make gate-compiler` builds five ownership/phase tests plus an independently instrumented whole CLI using `AXI_ALLOC_FAILPOINT`; it inherits the selected compiler, flags and sanitizer settings. Normal validation after the CLI cross-review: 201 C assertions and 3,385 CLI assertions. The full sweep reaches every allocation site for the selected compile (196), assembler (86), interface-diff (100), and noncanonical-form (31) fixtures before a final non-injected run proves the sweep reached the end. Exact peak succeeds; peak minus one refuses for every compiler command. Signing/publication failures retain an existing target. The sweep is bounded to these fixtures, not a claim that every possible program/control path has been exhausted.

Library callers opt in with `axi_parse_unit_budget` and keep the caller-owned budget alive until every AST, source and returned buffer has been released. Use `axi_compile_free` for budgeted returned text; ordinary `free` remains correct for legacy APIs using a null budget. Distinct budgets share no mutable accounting state. A single budget requires external serialization.

The two exact runtime memory goldens were recalculated from observed execution: the first module reservation grows from 130,744 to 130,752 bytes for the builder owner pointer; the total runtime peak grows from 260,717 to 260,749 bytes because simultaneously live module/model copies contain that new pointer. The 24 bytes added to `axi_mem_account` for the optional parent hooks did not change this measured golden: W60, with the hooks and without the builder pointer, still measured 260,717 bytes. The result and refusal behavior are unchanged. This small internal metadata cost is explicit; the frozen public embed header is not changed.

An independent CLI cross-review found that the initial option extractor also examined runtime arguments after `--` and values of other options. W62 now leaves noncompiler commands untouched and skips required source positions and compiler option values. Real signed `echo(str)` regressions cover both new option names as literal runtime arguments and as public-key file names; compiler regressions cover those same names as source files, both interface-diff inputs, output files, and signing-seed values.

The same `gate-compiler` passed with every product object and the injected CLI instrumented by AddressSanitizer and UndefinedBehaviorSanitizer (`-fno-sanitize-recover=all`). LeakSanitizer is unavailable under the host's process tracing, so that run explicitly used `ASAN_OPTIONS=detect_leaks=0`; zero-budget-balance assertions provide scoped cleanup evidence and are not presented as an independent heap leak scan. The 67 existing goldens and 23 driver assertions also pass with the documented internal-size updates.
