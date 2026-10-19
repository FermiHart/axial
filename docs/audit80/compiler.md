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
