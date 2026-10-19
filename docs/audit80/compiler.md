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
