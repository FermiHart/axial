# Migração W51–W68: linguagem, números e cota do compilador

Esta atualização preserva o cabeçalho público de embed v1, os formatos
existentes de AXB/manifesto/assinatura e os significados dos opcodes. Ela
completa formas de linguagem que o checker já aceitava e corrige a leitura
de strings e decimais. **Recompilar um fonte antigo pode mudar seus valores
ou seu custo em fuel.** A identidade do checker acompanha os fontes novos;
artefatos com selo CHECKED anterior exigem recertificação explícita.

Estas notas descrevem as mudanças e o procedimento de migração. Os resultados
de cada bloco e seus limites estão em [frontend.md](frontend.md),
[compiler.md](compiler.md) e no [índice de evidências](evidence/README.md).
Os registros preservados identificam revisões locais; este documento não
declara a aprovação do gate final integrado W80.

## 1. Mudanças observáveis

| Waves | Comportamento atual | Consequência para a migração |
| --- | --- | --- |
| W51 | `err.Name` é um valor executável, com namespace de constantes separado de strings. | Formas antes aceitas pelo checker e recusadas pelo codegen passam a compilar; o nome precisa pertencer ao conjunto de erros declarado. |
| W52 | Retornos `payload \| ok` usam os tags canônicos do manifesto. | A ordem dos átomos na assinatura não altera os braços; `false` continua sendo um payload booleano. |
| W53–W54 | `?` avalia o operando uma vez, propaga erros/ausência imediatamente e continua com o payload desembrulhado. | Reveja fluxo, chamadas aninhadas e o conjunto de erros/`ok` declarado pelo chamador. |
| W55–W56 | Fonte e AXS compartilham os cinco escapes de text-string v1 e sua forma canônica. | `\n`, `\t` e `\0` agora produzem um byte de controle; grafias antigas podem precisar de uma barra adicional. |
| W57–W62 | Comandos de compilação têm cota explícita por invocação, padrão de 256 MiB. | Arquivos que cabem no limite de entrada podem ser recusados quando a expansão em AST e buffers excede a cota. |
| W63–W64 | Decimal-f64 v1 arredonda o valor decimal exato uma vez para binary64, com empate para o significando par. | Alguns decimais antigos produzem bits corrigidos; overflow passa a ser uma recusa explícita. |
| W65–W66 | A grafia canônica deriva dos bits do literal; o sinal de literal f64 é emitido diretamente na constante. | Aliases convergem; literais negativos simples usam menos instruções e fuel. |
| W67–W68 | Caminhos inteiros mais rápidos mantêm as mesmas regras exatas de leitura e impressão. | A comparação de desempenho parte do núcleo já correto W65; não pressupõe equivalência com o leitor antigo. |

## 2. Erros, opções e propagação

`err.Name` constrói um erro nomeado sem payload arbitrário. O caminho admite
até dois componentes e 63 bytes ASCII, dentro do domínio do manifesto v1.
Um erro pode ser associado a um `let`, devolvido diretamente ou propagado.
A string `"Name"` e o erro `err.Name` mantêm tipos e identidades distintos.
A atualização conserva as distinções entre erro, `ok`, `false`, recusa,
trap e sucesso. Consulte a [gramática normativa](../SPEC-GRAMMAR.md).

O operador postfixo `?` respeita a forma de retorno verificada pelo checker.
Um erro declarado retorna imediatamente ao chamador, antes de qualquer
expressão posterior. Em `payload | ok`, o payload continua desembrulhado;
`ok` retorna a representação correspondente na assinatura do chamador.
O chamador deve declarar todo erro ou `ok` que possa propagar. Um escalar
simples não admite `?`, e uma chamada que só pode retornar erros não tem
caminho de continuação.

Exemplo de fonte válido, com erro preservado ao atravessar uma chamada:

```axi
cell value : fn(fail: bool) -> u64 | err.No
  fuel 100
  pure
{
  if fail { ret err.No }
  ret 7
}

cell outer : fn(fail: bool) -> u64 | err.No
  fuel 1000
  pure
{
  ret value(fail)?
}
```

No v7 existente, erros são valores escalares de erro. A opção `payload | ok`
usa tag 0 para payload e 1 para `ok`, independentemente da ordem no fonte.
Um payload `false` mantém tag 0. O lowering usa instruções existentes; o
significado anterior de `UCHK` em assembly continua preservado.

## 3. Strings: preservar os bytes pretendidos

Text-string v1 admite exatamente estes escapes em fonte e AXS:

| Grafia no texto | Byte decodificado |
| --- | --- |
| `\n` | LF, `0A` |
| `\t` | TAB, `09` |
| `\0` | NUL, `00` |
| `\\` | Barra invertida, `5C` |
| `\"` | Aspas, `22` |

A implementação anterior decodificava efetivamente apenas barra e aspas.
Assim, os três exemplos abaixo mudam de significado ao recompilar:

| Fonte antigo | Bytes que o decoder anterior produzia | Fonte novo que preserva esses bytes |
| --- | --- | --- |
| `"\n"` | Barra seguida de `n`: `5C 6E` | `"\\n"` |
| `"\t"` | Barra seguida de `t`: `5C 74` | `"\\t"` |
| `"\0"` | Barra seguida de `0`: `5C 30` | `"\\0"` |

Se a intenção já era LF, TAB ou NUL, conserve o escape de uma barra e
verifique o novo resultado. Se a intenção era texto literal, use a grafia
da última coluna. Faça essa revisão antes de aplicar o canonicalizador,
pois ele já usa a nova interpretação.

NUL escapado é dado com comprimento explícito e pode aparecer no meio de
uma string. TAB literal converge para `\t` na forma canônica. Outros
controles ASCII crus e DEL são recusados; escapes desconhecidos, como
`\r`, recebem diagnóstico. Constantes já armazenadas em binários mantêm
seus bytes. A migração alcança também AXS antigo: remontar texto com os três
escapes afetados usa text-string v1.

## 4. Decimais, forma canônica e zero da VM

Decimal-f64 v1 lê o racional decimal exato e aplica arredondamento para o
binary64 mais próximo, com empate para o significando par. O núcleo usa
aritmética inteira e um workspace explícito, sem depender de locale,
`strtod`, modo de arredondamento ou operações de ponto flutuante do host.
As verificações e os limites do algoritmo estão em [frontend.md](frontend.md).

A gramática continua usando ponto e sem expoente: `INT "." INT`. Os
separadores `_` aceitos na entrada não alteram o valor. A parte inteira de
um literal f64 pode ultrapassar u64; o limite u64 continua valendo para
tokens inteiros. Subnormais são admitidos. Underflow pode resultar em zero;
um decimal que arredondaria para infinito recusa com `AXI-L006`. Nenhuma
sintaxe de NaN ou infinito foi acrescentada ao fonte.

**O mesmo lexema antigo pode agora representar outro padrão de bits.** O
exemplo conhecido `0.3` era lido pelo acumulador anterior um ULP acima do
binary64 mais próximo. Agora resulta em `0x3fd3333333333333`. Para preservar
o padrão antigo `0x3fd3333333333334`, a nova grafia canônica é
`0.30000000000000004`. A referência para essa decisão deve ser o padrão
efetivamente armazenado no artefato antigo e o comportamento desejado,
não somente seu texto original.

O canonicalizador usa o menor número de dígitos significativos que retorna
aos mesmos bits; entre candidatos, escolhe o decimal exato mais próximo,
com coeficiente par em empate. Depois remove zeros finais do coeficiente
e expande com ponto, sem expoente. Portanto a forma de um número muito
pequeno ou muito grande pode ser longa. `2.0` continua sendo f64; `2` é um
token inteiro. Decimais que geram os mesmos bits de literal têm a mesma
grafia segundo essa regra.

O sinal permanece uma operação do fonte. O formatter e o pool de constantes
preservam `-0.0`, inclusive quando um literal negativo sofre underflow.
A VM existente normaliza zero negativo para positivo em importação,
carregamento e aritmética; consequentemente a execução devolve `+0` nesses
casos. Essa fronteira permanece explícita: unicidade de grafia é definida
pelos bits do literal, e a VM conserva seu contrato de normalização.

Um retorno direto de literal f64 negativo agora usa `LDK` e `RET`, com custo
2, no lugar da sequência anterior de custo 4. Os preços dos opcodes
permanecem iguais. Ao recompilar, hashes de corpo, registros, fuel consumido
e evidências derivadas do executável podem mudar. Revise asserções que
fixavam esses valores.

## 5. Cota W62: posição das opções e diagnósticos

Os comandos `lex`, `parse`, `canon`, `form`, `types`, `check`, `compile`,
`iface`, `iface-diff`, `lint-safe` e `asm` contratual compartilham uma cota
por invocação. O padrão é **268.435.456 bytes, ou 256 MiB**.
`--compile-mem BYTES` recebe uma contagem decimal de bytes. Zero solicita
uma recusa determinística por cota; não desativa o limite.

Coloque as opções **depois de FILE**, ou **depois de OLD e NEW** no diff:

```sh
build/axi check policy.axi --compile-mem 134217728 --compile-mem-report
build/axi iface-diff old.axi new.axi --json --compile-mem 134217728
build/axi compile policy.axi -o policy.axb --signing-key operator.seed \
  --compile-mem 134217728 --compile-mem-report
```

As posições obrigatórias de arquivos e os valores de `-o` e `--signing-key`
continuam sendo dados, mesmo se seus nomes coincidirem com essas opções.
Comandos de runtime mantêm seu parser e o limite `--` para argumentos
literais. `--mem` conserva seu significado de memória de execução. As novas
opções só pertencem ao conjunto de comandos de compilação listado acima.
Duplicação, valor malformado ou overflow de opção recebem `AXI-X005`.

A cota acompanha snapshots de fonte, nós e cabeçalhos da AST, análise,
formatação, projeção, geração, montagem, manifestos e os workspaces
explicitamente contabilizados. O limite independente de 64 MiB para um
arquivo fonte regular permanece; um fonte dentro desse tamanho ainda pode
exceder 256 MiB depois da expansão. A cota mede armazenamento solicitado,
cabeçalhos e reservas explícitas: RSS, metadados privados da libc, pilha C
em geral, páginas do sistema e page cache não são essa métrica.

| Diagnóstico | Causa |
| --- | --- |
| `AXI-M001` | Cota da invocação excedida. |
| `AXI-M002` | Alocação recusada pelo host. |
| `AXI-M003` | Overflow no cálculo de tamanho. |
| `AXI-M004` | Erro interno de propriedade/contabilização. |

Uma falha de memória termina com status 2. `--compile-mem-report` emite no
stderr um registro JSON `axi.compiler-memory.v1`, com `limit`, `peak`,
`live`, `allocations`, `fixed` e `failure`. `allocations` conta alocações
ainda vivas, e não o total histórico. O registro antecede a destruição
defensiva final do orçamento. Os testes documentados exigem saldo zero e
preservação de um arquivo de destino preexistente nas recusas de publicação.

Chamadores C podem optar por `axi_parse_unit_budget` e devem manter o
orçamento vivo até liberar fonte, AST e resultados associados. Textos desse
perfil usam `axi_compile_free` com o mesmo proprietário. APIs legadas com
orçamento `NULL` continuam compatíveis com `free`. Esses detalhes internos
não modificam o cabeçalho público embed v1.

## 6. Assinatura e recertificação

Preservar o formato binário e a ABI não preserva a identidade semântica do
checker. A identidade recalculada para os novos fontes evita apresentar
execuções de regras antigas como evidência de regras novas.

**Um artefato que carrega selo CHECKED antigo é recusado inclusive sob o
perfil `SIGNATURE_VALID`.** O decoder verifica o selo presente antes de
aplicar o perfil de admissão solicitado. Uma assinatura ordinária sem selo
é independente dessa identidade do checker e continua sujeita às regras
normais de formato, confiança e admissão. A assinatura autentica os bytes;
ela não transforma um selo antigo em certificado do checker novo.

Um procedimento de migração é:

1. Preserve os fontes, AXS revisados e artefatos anteriores como referência.
   Identifique os bytes de strings e padrões f64 que devem ser mantidos e
   aqueles para os quais se deseja a semântica corrigida.
2. Ajuste os escapes e decimais necessários. Canonicalize em outro arquivo
   e execute `check` com o build novo. Examine o diff de fonte, interface,
   comportamento e fuel relevante ao projeto.
3. Compile ou monte uma nova saída assinada com a chave explicitamente
   selecionada pelo operador. Esse passo produz o artefato novo; ele não
   transfere a validade de um selo anterior.
4. Para um artefato CHECKED, forneça ao `seal` o AXS contratual revisado com
   suas células `law_*`. O perfil atual exige leis puras, sem capacidades,
   sem argumentos e com retorno booleano; cada uma deve executar como
   `true` dentro de seu orçamento. Uma lei falsa ou um trap recusa o selo.
5. Verifique a assinatura e reexecute `check-seal` sobre a nova saída com
   a chave pública confiada pelo operador.

Exemplo de comandos, com arquivos de trabalho e chaves já selecionados pelo
operador:

```sh
build/axi canon policy.axi > policy.migrated.axi
build/axi check policy.migrated.axi --compile-mem 268435456
build/axi compile policy.migrated.axi -o policy.review.axb \
  --signing-key operator.seed --compile-mem 268435456
build/axi dis policy.review.axb --trusted-key operator.pk > policy.review.axs
# policy.review.axs deve conter as células law_* revisadas exigidas pelo projeto.
build/axi seal policy.review.axs -o policy.checked.axb --signing-key operator.seed
build/axi verify policy.checked.axb --trusted-key operator.pk
build/axi check-seal policy.checked.axb --trusted-key operator.pk
```

Um selo antigo recusado pelo novo decoder requer o fonte/AXS correspondente
para a reconstrução; trocar o perfil de admissão não libera sua leitura.
O comando `migrate` de formatos antigos conserva seu escopo próprio e não
é um comando de recertificação automática. Nenhum passo destas notas
reescreve binários existentes, relabela CHECKED, cria autoridade ou dispensa
a seleção explícita das chaves pelo operador.
