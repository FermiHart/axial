# W78 — projetar a interface uma vez por módulo

## Problema e mudança

`axi_codegen_contract_v1` chamava `axi_iface_manifest_v1` para cada célula do
módulo. Cada chamada projetava **todas** as células: copiava nomes, parâmetros,
tipos, erros e capacidades, formatava leis, ordenava conjuntos e calculava os
hashes de interface. Um módulo com *n* células fazia *n²* projeções de células,
embora precisasse de uma por célula.

A nova função interna `axi_iface_manifests_v1` projeta a unidade uma vez e
preenche os manifestos na ordem de `body.cells`. A busca por nome usa a ordenação
que a projeção já produzia, com comparação binária que respeita comprimentos.
A API individual permanece disponível e compartilha a mesma conversão por
célula. Os parâmetros mantêm sua ordem posicional; retornos continuam ordenados
pelos tags de wire, e erros, capacidades e leis mantêm a ordenação anterior.
As verificações de manifesto, os hashes do corpo, a renderização e as regras de
admissão permanecem nos caminhos existentes.

A projeção temporária continua alocada pelo `unit->budget`; as strings dos
manifestos pertencem à arena fornecida pelo chamador. A função libera a projeção
antes de retornar, inclusive em recusa, e zera todas as entradas de saída se a
conversão falhar. A arena pode reter as strings já copiadas até seu teardown
normal, como na API individual. Não há cache global, novo handle, alteração da
ABI embed, relaxamento de `axi_mem_account` ou reserva numérica adicional nesta
wave. A reserva do scratch numérico pertence à integração W77.

## Compatibilidade e recusas verificadas

O teste [compiler_manifest.c](../../tests/audit80/compiler_manifest.c) verifica
169 asserções: igualdade dos bytes codificados contra a API individual no mesmo
módulo; hashes de interface rederivados; `body_hash` ainda zerado na projeção;
ordem de parâmetros, opções e erros; flags de política; leis com decimal e
escape; capacidades ordenadas; consultas sem terminador NUL; nomes ausentes;
unidade sem aprovação do checker; quota da projeção e quota da arena separadas;
esgotamento da arena depois de uma conversão parcial; e limpeza de todos os
contadores de alocação/reserva. A ordem solicitada pelo teste difere tanto da
ordem do fonte quanto da ordenação da interface.

O comparador também compila **a implementação anterior**, em vez de depender
somente de duas entradas que compartilham código. A fixture rica de quatro
células produz os mesmos 969 bytes de AXS nos dois binários, com SHA-256
`faac3742a04e1907de6dcb8aa5bb2b04785cf3b6d02ca0bd60e5d3a4746dc216`.
Os módulos de 16, 64 e 256 células também preservam todos os bytes. Esses testes
incluem parâmetros, leis, opções e erros; a fixture rica acrescenta capacidades,
pureza, strings escapadas e f64. A verificação não executa efeitos.

A varredura [manifest_faults.py](../../tests/audit80/manifest_faults.py) injeta
falha em cada uma das **169 alocações reais** do caminho fonte verificado → AXS
contratual da fixture rica. Foram 1.360 asserções, com a recusa de memória
preservada, saída ausente e `live`, `fixed`, `allocations` e lista de blocos
zerados após limpeza. A varredura passou normal e sob ASan/UBSan. Esses números
são asserções e pontos de falha, não casos independentes de segurança.

## Medição

Base anterior à W78: `731e63476af8f9b15e316bcfe7d91af7a0e27fea`, contendo
W57–W62 e W63–W68. O arquivo
[manifest-benchmark.json](evidence/manifest-benchmark.json) conserva todas as
amostras, warmups, ordem dos pares, tempos de CPU e de parede, hashes dos
binários, da fixture e de cada arquivo de produto. O candidato é identificado
pelos bytes dos fontes; a medição antecedeu o commit. Apenas
`src/axi_iface.c`, `src/axi_iface.h` e `src/axi_contract.c` diferem entre os
fontes de produto comparados.

Ambos os binários foram compilados completos com GCC 13.3.0 e os mesmos flags
`-std=c99 -Wall -Wextra -Werror -O1 -D_POSIX_C_SOURCE=200809L`, vinculando a
mesma libm. O runner fixou a afinidade em CPU 0, fez um warmup por binário e
carga e coletou sete pares, alternando a ordem anterior/candidato. Não há limite
de desempenho usado como condição de aprovação.

O trecho cronometrado chama `axi_codegen_contract_v1`, compara integralmente o
texto com uma referência e libera o resultado. O AST já passou pelo parser e
checker. Geração do fonte, análise, referência inicial, SHA-256, inicialização
do processo e saída JSON ficam fora da medição. Cada política sintética tem
dois parâmetros, duas leis, dois erros e um retorno opcional; os nomes aparecem
em ordem inversa no fonte. Os tempos abaixo correspondem ao lote inteiro de
iterações, medidos com `clock()` em segundos de CPU do processo.

| Células | Iterações por amostra | Mediana anterior | Intervalo anterior | Mediana W78 | Intervalo W78 | Variação da mediana |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 256 | 0,217531 s | 0,209283–0,231317 s | 0,091620 s | 0,088235–0,152414 s | −57,88% |
| 64 | 64 | 0,770376 s | 0,731230–0,796349 s | 0,274679 s | 0,260321–0,288989 s | −64,34% |
| 256 | 16 | 3,108254 s | 2,995107–3,164601 s | 1,154301 s | 1,048936–1,196104 s | −62,86% |

O host é compartilhado. A amostra W78 de 16 células com 0,152414 s está cerca
de 66% acima da mediana de sua série; ela permanece no conjunto, sem descarte
ou escolha de uma repetição mais favorável. Os intervalos das duas versões não
se sobrepõem nesta execução, mas os valores são descritivos desta carga e
ambiente. Não representam latência de compilação assinada em produção,
performance de guests ou ganho universal do compilador.

O pico de quota, incluindo preparação e texto de referência retido, foi
331.900 → 331.900 bytes para 16 células, 973.425 → 972.865 para 64 e
3.566.385 → 3.565.825 para 256. A diferença de 560 bytes nos dois últimos
casos é pequena; esta wave reduz trabalho repetido, sem demonstrar uma redução
relevante de memória. Esses números contabilizam pedidos, cabeçalhos e reservas
explícitas, não RSS. Outras etapas ainda contribuem para o crescimento do
tempo total; remover o fator repetido da projeção não torna todo o pipeline
linear.

## Reprodução após um clone e gates locais

Os identificadores Git acima pertencem ao histórico local da medição. A
publicação pode recriar commits com outros metadados, e o produto integrado
também inclui mudanças de outras waves e nova identidade gerada do checker.
Por isso, a reprodução preservada usa os snapshots exatos em
[manifest-sources/](evidence/manifest-sources/README.md), disponíveis no
próprio repositório. Cada archive contém os 124 arquivos de
`src/include/vendor`; todos os caminhos e hashes foram confrontados com
`source_sha256` no JSON original. Ambos são tar/gzip determinísticos,
compostos exclusivamente de arquivos regulares e diretórios.

Na raiz do clone, extraia em um diretório novo. O extractor confere o hash
de cada bundle e de cada arquivo, recusa links e caminhos externos e não
substitui diretórios de saída existentes:

```sh
python3 docs/audit80/evidence/manifest-sources/extract.py \
  --output build/manifest80-snapshots
python3 tests/audit80/manifest_bench.py \
  --before-source build/manifest80-snapshots/before \
  --after-source build/manifest80-snapshots/after \
  --build build/manifest80-reproduced --build-only \
  --output build/manifest80-build-verification.json
```

`--build-only` compila ambos os conjuntos e compara a fixture rica uma vez,
sem warmups ou amostras de tempo. A verificação documental W79 executou esse
caminho e preserva seu resultado em
[build-verification.json](evidence/manifest-sources/build-verification.json).
Ela confirmou novamente os 969 bytes e o hash da fixture; as medições
originais não foram repetidas nem substituídas. No modo de diretórios,
revisões e árvore Git ficam `null`: a identificação dos snapshots deriva
dos hashes dos arquivos, sem atribuí-los ao HEAD do checkout.

Para repetir também a medição, execute explicitamente sem `--build-only`:

```sh
python3 tests/audit80/manifest_bench.py \
  --before-source build/manifest80-snapshots/before \
  --after-source build/manifest80-snapshots/after \
  --build build/manifest80-reproduced \
  --output build/manifest-benchmark-reproduced.json
```

O runner mantém `--base REV` como alternativa para um histórico Git local
disponível e um checkout candidato apropriado. Nos dois modos, exige
exatamente os três arquivos de produto diferentes da W78; a nova identidade
gerada do produto integrado não é ignorada para contornar essa verificação.
Use os snapshots para reproduzir esta medição histórica depois do clone.

Os gates funcionais continuam disponíveis no produto integrado:

```sh
make -j2 gate-fast gate-compiler
make -j2 BUILD=build-manifest-fail CPPFLAGS=-DAXI_ALLOC_FAILPOINT \
  build-manifest-fail/audit80/compiler_manifest
python3 tests/audit80/manifest_faults.py \
  build-manifest-fail/audit80/compiler_manifest
```

O teste `compiler_manifest.c` entra no wildcard já existente de
`gate-compiler`. Os números a seguir pertencem à validação local original
da W78; alterações de integração podem mudar contagens e picos posteriores.

Gates locais realizados: **67/67 goldens**, **370 asserções C** do conjunto de
quota/compilador, incluindo as 169 novas, e **3.212 asserções CLI**, que incluem
396 pontos reais de OOM: 179 em `compile`, 86 em `asm`, 31 em `form` e 100 em
`iface-diff`. O gate completo de compilador também passou com
`-g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie`, link
`-fsanitize=address,undefined -no-pie`, `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`
e `UBSAN_OPTIONS=halt_on_error=1`. A varredura específica de 169 pontos foi
repetida com esses mesmos sanitizers.

LeakSanitizer ficou desativado; os testes verificam explicitamente os saldos
dos dois mecanismos de quota. As evidências são locais. Esta wave não afirma
execução de CI hospedado ou atestação de produção, nem substitui os gates da
integração final W80.
