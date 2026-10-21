# Evidências de números e projeção — Audit80

Este diretório distingue medições de desempenho, revisão independente e
gates da integração. Os arquivos aqui preservados registram execuções
locais anteriores; sua cópia na W79 não representa uma nova execução ou
aprovação do gate final W80.

## Núcleo numérico: W65 → W68

[numeric-benchmark.json](numeric-benchmark.json) é a cópia byte a byte de
`build/numeric80-final-benchmark.json` do trabalho de frontend. SHA-256 do
arquivo completo:
`58fd43d10d46902844a545391bc991bbd25f7f6380df96103d57c876cc53898d`.

A base é o núcleo numérico **já correto de W65**, com fonte SHA-256
`9bd28fa159f1d57ec7a6d02a6cb47b5fee74df8b3f4726b963a78cbff8754253`.
O candidato inclui W67–W68, fonte SHA-256
`2f70e896cf45d1edb3cb3208bf3171fcac1ced5b6067680c33296c7b8fc0402a`.
A medição não compara a nova semântica com o antigo acumulador decimal
incorreto. O JSON inclui os hashes dos binários, flags, warmups, todas as
amostras, ordem dos pares, checksums e tamanho do workspace.

Ambos usaram GCC 13.3.0, C99, `-O1 -Wall -Wextra -Werror -Wpedantic`, CPU 0,
um warmup por binário/carga e sete pares alternados. O trecho cronometrado
usa `clock()` e não faz I/O. A carga do leitor repete a mistura explícita de
16 valores; a de impressão distribui 8.192 valores pelos campos de expoente.

| Carga | Mediana W65, ms | Intervalo W65, ms | Mediana W68, ms | Intervalo W68, ms | Variação |
| --- | ---: | ---: | ---: | ---: | ---: |
| Impressão de 8.192 valores | 453,746 | 435,144–470,197 | 121,553 | 118,503–125,474 | −73,21% |
| Leitura de 65.536 valores | 86,569 | 84,805–95,057 | 29,346 | 28,232–31,109 | −66,10% |

Os checksums coincidem em todos os warmups e pares; o workspace permanece
com 2.372 bytes na ABI testada. São custos locais dos helpers, com mistura
sintética e host compartilhado, sem promessa de latência de produção ou
ganho total do compilador. O núcleo e o header W65 estão preservados em
[numeric-w65/](numeric-w65/README.md), com receita completa para compilar
ambos os binários usando o candidato W68 da cross-review. Assim, a reprodução
funciona após um clone sem acesso aos commits locais originais. Os drivers
continuam em `tests/audit80/numeric_bench.*`.

## Revisão numérica independente

[numeric-crossreview/](numeric-crossreview/) preserva sete arquivos de
`/tmp/axial-numeric-crossreview`: o probe C, seu verificador Python, os
snapshots de `axi_numeric.c`/`.h`, instruções e duas saídas registradas.
As cópias são byte a byte; [SHA256SUMS](numeric-crossreview/SHA256SUMS)
permite conferir os arquivos. O executável temporário não foi incluído.
Os snapshots C e header correspondem aos hashes registrados na saída de
limites; o fonte C coincide com o candidato W68 acima.

O [REPRODUCE.md](numeric-crossreview/REPRODUCE.md) preserva os comandos,
ambiente e escopo exatos:

- **Leitor:** 33 fronteiras exatas entre binary64 adjacentes, com 15
  variantes cada, totalizando 495 entradas. Inclui valores abaixo, no
  empate e acima da fronteira, nas posições significativas
  799/800/801/1025/2048; separadores; sufixos longos de zeros; subnormais;
  transição para normais; e a fronteira de overflow. A maior fronteira
  examinada tem 768 dígitos significativos. Racionais Python verificam os
  vizinhos e a paridade; a perturbação decimal é demonstrada menor que
  um quarto do intervalo binário. `float` do CPython é uma comparação
  adicional, não a única origem dos vizinhos esperados.
- **Impressão:** 3.178 padrões de bits distintos, concentrados nas décadas
  decimais e vizinhos, com sinais e extremos. A **saída escolhida** é
  comparada com `repr` do CPython expandido por `Decimal` para texto sem
  expoente. Essa revisão não enumera todos os candidatos decimais e não
  implementa outro oráculo exaustivo de mínimo/próximo/par. As regras
  receberam também revisão matemática e do fonte. O oráculo independente
  de intervalos do teste principal continua sendo uma evidência separada.
- **Ambiente e limites:** cada uma das 3.673 entradas executa sob quatro
  modos fenv, somando **14.692 chamadas ao núcleo**. Flags de exceção
  preexistentes e modo permanecem iguais, assim como os canários em torno
  do workspace. Probe e núcleo foram compilados com ASan/UBSan;
  LeakSanitizer ficou desativado. Os limites de inteiros foram calculados
  separadamente com Python sem limitação de precisão.

As saídas [review-output.txt](numeric-crossreview/review-output.txt) e
[bounds-output.txt](numeric-crossreview/bounds-output.txt) registram PASS
nesse alcance e os limites 2.658 bits, 2.662 bits e 768 dígitos. Não são
enumeração de todo o espaço binary64, prova mecanizada, execução em outra
ABI/big-endian ou resultado de LeakSanitizer. A preservação documental não
acrescenta casos ao conjunto efetivamente executado.

## Projeção de manifestos: W78 isolada

[manifest-benchmark.json](manifest-benchmark.json), incorporado pelo commit
W78, compara a base imediatamente anterior à otimização com o candidato
que altera somente `axi_iface.c`, `axi_iface.h` e `axi_contract.c`.
[manifest.md](../manifest.md) explica os testes e a reprodução. Os dois
[bundles de fontes exatos](manifest-sources/README.md), com 124 arquivos
cada, tornam a medição reproduzível sem os commits locais e sem substituir
o candidato medido pelo produto integrado. Seus hashes e cada arquivo
coincidem com as identidades do JSON original. Um extractor seguro e as
opções `--before-source`/`--after-source` materializam e selecionam os
snapshots. O registro separado
[build-verification.json](manifest-sources/build-verification.json) comprova
somente a nova compilação e a igualdade de `--fixture`, sem nova medição.
As revisões/tree ficam `null` nesse modo. Essa
comparação já inclui a implementação numérica W68 nos dois lados; seus
percentuais não devem ser somados aos percentuais dos helpers acima.

O trecho medido parte de AST verificado e inclui
`axi_codegen_contract_v1`, comparação integral de saída e liberação. Fonte,
parser/checker, referência inicial, hash da referência e startup ficam fora
do relógio. Há módulos de 16/64/256 células, um warmup e sete pares
alternados, GCC 13.3.0, mesmos flags `-O1` e CPU 0. O JSON retém a amostra
mais alta do candidato de 16 células, as distribuições, os hashes e os
picos de quota. É uma comparação local do gerador contratual, sem assinatura
ou execução de efeitos, e não um benchmark de toda a integração W80.
