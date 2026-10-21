# Núcleo W65 preservado para reprodução

`axi_numeric.c` e `axi_numeric.h` são cópias byte a byte da revisão local
W65 `bfbf517ad692c6ae6a251522ad1f35bf3817975e`. Esse núcleo já implementa
leitura exata e impressão canônica. Ele é a base do
[numeric-benchmark.json](../numeric-benchmark.json), não o antigo leitor
decimal incorreto.

O fonte C tem SHA-256
`9bd28fa159f1d57ec7a6d02a6cb47b5fee74df8b3f4726b963a78cbff8754253`.
O candidato W68 e seu header estão preservados em
[numeric-crossreview/](../numeric-crossreview/REPRODUCE.md), com fonte C
SHA-256 `2f70e896cf45d1edb3cb3208bf3171fcac1ced5b6067680c33296c7b8fc0402a`.
[SHA256SUMS](SHA256SUMS) registra ambos os arquivos desta base. Nenhuma
consulta a um commit local é necessária depois do clone.

Na raiz do repositório, compile o mesmo driver contra cada núcleo e seus
próprios headers, usando os mesmos flags da medição original:

```sh
mkdir -p build/numeric80-reproduced
cc -std=c99 -Wall -Wextra -Werror -Wpedantic -O1 \
  -Idocs/audit80/evidence/numeric-w65 \
  tests/audit80/numeric_bench.c docs/audit80/evidence/numeric-w65/axi_numeric.c \
  -o build/numeric80-reproduced/before
cc -std=c99 -Wall -Wextra -Werror -Wpedantic -O1 \
  -Idocs/audit80/evidence/numeric-crossreview \
  tests/audit80/numeric_bench.c docs/audit80/evidence/numeric-crossreview/axi_numeric.c \
  -o build/numeric80-reproduced/after
```

Para solicitar uma nova medição pareada, após os testes de correção:

```sh
python3 tests/audit80/numeric_bench.py \
  build/numeric80-reproduced/before build/numeric80-reproduced/after \
  --before-source docs/audit80/evidence/numeric-w65/axi_numeric.c \
  --after-source docs/audit80/evidence/numeric-crossreview/axi_numeric.c \
  --flags='-std=c99 -Wall -Wextra -Werror -Wpedantic -O1' \
  --output build/numeric80-reproduced/measurement.json
```

O runner fixa CPU 0, registra o compilador local, checksums, hashes de fontes
e binários, warmups e sete pares alternados. Compiladores, máquinas e mistura
de valores podem mudar os tempos; os fontes preservados tornam os dois
lados da comparação concretos. Na W79, os fontes foram preservados, seus
hashes foram conferidos e os dois comandos de compilação acima passaram.
Os loops de benchmark não foram executados novamente; as medições
registradas permanecem intactas.
