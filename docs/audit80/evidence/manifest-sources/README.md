# Snapshots exatos da medição W78

Estes bundles preservam os fontes de produto que geraram a medição em
[manifest-benchmark.json](../manifest-benchmark.json). A reprodução não
depende da disponibilidade dos commits locais no histórico publicado e não
usa o produto corrente do checkout como substituto do candidato medido.

| Lado | Bundle | SHA-256 | Arquivos de produto |
| --- | --- | --- | ---: |
| Antes | [manifest-before.tar.gz](manifest-before.tar.gz) | `ba7426f1b35f83c8accce1857f937fbd7743eee6a3c0bbc75f513501a5d496cc` | 124 |
| Depois | [manifest-after.tar.gz](manifest-after.tar.gz) | `655b90dc8d863849486ff39864980a50c9afcc3c73a04354081b2ae53de2a6d6` | 124 |

[bundles.json](bundles.json) registra os hashes, tamanhos, árvores e revisões
locais de origem. Esses metadados de origem são históricos, sem atribuição
ao HEAD da publicação. [SHA256SUMS](SHA256SUMS) permite verificar os dois
archives separadamente. A correspondência exigida é exata entre todos os
caminhos/bytes arquivados e o campo `source_sha256` de cada lado no registro
original. Somente `axi_iface.c`, `axi_iface.h` e `axi_contract.c` diferem.

Os archives usam USTAR, caminhos ordenados, uid/gid/mtime zero e nomes de
usuário/grupo vazios. As permissões Git originais são preservadas no tar.
O gzip usa nível 9, mtime zero e nome de arquivo vazio. O empacotamento foi
repetido em memória com os mesmos dados e resultou em bytes idênticos.
Somente `src`, `include` e `vendor` estão presentes; não há symlinks,
hardlinks, devices ou executáveis de teste. Os binários de benchmark são
reconstruídos localmente.

## Extração e verificação após clone

Execute na raiz do repositório, escolhendo um diretório de saída novo:

```sh
python3 docs/audit80/evidence/manifest-sources/extract.py \
  --output build/manifest80-snapshots
python3 tests/audit80/manifest_bench.py \
  --before-source build/manifest80-snapshots/before \
  --after-source build/manifest80-snapshots/after \
  --build build/manifest80-reproduced --build-only \
  --output build/manifest80-build-verification.json
```

O [extractor](extract.py) valida os hashes dos bundles, a identidade do JSON
de referência e todos os arquivos antes de materializar os fontes. Só
aceita arquivos regulares/diretórios dentro dos três prefixos; recusa links,
caminhos externos, duplicação de entradas e diretórios de destino já
existentes. O runner compila cada produto contra os próprios headers com
o mesmo driver e flags. Em modo snapshot, as revisões e árvore Git do
resultado são `null`; a identidade é expressa pelos hashes dos arquivos.

O [build-verification.json](build-verification.json) registra a execução
W79 de `--build-only`: compilação dos dois snapshots e igualdade da fixture
de 969 bytes, SHA-256
`faac3742a04e1907de6dcb8aa5bb2b04785cf3b6d02ca0bd60e5d3a4746dc216`.
`benchmark_executed` é `false`, e `workloads` está vazio. Esse registro não
contém novas amostras de desempenho e não substitui a evidência original.

Para medir novamente, execute o mesmo runner retirando `--build-only` e
usando outro arquivo de saída. A receita completa e os limites da carga
estão em [manifest.md](../../manifest.md).
