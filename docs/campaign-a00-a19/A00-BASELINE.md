# A00 — Baseline, inventário e delta

**Estado:** DONE — inventário estático e plano qualificados.  
**Início:** 29/10/2026, 10h39, America/Sao_Paulo.  
**Escopo:** fontes e registries do Axial standalone; referências do receptor documentadas separadamente.

## Entrega

A campanha A00–A19 está registrada na branch work/axial-a00-a19-20261029, inicialmente publicada pelo commit bd4dc4be024124ad243f92abf55c9910a8ef4d81. O [plano](PLAN.md) contém os vinte cards e o [estado](STATUS.json) conserva dependências, progresso e checkpoints.

Esta wave acrescenta o gerador [axial-inventory.py](../../tools/axial-inventory.py), um inventário JSON reproduzível e a [matriz de delta](DELTA.json) para as vinte waves.

## Referências fixadas

| Componente | Branch ou vínculo | Commit |
| --- | --- | --- |
| Axial baseline | audit/axial-80-waves-20261019 | 26eec8630e8cf1dc3a1808f1580cc12d36410a8e |
| Axial main consultado | main | 2d6752255ffcc92e0b103c97609daf205a5a39de |
| Beyond receptor consultado | codex/gui20-phase1 | 050ba81e15dcd5304d2f833f4897964813f67e2f |
| Beyond main consultado | main | b72f4b6952cf61bac5664375776626b57cf23d63 |
| Jash fixado pelo receptor | tools/ci/payloads.lock.json | 6c8f61ada6385dbb75a6547fc263ecf2bea5d666 |

A árvore do baseline Axial é 069e92e1247544d7d7fae6138dd8e894f7a0265e. O vínculo commit/árvore foi consultado no GitHub; o gerador reconstrói o hash da árvore usando o manifesto completo e verifica os blobs efetivamente interpretados.

No receptor consultado, Docs/AXIAL-BOUNDARY.tsv continua UNWIRED/NONE/NONE. Esse registro não descreve automaticamente outras branches. Os perfis obrigatórios iniciais são núcleo standalone e consumidor host isolado. Jash e target Beyond permanecem perfis de qualificação separados, sujeitos aos contratos de ativação vigentes.

## Inventário extraído

| Item | Quantidade |
| --- | ---: |
| Blobs rastreados | 590 |
| Arquivos C/H no repositório | 175 |
| Arquivos C/H sob src/, include/ e vendor/ | 127 |
| Unidades de fonte agrupadas por stem | 74 |
| Opcodes registrados | 23 |
| Builtins registrados | 14 |
| Capacidades conhecidas, excluindo CAP_NONE | 16 |
| Métodos de capacidades registrados | 3 |

Essas são contagens de fontes e registros. Elas não representam módulos carregados, suporte de backend ou consumidores ativos. O filtro de 127 arquivos C/H não é o conjunto de identidade de 126 arquivos descrito pelo checker W80: os critérios de seleção são diferentes.

O inventário interpreta quatro arquivos: axi_bc.h, axi_builtin_registry.h, axi_cap_table.h e axi_cap_table.c. Os demais caminhos e hashes vêm da árvore Git. O último campo do registry de builtins é exposto como capability_gated; ele não é confundido com custo de fuel.

## Verificação executada

O [registro de verificação](evidence/A00-VERIFICATION.json) contém os resultados:

1. Duas gerações do baseline produziram bytes idênticos.
2. Os modos Git/ref e snapshot/mirror produziram bytes idênticos em uma fixture local com os quatro registries reais e um README inofensivo.
3. Uma cópia local divergente foi recusada por mismatch de blob.
4. Um manifesto declarado incompleto foi recusado.
5. A fila contém exatamente A00–A19, com dependências anteriores e sem ciclos.

SHA-256 do [inventário](evidence/axial-inventory.json):

~~~text
be24eace3332b8f8c6868d397a7a68d185ad0de1eeaa17db8f8e2b2e3276999b
~~~

A verificação corresponde ao gerador e à consistência da campanha. Não inclui build de produto, execução da VM ou boot guest. Nenhuma fonte de runtime, formato de artefato ou contrato ABI foi alterado por A00.

## Reproduzir

Em um checkout que contenha esta campanha e o commit baseline:

~~~sh
python3 tools/axial-inventory.py --repo . --ref 26eec8630e8cf1dc3a1808f1580cc12d36410a8e --output /tmp/axial-inventory.json
~~~

O modo alternativo lê o [manifesto fixado](evidence/source-snapshot.json) e um diretório com os quatro arquivos de fonte indicados, verificando seus hashes:

~~~sh
python3 tools/axial-inventory.py --snapshot docs/campaign-a00-a19/evidence/source-snapshot.json --sources . --output /tmp/axial-inventory.json
~~~

O parser aceita a gramática literal atual dos registries. Um formato não suportado gera erro explícito; não produz silenciosamente inventário vazio. O modo snapshot exige uma árvore completa, com caminhos relativos e fontes regulares para os registries inspecionados.

## Achados encaminhados

| Achado | Evidência | Destino |
| --- | --- | --- |
| Referências de geração ausentes no standalone | Os comentários da cap table citam docs/CAP-METHODS.tsv e tools/gen_cap_table.py; ambos estão ausentes da árvore fixada | A01 identifica a procedência e define o tratamento da fonte normativa |
| Status documental da ABI divergente | Header mantém redação de candidato; relatório e pins descrevem ABI preservada | A02 reconcilia o status, sem inferir quebra binária |
| Mapa Jash histórico e fronteira não ativada | Receptor registra proposta de mapa, ADR-042 e UNWIRED | A09 prepara consumidor sobre o contrato vigente |

O [delta das vinte waves](DELTA.json) aponta fontes existentes e classifica o trabalho restante. Fonte presente não equivale a implementação integrada ou qualificada.

## Aceite A00

- [x] Baseline e branch de campanha identificados.
- [x] Fontes C/H, opcodes, builtins, capacidades e métodos inventariados.
- [x] Tipos, capacidades e custos vêm dos registries atuais.
- [x] Identidades Git e SHA-256 dos arquivos interpretados verificadas.
- [x] Todas as vinte waves possuem destino e referências no delta.
- [x] Perfis obrigatórios e fronteiras de integração explicitados.
- [x] Evidência estática separada de execução de produto.

**Próxima wave:** A01 — reconciliar contratos, fonte normativa e responsabilidades de admissão, política, grant, efeito e recibo.
