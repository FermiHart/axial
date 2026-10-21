# Auditoria integral do Axial — 40 waves

> **Atualização W41–W80:** este relatório preserva os resultados e as pendências
> da entrega histórica W01–W40. O estado posterior dessas pendências está no
> [relatório Audit80](../audit80/REPORT.md) e nas
> [notas de migração](../audit80/migration.md).

**Data:** 19 de outubro de 2026. **Escopo:** compilador, VM, bytecode, efeitos, replay, evidências, armazenamento local, API de embedding, build e validação do projeto Axial.

**Revisão original:** `2d6752255ffcc92e0b103c97609daf205a5a39de`. As 39 etapas de
implementação e a wave 40 de integração formam o histórico desta entrega.
O [mapa de árvores](evidence/commit-trees.json) vincula cada commit local
revisado ao commit publicado com arquivos idênticos.

## Resultado da auditoria

Esta entrega consolida 40 waves de investigação, correção, otimização e integração. Os resultados mais relevantes são correções de corrupção de memória, resultados silenciosamente incorretos, efeitos executados antes de uma recusa previsível e registros que podiam descrever incorretamente um efeito já ocorrido. Também foram removidos percursos redundantes importantes no compilador, na verificação de selos e na busca de células da API pública.

Os gates locais completos passaram nas configurações normal `-O1`, otimizada `-O2` e AddressSanitizer/UndefinedBehaviorSanitizer. O cabeçalho público de embed v1 permanece idêntico ao original. Os formatos existentes de AXB e replay foram preservados; a identidade do checker mudou para representar as correções semânticas. Isso exige migração explícita de artefatos com selos CHECKED antigos, detalhada adiante.

Também foram inspecionados o site estático e as declarações de dependências. O site usa assets locais e um pequeno listener de scroll, sem scripts externos ou instalação de pacotes. README e site receberam comandos de clone executáveis e a distinção entre os 67 goldens e o gate ampliado. A biblioteca continua em C99 com crypto vendorizada e `libm`; Python 3 é ferramenta de validação, não dependência do runtime.

As mudanças estão restritas ao Axial. Esta auditoria não modificou os projetos externos Bythom, Jash, OSIF ou Beyond, nem acrescentou uma nova linguagem de autoridade. A análise parte da árvore pública original e usa reproduções executáveis, mutações de entradas, falhas injetadas e comparação de desempenho. Não constitui prova de ausência de defeitos ou certificação de produção. Os relatos técnicos por área estão em [frontend](frontend.md), [runtime](runtime.md), [segurança e evidências](security.md) e [driver e integração](driver.md).

## Defeitos de maior impacto

**Segurança de memória e disponibilidade.** Três reproduções particularmente fortes atingiram o digest de replay, o leitor TRS1 e a reserva de quotas de leases. Comprimentos controlados pelo chamador podiam ultrapassar um buffer automático de replay; prefixos TRS1 de 1–3 bytes chegavam a `memcmp` com ponteiro nulo; `nquota=255` ultrapassava arrays fixos. ASan/UBSan reproduziram essas falhas na implementação original. As correções validam limites antes de acessar ou publicar dados. O parser também deixa de encerrar o processo hospedeiro com `exit(2)` em falta de memória: agora limpa sua invocação e devolve `NULL` com diagnóstico. [Frontend W10](frontend.md), [runtime W14](runtime.md) e [segurança W21/W23](security.md).

**Resultados válidos, porém errados.** Uma chamada podia sobrescrever uma variável viva: o caso `let keep=99; add(1,2); ret keep` retornava `2`. A VM também alterava operandos antes de terminar operações com destino sobreposto à entrada; uma divisão por zero podia assim deixar de ser reconhecida. Operações de union perdiam tag, tipo ou payload, e igualdade tratava strings, erros e tipos distintos como iguais. As correções preservam operandos até a publicação do resultado e comparam os conteúdos dos tipos admitidos. Esses defeitos merecem prioridade alta por comprometerem decisões sem necessariamente produzir um crash. [Frontend W03](frontend.md); [runtime W11–W13](runtime.md).

**Efeito anterior à recusa e evidência incorreta.** A independência entre produtor e gravador de replay era verificada tarde: uma escrita podia ocorrer antes da rejeição da identidade do gravador. A validação passou para o preflight. Em outro caminho, um `rename` bem-sucedido seguido de falha no `fsync` do diretório era descrito como `FAILED/effect=0`; agora permanece `UNKNOWN/effect=1`. Isso preserva a diferença operacional entre “não aconteceu”, “aconteceu, mas a confirmação falhou” e “sucesso confirmado”. [Runtime W16](runtime.md); [segurança W27](security.md).

**Identidade, estado e caminhos locais.** Um sucessor de trust snapshot podia trocar organização/domínio temporal ou fazer a sequência voltar a zero. Stores e registros também tinham reabertura de caminhos, seguimento de symlinks e truncamento antes de validar o arquivo efetivamente aberto. As novas verificações vinculam identidades, recusam esgotamento e inspecionam o dirfd/arquivo mantido aberto. Registros de tentativa passam a exigir versão, comprimento e chave de filename compatíveis com o corpo. Isso reduz ataques e inconsistências concretos dentro do modelo local existente; não autentica um proprietário malicioso do armazenamento. [Segurança W22 e W25–W27](security.md).

**Fonte diferente da fonte verificada.** `iface` verificava um pathname e depois o reabria para projetar a interface. A segunda leitura podia observar outros bytes, sem a mesma checagem canônica. Agora a projeção usa exatamente a fonte e a AST tipada que passaram pelo checker. Essa correção também elimina um ciclo completo de parse/typecheck por arquivo. O leitor de assembly, por sua vez, passou a respeitar o comprimento fornecido, sem interpretar um sufixo fora do intervalo. [Driver W35](driver.md); [runtime W18](runtime.md).

## Evidência de validação

Os logs completos estão em [normal.log](evidence/normal.log), [sanitizers.log](evidence/sanitizers.log) e [release.log](evidence/release.log). [verification.json](evidence/verification.json) registra comandos, códigos de saída, flags e identidade. Os caminhos do workspace foram normalizados nos logs; resultados e diagnósticos foram preservados.

| Área | Resultado integrado |
| --- | --- |
| Goldens originais | **67 PASS, 0 FAIL** |
| CLI assinada, efeitos, replay e opções | **51 PASS, 0 FAIL** |
| Runtime | **1.033 assertions, zero falhas** |
| Workers com IPC local | **6 checks, zero falhas** |
| API pública de embed | **776 checks PASS** |
| Selos e contabilização | **77 checks PASS** |
| Leitor e snapshot do driver | **23 checks PASS** |
| ABI | **72 verificações de layout**, mais endian/version, PASS |
| Segurança e evidências | **14.775 assertions PASS** |
| Falhas de I/O injetadas | **109 checks PASS** |
| OOM do parser | **99 pontos de falha**, em cada um dos dois modos de enum |
| Floats | **75 fixtures** de parse, valor e ponto fixo |
| Fronteiras adicionais | Esgotamento de handles, 40 mil statements e custos determinísticos PASS |

Esses números têm unidades diferentes. As 14.775 assertions **não são 14.775 casos independentes**; incluem verificações dentro de loops e cenários relacionados. Também não somamos as repetições normal/release/sanitizers como nova cobertura funcional. O gate original falhava inicialmente por ausência de `xxd`: com a chave pública correta, o executável original já passava seus 67 goldens. W32 corrigiu a preparação e tornou a ausência de fixtures uma falha explícita. [Driver W32](driver.md).

O gate integrado instrumentou produto e testes com ASan/UBSan, incluindo CLI e workers. **LeakSanitizer foi desabilitado** porque o ambiente rastreado não permite sua inicialização; não há alegação de que um leak checker passou. O cleanup do parser tem verificação independente de ponteiros realmente alocados/liberados, e vários testes de contas verificam propriedade e saldo após recusas. Os testes positivos de workers utilizaram um host autorizado com IPC Unix local; o sandbox restrito recusava os envios de socket. [Normal](evidence/normal.log); [sanitizers](evidence/sanitizers.log).

A [configuração de CI](../../.github/workflows/audit.yml) foi adicionada com perfis normal, release e sanitizers, checkout fixado e permissões de leitura. **A evidência registrada neste relatório é local.** Os resultados hospedados devem ser consultados no workflow do GitHub para o commit publicado; não são inferidos a partir destes logs.

## Desempenho medido

### Método e tabela completa

O [runner reproduzível](../../tools/audit40-bench.py) compilou as duas árvores com **GCC 13.3.0 e as mesmas flags `-O1`**, em Linux x86-64/glibc 2.39. Cada cenário teve um aquecimento por revisão e **sete pares alternados** baseline/candidato; o processo de medição e seus filhos ficaram fixados na CPU 0. A compilação paralela terminou antes das medições. Frequência da CPU e atividade de outros usuários do host não foram controladas.

Os probes C cronometram internamente a operação indicada; as amostras de CLI incluem criação do processo. Os fixtures validam resultados e combustível quando aplicável, e o runner exige saída idêntica nos casos de CLI. As medições de embed usam um contexto já admitido e repetem a última célula do módulo. Não medem custo de criação do contexto. As [amostras brutas e metadados](benchmark.json) registram a identidade exata dos sources medidos, anterior apenas à consolidação documental.

Valores abaixo em **milissegundos por lote**, com mediana **[mínimo–máximo]** das sete amostras. O ponto decimal segue o JSON. Redução é `1 − candidato/baseline`; a razão é `baseline/candidato`.

| Cenário e lote | Baseline: ms [faixa] | Candidato: ms [faixa] | Redução da mediana | Razão |
| --- | ---: | ---: | ---: | ---: |
| Embed, 1 célula, 200.000 avaliações | 47.873 [43.028–67.586] | 44.136 [40.206–47.554] | 7.80% | 1.08× |
| Embed, 16 células, 200.000 avaliações | 65.124 [55.740–72.307] | 58.064 [42.960–62.498] | 10.84% | 1.12× |
| Embed, 256 células, 200.000 avaliações | 432.997 [390.346–445.154] | 91.933 [66.436–138.013] | 78.77% | 4.71× |
| Selo, 1 lei, 3.000 verificações | 40.062 [38.222–44.590] | 32.357 [26.799–43.910] | 19.23% | 1.24× |
| Selo, 16 leis, 300 verificações | 253.043 [233.088–297.259] | 22.687 [20.741–24.781] | 91.03% | 11.15× |
| Selo, 64 leis, 50 verificações | 607.622 [569.603–670.939] | 15.816 [12.554–20.152] | 97.40% | 38.42× |
| VM, 5.000.000 iterações | 179.139 [162.012–197.218] | 160.027 [154.017–165.554] | 10.67% | 1.12× |
| Conta de memória, 8.192 alocações | 100.682 [95.701–109.393] | 99.076 [94.199–110.531] | 1.59% | 1.02× |
| Conta de memória, liberar 8.192 blocos | 166.275 [155.648–183.690] | 94.154 [91.671–102.860] | 43.37% | 1.77× |
| Assembly, 250.001 instruções | 10.138 [9.482–10.536] | 9.543 [9.324–12.884] | 5.87% | 1.06× |
| Capabilities, 256 células × 100 statements | 186.852 [174.086–199.490] | 8.712 [6.754–10.392] | 95.34% | 21.45× |
| Diagnósticos, 65.536 bytes inválidos | 1488.324 [1428.368–1565.698] | 1.670 [1.346–5.296] | 99.89% | 891.21× |
| Interface canônica, 256 × 100 | 364.346 [337.012–392.515] | 13.017 [10.855–16.269] | 96.43% | 27.99× |

Os ganhos grandes são coerentes com a retirada de trabalho repetido: prefixos de fonte, propagação de capabilities, segunda análise da interface e reverificação integral por lei. O ganho de interface combina várias mudanças; não deve ser atribuído exclusivamente a W35. O loop da VM mantém exatamente **20 milhões de unidades de combustível** nos dois builds; o caso de 64 leis mantém **192 por verificação**. [Dados completos](benchmark.json).

As diferenças pequenas exigem prudência. Alocação, assembly, embed de módulos pequenos, selo de uma lei e até o loop de VM apresentam faixas sobrepostas. Especialmente os 1.59% de alocação e 5.87% de assembly são insuficientes para prometer aceleração estável. Há ruído substancial até em casos com ganho grande: embed com 256 células variou de 66.436 a 138.013 ms no candidato. Não foram calculados intervalos de confiança, nem medidas latência de produção, throughput concorrente ou SLA. O perfil `release -O2` passou no gate, mas **não foi usado para inflar a comparação**.

### Trabalho eliminado, independente do relógio

| Operação determinística | Antes → depois | Interpretação |
| --- | --- | --- |
| Escape JSON de 65.536 bytes seguros | 65.536 → 1 callbacks | Saída idêntica, menos chamadas ao sink |
| Crescimento de 10.001 instruções | 10.001 → 11 crescimentos | Arrays com crescimento geométrico |
| Folha de disclosure de 4.096 bytes | 4 hashes/8.444 bytes → 2/4.222 | 50% menos trabalho de hash |
| Delegação de profundidade 32 | 560 hashes/309.680 bytes → 32/17.696 | 94.29% menos trabalho de hash |
| RF1, 2.048 registros descendentes | 2.098.177 → 41.069 comparações | 98.04% menos comparações |

Essas contagens não são porcentagens de ganho de uma aplicação completa. Autoridade, atenuação, duplicatas e bytes canônicos continuam verificados. [Frontend W08](frontend.md), [runtime W18](runtime.md), [segurança W28–W29](security.md) e [log integrado](evidence/normal.log).

## Matriz das 40 waves

Todas as linhas abaixo têm mudança concreta ou integração de validação. As contagens intermediárias dos relatos de runtime são cumulativas; os totais finais estão na seção de validação.

| Wave | Resultado | Evidência principal |
| --- | --- | --- |
| W01 | Diagnósticos deixam de revarrer prefixos após lotação; contador satura. | [Frontend](frontend.md): 65.536 bytes inválidos e limites do contador. |
| W02 | Corrigida relocação textual de branches quando deslocamentos crescem. | [Codegen](../../tests/audit40/frontend_codegen.py): larguras variadas e branches aninhados. |
| W03 | Janela completa de chamada reservada antes dos argumentos; temporários liberados. | [Codegen](../../tests/audit40/frontend_codegen.py): variável 99 preservada; 0/16 argumentos. |
| W04 | `ret` vazio preserva UNIT; temporários de retornos deixam de acumular. | [Codegen](../../tests/audit40/frontend_codegen.py): ok/zero/falso e 80 retornos condicionais. |
| W05 | Uma coleta de builtins por unidade; irmãos percorridos sem recursão. | [Frontend](frontend.md): 40 mil statements sob stack de 2 MiB. |
| W06 | Magnitude negativa fora de i64 recusada; literal assinado emitido diretamente. | [Codegen](../../tests/audit40/frontend_codegen.py): extremos e pool de constantes. |
| W07 | Grafo de chamadas resolvido antes do ponto fixo de capabilities. | [Frontend](frontend.md): 256 células, ciclos, diamond e pureza transitiva. |
| W08 | Escape JSON agrupa trechos seguros de ASCII/UTF-8. | [JSON](../../tests/audit40/frontend_json.c): bytes, escapes e falha do sink. |
| W09 | Floats canônicos voltam a ser parseáveis e preservam o valor avaliado. | [Frontend](frontend.md): 75 fixtures com ponto fixo. |
| W10 | OOM do parser devolve recusa com cleanup; enums têm limites portáveis. | [Parser](../../tests/audit40/frontend_parser.py): 99 failpoints em ambos os modos de enum. |
| W11 | Aritmética consome operandos antes de publicar destino sobreposto. | [Runtime](runtime.md): tipos numéricos, aliases e divisão por zero. |
| W12 | Construção/extração de union preserva tag, tipo e payload com aliases. | [Runtime](runtime.md): oito tipos de payload e propagação. |
| W13 | Igualdade considera tipo, conteúdo, erro e semântica IEEE. | [Runtime](runtime.md): strings, bytes, NaN, zeros e destinos sobrepostos. |
| W14 | Replay valida comprimentos, forma e estado antes de hash/publicação. | [Runtime](runtime.md): overflow reproduzido com ASan; outputs intactos na recusa. |
| W15 | Ledger, journal e grants validam toda a estrutura; nomes JSON escapados. | [Runtime](runtime.md): duplicatas, corrupção, estado terminal e JSON válido. |
| W16 | Identidade do gravador validada antes do efeito; falha de worker observável. | [CLI](../../tests/audit40/cli.sh) e seis checks de IPC. |
| W17 | Transações toleram aliases; cleanup preserva dono; gerações não dão wrap. | [Handles](../../tests/audit40/runtime_handles.c): últimas gerações e recusa final. |
| W18 | Assembly respeita o intervalo de bytes; tokenizer consistente; arrays geométricos. | [Runtime](runtime.md): input sem NUL, suffix, tabs e limite de 256 células. |
| W19 | Free/realloc encontram o bloco durante a única verificação integral. | [Runtime](runtime.md): ponteiros estrangeiros/interiores e corrupção após match. |
| W20 | Dispatch usa tabela compacta derivada da declaração única dos opcodes. | [Runtime](runtime.md): 1.033 assertions e fronteiras exatas de combustível. |
| W21 | Leitor TRS1 recusa prefixos curtos antes de `memcmp`. | [Segurança](security.md): NULL/SEGV original e truncamentos recusados. |
| W22 | Sucessão de trust vincula organização, domínio e sequência sem wrap. | [Segurança](security.md): 472 truncamentos, trocas de identidade e rollback. |
| W23 | Lease valida quotas, unidades e slots antes de reservar. | [Segurança](security.md): overflow original; estado inalterado em recusas. |
| W24 | Decoders de evidência publicam somente objetos completos; chaves expandidas limpas. | [Segurança](security.md): corpos inválidos reassinados e sentinelas intactas. |
| W25 | Tentativas exigem comprimento da versão e grant root coerente com filename. | [Segurança](security.md): v1/v2 cruzados, renomeação e crash husks. |
| W26 | Store/records validam descritores mantidos abertos; symlinks e especiais recusados. | [Segurança](security.md): symlink, hardlink, FIFO e proteção de vítima. |
| W27 | Falha após rename mantém efeito desconhecido; erros de scan/write não somem. | [Falhas de I/O](../../tests/audit40/security_faults.sh): 109 checks. |
| W28 | Disclosure calcula um compromisso; delegação reutiliza raízes validadas. | [Custos](../../tests/audit40/security_costs.sh): 50%/94.29% menos hash. |
| W29 | RF1 verifica duplicatas com offsets ordenados, preservando bytes originais. | [Segurança](security.md): 4.096 registros, 64 KiB e falhas de alocação. |
| W30 | Coverage valida identidade, limites e slots futuros antes de operar. | [Segurança](security.md): todas as 64 posições e reserva pré-completada recusada. |
| W31 | Build incremental acompanha headers/flags e reutiliza objetos. | [Driver](driver.md): build limpo, no-op, mudança de header e demo. |
| W32 | Fixtures portáveis substituem `xxd`; suites ausentes fazem o gate falhar. | [Driver](driver.md): mesmos 67 goldens no original e candidato. |
| W33 | Gate atravessa a CLI assinada, efeitos, selos, fuel e replay. | [CLI](../../tests/audit40/cli.sh): 51 PASS, zero FAIL. |
| W34 | CLI limita inputs regulares a 64 MiB e trata OOM/EOF/erros. | [Driver](../../tests/audit40/driver.c): regulares, vazios, grandes e especiais. |
| W35 | Interface reutiliza exatamente o snapshot verificado. | [Driver](driver.md): uma abertura; projeção após unlink do pathname. |
| W36 | Opções desconhecidas e falhas de publicação deixam de retornar sucesso. | [CLI](../../tests/audit40/cli.sh): 11 formas e `/dev/full`. |
| W37 | Embed usa índice imutável; porta de policy publica booleanos canônicos. | [Embed](../../tests/audit40/embed.c): 776 checks em 256 células. |
| W38 | Leis usam modelo já verificado; execução de provas entra na conta de memória. | [Selos](../../tests/audit40/seal.c): 77 checks e 192 fuel para 64 leis. |
| W39 | Identidade reproduzível do checker e guarda do ABI público restauradas. | [Identidade](../../tools/axi-checker-identity.py) e [ABI](../../tests/audit40/abi.c): 72 layouts. |
| W40 | Gates completos, release opcional, CI, benchmarks e relatório integrados. | [Logs](evidence/verification.json), [medições](benchmark.json) e [workflow](../../.github/workflows/audit.yml). |

## Compatibilidade e migração

O SHA-256 do [cabeçalho público](../../include/axial/axi_embed_v1.h), antes e depois, é `d51b9faa33c8bf757ca2f607282c3c97c1666b6173c29b566f6ecb9cce17e213`. O gate também fixa o perfil de ABI e verifica tamanho, alinhamento e offsets no layout amd64 SysV LP64. A identidade reproduzível agora cobre 118 arquivos de source; o root medido é `bc0f4b1ef1f478745769a67a5f69037791d80f2a41279677e94ae96c09e5a03c`. [Identidade e ABI](driver.md); [metadados](benchmark.json).

**Todo artefato que carregue um selo CHECKED antigo será recusado, inclusive sob admissão `SIGNATURE_VALID`.** O decoder verifica um selo presente antes de aplicar o perfil solicitado. A migração correta é reexecutar as leis com o novo checker e produzir um novo selo explicitamente. Não há relabeling automático. Artefatos assinados sem selo permanecem independentes dessa identidade do checker, sujeitos às verificações normais de formato e confiança. Correções de igualdade, aritmética e compilação podem mudar resultados que antes estavam errados; preservar esses defeitos não seria compatibilidade semântica adequada. [Driver W39](driver.md).

Há limites intencionais novos ou mais estritos: a CLI aceita arquivos regulares de até **64 MiB**; stores recusam aliases finais por symlink e arquivos não privados ou com múltiplos links. Workers passam a exigir sockets Unix `SOCK_SEQPACKET`; hosts sem suporte recusam o efeito, sem transporte alternativo mais fraco. Gerações de handles saturam após **4.294.967.295** emissões no processo, recusando novas identidades para impedir reuso de handles antigos. [Driver W34](driver.md); [runtime W16–W17](runtime.md); [segurança W26](security.md).

As otimizações também têm custos explícitos: **8 bytes adicionais por nó de AST neste host de 64 bits**, **512 bytes por contexto de embed** e até **1.024 bytes de stack** no cache de uma cadeia de delegação de profundidade 32. A verificação de contas de memória continua linear no número de alocações vivas. Esses custos foram aceitos para manter cleanup, imutabilidade e integridade; não são apresentados como redução universal de memória. [Frontend](frontend.md); [driver](driver.md); [runtime](runtime.md); [segurança](security.md).

## Limites remanescentes e próximos investimentos

O consumidor local público continua sendo um perfil de fixture. Os campos `resource_device`, `resource_inode`, `previous.*`, `uid` e `executor_uid` entram em serializações e hashes, mas **não são todos observados novamente no ponto final do efeito**. A ADR-059 referenciada pelo projeto não veio nesta árvore; nem a interpretação exata do inode de recurso está plenamente definida ali. Uma assinatura vincula bytes a uma chave, não transforma declarações de fatos em verdade. Relógios, raízes de confiança e observações de coverage também dependem do chamador. [Fronteiras documentadas](security.md).

Antes de promover esse consumidor a um ambiente de produção, é necessário definir qual objeto efetivamente mantido aberto cada identidade representa, observá-lo sob a mesma exclusão mútua usada no commit e testar troca de recurso, conteúdo anterior alterado e identidade do executor. A aceitação deve exigir recusa explícita, nenhum gasto e nenhuma escrita para esses cenários. Esta auditoria não afirma confinamento de guest/kernel, runner confiável de produção, atestação do binário ou durabilidade sob queda real de energia. As falhas de I/O foram injetadas para validar controle de fluxo.

No frontend, o acumulador decimal herdado ainda não oferece conversão decimal→binário corretamente arredondada. W09 garante parseabilidade, bits preservados e ponto fixo nas condições descritas; seu fallback não prova uma grafia globalmente única para todo alias numérico. O typechecker ainda admite formas `err.Name` e `?` que o codegen de fonte recusa. Também permanece a divergência entre a gramática de escapes aceita/documentada e os dois escapes efetivamente decodificados. Corrigir essas diferenças exige decisão explícita de linguagem e testes de compatibilidade, sem alterar significados silenciosamente. [Limites do frontend](frontend.md).

O compilador inteiro ainda não tem uma cota única de memória cobrindo AST, análise e formatação; limitar a entrada a 64 MiB não estabelece esse orçamento. Os próximos investimentos recomendados são, nesta ordem: fechar a observação real de autoridade no consumidor que for usado em produção; alinhar typechecker, lowering e strings; estabelecer um orçamento total do compilador; medir workloads reais, criação de contextos, concorrência e memória máxima. O gate atual fornece regressões reutilizáveis para apoiar essas decisões, sem substituir essa validação adicional.

## Como reproduzir

Os gates exigem compilador C99, ferramentas POSIX, Python 3 e um host que permita IPC Unix local. Os fixtures usam identidades determinísticas públicas e diretórios temporários. A partir da raiz do repositório:

```sh
make -j2 gate
make release
make -j2 BUILD=build-release \
  CFLAGS='-std=c99 -Wall -Wextra -Werror -O2 -D_POSIX_C_SOURCE=200809L' gate

ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  make -j2 BUILD=build-sanitize \
  CFLAGS='-std=c99 -Wall -Wextra -Werror -O1 -g -D_POSIX_C_SOURCE=200809L -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -fno-pie -no-pie' \
  LDFLAGS='-fsanitize=address,undefined -fno-sanitize-recover=all -no-pie' gate
```

Para repetir a comparação, prepare um checkout separado da árvore original
(se ainda não existir nesse caminho) e execute:

```sh
git worktree add --detach ../axial-baseline 2d6752255ffcc92e0b103c97609daf205a5a39de
python3 tools/audit40-bench.py --baseline ../axial-baseline \
  --candidate . --samples 7 --output /tmp/axial-benchmark.json
```

`make gate-fast` mantém os goldens originais; `make gate` executa a validação ampliada. `make bench` apenas constrói probes, sem impor limiares de velocidade. Comandos de linking especiais do parser, dos handles e das falhas de I/O estão encapsulados nos respectivos runners e documentados nos quatro relatórios de área.
