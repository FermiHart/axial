# Audit80 — checkpoints de execução

Continuação autorizada da auditoria W01–W40, a partir de
`82596bf8faf607e25f7366e36381a8dad58302a1`. São 40 waves adicionais,
W41–W80, com um commit por wave e consolidação a cada dez. As frentes
trabalham em paralelo; os checkpoints integram os commits na ordem numérica.

## Checkpoint W50 — 10 de 40 waves adicionais

Entregue o perfil opt-in de autoridade local: emissor provisionado, diretório
retido por descriptor, observação real de UID/eUID, boot/tempo e conteúdo
anterior, epoch obrigatório, preparação imutável e reobservação sob o lock
antes de gasto e efeito. Expiração, troca de lock, concorrência e consulta
após interrupção conservam a distinção entre recusa, efeito e incerteza.

Duas falhas foram reproduzidas e corrigidas: cleanup de gasto malsucedido
não pode anunciar `NOT_ATTEMPTED`; retomada da ativação precisa sincronizar
também o arquivo de controle antes de confirmar sucesso.

Validação da árvore integrada:

- `make -j2 gate`: PASS no host, incluindo 67 goldens, 51 casos CLI,
  72 checks de layout ABI, 776 embed, 1.033 runtime, 14.775 security,
  77 seal, 23 driver, seis workers e as regressões frontend/faults.
- Perfil novo: 1.137 checks normais e 504 de falhas, com UID 1000/eUID 1001
  reais em subprocessos descartáveis: PASS.
- A mesma frente passou integralmente com ASan/UBSan e o provider desativado
  passou oito checks; resultados e flags estão em [security.md](security.md).
- Identidade do checker regenerada para os 121 arquivos de produto;
  os pins do header público embed v1 e da tabela ABI permanecem válidos.

O ambiente restrito impediu o teste existente de workers; a mesma árvore
passou na execução local autorizada do host. Não houve substituição por
identidades ou clocks simulados. LSan não foi executado sob process tracing.

O perfil cobre o `config` relativo ao store ativado. Administração, processo
do serviço, kernel e escritores não cooperativos com o mesmo UID permanecem
confiáveis. Isolamento de guest e perda física de energia não são resultados
deste checkpoint. A execução segue automaticamente para W51–W80.

## Checkpoint W60 — 20 de 40 waves adicionais

Erros nomeados, retornos opcionais e propagação com `?` agora percorrem
fonte, checker, bytecode assinado e VM. A emissão mantém a representação
canônica existente, distingue erros de strings e avalia cada expressão
propagada uma vez. Lexer, assembler e canon compartilham as cinco escapes
de string e preservam os bytes semânticos, inclusive NUL embutido.

O compilador ganhou contexto explícito de cota, sem contador global:
ownership de fonte/AST, análise de tipos, renderização, geração e projeções
usam a mesma conta. OOM e recusa não encerram o hospedeiro nem apagam a
primeira causa. Montagem/assinatura e ativação da cota na CLI entram em
W61–W62; este checkpoint não anuncia que essa integração já ocorreu.

Validação integrada: `make -j2 gate` completo PASS no host; todos os casos
W51–W56 PASS; 130 checks C novos do orçamento e suas fases PASS. Os
goldens de runtime permaneceram idênticos nesta árvore. A dependência do
runner isolado de strings foi atualizada para os módulos de ownership,
mantendo a compilação real do decoder. Identidade regenerada para 124
arquivos de produto e pins ABI v1 válidos. Execução segue para W61–W80.

## Checkpoint W70 — 30 de 40 waves adicionais

A cota de compilação agora acompanha montagem, manifestos, hashes,
assinatura e publicação atômica. Os onze comandos de compilador aceitam
`--compile-mem BYTES` e relatório JSON; uma recusa preserva o arquivo de
destino e limpa a conta. A revisão integrou também argumentos cujo valor
coincide com o nome de uma opção, sem consumir argumentos do runtime.

A conversão decimal usa aritmética inteira e arredondamento nearest/even;
a forma canônica deriva dos bits, inclusive subnormais e o sinal do zero.
Não depende de locale, arredondamento corrente ou buffers alocados no heap.
O workspace numérico tem 2.372 bytes nesta plataforma; sua reserva na cota
das fases será consolidada na W77. O runtime conserva seu contrato próprio
de normalizar zero ao avaliar valores.

Validação da árvore integrada:

- `make -j2 gate`: PASS no host, com os testes anteriores e 201 checks C
  de orçamento mais 3.385 asserts CLI / 413 pontos de OOM injetado.
- W51–W56: todos os casos fonte → checker → bytecode assinado → VM PASS.
- Numéricos: 3.785 entradas no leitor e novamente no lexer real; 8.318
  padrões canônicos com oráculo racional; 46 casos pela CLI; caudas de
  1 MiB e 12 combinações de locale/rounding disponíveis neste ambiente:
  PASS. A validação ampliada da frente, com locales de vírgula e
  ASan/UBSan, está registrada em [frontend.md](frontend.md).
- Runtime: 384 resultados/fuel em 12 famílias e 489 checks do ciclo de
  contexto, incluindo 120 recusas de alocação: PASS.
- Identidade regenerada para 126 arquivos de produto; pins ABI v1 válidos.

O novo ponteiro interno de ownership do módulo custa oito bytes por
instância; o golden de pico observado aumenta 32 bytes quando há cópias
simultâneas. A ABI pública e o formato serializado permanecem compatíveis.
Os ganhos de conversão são microbenchmarks com a implementação exata
anterior como base, documentados em [frontend.md](frontend.md). A execução
segue automaticamente para a integração e validação final W71–W80.

## Checkpoint W80 — 40 de 40 waves adicionais

Concluída a integração W41–W80 com um commit por wave. As dez últimas
waves fecham os probes e as correções de runtime, a contabilização dos
workspaces numéricos, os gates permanentes, a projeção de interfaces em
lote, a reprodução independente dos benchmarks e a documentação de migração.
O [relatório final](REPORT.md) reúne a matriz completa das 40 entregas.

Validação final local do mesmo produto integrado:

- Normal C99 `-O1`: gate completo PASS.
- Otimizado C99 `-O2`: gate completo PASS.
- ASan/UBSan: gate completo PASS, após recompilação e correção de modo em
  executáveis locais de teste; bytes preservados. As tentativas com
  `EACCES` e a tentativa de log parcial continuam registradas. A origem
  da perda do bit de execução não foi determinada.
- ThreadSanitizer: variantes cached, uncached e software do produto
  completo PASS; cada variante verifica 1.920 avaliações isoladas e
  1.920 compartilhadas. Não houve alteração global de ASLR ou fallback.

Os gates agora incluem 410 verificações C do compilador, 3.266 asserts CLI
com 396 pontos reais de OOM e 1.360 asserts de manifesto com 169 pontos de
OOM. Incluem também as suítes anteriores, a autoridade com credenciais
reais, as regressões numéricas e de linguagem, memória/pilha/concorrência
e recuperação após doze pontos de morte abrupta. O registro numérico final
cobre 12 combinações locale/rounding; a ampliação anterior com locales de
vírgula permanece identificada como execução separada.

Produto SHA-256:
`59dccaab79e2ab1e5dc4f32fc2a7f2d802f134579c4efd61fa6fc4fcff51a269`.
Checker:
`8304f6da573d02f6cd3975b19a4c93b12b786c8cab793acee104808b9b0b9a71`.
Pins da ABI pública v1 válidos. [Logs e metadados](evidence/validation/README.md)
preservam os quatro perfis sem somar repetições como casos independentes.

Os ganhos são medidos em escopos explícitos: leitura decimal −66,10% e
formatação −73,21% contra o núcleo já exato W65; geração de contratos
−57,88% a −64,34% contra a versão imediatamente anterior à W78, com saída
idêntica. Não há alegação de ganho universal da criação de contextos ou
de throughput com oito leitores. Bases e amostras estão no
[índice de evidências](evidence/README.md).

A entrega permanece na [PR #2](https://github.com/FermiHart/axial/pull/2),
baseada na PR #1, para revisão. Cada árvore enviada ao GitHub é comparada
com a árvore local correspondente. `main` permanece na revisão
`2d6752255ffcc92e0b103c97609daf205a5a39de`; não houve merge. Os limites de
integração do serviço, produção, outras ABIs e perda física de energia
continuam explícitos no relatório; não são alegações cobertas por estes testes.
