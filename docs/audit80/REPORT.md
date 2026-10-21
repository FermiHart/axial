# Axial — fechamento da auditoria W41–W80

Esta entrega executa **40 waves adicionais**, continuando W01–W40 a partir
da revisão `82596bf8faf607e25f7366e36381a8dad58302a1`. O histórico tem um
commit por wave e checkpoints W50, W60, W70 e W80. A
[PR #2](https://github.com/FermiHart/axial/pull/2) é baseada na branch da
[PR #1](https://github.com/FermiHart/axial/pull/1); as duas entregas continuam
separadas de `main` para revisão.

O trabalho fecha as pendências implementáveis apontadas no
[relatório W40](../audit40/REPORT.md): observação real da autoridade local,
representações de erros/opções e strings, conversão decimal exata e cota
completa do compilador. Amplia ainda a medição de contextos, memória,
concorrência, latência e recuperação de I/O. A investigação encontrou e
corrigiu um crash de pilha, uma corrida de dados na detecção SHA-NI e dois
caminhos de persistência que precisavam preservar incerteza corretamente.

Os relatórios por área preservam reproduções, comandos, resultados adversos
e limites: [autoridade](security.md), [compilador](compiler.md),
[linguagem e números](frontend.md), [runtime](runtime.md),
[projeção de manifestos](manifest.md). As
[notas de migração](migration.md) explicam as mudanças de comportamento.

## O que mudou e por quê

### Autoridade observada no host

O novo perfil é opt-in e atende à substituição de um `config` relativo a
um diretório privado retido por descriptor. O administrador provisiona o
emissor e o epoch; o consumidor observa o diretório e o conteúdo anterior,
os UID/eUID reais, a identidade de boot e o relógio do host. A preparação
retém uma cópia própria da ação e do payload. Antes de gastar o grant ou
publicar o efeito, o commit observa novamente os fatos sob o mesmo lock
exclusivo usado pelo protocolo de tentativa.

Troca de diretório, conteúdo, lock, credenciais ou geração do epoch passa a
ser motivo de recusa. O contexto continua associado ao diretório aberto
quando seu pathname muda. Expiração durante espera ou I/O não autoriza um
novo gasto; uma consulta posterior lê o histórico sem repetir o efeito.
O emissor e as raízes assinadas continuam sendo verificados pelo protocolo
existente. Após ativar o perfil, a entrada legada de mutação recusa naquele
store, inclusive diante de controle incompleto, evitando downgrade.

Dois defeitos tiveram reprodução antes da correção: uma falha ao limpar o
registro de gasto não pode anunciar `NOT_ATTEMPTED`; a retomada de uma
ativação interrompida precisa sincronizar também o arquivo de controle.
Ambos conservam uma resposta de incerteza quando o sistema ainda não pode
afirmar ausência ou durabilidade. [Contrato e evidência](security.md).

### Linguagem coerente até a VM

Erros `err.Name`, retornos opcionais e propagação com `?` agora atravessam
checker, codegen, manifesto, bytecode assinado e execução. A propagação
avalia sua expressão uma vez, preserva o erro ou `ok` apropriado e retorna
cedo; o caminho de sucesso extrai o payload correto. Erros e strings
continuam sendo valores de tipos diferentes.

Lexer, assembler e canonicalizador compartilham as cinco escapes definidas:
`\n`, `\t`, `\0`, `\\` e `\"`. A forma canônica representa os bytes
semânticos, inclusive NUL embutido. Isso corrige comportamentos anteriores
que preservavam a barra ou interpretavam a mesma grafia de formas diferentes;
programas que dependiam desses defeitos devem ser revisados.

A leitura decimal agora faz uma única decisão de arredondamento exata para
binary64, nearest com empate para par, incluindo subnormais e underflow.
Overflow é uma recusa. O formatter parte dos bits, escolhe o menor número
de dígitos significativos que retorna ao mesmo valor e resolve empates por
distância exata e significando decimal par. A implementação usa inteiros e um workspace
fixo de 2.372 bytes nesta ABI, sem depender de locale ou modo de
arredondamento do processo. O sinal do zero literal é preservado em fonte,
canon e pool; a VM mantém sua normalização de zero ao avaliar valores.
[Semântica e oráculos](frontend.md); [migração](migration.md).

### Cota por invocação, até a publicação assinada

O contexto `axi_compile_budget` pertence ao chamador e acompanha fonte,
AST, análise de tipos, canon, projeção, codegen, montagem, manifestos,
verificação, assinatura e publicação. A primeira causa de recusa é
preservada durante o cleanup. Os retornos de biblioteca não encerram o
processo hospedeiro por OOM.

Os onze comandos de compilação aceitam `--compile-mem BYTES`, com padrão de
256 MiB, e `--compile-mem-report`. As opções vêm após o argumento obrigatório
de arquivo, ou após OLD e NEW em `iface-diff`. Argumentos de runtime e
valores de outras opções conservam sua interpretação. Recusa não substitui
o destino por um artefato parcial. O relatório JSON informa limite, pico,
saldo e causa antes do cleanup defensivo final, tornando saldos indevidos
observáveis.

A W77 inclui o workspace decimal nas fases que o usam. A coleta de
comentários libera seus temporários antes da impressão; cada impressão de
float retém a reserva até copiar o texto. Assim não há duas reservas
numéricas simultâneas para fases que não se sobrepõem. A cota cobre
armazenamento solicitado, cabeçalhos e workspaces explicitamente reservados.
O limite de entrada regular de 64 MiB continua independente; a cota não mede
RSS, metadados privados da libc ou toda a pilha C. [Detalhes](compiler.md).

### Menos trabalho redundante e falhas concretas de runtime

O gerador de contratos antes projetava a interface completa para cada
célula. A W78 projeta a unidade uma vez e converte as células na ordem do
corpo, com busca binária sobre os nomes já ordenados. A projeção deixa de
processar n² células para processar n, preservando bytes de manifesto,
hashes, ordem de parâmetros e ownership. Isso não torna todo o pipeline
linear; outras etapas continuam contribuindo para seu custo.

No caminho puro da VM, cada chamada reservava 256 registradores, mesmo
quando usava um. Células válidas derrubavam o processo com 64 níveis em uma
pilha de 512 KiB ou 256 níveis em 2 MiB. O frame agora usa a contagem
validada de registradores. No caso de um registrador, elimina 22.440 bytes
de armazenamento desnecessário por nível; os casos profundos e o caso que
realmente usa 256 registradores preservam resultado e fuel.

ThreadSanitizer reproduziu uma corrida de primeira utilização no cache de
detecção SHA-NI. A correção usa acesso atômico ao indicador nos compiladores
suportados e mantém a opção sem cache. As operações independentes e os
leitores de um contexto imutável usam armazenamento próprio e terminam
antes de destruir o contexto. O produto não ganhou dependência de pthread;
ela pertence aos testes. [Runtime W71–W72](runtime.md).

## Validação integrada

Os quatro perfis locais terminaram com retorno zero, usando GCC 13.3.0 e
o mesmo produto integrado. O SHA-256 dos caminhos e bytes de todos os
arquivos em `src`, `include` e `vendor` permaneceu
`59dccaab79e2ab1e5dc4f32fc2a7f2d802f134579c4efd61fa6fc4fcff51a269`.
A W79 acrescenta reprodução e migração; a W80 registra evidência e
relatórios, sem alterar o produto validado. A identidade do checker é
`8304f6da573d02f6cd3975b19a4c93b12b786c8cab793acee104808b9b0b9a71`,
com 126 arquivos de produto e os pins públicos ABI v1 preservados.

| Perfil | Execução | Resultado | Registro |
| --- | --- | --- | --- |
| Normal C99 | `make -j2 gate`, `-O1` | PASS | [log](evidence/validation/normal.log), [flags e identidade](evidence/validation/normal.json) |
| Otimizado C99 | `make -j2 gate`, `-O2` | PASS | [log](evidence/validation/release.log), [flags e identidade](evidence/validation/release.json) |
| ASan/UBSan | Gate completo, `-O1`, sem recuperação de UB | PASS após correção de permissões locais dos executáveis de teste | [log final](evidence/validation/sanitizers.log), [flags e identidade](evidence/validation/sanitizers.json) |
| ThreadSanitizer | `gate-tsan`, três variantes do produto completo | PASS | [log](evidence/validation/tsan.log), [flags e identidade](evidence/validation/tsan.json) |

O conjunto final inclui:

- 67 goldens, 51 casos CLI, 72 verificações de layout ABI mais endian/versão,
  776 verificações embed, 1.033 de runtime legado, 14.775 de segurança,
  77 de selo, 23 de driver, seis de workers e 109 de falhas de I/O legadas.
- Frontend W01–W10 e W51–W56, incluindo 99 recusas de alocação em cada
  modo de enum e 40.000 statements sob pilha de 2 MiB.
- 410 verificações C do compilador; 3.266 asserts CLI com 396 pontos reais
  de OOM; mais 1.360 asserts de manifesto em 169 pontos reais de OOM.
- 3.785 entradas do leitor e novamente pelo lexer real, 8.318 casos
  canônicos com oráculo racional, 46 casos pela CLI e caudas de 1 MiB.
  Nesta execução final havia três nomes de locale, nenhum com separador
  de vírgula, totalizando 12 combinações locale/rounding. A evidência
  ampliada anterior com locales de vírgula está em [frontend.md](frontend.md).
- Autoridade com UID 1000/eUID 1001 reais: 1.137 verificações normais,
  504 de falhas e oito com provider desativado.
- Runtime: 384 verificações de resultado/fuel, 489 de lifecycle com 120
  falhas de alocação, 273 de memória e três probes de pilha. Cada uma das
  três variantes de concorrência executa 1.920 avaliações em contextos
  isolados e outras 1.920 num contexto imutável compartilhado.
- Persistência local: 187 verificações de I/O e 543 de interrupção e
  recuperação, incluindo os doze pontos de SIGKILL em três repetições.

As tentativas malsucedidas de ASan/UBSan foram preservadas. Executáveis
gerados localmente apareceram com modo `0644`, produzindo `EACCES` antes
da execução; uma tentativa intermediária deixou apenas log parcial e
retorno 2. A origem da perda do bit de execução não foi determinada.
Foram recompilados artefatos em diretório novo e restaurado o modo de dois
ELFs de teste, com SHA-256 dos bytes idêntico antes/depois. Só então o
gate completo foi marcado PASS. Não houve alteração de fonte para contornar
a falha nem supressão de diagnóstico de ASan/UBSan. A sequência, os logs
originais e hashes estão no [índice de validação](evidence/validation/README.md).
LeakSanitizer permaneceu desativado sob process tracing.

Os checkpoints W50, W60 e W70 passaram o gate local completo e a CI
hospedada nos perfis normal, otimizado e ASan/UBSan. Seus resultados são
registrados em [checkpoints.md](checkpoints.md). Os comandos permanentes e
as exigências de host estão em [gates.md](gates.md).
A CI da PR é uma checagem hospedada independente dos registros locais
acima. As árvores publicadas são comparadas com as árvores Git locais;
o [mapa W41–W79](evidence/commit-trees-w41-w79.json) preserva os pares,
e a igualdade da árvore W80 é conferida separadamente na publicação.

Os testes distinguem asserções, entradas, pontos de falha e repetições.
Não somamos execuções normal/release/sanitizers como novos casos
independentes. OOM é injetado em alocações realmente atingidas; quotas são
exercitadas no pico observado e um byte abaixo, com saldo verificado depois
da recusa. Os probes numéricos comparam razões inteiras exatas e
implementações independentes; não enumeram todo o espaço binary64.

A [revisão cruzada numérica](evidence/numeric-crossreview/REPRODUCE.md)
preserva 495 leituras em fronteiras e 3.178 saídas canônicas comparadas com
CPython, executadas nos quatro modos fenv com canários e ASan/UBSan.
São 14.692 chamadas ao produto. A revisão compara a saída escolhida do
formatter; não se apresenta como uma segunda enumeração completa de todos
os candidatos shortest/closest/even. As implementações de quota W77 e lote
W78 receberam também revisão cruzada de caminhos de falha e ownership.

## Desempenho: ganhos medidos e resultado adverso preservado

As comparações abaixo têm bases diferentes, identificadas explicitamente.
Não se deve somar as porcentagens. Todos os benchmarks preservam os
resultados esperados, usam flags iguais entre os lados de cada comparação
e mantêm suas amostras brutas. O host é compartilhado; frequência e carga
de terceiros não são controladas.

| Operação e comparação | Mediana anterior → posterior | Variação | Escopo |
| --- | ---: | ---: | --- |
| Formatar 8.192 valores; núcleo exato W65 → W68 | 453,746 → 121,553 ms | −73,21% | Microbenchmark do formatter |
| Ler 65.536 decimais; núcleo exato W65 → W68 | 86,569 → 29,346 ms | −66,10% | Mistura fixa de 16 valores |
| Gerar contratos, 16 células × 256 iterações; antes → depois W78 | 217,531 → 91,620 ms | −57,88% | AST já verificada |
| Gerar contratos, 64 células × 64 iterações; antes → depois W78 | 770,376 → 274,679 ms | −64,34% | AST já verificada |
| Gerar contratos, 256 células × 16 iterações; antes → depois W78 | 3.108,254 → 1.154,301 ms | −62,86% | AST já verificada |

As duas primeiras linhas comparam uma implementação já corretamente
arredondada à sua otimização, com sete pares alternados, aquecimento e
checksums idênticos. Não usam o antigo leitor inexato como concorrente.
[Amostras numéricas](evidence/numeric-benchmark.json).

A comparação W78 usa dois produtos que diferem apenas nos três arquivos
da otimização de projeção. Mede geração contratual, comparação completa
dos bytes e liberação, partindo de AST verificada. Não inclui parsing,
typechecking ou assinatura final. A fixture rica preserva seus 969 bytes
e hash; o outlier de 16 células foi mantido. O pico de cota ficou igual no
caso pequeno e caiu apenas 560 bytes nos dois maiores: não há alegação de
redução relevante de memória. [Método, intervalos e limites](manifest.md);
[amostras](evidence/manifest-benchmark.json).

O runtime foi medido separadamente contra W40, antes da integração das
outras frentes. Em 10.000 observações por família e versão, o caso de oito
chamadas passou de p50 712 ns / p99 1.252 ns para 651 ns / 1.102 ns, com
fuel 38 idêntico. O loop misto validado passou de mediana 1,153 para 1,205
milhão de avaliações/s. Com oito leitores, a mediana caiu de 5,908 para
5,418 milhões/s, com intervalos sobrepostos. Esses resultados não
demonstram ganho universal ou escalabilidade garantida.

A criação de contexto inicialmente piorou entre aproximadamente 11% e
23%, dependendo do tamanho. A W75 investigou esse resultado, preservando
todos os dados: entradas assinadas e código Ed25519 eram idênticos, e a
verificação Ed25519 respondia por mais de 96% do tempo. No controle pequeno
com o mesmo objeto criptográfico na mesma posição de link, p50 passou de
2,893 para 2,865 ms; as diferenças nos outros tamanhos e no perfil O2
mudam de direção. A evidência explica a maior discrepância daquele caso
por posição do código e ruído do host, sem justificar uma promessa de
aceleração global. Não alteramos a aritmética criptográfica nem removemos
verificações para melhorar números. [Latências](runtime-latency-w74.json),
[amostras completas](runtime-latency-w74.samples.json.gz) e
[diagnóstico controlado](runtime-context-w75.json).

## Matriz das 40 waves adicionais

| Wave | Entrega | Evidência |
| --- | --- | --- |
| W41 | Perfil local ativável, emissor provisionado e bloqueio de mutação legada. | [Autoridade](security.md) |
| W42 | Observação limitada do conteúdo anterior sob lock. | [Autoridade](security.md) |
| W43 | UID/eUID, boot e tempo reais; recusa de host incompatível. | [Autoridade](security.md) |
| W44 | Preparação com ownership e epoch ativo obrigatório. | [Autoridade](security.md) |
| W45 | Reobservação dos fatos sob o lock do commit. | [Autoridade](security.md) |
| W46 | Revalidação da janela temporal após espera e I/O. | [Autoridade](security.md) |
| W47 | Identidade do lock fixada e corrida de conteúdo anterior serializada. | [Autoridade](security.md) |
| W48 | Reconciliação pelo diretório retido, inclusive após reabertura. | [Autoridade](security.md) |
| W49 | Incerteza preservada em cleanup e sincronização de ativação. | [Autoridade](security.md) |
| W50 | Matriz completa, host desativado, sanitizers e checkpoint. | [Checkpoint](checkpoints.md) |
| W51 | Erros nomeados emitidos como valores próprios. | [Frontend](frontend.md) |
| W52 | Retornos opcionais na representação canônica v7. | [Frontend](frontend.md) |
| W53 | Propagação de erros e retornos antecipados. | [Frontend](frontend.md) |
| W54 | Propagação de opções e extração do payload. | [Frontend](frontend.md) |
| W55 | Decoder compartilhado das cinco escapes. | [Frontend](frontend.md) |
| W56 | Canonicalização dos bytes de string e fluxo completo de erros. | [Frontend](frontend.md) |
| W57 | Cota explícita por invocação e conta subordinada de backend. | [Compilador](compiler.md) |
| W58 | AST e cleanup de parses parciais pertencem à invocação. | [Compilador](compiler.md) |
| W59 | Tipos e canon recuperáveis sob recusa de memória. | [Compilador](compiler.md) |
| W60 | Codegen/projeção contabilizados e checkpoint. | [Checkpoint](checkpoints.md) |
| W61 | Cota até montagem, verificação, assinatura e publicação. | [Compilador](compiler.md) |
| W62 | CLI com limite, relatório e varredura de OOM. | [Compilador](compiler.md) |
| W63 | Leitor decimal exato com inteiros limitados. | [Frontend](frontend.md) |
| W64 | Lexer aceita a faixa finita f64 com rounding exato. | [Frontend](frontend.md) |
| W65 | Formatter canônico derivado de intervalos exatos. | [Frontend](frontend.md) |
| W66 | Fonte canônica deriva dos bits; sinal literal emitido diretamente. | [Frontend](frontend.md) |
| W67 | Potências reutilizadas e emissão em blocos de nove dígitos. | [Frontend](frontend.md) |
| W68 | Caminho curto exato, limites longos e fenv. | [Frontend](frontend.md) |
| W69 | Doze famílias de workloads com oráculos de resultado/fuel. | [Runtime](runtime.md) |
| W70 | Ciclo completo de contexto, todas as recusas de alocação e checkpoint. | [Checkpoint](checkpoints.md) |
| W71 | Frame puro usa os registradores necessários e evita crash profundo. | [Runtime](runtime.md) |
| W72 | Corrida do cache SHA corrigida; lifetimes concorrentes exercitados. | [Runtime](runtime.md) |
| W73 | Limites JSON, memória de contextos retidos e limpeza. | [Runtime](runtime.md) |
| W74 | Distribuições de latência e throughput com comparação W40. | [Runtime](runtime.md) |
| W75 | Diagnóstico da regressão de admissão com controle de link. | [Runtime](runtime.md) |
| W76 | Falhas de I/O e doze pontos de morte abrupta do escritor. | [Runtime](runtime.md) |
| W77 | Scratch numérico contabilizado e gates permanentes de todas as frentes. | [Compilador](compiler.md), [gates](gates.md) |
| W78 | Uma projeção de interface por módulo; bytes idênticos e benchmark. | [Manifestos](manifest.md) |
| W79 | Migração, preservação de evidências e revisão cruzada. | [Migração](migration.md), [evidências](evidence/README.md) |
| W80 | Matriz integrada final, checkpoint e publicação revisável. | Este relatório e [checkpoint](checkpoints.md) |

## Compatibilidade e limites que continuam externos

O header público embed v1 e o perfil de ABI permanecem fixados; a
serialização AXB v7, AG1 e os registros de tentativa não foram redesenhados.
O checker tem uma nova identidade de fonte. Artefatos com selo CHECKED
antigo precisam de execução das leis e selo novo, inclusive quando a
admissão solicitada é `SIGNATURE_VALID`. A assinatura antiga não autoriza
relabeling de um selo. Artefatos assinados sem selo continuam sujeitos às
verificações normais de formato e confiança. [Migração](migration.md).

Existem custos explícitos: pointers internos de AST para tipo de retorno e
orçamento; ponteiro de ownership de oito bytes por modelo de módulo; pico
de runtime do golden 260.717 → 260.749 bytes nas cópias simultâneas; reservas
temporárias agora cobertas pela cota. A API pública preservada não implica
que structs privadas possam ser misturadas entre objetos de builds antigos
e novos. Compile todo o produto de uma mesma revisão.

O novo perfil local exige integração deliberada do serviço: emissor e epoch
provisionados pelo administrador, dois UID distintos não zero e provider
Linux suportado. Ele verifica credenciais do processo, sem autenticar por
si uma identidade HTTP, socket, remota ou de guest. Administrador, processo,
kernel, proc mount e escritores não cooperativos com o mesmo UID continuam
na base de confiança. Preparar uma ação não executa a política nem emite
um grant; a decisão do emissor continua sendo necessária.

Os testes de SIGKILL interrompem somente escritores filhos de fixtures e
mantêm kernel e caches ativos. Injeção de EIO/ENOSPC verifica a resposta do
código; não simula integralmente falha física do dispositivo ou perda de
energia. A resposta UNKNOWN continua podendo coexistir com um registro
terminal visível em consulta posterior. Nenhuma dessas consultas repete o
efeito ou comprova o que sobreviveria à próxima falha de energia.

Não foi fornecido tráfego real, perfil de deployment ou processo de chegada
de produção. Os benchmarks descrevem as cargas documentadas, sem SLA.
Não há alegação de execução em guest, hardware big-endian, ABI diferente,
prova formal do espaço binary64 ou ausência de todos os defeitos.
LeakSanitizer permaneceu desativado no ambiente rastreado; os saldos e
ownership foram verificados pelos próprios probes e contas. Esses limites
não são pendências escondidas de implementação: são o alcance declarado
da evidência e as próximas validações de integração no ambiente de uso.
