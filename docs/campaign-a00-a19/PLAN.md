# Axial — Plano de implementação A00–A19

**Campanha:** contratos observáveis e mediação verificável  
**Data:** 29 de outubro de 2026  
**Decisão de referência:** ADR-AXIAL-0001, revisão 2  
**Estado atual:** A00 e A01 concluídas; A02 pronta para execução; A03–A19 pendentes. A00 começou em 29/10/2026 às 10h39 (America/Sao_Paulo).

**Branch:** work/axial-a00-a19-20261029. O estado operacional está em [STATUS.json](STATUS.json).

## Objetivo e base

Entregar descoberta estruturada sobre o Axial existente e uma ação real demonstrada em consumidor isolado, com autoridade vinculada, resultado explícito e recibo. O plano reaproveita registries, dossiê, diagnósticos, budgets e protocolos atuais. Cada wave deve produzir comportamento utilizável ou uma decisão necessária à implementação seguinte.

A referência inicial do núcleo é [FermiHart/axial@26eec863](https://github.com/FermiHart/axial/tree/26eec8630e8cf1dc3a1808f1580cc12d36410a8e), da branch audit/axial-80-waves-20261019. A00 confirma novamente os heads e fixa a branch da campanha. A análise anterior do receptor usa Beyond_BDM@050ba81e, branch codex/gui20-phase1, com fronteira UNWIRED; isso não descreve automaticamente outras branches.

**Perfis:** núcleo standalone e demonstração host isolada local-config-publication compõem a entrega inicial; ver [decisões A01](A01-CONTRACTS.md). Consumidor Jash e target Beyond recebem qualificação separada, conforme a seleção registrada em A00 e os contratos vigentes. Qualquer implementação de backend necessária deve ser decomposta explicitamente; vinte waves não constituem garantia de conclusão de todos os alvos.

## Regras de execução e continuidade

- Estados permitidos: PLANNED, READY, IN_PROGRESS, DONE e BLOCKED. DONE exige entrega, critério de aceite verificado e referência de evidência.
- Registrar por wave: revisão de entrada, arquivos alterados, decisão tomada, verificação executada, resultado e próximo passo. Não transformar resultado histórico em teste da revisão atual.
- Trabalhar a partir do delta real. Ampliar o componente existente antes de introduzir outro registry, parser, protocolo ou tabela.
- Usar verificações proporcionais à mudança e gates obrigatórios do perfil. Repetir ou ampliar testes apenas para resolver uma falha, risco concreto ou dependência exigida.
- Em BLOCKED, registrar requisito exato, impacto e trabalho independente que pode prosseguir. Falha de infraestrutura não equivale a PASS.
- Publicar checkpoints após A09 e A19, incluindo código, documentos, estado das waves e evidências. Commits intermediários podem preservar entregas menores.
- A10 é uma demonstração isolada. A promoção do primeiro consumidor Beyond depende da decisão de ativação e de todos os gates vigentes; a ordem das waves não dispensa dependências.
- No perfil Jash, classificar todas as mutações consequentes do conjunto de fontes. Operações protegidas sem suporte são recusadas; exclusões só existem quando previstas no contrato.
- Bythom permanece uma extensão opcional, condicionada à identificação de repositório, interface e consumidor. Sua ausência não bloqueia perfis que não dependem dele.

## Fila completa de execução

Todas as vinte waves estão registradas. Caixa marcada significa entrega concluída com evidência; detalhes e dependências aparecem nos cards abaixo.

- [x] **A00 — Baseline, inventário e delta** — CONCLUÍDA; ver [evidência](A00-BASELINE.md)
- [x] **A01 — Contratos e fronteira de confiança** — CONCLUÍDA; ver [decisões](A01-CONTRACTS.md)
- [ ] **A02 — ABI, schemas e compatibilidade** — PENDENTE
- [ ] **A03 — Catálogo de builtins, effects e backends** — PENDENTE
- [ ] **A04 — Inspeção unificada e resumida** — PENDENTE
- [ ] **A05 — Explicação de requisitos e recusas** — PENDENTE
- [ ] **A06 — Revisão de mudanças de contrato/política** — PENDENTE
- [ ] **A07 — Identidade completa da invocação** — PENDENTE
- [ ] **A08 — Orçamento aplicado de ponta a ponta** — PENDENTE
- [ ] **A09 — Registry fechado e descriptor do consumidor** — PENDENTE
- [ ] **A10 — Ação mediada em consumidor isolado** — PENDENTE
- [ ] **A11 — Resultados parciais e reconciliação** — PENDENTE
- [ ] **A12 — Confiança, selagem e migração** — PENDENTE
- [ ] **A13 — Ciclo de vida e reutilização de contextos** — PENDENTE
- [ ] **A14 — Planejamento limitado** — PENDENTE
- [ ] **A15 — Grafo e correlação causal** — PENDENTE
- [ ] **A16 — Qualificação do receptor/plataforma** — PENDENTE
- [ ] **A17 — Conformidade e regressão delimitadas** — PENDENTE
- [ ] **A18 — Performance por workload e ambiente** — PENDENTE
- [ ] **A19 — Qualificação e checkpoint final** — PENDENTE

## Visão da campanha

| Wave | Entrega | Estado inicial |
| --- | --- | --- |
| A00 | Baseline, inventário e delta | DONE |
| A01 | Contratos e fronteira de confiança | DONE |
| A02 | ABI, schemas e compatibilidade | READY |
| A03 | Catálogo de builtins, effects e backends | PLANNED |
| A04 | Inspeção unificada e resumida | PLANNED |
| A05 | Explicação de requisitos e recusas | PLANNED |
| A06 | Revisão de mudanças de contrato/política | PLANNED |
| A07 | Identidade completa da invocação | PLANNED |
| A08 | Orçamento aplicado de ponta a ponta | PLANNED |
| A09 | Registry fechado e descriptor do consumidor | PLANNED |
| A10 | Ação mediada em consumidor isolado | PLANNED |
| A11 | Resultados parciais e reconciliação | PLANNED |
| A12 | Confiança, selagem e migração | PLANNED |
| A13 | Ciclo de vida e reutilização de contextos | PLANNED |
| A14 | Planejamento limitado | PLANNED |
| A15 | Grafo e correlação causal | PLANNED |
| A16 | Qualificação do receptor/plataforma | PLANNED |
| A17 | Conformidade e regressão delimitadas | PLANNED |
| A18 | Performance por workload e ambiente | PLANNED |
| A19 | Qualificação e checkpoint final | PLANNED |

## Fase 1 — Rebase e descoberta

### A00 — Baseline, inventário e delta

**Estado:** DONE. **Dependências:** nenhuma. **Evidência:** [A00-BASELINE.md](A00-BASELINE.md).

Fixar commits e escopos de Axial, receptor e consumidor. Inventariar fontes, opcodes, builtins, capacidades e interfaces usando os registries existentes; separar presença no código de integração ativa. Classificar cada intenção da ADR como EXISTE, ESTENDER, INTEGRAR ou INVESTIGAR.

- **Entrega:** inventário reproduzível, referências Git, matriz de delta e perfis obrigatórios da campanha.
- **Componentes:** árvore Git, AXB_OPCODES, AXI_BUILTIN_REGISTRY, cap table, pins, UPSTREAM, boundary e claims do receptor.
- **Aceite:** cada item tem origem verificável e destino; nomes e contagens derivam das fontes fixadas; os campos declarados desconhecidos permanecem explícitos. Documentar o alcance da inspeção sem alegar build, boot ou consumo não exercitados.

### A01 — Contratos e fronteira de confiança

**Estado:** DONE. **Dependência:** A00. **Evidência:** [A01-CONTRACTS.md](A01-CONTRACTS.md).

Resolver conflitos documentais que afetem a implementação. Identificar quem admite o artefato, calcula a decisão, concede autoridade, publica o efeito e registra seu resultado. Usar ADR-042/043/044 para o consumidor e classificar o mapa Jash antigo como referência histórica.

- **Entrega:** matriz de responsabilidades e decisões de compatibilidade com as ADRs vigentes.
- **Componentes:** admission, builtin/effect, gateway, JM1, AG1/AER e contratos do receptor.
- **Aceite:** cada efeito do perfil possui owner e porta de autorização definidos; computação pura, autoridade requerida e grants efetivos têm significados distintos. Nenhum estado de integração é promovido pela edição de documentação. Resolver ambiguidades antes de cristalizá-las no catálogo.

### A02 — ABI, schemas e compatibilidade

**Estado:** READY. **Dependências:** A00–A01.

Reconciliar o status do header embed v1 com o perfil ABI e a documentação. Separar compatibilidade binária, formato de artefato, interface de célula e schema de inspeção. Definir versões, limites e representação sem perda de u64 e bytes para as extensões necessárias.

- **Entrega:** matriz produtor/consumidor e política de evolução dos campos públicos.
- **Componentes:** include/axial/axi_embed_v1.h, abi/, axi_iface, axi_json e schemas existentes.
- **Aceite:** a ABI preservada continua conferindo com seus pins; uma alteração incompatível de fixture é identificada pelo gate pertinente. Novos metadados não exigem cópia de structs privadas. Campos desconhecidos e opcionais têm comportamento documentado.

### A03 — Catálogo de builtins, effects e backends

**Estado:** PLANNED. **Dependências:** A01–A02.

Expor uma projeção legível por máquina dos registries atuais. Distinguir computações OP_BUILTIN, operações OP_EFF e suporte de backend. Acrescentar apenas metadados necessários ao consumidor, como tipos, autoridade, regra de custo e capacidade de planejamento.

- **Entrega:** catálogo estruturado com IDs estáveis, versão e origem dos fatos.
- **Componentes:** axi_builtin_registry, axi_builtin, axi_bc, axi_effect e interfaces de plataforma.
- **Aceite:** conjuntos de IDs do catálogo e registries correspondem; todos os campos obrigatórios existem; operação desconhecida recebe diagnóstico definido. Custos derivados não são mantidos em tabela paralela. Verificadores independentes conservam sua função e ganham comparação de conformidade.

### A04 — Inspeção unificada e resumida

**Estado:** PLANNED. **Dependências:** A02–A03.

Oferecer uma visão compacta de contrato, confiança e disponibilidade usando iface, caps e axi-dossier. Permitir aprofundamento por célula sem exigir que um agente receba todo o artefato. Separar informações obtidas da fonte das disponíveis no módulo compilado.

- **Entrega:** entrada de inspeção documentada e projeção resumida com identidade e limites de saída.
- **Componentes:** axi_main, axi_iface, axi_dossier e serializers existentes.
- **Aceite:** a consulta offline não executa o módulo; trusted, valid-unanchored e UNOBSERVED mantêm seus significados. Localização de fonte ausente não é inventada. Um consumidor consegue identificar contrato, capacidades e suporte usando a saída documentada.

**Marco 1:** descoberta útil do Axial real, com implementação, autoridade e qualificação distinguíveis.

## Fase 2 — Decisão e preparação do consumidor

### A05 — Explicação de requisitos e recusas

**Estado:** PLANNED. **Dependências:** A01–A04.

Ligar os diagnósticos à regra e à operação relevantes. Apresentar requisitos declarados e autoridade efetiva sem confundir ausência de grant com incompatibilidade de formato. Aproveitar códigos e sugestões existentes; limitar detalhes à visão autorizada do observador.

- **Entrega:** explicação estruturada por célula/efeito, com fase, código, causa e correção possível.
- **Componentes:** axi_cap_infer, axi_cap_table, axi_admission_v1 e axi_diag.
- **Aceite:** recusas representativas têm causa estável e acionável; informações protegidas não aparecem na visão restrita. Hints não elevam grants nem executam edições automaticamente. Texto originado de módulos permanece dado, e mensagens humanas não viram identificadores de protocolo.

### A06 — Revisão de mudança de contrato e política

**Estado:** PLANNED. **Dependências:** A02, A04–A05.

Construir a revisão de atualização sobre axi_iface_diff. Mostrar alterações de parâmetros, retornos, capacidades e budget, acompanhadas de cenários representativos que revelem mudanças de decisão. Separar compatibilidade de interface da equivalência semântica da política.

- **Entrega:** relatório direcional OLD→NEW e conjunto pequeno de cenários relevantes ao consumidor.
- **Componentes:** axi_iface, contratos, pins e fixtures de policy existentes.
- **Aceite:** um aumento declarado de autoridade e uma alteração incompatível aparecem claramente; versões equivalentes preservam a classificação adequada. O relatório identifica a revisão e as entradas usadas. Não afirma equivalência universal a partir de um diff ou de um corpus finito.

### A07 — Identidade completa da invocação

**Estado:** PLANNED. **Dependências:** A01–A03, A06.

Mapear quais campos do AXR4 e dos contratos vinculam artefato, célula, argumentos, grants e resultado. Incorporar somente lacunas justificadas de política, versão de custos, semântica ou observações externas mediante extensão compatível. Classificar separadamente entropia de autenticação e dados operacionais.

- **Entrega:** contrato de identidade e projeção dos campos determinísticos.
- **Componentes:** axi_replay_v4, axi_contract, hash, VM e autoridade.
- **Aceite:** repetir avaliação com entradas completas preserva resultado e contabilização normativa; alterar entrada relevante altera a vinculação correspondente. Reprodução não publica efeitos reais. Timestamps e material criptográfico não entram acidentalmente no critério de igualdade semântica.

### A08 — Orçamento aplicado de ponta a ponta

**Estado:** PLANNED. **Dependências:** A03, A07.

Conectar a visão de orçamento aos mecanismos existentes e ao perfil de ação escolhido. Identificar quais limites são reservados antes do trabalho e quais consumos retornam ao chamador. Distinguir fuel, memória, bytes, chamadas, recursos vivos e deadline.

- **Entrega:** orçamento consultável e contabilidade coerente da preparação à liberação.
- **Componentes:** AXB_OPCODES, VM, axi_mem_account, axi_compile_budget e axi_resource_envelope.
- **Aceite:** um limite pertinente interrompe ou recusa o trabalho conforme o contrato e preserva a primeira causa; recursos são liberados nos caminhos exercitados. Parsing e saída também têm limites. Não atribuir cancelamento universal de I/O bloqueante apenas à existência de deadline.

### A09 — Registry fechado e descriptor do consumidor

**Estado:** PLANNED. **Dependências:** A01–A08.

Fixar a revisão do consumidor e enumerar os pontos consequentes de seu conjunto de fontes. Preparar a integração para que resolução produza um descriptor imutável usado pela decisão e pela porta final. Tratar redirecionamentos e outros efeitos anteriores ao despacho convencional.

- **Entrega:** inventário de ações, vinculação do descriptor e implementação preparatória isolada.
- **Componentes:** ADR-042, axi_jm1_v1, gateway e checkout Jash identificado em A00.
- **Aceite:** todas as mutações do escopo estão classificadas; ações desconhecidas ou plugins não registrados seguem a recusa prevista. Descriptor, decisão e tentativa têm identidade consistente. A preparação não promove a fronteira Beyond para WIRED.

**Checkpoint A09:** publicar as dez primeiras waves, revisão exata, estado dos perfis, evidências e handoff para A10. Qualquer item BLOCKED permanece explícito.

## Fase 3 — Ação real em ambiente isolado

### A10 — Primeira ação mediada demonstrada

**Estado:** PLANNED. **Dependências:** A07–A09; requisitos de confiança, lifecycle e evidência necessários antecipados de A11–A13.

Executar uma operação pequena do perfil escolhido em consumidor isolado, como atualização de configuração de fixture. Ligar decisão, AG1, porta final e o recibo do perfil à mesma ação resolvida; AER2 local e AER1 Jash conservam seus contratos conforme A01. Preservar as exigências do contrato mesmo nessa demonstração.

- **Entrega:** cenário utilizável de permissão e recusa com resultado consultável.
- **Componentes:** gateway, AG1, porta de efeito, AER e consumidor isolado.
- **Aceite:** permissão publica o efeito esperado e seu recibo; recusa preserva o estado protegido; consumo pertence à tentativa correta. A demonstração não qualifica o Jash inteiro nem ativa o consumidor Beyond. Promoção depende dos gates obrigatórios do perfil.

### A11 — Resultados parciais e reconciliação

**Estado:** PLANNED. **Dependência:** A10.

Propagar estados de execução existentes até o consumidor. Distinguir recusa anterior ao efeito, conclusão, parcial conhecido e resultado desconhecido. Usar a consulta de tentativa para esclarecer incerteza sem repetir automaticamente uma operação.

- **Entrega:** resultado estruturado e caminho de consulta/reconciliação documentados.
- **Componentes:** effect state machine, local attempts, AER, ledger/journal e perfil local W80.
- **Aceite:** casos de falha já previstos pelas suites mantêm informação de efeito e persistência; consulta não publica novamente. O consumidor informa quando repetição é admissível ou depende de reconciliação. Timeout ou TRAP não é convertido genericamente em “nenhum efeito ocorreu”.

### A12 — Confiança, selagem e migração no consumidor

**Estado:** PLANNED. **Dependências:** A02, A07, A10–A11.

Verificar que o consumidor usa a admissão do artefato e a política de confiança corretas. Preservar AXB v7, AXBS, SHA-256/Ed25519 e a distinção entre assinatura, CHECKED e autoridade. Aplicar a migração de identidade do checker quando exigida.

- **Entrega:** caminho de carga qualificado para os formatos e perfis adotados.
- **Componentes:** axi_contract, axi_sign, admission, checker identity e fixtures de migração.
- **Aceite:** entradas incompatíveis e chaves sem a confiança exigida são recusadas conforme o perfil; artefatos válidos mantêm comportamento. Selo antigo segue reexecução/resealing aplicáveis. Nenhum grant nasce apenas da assinatura. A verificação preserva dependências públicas e formato compatível.

### A13 — Ciclo de vida e reutilização de contextos

**Estado:** PLANNED. **Dependências:** A10–A12.

Ampliar o consumidor para reutilizar estruturas imutáveis quando vantajoso. Definir ownership, limites de concorrência, invalidação e destruição. Manter grants, política viva e decisão da tentativa separados de qualquer cache de parsing ou verificação.

- **Entrega:** lifecycle explícito e caminho de reutilização para o workload selecionado.
- **Componentes:** axi_embed_v1, contexto admitido, memória e benchmarks/lifecycles W70–W75.
- **Aceite:** avaliações equivalentes preservam resultados e budgets; revisão incompatível ou mudança relevante de confiança não reutiliza identidade incorreta. Cleanup e lifetimes compartilhados são exercitados pelos testes pertinentes. Medir se a reutilização reduz o custo identificado sem retirar verificações necessárias.

### A14 — Planejamento limitado e explícito

**Estado:** PLANNED. **Dependências:** A03–A05, A07–A08, A11–A13.

Expor planejamento para os efeitos que conseguem descrevê-lo com segurança. Retornar complete, partial ou unsupported, junto de precondições, operações conhecidas e custo classificado como estimativa, teto ou desconhecido. Leituras necessárias têm autoridade e origem explícitas.

- **Entrega:** contrato de planejamento e implementação para o perfil demonstrado.
- **Componentes:** catálogo de effects, contexto de observações e consumidor.
- **Aceite:** planejar não publica efeitos nem concede grants; dependências desconhecidas aparecem na resposta. A execução revalida as condições relevantes. Um cenário cujo estado muda entre plano e tentativa segue recusa ou reavaliação definida, sem prometer correspondência irrestrita.

**Marco 2:** ação isolada utilizável, explicável e reconciliável. A classificação completa do perfil continua obrigatória para qualquer qualificação mais ampla.

## Fase 4 — Correlação e qualificação

### A15 — Grafo e correlação causal

**Estado:** PLANNED. **Dependências:** A04–A05, A07, A10–A14.

Derivar o grafo de contratos e chamadas do dossiê e associá-lo às tentativas e recibos observados. Preservar axi_trace como testemunho determinístico; spans operacionais opcionais devem usar correlação explícita sem mudar o resultado da avaliação.

- **Entrega:** grafo consultável e trilha causal entre decisão, tentativa e resultado.
- **Componentes:** axi_dossier, axi_trace, AER, ledger/journal e projeções de inspeção.
- **Aceite:** arestas declaradas, resolvidas e observadas têm distinção inequívoca; paths desconhecidos não são fabricados. Desligar spans não elimina evidência obrigatória. Saída e buffers têm limites, e a política de perda de dados segue o perfil.

### A16 — Qualificação do receptor e da plataforma

**Estado:** PLANNED. **Dependências:** A09–A15 e implementação das dependências do perfil selecionado.

Verificar recebimento, identidade do produto e consumidor real no ambiente de destino. Separar resultado standalone, host e target. Para Beyond, aplicar os contratos de backend, composição soberana e porta final das ADR-043/044, com decisão de ativação registrada.

- **Entrega:** relatório por perfil e dependências ainda não implementadas decompostas.
- **Componentes:** pins/UPSTREAM, boundary, build Bear/Basm/blibc, backend e composição, conforme o alvo.
- **Aceite:** claim target identifica o artefato realmente composto e exercitado; paridade usa campos normativos. Host verde não qualifica guest. Ausência de backend obrigatório bloqueia aquele perfil, sem fabricar aprovação por documentação.

### A17 — Conformidade e regressão delimitadas

**Estado:** PLANNED. **Dependências:** A03–A16 nos perfis disponíveis.

Consolidar as verificações necessárias às mudanças efetivas, reaproveitando corpora e suites. Cobrir formato, limites, autoridade, planejamento sem publicação e correspondência entre decisão e recibo. Definir orçamento da campanha e guardar entradas mínimas que representem regressões relevantes.

- **Entrega:** matriz de propriedades e resultados vinculados ao produto testado.
- **Componentes:** testes existentes de CLI, embed, effects, admission, replay e integração.
- **Aceite:** cada propriedade obrigatória possui resultado no perfil correto e falhas diagnosticadas. Casos e repetições não são inflados como cobertura independente. Semente fixa serve à reprodução; passagem do corpus não vira alegação universal de ausência de defeitos.

### A18 — Performance por workload e ambiente

**Estado:** PLANNED. **Dependências:** A13, A15–A17.

Medir as operações relevantes à experiência entregue: inspeção, carga/admissão, avaliação quente, planejamento e consulta de recibo. Fixar tamanhos, flags, revisão, alvo e método. Usar baselines W74/W75 como referência de método, sem transferir tempos entre ambientes.

- **Entrega:** distribuições e orçamento de regressão para workloads explicitamente nomeados.
- **Componentes:** benchmarks atuais, consumidor e perfil de build.
- **Aceite:** resultados preservam correção e contabilização; p50/p95/p99 distinguem frio e quente. Ruído e resultados adversos permanecem registrados. Regressão concreta recebe investigação proporcional. Tempos TCG não são apresentados como latência nativa, e verificações de confiança não são removidas para melhorar números.

### A19 — Qualificação e checkpoint final

**Estado:** PLANNED. **Dependências:** A00–A18; qualificação apenas dos perfis que cumpriram suas exigências.

Consolidar a release da campanha com revisões de produto, consumidores, schemas e evidências. Atualizar claims apenas onde o comportamento foi demonstrado. Explicitar implementação, conexão e qualificação como dimensões distintas e registrar pendências por perfil.

- **Entrega:** relatório final, matriz de claims, comandos de reprodução e handoff.
- **Componentes:** registro da campanha, pins, boundary, CLAIMS e gates vigentes.
- **Aceite:** cada alegação aponta para evidência correspondente à revisão entregue; requisito obrigatório pendente impede aprovação daquele perfil. Confirmar o checkpoint GitHub e a possibilidade de retomar do commit registrado. A conclusão não depende de Bythom quando ele está fora do escopo selecionado.

## Formato mínimo de encerramento de uma wave

Registrar uma entrada curta com: ID e estado; revisão inicial/final; mudança e benefício; arquivos afetados; comando ou método de verificação; resultado real; limitações; dependência desbloqueada; próximo passo. Associar evidências de máquina quando elas existirem.

Para retomar em outra sessão, ler o último checkpoint, o estado da campanha e o registro da wave ativa; conferir a branch e seu head antes de editar. Preservar trabalho concorrente e não repetir etapas já verificadas sem uma mudança relevante de entrada.
