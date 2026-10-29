# ADR-AXIAL-0001 — Contratos observáveis e mediação verificável do Axial

| Campo | Valor |
| --- | --- |
| Status | PROPOSTA REVISADA — revisão 2 |
| Data | 29 de outubro de 2026 |
| Autor do projeto | F E R M I ∞ H A R T |
| Objeto | Evolução do Axial existente, descoberta por agentes e integração verificável com consumidores |
| Escopo desta entrega | Revisão arquitetural e plano de implementação; leitura de código e contratos, sem nova execução de builds, testes ou boot |
| Relação com o anexo | Substitui a proposta de execução literal das waves A00–A19; preserva seus objetivos úteis e corrige suas premissas |
| Relação com ADRs existentes | Complementa os contratos vigentes identificados no baseline. Não altera automaticamente o status das ADRs anteriores nem ativa consumidores |

## 1. Decisão proposta

Evoluir o Axial por integração e extensão dos mecanismos existentes: contratos de células, capacidades, effects, fuel, orçamento de recursos, admissão, selagem, recibos e replay. A experiência oferecida a um agente deverá permitir descobrir uma operação, compreender sua autoridade, preparar um plano limitado, solicitar uma execução vinculada a esse plano e verificar o resultado efetivamente observado.

A primeira entrega operacional deve ser uma ação real, de escopo fechado, com autorização no ponto que efetua a mutação e recibo correlacionável. Catálogos, explicações e grafos devem descrever esse mesmo caminho executável.

O programa adota três decisões centrais:

1. **Reutilizar os contratos atuais.** O novo trabalho começa pelo delta entre a proposta e as implementações verificadas, incluindo o dossiê offline e as ADRs de mediação já existentes.
2. **Qualificar cada ambiente separadamente.** Núcleo, host, consumidor Jash e runtime Beyond têm identidades, dependências e evidências próprias.
3. **Vincular intenção, autoridade e resultado.** Um ALLOW só pode ser consumido para a ação e o contexto aos quais foi vinculado. Planejamento, assinatura e inspeção não concedem autoridade por si.

O critério de sucesso é operacional: um agente consegue responder, com evidência e dentro de sua autorização, **o que pode fazer, por que uma ação foi permitida ou recusada, o que aconteceu e se pode repetir a tentativa**.

## 2. Baseline e alcance das evidências

### 2.1 Revisões identificadas

| Componente | Referência consultada | Implicação |
| --- | --- | --- |
| Axial standalone, main | 2d6752255ffcc92e0b103c97609daf205a5a39de | A referência pública inicial não contém automaticamente o trabalho da branch de auditoria |
| Axial standalone, audit/axial-80-waves-20261019 | 26eec8630e8cf1dc3a1808f1580cc12d36410a8e | Baseline principal da revisão do núcleo |
| Beyond_BDM, codex/gui20-phase1 | 050ba81e15dcd5304d2f833f4897964813f67e2f | Snapshot usado para examinar recebimento e contratos de integração |
| Axial recebido nesse Beyond | 26eec8630e8cf1dc3a1808f1580cc12d36410a8e | O recebimento mantém adaptações e identidade próprias |
| Jash fixado nesse Beyond | 6c8f61ada6385dbb75a6547fc263ecf2bea5d666 | O checkout é um repositório irmão, resolvido pelo mecanismo de payloads |

Esses SHAs delimitam a análise. O estado da branch GUI20 não descreve automaticamente main ou outras branches do Beyond. Antes de implementar, A00 deve resolver novamente os heads e selecionar a base de destino.

O relatório W80 registra validação host e limita expressamente suas conclusões; esses resultados são evidência histórica do repositório, não testes reexecutados nesta revisão. [S1]

### 2.2 Integração recebida e integração ativa

No snapshot Beyond examinado, Docs/AXIAL-BOUNDARY.tsv registra:

~~~text
state = UNWIRED
consumer = NONE
release = NONE
~~~

A nota de atualização explica que receber os arquivos W80 e seu perfil local não ativa consumidor no kernel ou no Jash. CLAIMS.tsv registra como DOES_NOT_HOLD as alegações de mediação universal do Jash, plataforma nativa/Single Door e consumo do embed v1 pelo Beyond. [S9–S11]

O arquivo jash-axial-map.md se apresenta como PROPOSED MAP. A ADR-042, já aceita para implementação de core, identifica esse mapa como desatualizado e define um contrato de mediação mais preciso. Portanto, ele deixa de ser proposto aqui como autoridade operacional do sistema. [S12–S13]

### 2.3 Vocabulário de maturidade

O inventário deve manter duas dimensões:

- **Implementação:** planejada, presente em código, conectada a consumidor.
- **Evidência:** inspecionada, exercitada em teste, qualificada no ambiente e revisão identificados.

Um arquivo presente não demonstra consumo. Um core testado não demonstra enforcement do host ou do kernel. Um recibo ou selo válido tem o alcance definido por sua cadeia de confiança.

## 3. O que já existe e deve ser aproveitado

| Tema do anexo | Evidência encontrada | Decisão desta revisão |
| --- | --- | --- |
| ABI e interface pública | Header embed v1, perfil ABI registrado, funções de criação/destruição de contexto e avaliação | Preservar o contrato público e esclarecer sua documentação; não copiar headers internos para consumidores |
| Introspecção de contratos | axi iface FILE --json e axi_iface_json | Usar como projeção de fonte verificada |
| Comparação de contratos | axi iface-diff OLD NEW --json | Expandir a experiência de revisão de mudança sobre o mecanismo existente |
| Catálogo de capacidades | axi caps --json | Integrar à descoberta e explicação |
| Inspeção de artefato | axi-dossier e schema axi.dossier.v1 | Reutilizar para contratos, chamadas, capacidades, proveniência e estado do selo |
| Registry de builtins | AXI_BUILTIN_REGISTRY | Acrescentar projeções e metadados faltantes ao registry existente |
| Fuel de opcodes | AXB_OPCODES e cobrança no dispatcher | Versionar e expor o modelo existente; evitar uma segunda tabela |
| Orçamentos externos | axi_resource_envelope, memória de invocação e quota do compilador | Consolidar visibilidade e consumo real em cada adaptador |
| Diagnósticos estruturados | axi.diags.v1, códigos, localização, fix e edit opcional | Estender cobertura e contexto, preservando o schema compatível |
| Trace | axi_trace como testemunho determinístico de execução | Preservar esse significado; spans operacionais são outra projeção |
| Selagem e confiança | AXB v7/AXBS, SHA-256, Ed25519 e certificado CHECKED | Manter os formatos e a migração explícita |
| Replay | Envelope AXR4 vinculado a artefato, célula, argumentos, grants e resultado | Reutilizar a identidade existente; qualificar o caminho consumidor |
| Mediação Jash | ADR-042 e core axi_jm1_v1 | Implementar e qualificar a ativação do contrato vigente |
| Plataforma Beyond | ADR-043/044 e cores correspondentes | Distinguir mapeamento/core de backend, imagem e porta final reais |

Fontes: headers, CLI e implementações do baseline, além dos contratos de integração. [S2–S8, S13–S15]

O dossiê já distingue assinatura trusted de valid-unanchored e apresenta a execução do selo como UNOBSERVED na inspeção offline. Essa distinção deve permanecer visível ao agente. Um dossiê aceito não se converte em permissão de execução. [S5]

## 4. Decisões arquiteturais

### D01 — Contratos normativos, implementação e documentação devem concordar

Manter as identidades e fontes normativas existentes: registries, formatos, headers públicos, pins, ADRs e claims. Gerar catálogos e documentação derivados quando possível, com checagem de correspondência.

Uma lista em Markdown não será prova de cobertura de mutações. Para cada integração, identificar o conjunto de fontes, o registry de ações e o consumidor que realmente o utiliza.

A geração de metadados não deve eliminar verificadores independentes. O dossiê possui uma implementação de inspeção isolada; a evolução exige conformidade entre suas interpretações e o loader, sem transformar os dois em uma única implementação incapaz de detectar divergência. [S5]

### D02 — Builtins puros e efeitos externos mantêm caminhos distintos

O contrato atual declara que builtins são computações determinísticas por OP_BUILTIN e não acessam o host. As operações externas pertencem a OP_EFF. [S3]

O catálogo proposto deve distinguir:

| Categoria | Informação necessária |
| --- | --- |
| Builtin | ID, nome, tipos, aridade, classificação de capacidade, custo e versão semântica |
| Effect | ID, argumentos e resultado, recurso, autoridade, orçamento, comportamento de falha e suporte a planejamento |
| Adaptador | Backend, operações implementadas, identidade de build e perfil qualificado |
| Consumidor | Integração ativa, contrato público usado, escopo coberto e evidências |

Metadados como mutates ou simulation_support pertencem à categoria adequada. Não mover efeitos de sistema para builtins para acomodar a proposta original.

### D03 — Determinismo é uma propriedade de uma invocação completa

A garantia proposta é:

> Para a mesma semântica versionada, artefato admitido, entrada canônica, política, autoridade efetiva, orçamento e observações externas fornecidas, a avaliação determinística produz o mesmo resultado semântico e a mesma contabilização determinística.

A identidade relevante inclui, conforme o perfil:

- Raiz do artefato e hashes de corpo e interface.
- Célula de entrada e argumentos canônicos.
- Versões da VM, checker, contratos e tabela de custos.
- Política, época de autoridade e grants aplicáveis.
- Limites iniciais e perfil do backend.
- Snapshot ou sequência ordenada das observações externas usadas pela avaliação.

O AXR4 já transporta parte substancial dessa vinculação. A00/A07 devem mapear campos existentes e apenas adicionar o que for necessário por extensão versionada. [S8]

Comparar separadamente:

1. Resultado e contabilização determinísticos.
2. Serialização canônica desses campos.
3. Observações do mundo real, incluindo tempo e resultado de I/O.
4. Dados operacionais como timestamps e spans.

Reexecutar uma decisão com entradas registradas não repete efeitos reais. Igualdade semântica entre backends deve usar os campos normativos; errno e tempo específicos do host não são identidades portáveis. [S14]

### D04 — Tempo e entropia têm domínios explícitos

O núcleo puro não consulta tempo ou aleatoriedade ambientes para decidir silenciosamente. Valores externos necessários à política entram pelo contexto definido ou pelo registro de replay.

O runtime atual usa axi_platform_random para material de autenticação de capabilities de invocação. Um gate que proíbe toda aleatoriedade destruiria essa separação de responsabilidades. [S4]

O gate de não determinismo deve classificar domínios: avaliação pura, backend, autoridade/criptografia e observabilidade. Busca textual é um alerta de revisão; o critério real é a ausência de dependências externas não declaradas na semântica determinística. Comentário em allowlist não é prova suficiente.

### D05 — Autoridade requerida, concedida e efetiva são diferentes

Uma capacidade mencionada por uma célula representa uma exigência, não uma concessão. A autoridade efetiva deriva dos grants válidos e das restrições do chamador, política, recurso e contexto.

Chamadas e delegações preservam ou restringem autoridade. Mudanças de política, epoch ou validade temporal devem seguir os mecanismos existentes e ser verificadas no ponto exigido pelo protocolo.

Grants vazios devem impedir operações protegidas. Computações realmente puras e com contrato sem capacidade não devem ser recusadas apenas por uma interpretação informal de “negar tudo”; a semântica vigente será fixada em A01.

Leituras protegidas e saída de informações também podem exigir autoridade. Uma taxonomia centrada apenas em escrita seria incompleta.

### D06 — A autorização se vincula à ação resolvida e à porta final

Adotar o fluxo da ADR-042: resolução, descriptor imutável, admission/policy, grant AG1, consumo na porta final e AER1. O mesmo descriptor e suas identidades devem atravessar esses passos. [S13]

O predicado fs.path_under é lexical. A identidade do recurso efetivamente usado e a contenção do backend devem ser verificadas pelo mecanismo apropriado de efeito. A comparação de strings de path não representa sozinha esse contrato. [S3]

A cobertura deve incluir operações que ocorrem antes do despacho convencional de builtin, como preparação de redirecionamentos. Registrar que um callback foi executado não demonstra que a mutação foi impedida quando deveria.

A ativação do primeiro consumidor no Beyond precisa satisfazer a promoção atômica prevista nos contratos vigentes: release fixada, consumidor identificado, gates obrigatórios e evidência da composição correspondente. Alterar apenas o texto UNWIRED seria insuficiente. [S13–S15]

A ADR-042 registra aprovação para o core e uma decisão separada para promoção. A futura ativação deve registrar essa decisão de arquitetura, ou uma substituição explícita do contrato, junto da evidência técnica. Esta revisão não converte aprovação de core em aprovação de implantação.

### D07 — Fuel integra um orçamento multidimensional

Reutilizar a tabela de opcodes, a contabilidade de memória, a quota de compilação e axi_resource_envelope. Este já modela calls, bytes de entrada e saída, handles, children e deadline com relógio injetado. [S4, S6]

A implementação deve demonstrar que cada adaptador realmente reserva, consome e libera os limites aplicáveis. O custo de uma operação cujo trabalho cresce com a entrada precisa de regra explícita, ou de limite próprio que torne esse trabalho controlável.

Fuel determinístico e prazo de tempo de parede são mecanismos distintos. Um prazo pode limitar a tentativa, mas não prova cancelamento de todo I/O bloqueante. Esse alcance precisa permanecer no relatório de perfil.

Parsing, carregamento, inspeção, geração de saída e cleanup também têm limites. Não inventar um fuel_est exato para um trabalho cujo custo depende de respostas desconhecidas.

### D08 — Integridade, autenticidade, CHECKED e autorização permanecem separados

O formato atual usa assinatura Ed25519 sobre um digest SHA-256 com separação de domínio. A confiança vem de uma chave escolhida externamente ao artefato. A assinatura não concede autoridade para efeitos. [S7]

Consequências:

- “Identificado por hash” é o termo correto para um pin sem assinatura.
- Manter SHA-256/Ed25519 e os formatos existentes neste programa.
- Uma migração para outro algoritmo exigiria justificativa, versão de formato e plano próprio.
- CHECKED representa o certificado e as leis verificadas sob a identidade do checker correspondente; não é prova universal de correção do programa.
- Alterações relevantes de semântica/checker exigem a migração já definida, incluindo reexecução das leis e resealing quando aplicável. [S1]

O nome do arquivo não define seu nível de confiança. A implementação atual usa artefatos .axb e estruturas internas de assinatura e certificado; .axb.sealed não será introduzido como um segundo protocolo informal.

### D09 — O resultado precisa informar se houve efeito

Reutilizar as máquinas de estado e recibos existentes, preservando a distinção entre recusa anterior à tentativa, conclusão, execução parcial conhecida e resultado desconhecido.

A API para agentes deve mapear esses estados sem apagar informação:

| Situação | Conduta do consumidor |
| --- | --- |
| Recusa antes de qualquer efeito protegido | Pode corrigir o pedido e iniciar nova avaliação |
| Efeito confirmado | Apresentar resultado e recibo |
| Efeito parcial conhecido | Informar os membros concluídos e os não concluídos |
| Resultado desconhecido | Consultar/reconciliar a tentativa antes de decidir sobre repetição |

Um TRAP não implica automaticamente “nada aconteceu”. Idempotência e compensação devem ser propriedades declaradas de cada efeito; rollback global não é presumido.

O perfil host-local W80 já preserva incerteza em falhas de persistência e distingue consulta de repetição de efeito. Esse comportamento é uma base a conectar, não uma funcionalidade a reconstruir. [S1]

### D10 — Planejamento deve declarar limites e nunca conceder autoridade

O modo de planejamento retorna uma das classificações propostas:

- complete: plano completo sob as precondições declaradas.
- partial: há valores, ramificações ou observações ainda desconhecidos.
- unsupported: algum efeito não possui planejamento seguro nesse perfil.

Retorna operações previstas, recursos conhecidos, capacidades requeridas, precondições e limites de custo conhecidos. Uma estimativa deve ser distinguida de um teto garantido e de um valor desconhecido.

O executor de planejamento não recebe acesso ao adaptador que publica efeitos. Leituras necessárias à preparação devem ser autorizadas e identificadas como observações.

A execução valida novamente as precondições relevantes. O plano não reserva direitos ilimitados, não transforma metadata em autorização e não garante o mesmo resultado se o mundo mudou.

### D11 — Descoberta deve ser compacta, exata e compatível

Priorizar as projeções que já existem:

- Fonte verificada: interface e diff.
- Artefato: dossiê offline, assinatura, certificado, contratos e chamadas.
- Build: capacidades e registries disponíveis.
- Invocação: requisitos resolvidos, orçamento, decisão e resultado.

AST da fonte, IR, bytecode, manifesto e dados de depuração são representações diferentes. Um artefato que não contém localização de fonte deve declarar essa ausência, sem fabricar file:line.

Os schemas devem definir versão, limites, ordenação, encoding, campos opcionais e interpretação de enums desconhecidos. Inteiros u64 expostos a consumidores JavaScript precisam de representação sem perda, como string decimal validada; bytes arbitrários precisam de representação binária explícita.

Para documentos JSON que participem de hashes, definir uma serialização canônica. RFC 8785 é uma referência possível para documentos novos, com atenção aos limites numéricos e à preservação de strings; adotá-la não autoriza alterar silenciosamente os formatos canônicos existentes do Axial. [S16]

O dossiê completo pode ser grande. A experiência de agente deve oferecer uma visão resumida e consultas seletivas por célula, operação ou decisão, preservando a possibilidade de inspecionar o detalhe.

### D12 — Explain orienta a correção sem ampliar privilégios

Expandir os diagnósticos existentes para informar fase, código estável, causa, requisito relevante e ação corretiva possível. O schema axi.diags.v1 e seus campos fix/edit já são uma base. [S2]

Uma cadeia de explicação deve relacionar célula, chamada ou efeito, regra, recurso e decisão. Campos retornados dependem da autoridade do observador.

O hint pode sugerir reduzir o pedido, corrigir uma entrada ou solicitar revisão humana. Não deve levar o agente a elevar automaticamente grants, desativar políticas ou aumentar fuel sem limite. Nomes, mensagens e metadata vindos do módulo são dados, inclusive quando contêm texto semelhante a instruções.

### D13 — Testemunho, recibo e span têm funções diferentes

Preservar axi_trace como testemunho determinístico da VM. Manter AER/ledger/journal como evidência do protocolo correspondente. Acrescentar spans operacionais apenas como correlação e diagnóstico.

Dados como trace_id, span_id e timestamps não devem mudar o resultado semântico nem a raiz determinística de forma acidental. A correlação deve usar IDs de invocação/tentativa e raízes já existentes.

O perfil de auditoria define a política para perda de evidência, buffer cheio ou falha no destino. Tracing detalhado pode ser opcional; a evidência obrigatória de uma ação não deve desaparecer por uma flag de debug.

Substituir “zero overhead” por propriedades demonstráveis: ausência de alocações quando desativado, instrumentação removível no build quando aplicável e overhead medido no workload definido.

### D14 — Portabilidade preserva a semântica e separa os mecanismos

O núcleo e a API pública permanecem independentes do backend. O host possui um provider POSIX deliberado; o Beyond exige o provider e a porta soberanos previstos nas ADR-043/044. [S14–S15]

O perfil target deve usar a toolchain soberana e os componentes aprovados do Beyond, incluindo Bear/Basm e blibc conforme o contrato de build. Ferramentas host de geração e verificação podem auxiliar o desenvolvimento sem se tornar dependências do runtime target. A identidade do binário composto deve demonstrar quais componentes foram usados.

O vocabulário público continua centrado nos contratos do Axial e do Beyond. Conceitos internos de um backend não serão proibidos por uma busca de palavras, nem expostos como autoridade global ao chamador.

Célula Axial, como unidade de programa/contrato, e identidade de célula/superfície do Beyond precisam de campos e namespaces distintos. A associação entre elas deve ser explícita no adaptador.

### D15 — ABI, inspeção e evolução de política têm compatibilidades distintas

Separar compatibilidade binária, formato do artefato, schema de inspeção, contrato de célula e semântica da política.

O código oferece axi_iface_diff para comparação direcional de contratos. Essa comparação não prova equivalência entre todas as decisões de duas políticas. Uma revisão de política também precisa de um conjunto limitado de decisões representativas e de uma descrição de aumento ou redução de autoridade. [S2]

Há uma inconsistência documental a corrigir: o header público começa com “Phase A candidate”, enquanto README e relatório descrevem pins/ABI preservados. Isso exige reconciliação do status e dos consumidores, sem concluir por si que ocorreu quebra binária. [S1, S17]

A extensão de inspeção não deve quebrar a ABI v1 apenas por conveniência. Usar os mecanismos de versionamento e extensão adequados.

### D16 — Bythom é uma integração condicionada à identificação do consumidor

A revisão não confirmou o repositório, commit e contrato efetivo de Bythom. A descrição “orquestrador de alto nível” permanece uma hipótese do anexo.

Antes de propor interop, identificar proprietário do contrato, tipos, fluxo real, requisitos de autoridade e valor para um consumidor. A integração deve usar a mesma disciplina de capacidades, orçamento e resultado.

Bythom não bloqueia a qualificação do núcleo ou do perfil Jash quando não pertence ao escopo desse perfil. O programa não funde runtimes nem cria uma interface sem consumidor demonstrado.

## 5. Fluxo operacional pretendido

~~~mermaid
flowchart TD
    P["Pedido e contexto autorizado"] --> R["Resolver ação e precondições"]
    R --> D["Descriptor imutável"]
    D --> V["Admissão e avaliação"]
    V -->|Recusa| N["Resultado sem efeito protegido"]
    V -->|Permissão vinculada| G["Grant para a tentativa"]
    G --> F["Porta final revalida e consome"]
    F --> E["Efeito e estado terminal"]
    N --> A["Recibo e explicação"]
    E --> A
    A --> Q["Consulta e reconciliação"]
~~~

O diagrama representa o contrato proposto sobre as peças existentes. A ativação deve demonstrar o consumidor e a porta reais. O modo de planejamento termina antes da concessão e do consumo de autoridade.

## 6. Plano A00–A19 revisado

As waves representam entregas delimitadas, não uma estimativa de que todo o runtime nativo e todos os consumidores cabem em vinte tarefas. A00 fixa os perfis obrigatórios. Se o alvo incluir um backend ainda ausente, o plano precisa incluir sua implementação e decomposição, preservando os critérios da integração.

Cada wave deve produzir uma mudança útil, sua verificação proporcional e um registro curto de resultado. Testes existentes são reutilizados. Repetição adicional exige uma falha concreta, risco identificado ou gate obrigatório.

### Fase 1 — Rebase e descoberta aproveitável

| Wave | Entrega | Base a reutilizar | Critério de aceite |
| --- | --- | --- | --- |
| A00 | Baseline por commit, consumidor e perfil; matriz EXISTE / ESTENDER / INTEGRAR / INVESTIGAR | Pins, UPSTREAM, boundary e claims | Todo item do anexo tem destino, evidência e escopo; branches e checkouts corretos identificados |
| A01 | Contratos reconciliados e fronteira de confiança explícita | ADRs vigentes, em especial 042–044 | Registro de decisões sem contradizer core/host/target; Jash map antigo classificado como histórico |
| A02 | Compatibilidade e status públicos | Header embed v1, perfil ABI e schemas | Status documental consistente, matriz produtor/consumidor e alterações incompatíveis detectadas |
| A03 | Catálogo estruturado de builtins, effects e backends | Registries existentes | IDs registrados correspondem ao catálogo; tipos, autoridade e limites são consultáveis |
| A04 | Inspeção unificada com visão resumida | iface, caps e axi-dossier | Agente identifica contrato e maturidade sem executar o módulo; ausência de origem/execução continua explícita |

**Marco 1:** o agente descobre o Axial real e distingue capacidade declarada, implementação disponível e integração qualificada.

### Fase 2 — Contratos de decisão e preparação do consumidor

| Wave | Entrega | Base a reutilizar | Critério de aceite |
| --- | --- | --- | --- |
| A05 | Explain de requisitos e recusas | Inferência, diagnostics e admission | Razão estável, cadeia causal relevante e divulgação limitada à autoridade do observador |
| A06 | Revisão de mudança de contrato/política | iface-diff, pins e fixtures de decisão | Mudanças incompatíveis e aumentos de autoridade são apresentados; equivalência total não é inferida do diff |
| A07 | Identidade da invocação e domínio de determinismo | AXR4, hashes e formatos atuais | Resultado determinístico reproduzível sob entradas completas; variações operacionais classificadas |
| A08 | Orçamento de ponta a ponta | Fuel, mem_account, compile_budget e resource_envelope | Limites aplicáveis chegam ao adaptador; consumo, recusa e cleanup observáveis |
| A09 | Registry fechado de ações do consumidor e descriptor | ADR-042, axi_jm1_v1 e checkout Jash fixado | Todos os pontos consequentes do escopo classificados; decisão e futura porta usam o mesmo descriptor |

**Checkpoint 1:** dez waves concluídas, com estado persistido, perfil e pendências explícitos. Não mudar a fronteira para WIRED apenas porque a preparação do consumidor está pronta.

### Fase 3 — Uma operação real e utilizável

| Wave | Entrega | Base a reutilizar | Critério de aceite |
| --- | --- | --- | --- |
| A10 | Primeira ação mediada demonstrada em consumidor isolado | AG1, gateway/porta final, AER e ADR-042 | Efeito permitido produz recibo; recusa preserva estado protegido; identidade da ação é mantida; demonstração não ativa o consumidor Beyond |
| A11 | Resultados parciais, incerteza e reconciliação | Máquinas de estado, attempts e perfil local W80 | Agente distingue efeito ausente, concluído, parcial e desconhecido; consulta não repete efeito |
| A12 | Confiança, selagem e migração no caminho adotado | AXB v7, AXBS, CHECKED e identidade do checker | Artefato e perfil incompatíveis são recusados; resealing segue migração; nenhuma concessão vem apenas da assinatura |
| A13 | Ciclo de vida e reutilização segura de contextos | Contextos imutáveis e evidência W70–W75 | Avaliações equivalentes preservadas; recursos liberados; grants/decisões transitórias não se tornam permissões em cache |
| A14 | Planejamento limitado e explícito | Contratos dos effects e observações autorizadas | complete/partial/unsupported definidos; zero publicação real; precondições revalidadas antes de executar |

**Marco 2:** uma ação útil, por exemplo atualização de configuração no escopo autorizado, percorre decisão, efeito e recibo em ambiente isolado. Operações pertencentes à fronteira protegida que não têm implementação suportada são recusadas. Exclusões só existem quando o contrato vigente as admite explicitamente.

No perfil Jash da ADR-042, a classificação deve cobrir todas as mutações consequentes do conjunto de fontes identificado; plugins nativos dinâmicos não registrados são recusados. OPAQUE/PARTIAL aplica-se aos efeitos de processos externos conforme o limite declarado, sem servir de exceção para mutações internas não mediadas. Uma demonstração de atualização de configuração não qualifica o perfil Jash inteiro.

A10 não antecipa a promoção do consumidor Beyond. Ela depende de confiança, ciclo de vida, plataforma, cobertura e gates obrigatórios do perfil, incluindo os itens de A12/A13/A16–A19 pertinentes. Essas verificações podem ser antecipadas; a ordem das waves nunca dispensa uma dependência de ativação.

### Fase 4 — Correlação, qualificação e release

| Wave | Entrega | Base a reutilizar | Critério de aceite |
| --- | --- | --- | --- |
| A15 | Grafo e correlação causal | Chamadas do dossier, axi_trace, AER e ledger/journal | Arestas declaradas, resolvidas e observadas distinguíveis; recursos desconhecidos não fabricados |
| A16 | Qualificação do receptor e do perfil de plataforma escolhido | Recebimento upstream e ADR-043/044 | Host e target têm identidades e resultados separados; claim Beyond depende do artefato efetivamente composto e do consumidor |
| A17 | Conformidade limitada e regressão defensiva | Suites e corpora existentes | Propriedades relevantes exercitadas; casos, duração e limites documentados; falhas do ambiente não viram PASS |
| A18 | Budget de performance por workload e ambiente | Benchmarks W74/W75 e protocolo existente | Frio/quente, tamanhos e p50/p95/p99 comparáveis; regressão avaliada com ruído conhecido |
| A19 | Relatório de qualificação e pacote de evidências | CLAIMS.tsv, boundary, pins e gates existentes | Cada claim tem perfil, revisão, consumidor e evidência; obrigatório pendente bloqueia aquele perfil; limitações permanecem visíveis |

**Checkpoint 2:** vinte waves registradas, com entrega qualificada apenas para os perfis que cumpriram seus contratos. O trabalho Bythom é uma extensão opcional identificada separadamente.

## 7. Aceite por comportamento

### 7.1 Descoberta

Para uma célula e artefato selecionados, a ferramenta apresenta contrato, capacidades, efeitos, orçamento, identidade, confiança e integração disponível. A consulta offline não executa o artefato. Informações não disponíveis aparecem como ausentes ou não observadas.

### 7.2 Recusa

Uma operação protegida sem autoridade suficiente retorna código e motivo estruturados. O estado protegido permanece inalterado até a primeira tentativa autorizada, ressalvado o canal de evidência negativa reservado pelo protocolo.

### 7.3 Execução permitida

Uma operação autorizada usa o descriptor resolvido, a política/época aplicável e o grant da tentativa. O consumidor registra o resultado e permite sua correlação com a avaliação.

### 7.4 Mudança de precondições

Quando um fato relevante muda entre preparação e consumo, o contrato determina reavaliação ou recusa. A evidência identifica a condição que invalidou a tentativa, dentro da visão permitida ao observador.

### 7.5 Falha e resultado desconhecido

Falhas preservam o estado do protocolo e a informação necessária à reconciliação. O agente não transforma timeout, falha de recibo ou erro de persistência em repetição automática de um efeito potencialmente já realizado.

### 7.6 Planejamento

O consumidor recebe limites de completude e custo. Uma execução futura precisa de autorização própria e de precondições ainda válidas.

### 7.7 Replay

Reprodução da decisão consome observações registradas, sem publicar os efeitos reais novamente. O relatório distingue recorder confiável, integridade do registro e verdade externa efetivamente atestada pelo perfil.

## 8. Medição e critérios honestos

| Tema | Medir | Evitar como conclusão |
| --- | --- | --- |
| Descoberta | Cobertura do registry do perfil e campos obrigatórios | “Qualquer LLM entende tudo” |
| Mediação | Cobertura de ações e pontos de mutação do conjunto fechado | “100% seguro” por contagem de arquivos |
| Determinismo | Igualdade dos campos normativos com envelope fixado | Igualdade irrestrita de efeitos, timestamps e sistema externo |
| Robustez | Casos, duração, entradas, versões e resultados | Ausência universal de bugs porque um corpus passou |
| Selagem | Propriedades verificadas do formato e âncoras de confiança | “Zero falsos positivos/negativos” sem domínio definido |
| Performance | Distribuições por workload, alvo e modo de build | Limite único em microssegundos para toda operação |
| Backend | Comportamento e artefato do perfil exercitado | Host verde como evidência de runtime soberano |
| Auditoria | Continuidade e política de falha do canal exigido | Span opcional como recibo de autoridade |

O relatório W80 já mostra que avaliação quente e criação de contexto têm custos muito diferentes e que ruído/posição de código influenciaram comparações. Os limites 500 µs / 2 ms / 5 ms do anexo devem ser substituídos por baselines adequados ao workload, não adotados como SLA. [S1, S18]

TCG pode fornecer evidência funcional do guest quando o perfil for executado nele. Seus tempos não devem ser comparados diretamente a metas de execução nativa.

## 9. Riscos e consequências

| Risco | Consequência | Tratamento |
| --- | --- | --- |
| Repetir infraestrutura já presente | Mais caminhos para manter e mais divergência | Delta obrigatório em A00 e owner claro por mecanismo |
| Congelar contratos antigos | Integração seguindo mapa obsoleto | ADRs vigentes e registry executável como referência operacional |
| Confundir célula de linguagem com principal do Beyond | Autoridade associada à entidade errada | IDs e mapeamento explícitos no adaptador |
| Explicação revelar dados protegidos | Paths, políticas ou payloads expostos | Visões autorizadas, limites e redaction |
| Reutilizar contexto como se fosse autorização eterna | Decisão antiga usada em outro estado | Cache de estruturas imutáveis separado de grants e decisão viva |
| Quebrar artefatos existentes | Recusas ou interpretação divergente | Versionamento, matriz de compatibilidade e migração explícita |
| Misturar host e target | Claim nativo sem consumidor real | Qualificação por perfil e evidência da composição |
| Nova inspeção divergir do loader | Agente lê um contrato diferente do executado | Conformidade entre projeções e verificadores independentes |
| Política de auditoria indisponível | Efeito sem evidência obrigatória | Política de backpressure/recusa/estado desconhecido definida por perfil |
| Gate genérico reter toda entrega | Ciclos de teste sem mudança útil | Gates proporcionais ao contrato; bloqueios exatos e perfis separados |

A separação de perfis não relaxa um gate obrigatório. Ela impede que uma evidência de host seja usada indevidamente para aprovar o target, ou que uma integração opcional seja tratada como requisito do núcleo.

## 10. Alternativas consideradas

### Executar o anexo literalmente

Rejeitada como plano de implementação: usa o mapa antigo como contrato, mistura builtins e effects, cria arquivos que já existem e promete propriedades sem domínio verificável.

### Reescrever a VM e os protocolos de autoridade

Fora do escopo. A revisão encontrou componentes úteis, contratos e evidência acumulada suficientes para priorizar ligação, cobertura e ergonomia.

### Adicionar um serviço externo obrigatório

Fora do escopo. A inspeção e a integração devem funcionar localmente. Um consumidor externo futuro pode usar as interfaces públicas sem impor uma dependência ao núcleo ou ao build soberano.

### Expor toda a AST como primeiro produto para agentes

Adiada em favor de contratos compactos, dossier e explicações. AST/IR completo continua possível quando houver consumidor e origem disponíveis, mas não é pré-requisito para obter valor da introspecção existente.

### Qualificar o produto com um único selo genérico

Substituída por um relatório de perfil e claims vinculados à revisão. Um nome de release pode existir, mas deve apontar para as garantias específicas e seus limites.

## 11. Destino das waves do anexo

| Wave original | Destino |
| --- | --- |
| A00 baseline-freeze | Preservar e ampliar para pins, consumidor, maturidade e delta |
| A01 opcode-audit | Verificar tabela vigente e semântica; integrar A07/A08 |
| A02 abi-contract-lock | Reconciliar ABI público e compatibilidade; revisão A02 |
| A03 ir-schema-v1 | Priorizar schemas de contratos existentes; AST/IR como extensão |
| A04 dump-ir-json | Reutilizar iface/dossier; separar fonte, artefato e debug |
| A05 builtin-introspect | Estender registry e distinguir effect/backend |
| A06 cap-lattice-explain | Preservar, acrescentando autoridade efetiva e privacidade |
| A07 cell-graph-export | Derivar de chamadas existentes; separar declarado de observado |
| A08 fuel-model-strict | Reutilizar AXB_OPCODES e orçamento multidimensional |
| A09 effects-enforcement | Rebase em OP_EFF, consumidor e porta final |
| A10 nondet-ban | Delimitar domínios e preservar entropia de autenticação |
| A11 sealing-hard | Preservar formato e reforçar confiança/migração no consumidor |
| A12 error-decoder | Estender axi.diags.v1 e resultados de execução |
| A13 jash-bridge-audit | Aplicar ADR-042 e inventário fechado; conferir checkout real |
| A14 bythom-interop | Investigar consumidor; integração opcional separada |
| A15 span-trace | Correlacionar mecanismos existentes; spans opcionais distintos do witness |
| A16 dry-run-mode | Planejamento com completude e precondições explícitas |
| A17 fuzz-conformance | Reutilizar corpus; campanha delimitada e propriedades relevantes |
| A18 perf-budget | Baseline por operação, perfil e ambiente |
| A19 hardened-gate | Relatório de conformidade por perfil sobre claims e gates existentes |

## 12. Oportunidades concretas de uso

### 12.1 Inspeção no Beyond

Uma superfície pode mostrar uma célula, seu contrato, origem, permissões requeridas, política que decidiu e recibos disponíveis. A UI deve distinguir o que foi declarado, resolvido e observado, incluindo integração ausente ou ainda não qualificada.

### 12.2 Agentes com execução limitada

O agente consulta um contrato compacto, produz uma solicitação compatível e recebe uma decisão reparável. Depois da ação, usa o resultado/recibo para decidir o próximo passo sem adivinhar se um erro deixou efeitos.

### 12.3 Revisão de políticas

A ferramenta apresenta diferenças de interface e de autoridade, executa cenários representativos sobre dados fornecidos e permite entender o impacto antes da ativação. Rollout e recuperação seguem seus protocolos próprios; voltar um binário não deve restaurar automaticamente autoridade revogada.

### 12.4 SDK embutido

A API pública pode servir de base a consumidores locais que precisem de decisão e contratos inspecionáveis. A proposta de valor é uma operação limitada e verificável, com perfil e backend documentados. A existência do header, sozinha, não qualifica todos os consumidores.

Esses usos são recomendações arquiteturais. Sua validação comercial e adoção externa exigem trabalho específico e não são inferidas dos testes do repositório.

## 13. Condições para revisão desta ADR

Revisar a decisão se mudar o baseline principal, o formato de artefato, a ABI pública, a semântica de fuel/autoridade, o conjunto de consumidores, o modelo de confiança ou o backend soberano.

A implantação de um perfil exige que sua documentação, comportamento e evidência correspondam à mesma revisão. O programa termina com um resultado que um usuário ou agente consegue utilizar e verificar.

## Referências

As referências GitHub abaixo estão fixadas por commit. Fontes de código demonstram estruturas e contratos presentes; relatórios demonstram o que seus autores registraram naquele ambiente.

- [S1 — Relatório Axial W41–W80](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/docs/audit80/REPORT.md)
- [S2 — CLI e diagnósticos estruturados](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_main.c) e [interface projection](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_iface.h)
- [S3 — Contrato de builtins](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_builtin.h) e [registry](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_builtin_registry.h)
- [S4 — VM e cobrança de fuel](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_vm.c) e [tabela de opcodes](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_bc.h)
- [S5 — Dossiê offline](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_dossier.c) e [CLI do dossiê](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_dossier_main.c)
- [S6 — Orçamento de recursos](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_resource_envelope.h)
- [S7 — Assinatura e âncora de confiança](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_sign.h) e [contrato AXB v7/CHECKED](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_contract.h)
- [S8 — Envelope AXR4](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_replay_v4.h)
- [S9 — Fronteira Axial/Beyond](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/Docs/AXIAL-BOUNDARY.tsv)
- [S10 — Recebimento W80 no Beyond](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/Docs/AXIAL-UPDATE-20261022.md) e [pin upstream](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/toolchain/axial/UPSTREAM.json)
- [S11 — Claims no snapshot Beyond](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/toolchain/axial/docs/CLAIMS.tsv)
- [S12 — Mapa Jash proposto](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/toolchain/axial/docs/jash-axial-map.md)
- [S13 — ADR-042: mediação de mutações Jash](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/toolchain/axial/docs/ADR-042-closed-jash-mutation-mediation.md)
- [S14 — ADR-043: plataforma Beyond](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/toolchain/axial/docs/ADR-043-beyond-native-platform.md)
- [S15 — ADR-044: Single Door](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/toolchain/axial/docs/ADR-044-single-door-gaiola-cartorio.md)
- [S16 — RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [S17 — Header público embed v1](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/include/axial/axi_embed_v1.h) e [perfil ABI](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/abi/axi_embed_v1-amd64-sysv-lp64.tsv)
- [S18 — Runtime e medições W69–W76](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/docs/audit80/runtime.md)
- [S19 — Testemunho determinístico](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_trace.h)
- [S20 — Pin Jash no receptor](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/tools/ci/payloads.lock.json)
