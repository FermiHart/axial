# A01 — Contratos e fronteiras de responsabilidade

**Estado:** DONE — decisões documentais da campanha registradas e verificadas por leitura  
**Campanha:** A00–A19, contratos observáveis e mediação verificável  
**Data:** 29 de outubro de 2026  
**Perfil inicial:** local-config-publication, demonstração host isolada  
**Escopo desta wave:** leitura de fontes e reconciliação de contratos; sem execução de runtime, publicação de efeitos ou alteração de fronteira

## 1. Base e alcance

As fontes do núcleo examinadas correspondem a FermiHart/axial@26eec8630e8cf1dc3a1808f1580cc12d36410a8e. O inventário concluído em A00, commit 71b2198062a14b81e255ae39cf9522631a3b7db2, identifica a mesma árvore 069e92e1247544d7d7fae6138dd8e894f7a0265e. A campanha foi publicada separadamente; este documento não atribui qualificação de runtime aos commits documentais.

Os contratos do receptor foram lidos em FermiHart/Beyond_BDM@050ba81e15dcd5304d2f833f4897964813f67e2f, branch codex/gui20-phase1. Nesse snapshot, a fronteira continua UNWIRED / NONE / NONE. As conclusões sobre integração estão limitadas a essa revisão. [B1–B5]

Empregam-se três classes de afirmação:

- **Fato de fonte:** campo, função ou contrato presente no snapshot lido.
- **Interpretação estática:** consequência dos ramos e interfaces examinados, sem validação dinâmica nesta preparação.
- **Decisão da campanha:** regra adotada para orientar a implementação dependente, preservando os contratos vigentes.

## 2. Decisões que orientam as próximas waves

| ID | Decisão da campanha | Motivo e consequência |
| --- | --- | --- |
| A01-D01 | O primeiro consumidor demonstrativo usa local-config-publication em fixture host isolada | Reutiliza o perfil local W80, com recurso e efeito estreitos; não qualifica Jash nem Beyond |
| A01-D02 | Admissão, decisão de policy, concessão e consumo são responsabilidades separadas | Uma função chamada authorize ou prepare não será apresentada como autorização completa quando apenas avalia precondições |
| A01-D03 | O caminho local observado usa axi_local_authority_v1 para observação e consumo | Fatos decisivos vêm do host, não de campos que o solicitante apenas afirma |
| A01-D04 | O adaptador de campanha liga decisão de policy a emissão AG1 e resultado a evidência | Esses vínculos ainda precisam ser implementados ou identificados e qualificados; não são presumidos dos nomes das APIs |
| A01-D05 | AER2 do perfil local e AER1 do contrato Jash mantêm seus escopos | Não substituir um formato por outro nem ampliar cobertura por conversão informal |
| A01-D06 | Grants vazios negam operações protegidas; computação realmente sem capacidade pode continuar | Preserva a separação existente entre avaliação pura e autoridade externa |
| A01-D07 | OP_BUILTIN continua sem acesso direto ao host; OP_EFF mantém a porta de efeitos da VM | Pureza em relação ao host não elimina necessariamente a classificação de capability de um builtin |
| A01-D08 | Registros de código, integração e qualificação permanecem separados | Arquivos e cores existentes não alteram automaticamente claims do receptor |
| A01-D09 | A origem geradora ausente da cap table será recuperada ou formalmente reconciliada antes de expandir a tabela | Os arquivos C/H atuais são evidência do snapshot, mas seus comentários apontam para fontes não presentes no standalone |
| A01-D10 | O receptor Beyond conserva UNWIRED até a ativação prevista nos contratos | Demonstração host, catálogo ou documentação não cumprem a promoção da fronteira |

## 3. Matriz de responsabilidades

### 3.1 Do artefato à execução

| Etapa | Responsável atual ou proposto | Entrada relevante | Saída e alcance | Não concede por si |
| --- | --- | --- | --- | --- |
| Identidade do artefato | Contrato AXB v7 e hash | Bytes do módulo | Raiz e fatos derivados | Confiança no produtor |
| Autenticidade/admissão | Decoder trusted, perfil de admission e chave escolhida externamente | Artefato, âncora de confiança, perfil | Modelo admitido ou recusa | Permissão para modificar recurso |
| Contrato de célula | Manifesto, checker e VM | Tipos, caps, efeitos, budget | Exigências declaradas e verificações | Grants do operador |
| Avaliação da política | Runtime/embed apropriado, invocado pelo adaptador do perfil | Modelo admitido e contexto de fatos | Valor ou verdict, fuel e diagnóstico | AG1 válido ou efeito |
| Identidade da ação local | axi_local_action_v1 | Ação canônica e payload identificado | Roots de ação, principal, política, recurso e budget | Verdade dos fatos fornecidos |
| Observação/preparação local | axi_local_authority_v1_observe/prepare | Contexto host ativado, ação, payload | Fatos observados e requisição preparada | Execução da policy ou emissão de grant |
| Concessão | Emissor confiável provisionado, integrado pelo adaptador | Decisão de policy e roots/contexto exatos | AG1 assinado para a tentativa | Sucesso futuro do efeito |
| Consumo e publicação local | axi_local_authority_v1_commit e protocolo de tentativa | Requisição preparada e AG1 | Consumo, reobservação e resultado da tentativa | Mediação de outros caminhos host/guest |
| Evidência da ação local | Adaptador + função de evidence/AER2 aplicável | Resultado observado, roots e chave do emissor do recibo | Recibo dentro do perfil | Verdade fora da observação do emissor |
| Consulta/reconciliação | axi_local_authority_v1_status | Contexto e root conhecido de grant | Registro histórico da tentativa | Novo efeito ou verdade atual de config |
| Replay | AXR4 e adaptador de execução correspondente | Artefato e episódio vinculados | Validação/reprodução da decisão com observações registradas | Nova autorização ou repetição real da publicação |

Os headers de action, consumer e authority sustentam essas separações. action_encode/decode/roots apenas manipulam representação e identidade. consumer_authorize realiza appraisal comum e não emite grant. authority_prepare observa e prepara, mas não executa política; authority_commit não emite recibo. [C1–C3]

A existência de funções para cada etapa não demonstra um consumidor que ligue todas elas corretamente. Essa ligação é trabalho de A09–A12, inicialmente em demonstração isolada.

### 3.2 Três mecanismos de autoridade que não são intercambiáveis

| Mecanismo | Fato de fonte | Regra para o consumidor |
| --- | --- | --- |
| axi_grants | Lista de nomes concedidos à invocação, conferida por OP_EFF e por builtins classificados | Não tratar a lista como autenticação independente de usuário, recurso ou tentativa |
| Valor CAP da VM | Valor vinculado a modelo, geração e segredo de invocação | Preservar ownership e validade da invocação; não exportar structs privadas como protocolo público |
| AG1 da ação local | Grant assinado consumido para roots/contexto de uma tentativa | Emissor e porta final devem concordar sobre a ação exata; um booleano ALLOW não substitui esse grant |

O contrato público embed v1 possui seu próprio modelo de requisição e resultado; as APIs de autoridade local são privadas e dizem expressamente que não constituem nova ABI instalada. A campanha não mistura objetos privados de revisões distintas. [C1–C3, C6–C7]

## 4. Perfil inicial local-config-publication

### 4.1 Escopo selecionado

O perfil usa o mecanismo host-local opt-in W80: substituição da entrada relativa config dentro de um diretório privado mantido aberto pelo contexto. A identidade do recurso refere-se ao diretório retido; previous descreve a entrada config. Isso está explícito no header authority. [C3]

O primeiro cenário da campanha será uma fixture desse perfil, com dados e identidades de teste adequados ao ambiente permitido. O trabalho não ativa stores de produção, não autentica clientes remotos e não adiciona hooks ao Jash ou ao kernel.

| Aspecto | Contrato observado | Implicação de integração |
| --- | --- | --- |
| Provisionamento | Administrador habilita emissor e epoch; perfil é opt-in | A preparação do cenário precisa fornecer essas condições deliberadamente |
| Identidade | UID/eUID atuais não zero e distintos, boot e relógios do provider Linux | Identifica o processo observado; não representa identidade HTTP, remota ou de guest |
| Recurso | Diretório retido e identidade de lock | O descriptor preparado mantém a associação ao recurso observado |
| Payload | Preparação conserva cópia própria dos bytes relevantes | O emissor vincula o grant a esses bytes, não a conteúdo mutável depois |
| Consumo | Reobservação de recurso, conteúdo anterior, epoch e janelas sob lock | Preparação não garante que a execução posterior ainda seja admissível |
| Resultado | Estados do protocolo existente, incluindo incerteza | Falhas não são todas convertidas em policy DENY |
| Consulta | Leitura histórica sem repetir efeito | Registro terminal não prova, sozinho, o conteúdo atual de config |
| Base de confiança | Administrador/serviço, kernel, proc mount e escritores com o mesmo UID | A demonstração precisa declarar essa base de confiança |

Essas são condições do perfil existente, não validações realizadas nesta wave. O relatório W80 descreve seus ensaios e limites históricos. [C3, C8]

### 4.2 Escolha de caminho

O consumer genérico oferece commit que recebe pins, observações e tempo do chamador. O perfil observado W80 oferece a porta authority, que obtém fatos do host e reobserva antes do consumo. Essas APIs possuem responsabilidades diferentes; a campanha deve usar a segunda para sustentar a afirmação de autoridade observada. [C1, C3]

O fluxo a conectar é:

1. Abrir contexto local previamente ativado e observar os fatos relevantes.
2. Construir e preparar a ação canônica com seu payload.
3. Avaliar a política sobre o contexto vinculado, identificando o modelo e resultado.
4. Fazer o emissor confiável conceder AG1 apenas para a ação/contexto aprovados.
5. Consumir pela porta authority_commit, preservando o resultado real.
6. Produzir evidência com o mecanismo apropriado a esse resultado, sem inventar sucesso ou cobertura.
7. Usar status para reconciliação quando a tentativa não permite conclusão imediata.

Prepare não executa o passo 3 ou 4. Commit não executa o passo 6. Esses vínculos são requisitos explícitos do adaptador demonstrativo.

A função consumer_evidence é uma candidata a formar AER2 a partir do outcome observado, pois seu contrato oferece evidência de terminal de um owner. Seu uso, mapeamento de estados e cobertura devem ser verificados em A10–A12. A assinatura de um recibo não justifica promover cobertura para outras portas. [C1]

## 5. Grants vazios, pureza e capacidades

### 5.1 Fatos examinados

- OP_EFF verifica a declaração e recusa quando grants é NULL ou o nome requerido não está presente. Exige ainda implementação e contexto de ledger antes do host call. [C4]
- OP_BUILTIN exige grant quando bi->cap difere de CAP_NONE. Portanto, ausência de acesso ao host não implica ausência de capability. [C4–C5]
- fs.path_under é lexical e não acessa o host, mas o registry o associa a CAP_FS_READ/fs.Read. Os builtins JSON, budget e math enumerados no snapshot usam CAP_NONE. [C5]
- As portas internas preverified_pure da VM passam grants e sink NULL ao executor comum. O header descreve o caminho puro. [C4, C6]
- O comentário “empty policy refuses everything” aparece junto ao estado do effect plane; interpretá-lo como proibição de qualquer cálculo contradiria os caminhos puros identificados. [C4]

### 5.2 Interpretação estática e decisão

A leitura suporta a distinção entre computação sem exigência de capacidade e operação protegida. Não houve execução nesta preparação para comprovar um programa concreto.

**Decisão da campanha:** grants vazios não adicionam autoridade; qualquer operação protegida mantém sua recusa. Uma célula admissível, limitada e cuja execução não exige capability pode calcular e retornar um valor. Não retirar o requisito fs.Read de fs.path_under apenas porque ele é lexical: alterar essa classificação seria uma mudança semântica independente.

A02/A03 devem usar nomes distintos para acesso externo e capability_gated. O último campo de AXI_BUILTIN_REGISTRY representa classificação do checker; não é preço de fuel. A00 registra essa distinção.

Para encerrar a ambiguidade operacional quando o runtime for exercitado, usar os testes pertinentes do perfil puro e uma recusa por capability necessária ausente. O resultado deverá ser vinculado à revisão executada, sem alterar a semântica apenas para fazer o cenário passar.

## 6. Hierarquia dos contratos e da evidência

| Fonte | Como usá-la na campanha |
| --- | --- |
| Formato público, header e perfil ABI | Referência de interoperabilidade; inconsistências de status são reconciliadas em A02, sem alterar layout por inferência |
| Código e registries fixados | Evidência do comportamento implementado e dos IDs daquele snapshot; presença não equivale a runtime qualificado |
| ADR vigente de um perfil | Define finalidade, condições e exclusões daquele perfil |
| Boundary e claims do receptor | Registram o estado de integração/alegações do receptor na revisão examinada |
| Relatórios de execução | Evidência histórica apenas para produto, ambiente e casos identificados |
| Mapa Jash/ADR-001 antigo | Fonte histórica de intenção; ADR-042 já declara suas lacunas e não o admite como prova de integração |
| Este documento e ADR-AXIAL-0001 r2 | Decisões da campanha; não substituem silenciosamente os contratos anteriores |

Não resolver divergências escolhendo a fonte que produz a conclusão mais conveniente. Registrar o conflito, seu escopo e a decisão necessária. Por exemplo, o header embed v1 conserva comentários de fase candidata, enquanto o relatório registra pins ABI preservados: isso é uma inconsistência documental para A02, não evidência suficiente de quebra binária. [C7–C8]

Claims sobre AG1/AER podem permanecer PLANNED no receptor apesar de existirem componentes correspondentes no núcleo. A campanha mantém as duas observações até reconciliar suas datas e escopos; não promove uma alegação de produto apenas porque encontrou funções.

### 6.1 Origem da cap table ausente no standalone

axi_cap_table.c/h declaram geração por docs/CAP-METHODS.tsv e tools/gen_cap_table.py. O inventário A00 registra ambos como ausentes em 26eec863. O snapshot contém os arquivos C/H, com tabela efetiva de capacidades e conjunto fechado de métodos; não contém a cadeia de geração nomeada nos comentários. [C9, A00]

**Decisão da campanha:** até resolver essa lacuna, inventário e documentação podem descrever a tabela efetiva fixada, mas não devem alegar regeneração a partir da fonte canônica ausente. A03 deve localizar a origem na história/receptor e validá-la, ou propor explicitamente a restauração de fonte e gerador com saída equivalente. Não editar manualmente a tabela gerada nem criar um segundo catálogo autoritativo por conveniência.

A simples ausência desses arquivos não prova que o runtime falha; demonstra uma lacuna de proveniência e manutenção no standalone que precisa ser fechada antes de ampliar esse contrato.

## 7. Perfis Jash e Beyond permanecem distintos

| Perfil | Estado que a fonte permite descrever | Condição para uma alegação posterior |
| --- | --- | --- |
| Core standalone | Componentes e contratos presentes; A00 é inventário estático | Exercitar o comportamento específico na revisão de campanha |
| local-config-publication | Perfil W80 de substituição local e observação host descrito | Conectar policy/emissor/porta/evidência e qualificar a demonstração isolada |
| Jash | ADR-042 aceita para core; integração do receptor permanece UNWIRED | Cobertura fechada, descriptor, grant na porta real, recibo e gates do consumidor |
| Backend Beyond | ADR-043 core não adiciona provider target, build Bear ou imagem | Implementação do backend, composição e equivalência semântica por campos |
| Single Door Beyond | ADR-044 core não instala enforcement kernel ou journal durável | Porta final, orçamento/evidência target e gates mistos exigidos pelo contrato |

O perfil Jash exige classificação das mutações consequentes de seu conjunto de fontes. Plugins nativos dinâmicos não registrados recusam. OPAQUE/PARTIAL de processos externos não é uma exceção para mutações internas sem mediação. A demonstração local não substitui essas exigências. [B2]

Os contratos de target preservam toolchain e mecanismos soberanos; resultados host não qualificam automaticamente guest. Tempos e errno específicos do host não são critérios portáveis de igualdade de todos os bytes. [B3–B4]

**Decisão da campanha:** manter UNWIRED / NONE / NONE no receptor examinado. A ativação futura registra a decisão de promoção ou supersessão explícita do contrato e satisfaz os gates técnicos aplicáveis. A decisão documental desta wave não realiza a ativação do consumidor.

## 8. Registro de decisão e aceite A01

A01 adota A01-D01–D10 como decisões de implementação desta campanha. A verificação consistiu em confrontar a matriz com os headers públicos e privados, ramos relevantes da VM, inventário A00 e contratos do receptor fixado. Adoção documental não promove boundary, altera ABI ou qualifica execução.

| Próxima wave responsável | Obrigação registrada |
| --- | --- |
| A02 | Reconciliar status textual da ABI com pins, sem alterar layout por inferência |
| A03 | Recuperar ou reconciliar a fonte geradora da cap table antes de ampliar o contrato; distinguir capability_gated de acesso externo |
| A09 | Vincular descriptor, política, concessão e porta do consumidor ao mesmo contexto |
| A10 | Conectar demonstração local observada, preservando separação entre prepare, policy e emissão AG1 |
| A11 | Propagar resultado real e consulta, sem repetir automaticamente efeito desconhecido |
| A12 | Qualificar confiança e correspondência do recibo; AER2 local e AER1 Jash conservam seus escopos |
| A16 | Qualificar o receptor/target somente com consumidor, artefato e gates pertinentes |

- [x] A00 encerrada e referência de inventário conferida.
- [x] Responsabilidades de admissão, decisão, grant, consumo, resultado e replay identificadas.
- [x] Perfil inicial local-config-publication delimitado como demonstração host isolada.
- [x] Semântica de grants vazios e de builtins capability-gated explicitada por leitura.
- [x] Fonte geradora ausente tratada como pendência de proveniência/manutenção, atribuída a A03.
- [x] Mapa Jash histórico separado do contrato vigente de mediação.
- [x] Boundary, claims, fontes runtime e ABI existentes preservados nesta wave documental.

Nenhum build, boot ou efeito real foi executado em A01. A ligação entre policy, emissor, authority e evidência permanece uma entrega de integração das waves atribuídas acima.

## Fontes fixadas

- [A00 — inventário da campanha](evidence/axial-inventory.json): escopo static_source_inventory; [baseline e verificação](A00-BASELINE.md).
- [C1 — Interface do consumidor local](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_local_consumer_v1.h)
- [C2 — Identidade da ação local](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_local_action_v1.h)
- [C3 — Autoridade host-local observada](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_local_authority_v1.h)
- [C4 — Portas da VM](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_vm.c)
- [C5 — Registry de builtins](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_builtin_registry.h) e [contrato de builtin](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_builtin.h)
- [C6 — Superfície da VM e invocações](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_vm.h)
- [C7 — Header público embed v1](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/include/axial/axi_embed_v1.h)
- [C8 — Relatório W80, autoridade observada e limites](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/docs/audit80/REPORT.md)
- [C9 — Cap table](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_cap_table.c) e [header gerado](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_cap_table.h)
- [C10 — Effect plane e resultado](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_effect.h)
- [C11 — Assinatura e confiança](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_sign.h)
- [C12 — Envelope de replay](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_replay_v4.h)
- [C13 — Envelope de recursos](https://github.com/FermiHart/axial/blob/26eec8630e8cf1dc3a1808f1580cc12d36410a8e/src/axi_resource_envelope.h)
- [B1 — Fronteira no receptor](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/Docs/AXIAL-BOUNDARY.tsv)
- [B2 — ADR-042, mediação Jash](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/toolchain/axial/docs/ADR-042-closed-jash-mutation-mediation.md)
- [B3 — ADR-043, plataforma Beyond](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/toolchain/axial/docs/ADR-043-beyond-native-platform.md)
- [B4 — ADR-044, Single Door](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/toolchain/axial/docs/ADR-044-single-door-gaiola-cartorio.md)
- [B5 — Claims do receptor](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/toolchain/axial/docs/CLAIMS.tsv)
- [B6 — Mapa histórico Jash](https://github.com/FermiHart/Beyond_BDM/blob/050ba81e15dcd5304d2f833f4897964813f67e2f/toolchain/axial/docs/jash-axial-map.md)
