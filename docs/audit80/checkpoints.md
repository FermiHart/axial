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
