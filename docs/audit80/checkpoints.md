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
