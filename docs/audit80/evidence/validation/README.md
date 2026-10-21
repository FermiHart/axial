# Gates finais W80

O [índice JSON](index.json) associa os quatro perfis aprovados e as
tentativas anteriores aos arquivos originais. [SHA256SUMS](SHA256SUMS)
permite verificar a integridade. Logs e metadados das execuções foram
copiados byte a byte; seus caminhos absolutos identificam o ambiente em
que foram executados, sem serem pré-requisitos para reproduzir os testes.

| Perfil | Resultado | Log | Metadados |
| --- | --- | --- | --- |
| Normal C99, `-O1` | PASS, retorno 0 | [normal.log](normal.log) | [normal.json](normal.json) |
| Otimizado C99, `-O2` | PASS, retorno 0 | [release.log](release.log) | [release.json](release.json) |
| ASan/UBSan | PASS, retorno 0 | [sanitizers.log](sanitizers.log) | [sanitizers.json](sanitizers.json) |
| ThreadSanitizer | PASS, retorno 0 | [tsan.log](tsan.log) | [tsan.json](tsan.json) |

Todos registram produto inalterado antes/depois e SHA-256
`59dccaab79e2ab1e5dc4f32fc2a7f2d802f134579c4efd61fa6fc4fcff51a269`.
O cálculo ordena os caminhos relativos de todos os arquivos regulares sob
`src`, `include` e `vendor`, concatenando para cada um caminho UTF-8,
um byte NUL e os bytes do arquivo. As revisões iniciais são W78 ou W79;
o produto é idêntico. W79 altera somente evidências, documentação e o
runner opcional de reprodução; W80 registra o fechamento.

Os três gates completos incluem autoridade com UID/eUID reais e falhas
de alocação, além das suítes antigas e novas. TSan é um gate específico
de concorrência e instrumenta todas as unidades do produto em cada uma
das variantes cached, uncached e software. Não substitui o gate completo.
Os comandos reproduzíveis e os requisitos de host estão em
[gates.md](../../gates.md). LeakSanitizer não foi executado.

## Tentativas anteriores preservadas

O PASS final não substitui nem apaga falhas anteriores:

1. [sanitizers-initial-exec-permission.log](sanitizers-initial-exec-permission.log)
   registra `EACCES` ao iniciar `runtime_workloads`. Esse ELF e o de
   concorrência software tinham modo `0644`; a execução daquele teste
   não chegou a começar. [Metadados](sanitizers-initial-exec-permission.json).
2. [sanitizers-recheck-incomplete.log](sanitizers-recheck-incomplete.log)
   veio de recompilação em diretório novo, terminou com retorno 2 e deixou
   apenas um prefixo de saída. Esse registro não permite atribuir uma
   causa adicional. [Metadados](sanitizers-recheck-incomplete.json).
3. [sanitizers-recovery-exec-permission.log](sanitizers-recovery-exec-permission.log)
   registra `EACCES` ao iniciar `runtime_recovery`, novamente com modo
   `0644`. [Metadados](sanitizers-recovery-exec-permission.json).
4. [sanitizers-manifest-exec-permission.log](sanitizers-manifest-exec-permission.log)
   registra `EACCES` no executável de manifesto com injeção de OOM.
   [Metadados](sanitizers-manifest-exec-permission.json).

A origem dos bits de execução ausentes não foi determinada. Não foi
identificado no código dos fixtures um caminho que alterasse os modos
desses executáveis irmãos. A correção local restaurou `0755` somente nos
ELFs de teste produzidos no diretório de build. Os registros
[runtime](sanitizers-local-mode-repair.json) e
[manifesto](sanitizers-generated-elf-modes.json) demonstram SHA-256 dos
bytes idêntico antes/depois. Não houve mudança de fonte ou de flags para
ignorar o problema. A execução final do gate completo retornou zero.

Os metadados preservados das tentativas anteriores mantêm o nome original
`log_file: sanitizers.log`. Para cada um, use o arquivo `.log` de mesmo
prefixo ou o mapeamento do índice. Seus `raw_log_sha256` conferem com essas
cópias. Os tempos de execução incluem diferentes estados de cache de build
e não constituem um benchmark de performance.
