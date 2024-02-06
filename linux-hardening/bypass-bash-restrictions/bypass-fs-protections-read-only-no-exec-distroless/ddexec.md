# DDexec / EverythingExec

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Contexto

No Linux, para executar um programa, ele deve existir como um arquivo, deve ser acessível de alguma forma através da hierarquia do sistema de arquivos (é assim que `execve()` funciona). Este arquivo pode residir no disco ou na memória (tmpfs, memfd), mas você precisa de um caminho de arquivo. Isso tornou muito fácil controlar o que é executado em um sistema Linux, facilita a detecção de ameaças e ferramentas de atacantes ou impedi-los de tentar executar qualquer coisa deles (_por exemplo_, não permitindo que usuários não privilegiados coloquem arquivos executáveis em qualquer lugar).

Mas essa técnica está aqui para mudar tudo isso. Se você não pode iniciar o processo que deseja... **então você sequestra um que já existe**.

Essa técnica permite que você **bypass técnicas de proteção comuns, como somente leitura, noexec, lista branca de nomes de arquivos, lista branca de hash...**

## Dependências

O script final depende das seguintes ferramentas para funcionar, elas precisam estar acessíveis no sistema que você está atacando (por padrão, você encontrará todas elas em todos os lugares):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## A técnica

Se você for capaz de modificar arbitrariamente a memória de um processo, então você pode assumi-lo. Isso pode ser usado para se apropriar de um processo já existente e substituí-lo por outro programa. Podemos alcançar isso usando a chamada de sistema `ptrace()` (que requer que você tenha a capacidade de executar chamadas de sistema ou ter o gdb disponível no sistema) ou, de forma mais interessante, escrevendo em `/proc/$pid/mem`.

O arquivo `/proc/$pid/mem` é um mapeamento um para um de todo o espaço de endereço de um processo (por exemplo, de `0x0000000000000000` a `0x7ffffffffffff000` em x86-64). Isso significa que ler ou escrever neste arquivo em um deslocamento `x` é o mesmo que ler ou modificar o conteúdo no endereço virtual `x`.

Agora, temos quatro problemas básicos a enfrentar:

- Em geral, apenas o root e o proprietário do programa do arquivo podem modificá-lo.
- ASLR.
- Se tentarmos ler ou escrever em um endereço não mapeado no espaço de endereço do programa, receberemos um erro de E/S.

Esses problemas têm soluções que, embora não sejam perfeitas, são boas:

- A maioria dos interpretadores de shell permitem a criação de descritores de arquivo que serão herdados pelos processos filhos. Podemos criar um descritor de arquivo apontando para o arquivo `mem` do shell com permissões de escrita... assim, os processos filhos que usarem esse descritor de arquivo poderão modificar a memória do shell.
- ASLR nem é um problema, podemos verificar o arquivo `maps` do shell ou qualquer outro do procfs para obter informações sobre o espaço de endereço do processo.
- Então precisamos fazer `lseek()` sobre o arquivo. A partir do shell, isso não pode ser feito a menos que usando o infame `dd`.

### Em mais detalhes

Os passos são relativamente fáceis e não exigem nenhum tipo de especialização para entendê-los:

- Analisar o binário que queremos executar e o carregador para descobrir quais mapeamentos eles precisam. Em seguida, criar um "código"shell que executará, em termos gerais, as mesmas etapas que o kernel faz a cada chamada para `execve()`:
- Criar os mapeamentos mencionados.
- Ler os binários neles.
- Configurar permissões.
- Finalmente, inicializar a pilha com os argumentos para o programa e colocar o vetor auxiliar (necessário pelo carregador).
- Pular para o carregador e deixá-lo fazer o resto (carregar bibliotecas necessárias pelo programa).
- Obter do arquivo `syscall` o endereço para o qual o processo retornará após a chamada do sistema que está executando.
- Sobrescrever esse local, que será executável, com nosso código shell (através de `mem` podemos modificar páginas não graváveis).
- Passar o programa que queremos executar para o stdin do processo (será `lido()` por esse código shell).
- Neste ponto, cabe ao carregador carregar as bibliotecas necessárias para nosso programa e pular para ele.

**Confira a ferramenta em** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

A partir de 12/12/2022, encontrei várias alternativas para `dd`, uma das quais, `tail`, é atualmente o programa padrão usado para `lseek()` através do arquivo `mem` (que era o único propósito para usar `dd`). Tais alternativas são:
```bash
tail
hexdump
cmp
xxd
```
Definindo a variável `SEEKER`, você pode alterar o seeker usado, _por exemplo_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se encontrar outro buscador válido não implementado no script, ainda pode usá-lo definindo a variável `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloqueie isso, EDRs.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
