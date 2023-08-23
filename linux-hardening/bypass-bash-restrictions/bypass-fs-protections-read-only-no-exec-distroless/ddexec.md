# DDexec / EverythingExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Contexto

No Linux, para executar um programa, ele deve existir como um arquivo, ele deve ser acessível de alguma forma através da hierarquia do sistema de arquivos (é assim que `execve()` funciona). Esse arquivo pode residir no disco ou na memória (tmpfs, memfd), mas você precisa de um caminho de arquivo. Isso tornou muito fácil controlar o que é executado em um sistema Linux, torna fácil detectar ameaças e ferramentas de ataque ou impedi-las de tentar executar qualquer coisa delas (_por exemplo_, não permitindo que usuários não privilegiados coloquem arquivos executáveis em qualquer lugar).

Mas essa técnica está aqui para mudar tudo isso. Se você não pode iniciar o processo que deseja... **então você sequestra um que já existe**.

Essa técnica permite que você **bypass técnicas de proteção comuns, como somente leitura, noexec, lista de nomes de arquivos permitidos, lista de hash permitidos...**

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

Se você conseguir modificar arbitrariamente a memória de um processo, poderá assumi-lo. Isso pode ser usado para sequestrar um processo já existente e substituí-lo por outro programa. Podemos conseguir isso usando a chamada de sistema `ptrace()` (que requer a capacidade de executar chamadas de sistema ou ter o gdb disponível no sistema) ou, de forma mais interessante, escrevendo em `/proc/$pid/mem`.

O arquivo `/proc/$pid/mem` é um mapeamento um-para-um de todo o espaço de endereço de um processo (por exemplo, de `0x0000000000000000` a `0x7ffffffffffff000` em x86-64). Isso significa que ler ou escrever neste arquivo em um deslocamento `x` é o mesmo que ler ou modificar o conteúdo no endereço virtual `x`.

Agora, temos quatro problemas básicos para enfrentar:

* Em geral, apenas o root e o proprietário do programa podem modificá-lo.
* ASLR.
* Se tentarmos ler ou escrever em um endereço não mapeado no espaço de endereço do programa, receberemos um erro de E/S.

Esses problemas têm soluções que, embora não sejam perfeitas, são boas:

* A maioria dos interpretadores de shell permite a criação de descritores de arquivo que serão herdados pelos processos filhos. Podemos criar um descritor de arquivo apontando para o arquivo `mem` do shell com permissões de escrita... assim, os processos filhos que usarem esse descritor de arquivo poderão modificar a memória do shell.
* O ASLR nem é um problema, podemos verificar o arquivo `maps` do shell ou qualquer outro do procfs para obter informações sobre o espaço de endereço do processo.
* Portanto, precisamos usar `lseek()` no arquivo. A partir do shell, isso não pode ser feito a menos que usemos o infame `dd`.

### Com mais detalhes

Os passos são relativamente fáceis e não exigem nenhum tipo de especialização para entendê-los:

* Analise o binário que queremos executar e o carregador para descobrir quais mapeamentos eles precisam. Em seguida, crie um "shell"code que executará, em termos gerais, as mesmas etapas que o kernel faz em cada chamada para `execve()`:
* Crie os mapeamentos mencionados.
* Leia os binários neles.
* Configure as permissões.
* Finalmente, inicialize a pilha com os argumentos do programa e coloque o vetor auxiliar (necessário pelo carregador).
* Pule para o carregador e deixe-o fazer o resto (carregar bibliotecas necessárias pelo programa).
* Obtenha do arquivo `syscall` o endereço para o qual o processo retornará após a chamada de sistema que está executando.
* Sobrescreva esse local, que será executável, com nosso shellcode (por meio de `mem`, podemos modificar páginas não graváveis).
* Passe o programa que queremos executar para o stdin do processo (será `lido()` pelo referido "shell"code).
* Neste ponto, cabe ao carregador carregar as bibliotecas necessárias para nosso programa e pular para ele.

**Confira a ferramenta em** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

A partir de 12/12/2022, encontrei várias alternativas para o `dd`, uma das quais, `tail`, é atualmente o programa padrão usado para `lseek()` através do arquivo `mem` (que era o único propósito de usar o `dd`). Essas alternativas são:
```bash
tail
hexdump
cmp
xxd
```
Definindo a variável `SEEKER`, você pode alterar o buscador usado, _por exemplo_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se você encontrar outro buscador válido que não esteja implementado no script, ainda é possível usá-lo definindo a variável `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloqueie isso, EDRs.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
