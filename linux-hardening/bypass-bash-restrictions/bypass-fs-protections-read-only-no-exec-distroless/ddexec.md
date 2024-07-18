# DDexec / EverythingExec

{% hint style="success" %}
Aprenda e pratique Hacking na AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking no GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Contexto

No Linux, para executar um programa, ele deve existir como um arquivo, deve ser acessível de alguma forma através da hierarquia do sistema de arquivos (é assim que `execve()` funciona). Este arquivo pode residir no disco ou na memória (tmpfs, memfd), mas você precisa de um caminho de arquivo. Isso tornou muito fácil controlar o que é executado em um sistema Linux, facilita a detecção de ameaças e ferramentas de atacantes ou impedi-los de tentar executar qualquer coisa deles (_por exemplo_, não permitindo que usuários não privilegiados coloquem arquivos executáveis em qualquer lugar).

Mas essa técnica está aqui para mudar tudo isso. Se você não pode iniciar o processo que deseja... **então você sequestra um que já existe**.

Essa técnica permite que você **bypass técnicas comuns de proteção, como somente leitura, noexec, lista branca de nomes de arquivos, lista branca de hash...**

## Dependências

O script final depende das seguintes ferramentas para funcionar, elas precisam estar acessíveis no sistema que você está atacando (por padrão, você as encontrará em todos os lugares):
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

Agora, temos quatro problemas básicos para enfrentar:

- Em geral, apenas o root e o proprietário do programa do arquivo podem modificá-lo.
- ASLR.
- Se tentarmos ler ou escrever em um endereço não mapeado no espaço de endereço do programa, receberemos um erro de E/S.

Esses problemas têm soluções que, embora não sejam perfeitas, são boas:

- A maioria dos interpretadores de shell permitem a criação de descritores de arquivo que serão herdados pelos processos filhos. Podemos criar um descritor de arquivo apontando para o arquivo `mem` do shell com permissões de escrita... então os processos filhos que usarem esse descritor de arquivo poderão modificar a memória do shell.
- ASLR nem é um problema, podemos verificar o arquivo `maps` do shell ou qualquer outro do procfs para obter informações sobre o espaço de endereço do processo.
- Então precisamos fazer `lseek()` sobre o arquivo. A partir do shell, isso não pode ser feito a menos que usando o infame `dd`.

### Em mais detalhes

Os passos são relativamente fáceis e não exigem nenhum tipo de expertise para entendê-los:

- Analisar o binário que queremos executar e o loader para descobrir quais mapeamentos eles precisam. Em seguida, criar um "código"shell que executará, em termos gerais, as mesmas etapas que o kernel faz em cada chamada para `execve()`:
- Criar os mapeamentos mencionados.
- Ler os binários neles.
- Configurar permissões.
- Finalmente, inicializar a pilha com os argumentos para o programa e colocar o vetor auxiliar (necessário pelo loader).
- Pular para o loader e deixá-lo fazer o resto (carregar bibliotecas necessárias pelo programa).
- Obter do arquivo `syscall` o endereço para o qual o processo retornará após a chamada de sistema que está executando.
- Sobrescrever esse local, que será executável, com nosso código shell (através de `mem` podemos modificar páginas não graváveis).
- Passar o programa que queremos executar para o stdin do processo (será `lido()` por esse código shell).
- Neste ponto, cabe ao loader carregar as bibliotecas necessárias para nosso programa e pular para ele.

**Confira a ferramenta em** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Existem várias alternativas para `dd`, uma das quais, `tail`, é atualmente o programa padrão usado para `lseek()` através do arquivo `mem` (que era o único propósito para usar `dd`). Tais alternativas são:
```bash
tail
hexdump
cmp
xxd
```
Ao definir a variável `SEEKER`, você pode alterar o seeker usado, _por exemplo_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se encontrar outro buscador válido não implementado no script, ainda pode usá-lo definindo a variável `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloqueie isso, EDRs.

## Referências
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
