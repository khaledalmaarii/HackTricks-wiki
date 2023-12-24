# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Trabalha numa **empresa de cibersegurança**? Quer ver a sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Informações Básicas**

**System Integrity Protection (SIP)** é uma tecnologia de segurança no macOS que protege certos diretórios do sistema contra acessos não autorizados, mesmo para o usuário root. Ela impede modificações nesses diretórios, incluindo criação, alteração ou exclusão de arquivos. Os principais diretórios que o SIP protege são:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

As regras de proteção para esses diretórios e seus subdiretórios são especificadas no arquivo **`/System/Library/Sandbox/rootless.conf`**. Neste arquivo, caminhos que começam com um asterisco (\*) representam exceções às restrições do SIP.

Por exemplo, a seguinte configuração:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
indica que o diretório **`/usr`** é geralmente protegido pelo SIP. No entanto, modificações são permitidas nos três subdiretórios especificados (`/usr/libexec/cups`, `/usr/local` e `/usr/share/man`), pois eles estão listados com um asterisco inicial (\*).

Para verificar se um diretório ou arquivo está protegido pelo SIP, você pode usar o comando **`ls -lOd`** para verificar a presença da flag **`restricted`** ou **`sunlnk`**. Por exemplo:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Neste caso, a flag **`sunlnk`** indica que o diretório `/usr/libexec/cups` **não pode ser excluído**, embora arquivos dentro dele possam ser criados, modificados ou excluídos.

Por outro lado:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Aqui, a flag **`restricted`** indica que o diretório `/usr/libexec` é protegido pelo SIP. Em um diretório protegido pelo SIP, arquivos não podem ser criados, modificados ou deletados.

Além disso, se um arquivo contém o atributo estendido **`com.apple.rootless`**, esse arquivo também será **protegido pelo SIP**.

**O SIP também limita outras ações do root** como:

* Carregar extensões de kernel não confiáveis
* Obter task-ports para processos assinados pela Apple
* Modificar variáveis NVRAM
* Permitir depuração do kernel

As opções são mantidas na variável nvram como um bitflag (`csr-active-config` em Intel e `lp-sip0` é lido da Árvore de Dispositivos inicializada para ARM). Você pode encontrar as flags no código-fonte do XNU em `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### Status do SIP

Você pode verificar se o SIP está habilitado no seu sistema com o seguinte comando:
```bash
csrutil status
```
Se precisar desativar o SIP, você deve reiniciar o computador em modo de recuperação (pressionando Command+R durante a inicialização), e então executar o seguinte comando:
```bash
csrutil disable
```
Se desejar manter o SIP ativado, mas remover as proteções de depuração, você pode fazer isso com:
```bash
csrutil enable --without debug
```
### Outras Restrições

O SIP também impõe várias outras restrições. Por exemplo, ele proíbe o **carregamento de extensões de kernel não assinadas** (kexts) e impede o **debugging** de processos do sistema macOS. Também inibe ferramentas como dtrace de inspecionar processos do sistema.

## Bypasses do SIP

Se um atacante conseguir contornar o SIP, ele poderá fazer o seguinte:

* Ler e-mails, mensagens, histórico do Safari... de todos os usuários
* Conceder permissões para webcam, microfone ou qualquer coisa (escrevendo diretamente sobre o banco de dados TCC protegido pelo SIP)
* Persistência: Ele poderia salvar um malware em um local protegido pelo SIP e nem mesmo root será capaz de deletá-lo. Além disso, ele poderia adulterar o MRT.
* Facilidade para carregar extensões de kernel (ainda existem outras proteções avançadas em vigor para isso).

### Pacotes de Instalação

**Pacotes de instalação assinados com o certificado da Apple** podem contornar suas proteções. Isso significa que até pacotes assinados por desenvolvedores padrão serão bloqueados se tentarem modificar diretórios protegidos pelo SIP.

### Arquivo SIP Inexistente

Uma possível brecha é que se um arquivo é especificado em **`rootless.conf` mas atualmente não existe**, ele pode ser criado. Malwares poderiam explorar isso para **estabelecer persistência** no sistema. Por exemplo, um programa malicioso poderia criar um arquivo .plist em `/System/Library/LaunchDaemons` se ele estiver listado em `rootless.conf` mas não estiver presente.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
O entitlement **`com.apple.rootless.install.heritable`** permite contornar o SIP
{% endhint %}

[**Pesquisadores deste post do blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) descobriram uma vulnerabilidade no mecanismo de Proteção de Integridade do Sistema (SIP) do macOS, apelidada de vulnerabilidade 'Shrootless'. Essa vulnerabilidade gira em torno do daemon **`system_installd`**, que possui um entitlement, **`com.apple.rootless.install.heritable`**, que permite que qualquer um de seus processos filhos contorne as restrições de sistema de arquivos do SIP.

O daemon **`system_installd`** instalará pacotes que foram assinados pela **Apple**.

Os pesquisadores descobriram que durante a instalação de um pacote assinado pela Apple (.pkg file), o **`system_installd`** **executa** quaisquer scripts **pós-instalação** incluídos no pacote. Esses scripts são executados pelo shell padrão, **`zsh`**, que automaticamente **executa** comandos do arquivo **`/etc/zshenv`**, se ele existir, mesmo em modo não interativo. Esse comportamento poderia ser explorado por atacantes: criando um arquivo `/etc/zshenv` malicioso e esperando que **`system_installd` invoque `zsh`**, eles poderiam realizar operações arbitrárias no dispositivo.

Além disso, foi descoberto que **`/etc/zshenv` poderia ser usado como uma técnica de ataque geral**, não apenas para um bypass do SIP. Cada perfil de usuário tem um arquivo `~/.zshenv`, que se comporta da mesma maneira que `/etc/zshenv` mas não requer permissões de root. Esse arquivo poderia ser usado como um mecanismo de persistência, acionando toda vez que `zsh` é iniciado, ou como um mecanismo de elevação de privilégio. Se um usuário administrador se elevar a root usando `sudo -s` ou `sudo <comando>`, o arquivo `~/.zshenv` seria acionado, efetivamente elevando a root.

Em [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) foi descoberto que o mesmo processo **`system_installd`** ainda poderia ser abusado porque estava colocando o script **pós-instalação dentro de uma pasta com nome aleatório protegida pelo SIP dentro de `/tmp`**. O fato é que **`/tmp` em si não é protegido pelo SIP**, então era possível **montar** uma **imagem virtual sobre ele**, então o **instalador** colocaria lá o script **pós-instalação**, **desmontaria** a imagem virtual, **recriaria** todas as **pastas** e **adicionaria** o script **pós-instalação** com o **payload** para executar.

### **com.apple.rootless.install**

{% hint style="danger" %}
O entitlement **`com.apple.rootless.install`** permite contornar o SIP
{% endhint %}

De [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) O serviço XPC do sistema `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possui o entitlement **`com.apple.rootless.install`**, que concede ao processo permissão para contornar as restrições do SIP. Ele também **expõe um método para mover arquivos sem qualquer verificação de segurança.**

## Sealed System Snapshots

Sealed System Snapshots são um recurso introduzido pela Apple no **macOS Big Sur (macOS 11)** como parte de seu mecanismo de Proteção de Integridade do Sistema (SIP) para fornecer uma camada adicional de segurança e estabilidade do sistema. Eles são essencialmente versões somente leitura do volume do sistema.

Aqui está um olhar mais detalhado:

1. **Sistema Imutável**: Sealed System Snapshots tornam o volume do sistema macOS "imutável", o que significa que ele não pode ser modificado. Isso impede quaisquer alterações não autorizadas ou acidentais no sistema que possam comprometer a segurança ou a estabilidade do sistema.
2. **Atualizações de Software do Sistema**: Quando você instala atualizações ou upgrades do macOS, o macOS cria um novo snapshot do sistema. O volume de inicialização do macOS então usa **APFS (Apple File System)** para mudar para este novo snapshot. Todo o processo de aplicação de atualizações se torna mais seguro e confiável, pois o sistema pode sempre reverter para o snapshot anterior se algo der errado durante a atualização.
3. **Separação de Dados**: Em conjunto com o conceito de separação de volumes de Dados e Sistema introduzido no macOS Catalina, o recurso Sealed System Snapshot garante que todos os seus dados e configurações sejam armazenados em um volume "**Data**" separado. Essa separação torna seus dados independentes do sistema, o que simplifica o processo de atualizações do sistema e aumenta a segurança do sistema.

Lembre-se de que esses snapshots são gerenciados automaticamente pelo macOS e não ocupam espaço adicional no seu disco, graças às capacidades de compartilhamento de espaço do APFS. Também é importante notar que esses snapshots são diferentes dos **snapshots do Time Machine**, que são backups acessíveis pelo usuário de todo o sistema.

### Verificar Snapshots

O comando **`diskutil apfs list`** lista os **detalhes dos volumes APFS** e seu layout:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Ponto de Montagem do Snapshot:      /
</strong><strong>|   |   Snapshot Selado:           Sim
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Papel):   disk3s5 (Dados)
|   Nome:                      Macintosh HD - Dados (Case-insensitive)
<strong>    |   Ponto de Montagem:               /System/Volumes/Data
</strong><strong>    |   Capacidade Consumida:         412071784448 B (412.1 GB)
</strong>    |   Selado:                    Não
|   FileVault:                 Sim (Desbloqueado)
</code></pre>

No output anterior é possível ver que **locais acessíveis pelo usuário** estão montados em `/System/Volumes/Data`.

Além disso, **snapshot do volume do sistema macOS** está montado em `/` e está **selado** (assinado criptograficamente pelo SO). Então, se o SIP for contornado e modificado, o **SO não iniciará mais**.

Também é possível **verificar se o selo está ativado** executando:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Além disso, o disco de snapshot também é montado como **somente leitura**:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Trabalha numa **empresa de cibersegurança**? Quer ver a sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
