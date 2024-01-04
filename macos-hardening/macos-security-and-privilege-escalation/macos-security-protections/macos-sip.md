# macOS SIP

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Participe do grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou do grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

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

Para verificar se um diretório ou arquivo está protegido pelo SIP, você pode usar o comando **`ls -lOd`** para checar a presença da flag **`restricted`** ou **`sunlnk`**. Por exemplo:
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
Aqui, a flag **`restricted`** indica que o diretório `/usr/libexec` está protegido pelo SIP. Em um diretório protegido pelo SIP, arquivos não podem ser criados, modificados ou deletados.

Além disso, se um arquivo contém o atributo **`com.apple.rootless`** como um **atributo estendido**, esse arquivo também estará **protegido pelo SIP**.

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
Se você deseja manter o SIP ativado, mas remover as proteções de depuração, pode fazer isso com:
```bash
csrutil enable --without debug
```
### Outras Restrições

O SIP também impõe várias outras restrições. Por exemplo, ele proíbe o **carregamento de extensões de kernel não assinadas** (kexts) e impede o **depuração** de processos do sistema macOS. Também inibe ferramentas como dtrace de inspecionar processos do sistema.

[Mais informações sobre SIP nesta palestra](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship).

## Bypasses do SIP

Se um atacante conseguir contornar o SIP, ele poderá fazer o seguinte:

* Ler e-mails, mensagens, histórico do Safari... de todos os usuários
* Conceder permissões para webcam, microfone ou qualquer coisa (escrevendo diretamente sobre o banco de dados TCC protegido pelo SIP) - Bypass do TCC
* Persistência: Ele poderia salvar um malware em um local protegido pelo SIP e nem mesmo root poderá deletá-lo. Além disso, ele poderia adulterar o MRT.
* Facilidade para carregar extensões de kernel (ainda existem outras proteções avançadas em vigor para isso).

### Pacotes de Instalação

**Pacotes de instalação assinados com o certificado da Apple** podem contornar suas proteções. Isso significa que até pacotes assinados por desenvolvedores padrão serão bloqueados se tentarem modificar diretórios protegidos pelo SIP.

### Arquivo SIP Inexistente

Uma possível brecha é que se um arquivo é especificado em **`rootless.conf` mas atualmente não existe**, ele pode ser criado. Malwares poderiam explorar isso para **estabelecer persistência** no sistema. Por exemplo, um programa malicioso poderia criar um arquivo .plist em `/System/Library/LaunchDaemons` se ele estiver listado em `rootless.conf` mas não estiver presente.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
O direito **`com.apple.rootless.install.heritable`** permite contornar o SIP
{% endhint %}

#### Shrootless

[**Pesquisadores deste post do blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) descobriram uma vulnerabilidade no mecanismo de Proteção de Integridade do Sistema (SIP) do macOS, apelidada de vulnerabilidade 'Shrootless'. Essa vulnerabilidade gira em torno do daemon **`system_installd`**, que possui um direito, **`com.apple.rootless.install.heritable`**, que permite que qualquer um de seus processos filhos contorne as restrições do sistema de arquivos do SIP.

O daemon **`system_installd`** instalará pacotes que foram assinados pela **Apple**.

Os pesquisadores descobriram que durante a instalação de um pacote assinado pela Apple (.pkg), o **`system_installd`** **executa** quaisquer scripts **pós-instalação** incluídos no pacote. Esses scripts são executados pelo shell padrão, **`zsh`**, que automaticamente **executa** comandos do arquivo **`/etc/zshenv`**, se ele existir, mesmo em modo não interativo. Esse comportamento poderia ser explorado por atacantes: criando um arquivo `/etc/zshenv` malicioso e esperando que **`system_installd` invoque `zsh`**, eles poderiam realizar operações arbitrárias no dispositivo.

Além disso, descobriu-se que **`/etc/zshenv` poderia ser usado como uma técnica de ataque geral**, não apenas para um bypass do SIP. Cada perfil de usuário tem um arquivo `~/.zshenv`, que se comporta da mesma maneira que `/etc/zshenv`, mas não requer permissões de root. Esse arquivo poderia ser usado como um mecanismo de persistência, acionado toda vez que `zsh` é iniciado, ou como um mecanismo de elevação de privilégios. Se um usuário administrador se elevar a root usando `sudo -s` ou `sudo <comando>`, o arquivo `~/.zshenv` seria acionado, efetivamente elevando a root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

No [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/), descobriu-se que o mesmo processo **`system_installd`** ainda poderia ser abusado porque colocava o script **pós-instalação dentro de uma pasta com nome aleatório protegida pelo SIP dentro de `/tmp`**. O fato é que **`/tmp` em si não é protegido pelo SIP**, então era possível **montar** uma **imagem virtual sobre ele**, então o **instalador** colocaria lá o script **pós-instalação**, **desmontaria** a imagem virtual, **recriaria** todas as **pastas** e **adicionaria** o script de **pós-instalação** com o **payload** para executar.

#### [utilitário fsck\_cs](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

O bypass explorava o fato de que **`fsck_cs`** seguiria **links simbólicos** e tentaria corrigir o sistema de arquivos apresentado a ele.

Portanto, um atacante poderia criar um link simbólico apontando de _`/dev/diskX`_ para `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` e invocar **`fsck_cs`** no primeiro. Como o arquivo `Info.plist` fica corrompido, o sistema operacional não poderia **mais controlar as exclusões de extensão de kernel**, contornando assim o SIP.

{% code overflow="wrap" %}
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
{% endcode %}

O arquivo Info.plist mencionado, agora destruído, é usado pelo **SIP para colocar em lista branca algumas extensões de kernel** e especificamente **bloquear** **outras** de serem carregadas. Normalmente, ele coloca na lista negra a própria extensão de kernel da Apple **`AppleHWAccess.kext`**, mas com o arquivo de configuração destruído, agora podemos carregá-lo e usá-lo para ler e escrever como quisermos de e para a RAM do sistema.

#### [Montar sobre pastas protegidas pelo SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Era possível montar um novo sistema de arquivos sobre **pastas protegidas pelo SIP para contornar a proteção**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Bypass de Atualização (2016)](https://objective-see.org/blog/blog\_0x14.html)

Quando executado, o aplicativo de atualização/instalação (ou seja, `Install macOS Sierra.app`) configura o sistema para inicializar a partir de uma imagem de disco de instalação (que está embutida dentro do aplicativo baixado). Esta imagem de disco de instalação contém a lógica para atualizar o sistema operacional, por exemplo, de OS X El Capitan para macOS Sierra.

Para inicializar o sistema a partir da imagem de atualização/instalação (`InstallESD.dmg`), o `Install macOS Sierra.app` utiliza a utilidade **`bless`** (que herda o entitlement `com.apple.rootless.install.heritable`):

{% code overflow="wrap" %}
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
{% endcode %}

Portanto, se um atacante conseguir modificar a imagem de atualização (`InstallESD.dmg`) antes do sistema inicializar a partir dela, ele pode contornar o SIP.

A maneira de modificar a imagem para infectá-la era substituir um carregador dinâmico (dyld) que carregaria e executaria ingenuamente a biblioteca dinâmica maliciosa no contexto do aplicativo. Como a biblioteca dinâmica **`libBaseIA`**. Assim, sempre que o aplicativo instalador for iniciado pelo usuário (ou seja, para atualizar o sistema), nossa biblioteca dinâmica maliciosa (chamada libBaseIA.dylib) também será carregada e executada no instalador.

Agora 'dentro' do aplicativo instalador, podemos controlar essa fase do processo de atualização. Como o instalador vai 'abençoar' a imagem, tudo o que temos a fazer é subverter a imagem, **`InstallESD.dmg`**, antes de ser usada. Foi possível fazer isso interceptando o método **`extractBootBits`** com um swizzling de método.\
Tendo o código malicioso executado logo antes da imagem de disco ser usada, é hora de infectá-la.

Dentro de `InstallESD.dmg` há outra imagem de disco embutida `BaseSystem.dmg` que é o 'sistema de arquivos raiz' do código de atualização. Foi possível injetar uma biblioteca dinâmica no `BaseSystem.dmg` para que o código malicioso seja executado dentro do contexto de um processo que pode modificar arquivos no nível do sistema operacional.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Nesta palestra do [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), é mostrado como o **`systemmigrationd`** (que pode contornar o SIP) executa um script **bash** e um script **perl**, que podem ser abusados através das variáveis de ambiente **`BASH_ENV`** e **`PERL5OPT`**.

### **com.apple.rootless.install**

{% hint style="danger" %}
O direito **`com.apple.rootless.install`** permite contornar o SIP
{% endhint %}

De [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) O serviço XPC do sistema `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possui o direito **`com.apple.rootless.install`**, que concede ao processo permissão para contornar as restrições do SIP. Ele também **expõe um método para mover arquivos sem qualquer verificação de segurança.**

## Sealed System Snapshots

Sealed System Snapshots são um recurso introduzido pela Apple no **macOS Big Sur (macOS 11)** como parte do seu mecanismo de **System Integrity Protection (SIP)** para fornecer uma camada adicional de segurança e estabilidade do sistema. Eles são essencialmente versões somente leitura do volume do sistema.

Aqui está um olhar mais detalhado:

1. **Sistema Imutável**: Sealed System Snapshots tornam o volume do sistema macOS "imutável", o que significa que ele não pode ser modificado. Isso impede quaisquer alterações não autorizadas ou acidentais no sistema que possam comprometer a segurança ou a estabilidade do sistema.
2. **Atualizações de Software do Sistema**: Quando você instala atualizações ou upgrades do macOS, o macOS cria um novo snapshot do sistema. O volume de inicialização do macOS então usa o **APFS (Apple File System)** para mudar para este novo snapshot. Todo o processo de aplicação de atualizações se torna mais seguro e confiável, pois o sistema sempre pode reverter para o snapshot anterior se algo der errado durante a atualização.
3. **Separação de Dados**: Em conjunto com o conceito de separação de volumes de Dados e Sistema introduzido no macOS Catalina, o recurso Sealed System Snapshot garante que todos os seus dados e configurações sejam armazenados em um volume "**Data**" separado. Essa separação torna seus dados independentes do sistema, o que simplifica o processo de atualizações do sistema e aumenta a segurança do sistema.

Lembre-se de que esses snapshots são gerenciados automaticamente pelo macOS e não ocupam espaço adicional no seu disco, graças às capacidades de compartilhamento de espaço do APFS. Também é importante notar que esses snapshots são diferentes dos **snapshots do Time Machine**, que são backups acessíveis pelo usuário de todo o sistema.

### Verificar Snapshots

O comando **`diskutil apfs list`** lista os **detalhes dos volumes APFS** e seu layout:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% usado)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% livre)
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
|   |   Sealed:                    Quebrado
|   |   FileVault:                 Sim (Desbloqueado)
|   |   Encrypted:                 Não
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Sim
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    Não
|   FileVault:                 Sim (Desbloqueado)
</code></pre>

Na saída anterior é possível ver que **locais acessíveis pelo usuário** estão montados em `/System/Volumes/Data`.

Além disso, **snapshot do volume do sistema macOS** está montado em `/` e está **selado** (assinado criptograficamente pelo sistema operacional). Então, se o SIP for contornado e modificado, o **sistema operacional não inicializará mais**.

Também é possível **verificar se o selo está habilitado** executando:
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

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
