# macOS SIP

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## **Informações Básicas**

**Proteção da Integridade do Sistema (SIP)** no macOS é um mecanismo projetado para evitar que até mesmo os usuários mais privilegiados façam alterações não autorizadas em pastas-chave do sistema. Essa funcionalidade desempenha um papel crucial na manutenção da integridade do sistema, restringindo ações como adicionar, modificar ou excluir arquivos em áreas protegidas. As principais pastas protegidas pelo SIP incluem:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

As regras que governam o comportamento do SIP são definidas no arquivo de configuração localizado em **`/System/Library/Sandbox/rootless.conf`**. Dentro deste arquivo, os caminhos prefixados com um asterisco (*) são considerados exceções às restrições rigorosas do SIP.

Considere o exemplo abaixo:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Este trecho implica que, embora o SIP geralmente proteja o diretório **`/usr`**, existem subdiretórios específicos (`/usr/libexec/cups`, `/usr/local` e `/usr/share/man`) onde modificações são permitidas, conforme indicado pelo asterisco (*) precedendo seus caminhos.

Para verificar se um diretório ou arquivo está protegido pelo SIP, você pode usar o comando **`ls -lOd`** para verificar a presença da marca **`restricted`** ou **`sunlnk`**. Por exemplo:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Neste caso, a bandeira **`sunlnk`** significa que o diretório `/usr/libexec/cups` em si **não pode ser excluído**, embora arquivos dentro dele possam ser criados, modificados ou excluídos.

Por outro lado:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Aqui, a bandeira **`restricted`** indica que o diretório `/usr/libexec` é protegido pelo SIP. Em um diretório protegido pelo SIP, arquivos não podem ser criados, modificados ou excluídos.

Além disso, se um arquivo contiver o atributo estendido **`com.apple.rootless`**, esse arquivo também será **protegido pelo SIP**.

**O SIP também limita outras ações de root** como:

* Carregar extensões de kernel não confiáveis
* Obter portas de tarefa para processos assinados pela Apple
* Modificar variáveis NVRAM
* Permitir a depuração do kernel

As opções são mantidas na variável nvram como um bitflag (`csr-active-config` no Intel e `lp-sip0` é lido a partir da Árvore de Dispositivos inicializada para ARM). Você pode encontrar as bandeiras no código-fonte do XNU em `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### Status do SIP

Você pode verificar se o SIP está habilitado em seu sistema com o seguinte comando:
```bash
csrutil status
```
Se precisar desativar o SIP, você deve reiniciar o seu computador no modo de recuperação (pressionando Command+R durante a inicialização) e, em seguida, executar o seguinte comando:
```bash
csrutil disable
```
Se desejar manter o SIP ativado, mas remover as proteções de depuração, você pode fazer isso com:
```bash
csrutil enable --without debug
```
### Outras Restrições

- **Impede o carregamento de extensões de kernel não assinadas** (kexts), garantindo que apenas extensões verificadas interajam com o kernel do sistema.
- **Previne a depuração** dos processos do sistema macOS, protegendo os componentes principais do sistema contra acesso e modificação não autorizados.
- **Inibe ferramentas** como dtrace de inspecionar processos do sistema, protegendo ainda mais a integridade da operação do sistema.

**[Saiba mais sobre as informações do SIP nesta palestra](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship).**

## Contornos do SIP

Contornar o SIP permite a um atacante:

- **Acessar Dados do Usuário**: Ler dados sensíveis do usuário, como e-mails, mensagens e histórico do Safari de todas as contas de usuário.
- **Bypass do TCC**: Manipular diretamente o banco de dados TCC (Transparência, Consentimento e Controle) para conceder acesso não autorizado à webcam, microfone e outros recursos.
- **Estabelecer Persistência**: Colocar malware em locais protegidos pelo SIP, tornando-o resistente à remoção, mesmo com privilégios de root. Isso também inclui a possibilidade de manipular a Ferramenta de Remoção de Malware (MRT).
- **Carregar Extensões de Kernel**: Embora existam salvaguardas adicionais, contornar o SIP simplifica o processo de carregar extensões de kernel não assinadas.

### Pacotes de Instalador

**Pacotes de instalador assinados com o certificado da Apple** podem contornar suas proteções. Isso significa que mesmo pacotes assinados por desenvolvedores padrão serão bloqueados se tentarem modificar diretórios protegidos pelo SIP.

### Arquivo SIP inexistente

Uma possível brecha é que se um arquivo for especificado em **`rootless.conf` mas não existir atualmente**, ele pode ser criado. Malware poderia explorar isso para **estabelecer persistência** no sistema. Por exemplo, um programa malicioso poderia criar um arquivo .plist em `/System/Library/LaunchDaemons` se estiver listado em `rootless.conf` mas não estiver presente.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
A permissão **`com.apple.rootless.install.heritable`** permite contornar o SIP
{% endhint %}

#### Shrootless

[**Pesquisadores deste post de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) descobriram uma vulnerabilidade no mecanismo de Proteção de Integridade do Sistema (SIP) do macOS, chamada vulnerabilidade 'Shrootless'. Essa vulnerabilidade gira em torno do daemon **`system_installd`**, que possui uma permissão, **`com.apple.rootless.install.heritable`**, que permite que qualquer um de seus processos filhos contorne as restrições do sistema de arquivos do SIP.

O daemon **`system_installd`** instalará pacotes que foram assinados pela **Apple**.

Os pesquisadores descobriram que durante a instalação de um pacote assinado pela Apple (.pkg), o **`system_installd`** **executa** quaisquer scripts **pós-instalação** incluídos no pacote. Esses scripts são executados pelo shell padrão, **`zsh`**, que automaticamente **executa** comandos do arquivo **`/etc/zshenv`**, se existir, mesmo no modo não interativo. Esse comportamento poderia ser explorado por atacantes: criando um arquivo malicioso `/etc/zshenv` e aguardando o **`system_installd` invocar o `zsh`**, eles poderiam realizar operações arbitrárias no dispositivo.

Além disso, foi descoberto que **`/etc/zshenv` poderia ser usado como uma técnica de ataque geral**, não apenas para contornar o SIP. Cada perfil de usuário possui um arquivo `~/.zshenv`, que se comporta da mesma maneira que `/etc/zshenv` mas não requer permissões de root. Esse arquivo poderia ser usado como um mecanismo de persistência, acionando toda vez que o `zsh` é iniciado, ou como um mecanismo de elevação de privilégio. Se um usuário administrador se eleva para root usando `sudo -s` ou `sudo <comando>`, o arquivo `~/.zshenv` seria acionado, efetivamente elevando para root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Em [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/), foi descoberto que o mesmo processo **`system_installd`** ainda poderia ser abusado porque estava colocando o **script pós-instalação dentro de uma pasta com nome aleatório protegida pelo SIP dentro de `/tmp`**. A questão é que **`/tmp` em si não é protegido pelo SIP**, então era possível **montar** uma **imagem virtual nele**, então o **instalador** colocaria lá o **script pós-instalação**, **desmontaria** a imagem virtual, **recriaria** todas as **pastas** e **adicionaria** o **script de pós-instalação** com a **carga útil** a ser executada.

#### [Utilitário fsck\_cs](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Foi identificada uma vulnerabilidade em que o **`fsck_cs`** foi enganado para corromper um arquivo crucial, devido à sua capacidade de seguir **links simbólicos**. Especificamente, os atacantes criaram um link de _`/dev/diskX`_ para o arquivo `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Executar o **`fsck_cs`** em _`/dev/diskX`_ levou à corrupção do `Info.plist`. A integridade deste arquivo é vital para a Proteção de Integridade do Sistema (SIP) do sistema operacional, que controla o carregamento de extensões de kernel. Uma vez corrompido, a capacidade do SIP de gerenciar exclusões de kernel é comprometida.

Os comandos para explorar essa vulnerabilidade são:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
A exploração dessa vulnerabilidade tem implicações graves. O arquivo `Info.plist`, normalmente responsável por gerenciar permissões para extensões de kernel, se torna ineficaz. Isso inclui a incapacidade de listar certas extensões, como `AppleHWAccess.kext`. Consequentemente, com o mecanismo de controle do SIP desativado, essa extensão pode ser carregada, concedendo acesso não autorizado de leitura e gravação à RAM do sistema.


#### [Montar sobre pastas protegidas pelo SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Foi possível montar um novo sistema de arquivos sobre **pastas protegidas pelo SIP para burlar a proteção**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Bypass do Upgrader (2016)](https://objective-see.org/blog/blog\_0x14.html)

O sistema está configurado para inicializar a partir de uma imagem de disco do instalador incorporado dentro do `Install macOS Sierra.app` para atualizar o sistema operacional, utilizando o utilitário `bless`. O comando utilizado é o seguinte:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
A segurança desse processo pode ser comprometida se um atacante alterar a imagem de atualização (`InstallESD.dmg`) antes do boot. A estratégia envolve substituir um carregador dinâmico (dyld) por uma versão maliciosa (`libBaseIA.dylib`). Essa substituição resulta na execução do código do atacante quando o instalador é iniciado.

O código do atacante ganha controle durante o processo de atualização, explorando a confiança do sistema no instalador. O ataque continua alterando a imagem `InstallESD.dmg` por meio de swizzling de método, direcionando especialmente o método `extractBootBits`. Isso permite a injeção de código malicioso antes que a imagem do disco seja utilizada.

Além disso, dentro do `InstallESD.dmg`, há um `BaseSystem.dmg`, que serve como sistema de arquivos raiz do código de atualização. Injetar uma biblioteca dinâmica nisso permite que o código malicioso opere dentro de um processo capaz de alterar arquivos de nível de sistema, aumentando significativamente o potencial de comprometimento do sistema.


#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Nesta palestra da [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), é mostrado como o **`systemmigrationd`** (que pode contornar o SIP) executa um script **bash** e um script **perl**, que podem ser abusados via variáveis de ambiente **`BASH_ENV`** e **`PERL5OPT`**.

### **com.apple.rootless.install**

{% hint style="danger" %}
A permissão **`com.apple.rootless.install`** permite contornar o SIP
{% endhint %}

A permissão `com.apple.rootless.install` é conhecida por contornar a Proteção de Integridade do Sistema (SIP) no macOS. Isso foi mencionado especialmente em relação ao [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

Neste caso específico, o serviço XPC do sistema localizado em `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possui essa permissão. Isso permite que o processo relacionado contorne as restrições do SIP. Além disso, esse serviço apresenta um método que permite a movimentação de arquivos sem impor medidas de segurança.

## Instantâneos do Sistema Lacrados

Os Instantâneos do Sistema Lacrados são um recurso introduzido pela Apple no **macOS Big Sur (macOS 11)** como parte de seu mecanismo de **Proteção de Integridade do Sistema (SIP)** para fornecer uma camada adicional de segurança e estabilidade do sistema. Eles são essencialmente versões somente leitura do volume do sistema.

Aqui está uma visão mais detalhada:

1. **Sistema Imutável**: Os Instantâneos do Sistema Lacrados tornam o volume do sistema macOS "imutável", o que significa que ele não pode ser modificado. Isso impede quaisquer alterações não autorizadas ou acidentais no sistema que possam comprometer a segurança ou a estabilidade do sistema.
2. **Atualizações de Software do Sistema**: Quando você instala atualizações ou upgrades do macOS, o macOS cria um novo instantâneo do sistema. O volume de inicialização do macOS então usa o **APFS (Apple File System)** para alternar para esse novo instantâneo. Todo o processo de aplicação de atualizações se torna mais seguro e confiável, pois o sistema sempre pode reverter para o instantâneo anterior se algo der errado durante a atualização.
3. **Separação de Dados**: Em conjunto com o conceito de separação de volumes de Dados e Sistema introduzido no macOS Catalina, o recurso de Instantâneos do Sistema Lacrados garante que todos os seus dados e configurações sejam armazenados em um volume "**Dados**" separado. Essa separação torna seus dados independentes do sistema, o que simplifica o processo de atualizações do sistema e aprimora a segurança do sistema.

Lembre-se de que esses instantâneos são gerenciados automaticamente pelo macOS e não ocupam espaço adicional em seu disco, graças às capacidades de compartilhamento de espaço do APFS. Também é importante observar que esses instantâneos são diferentes dos **instantâneos do Time Machine**, que são backups acessíveis pelo usuário de todo o sistema.

### Verificar Instantâneos

O comando **`diskutil apfs list`** lista os **detalhes dos volumes APFS** e sua disposição:

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
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

No output anterior, é possível ver que as **localizações acessíveis pelo usuário** estão montadas em `/System/Volumes/Data`.

Além disso, o **instantâneo do volume do sistema macOS** está montado em `/` e está **lacrado** (assinado criptograficamente pelo sistema operacional). Portanto, se o SIP for contornado e modificado, o **sistema não inicializará mais**.

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

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
