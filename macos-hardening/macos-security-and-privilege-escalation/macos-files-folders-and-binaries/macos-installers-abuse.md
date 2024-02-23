# Abuso de Instaladores no macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações Básicas sobre Pkg

Um **pacote de instalação do macOS** (também conhecido como arquivo `.pkg`) é um formato de arquivo usado pelo macOS para **distribuir software**. Esses arquivos são como uma **caixa que contém tudo o que um software** precisa para instalar e funcionar corretamente.

O arquivo do pacote em si é um arquivo compactado que contém uma **hierarquia de arquivos e diretórios que serão instalados no computador de destino**. Ele também pode incluir **scripts** para realizar tarefas antes e depois da instalação, como configurar arquivos de configuração ou limpar versões antigas do software.

### Hierarquia

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribuição (xml)**: Personalizações (título, texto de boas-vindas...) e verificações de script/instalação
* **PackageInfo (xml)**: Informações, requisitos de instalação, local de instalação, caminhos para scripts a serem executados
* **Lista de materiais (bom)**: Lista de arquivos para instalar, atualizar ou remover com permissões de arquivo
* **Carga (arquivo CPIO compactado com gzip)**: Arquivos para instalar no `local de instalação` do PackageInfo
* **Scripts (arquivo CPIO compactado com gzip)**: Scripts de pré e pós-instalação e mais recursos extraídos para um diretório temporário para execução.

### Descompactar
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

Os arquivos DMG, ou Apple Disk Images, são um formato de arquivo usado pelo macOS da Apple para imagens de disco. Um arquivo DMG é essencialmente uma **imagem de disco montável** (ele contém seu próprio sistema de arquivos) que contém dados de bloco brutos normalmente comprimidos e às vezes criptografados. Quando você abre um arquivo DMG, o macOS o **monta como se fosse um disco físico**, permitindo que você acesse seu conteúdo.

### Hierarquia

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

A hierarquia de um arquivo DMG pode ser diferente com base no conteúdo. No entanto, para DMGs de aplicativos, geralmente segue esta estrutura:

- Nível Superior: Este é a raiz da imagem do disco. Geralmente contém o aplicativo e possivelmente um link para a pasta Aplicativos.
- Aplicativo (.app): Este é o aplicativo real. No macOS, um aplicativo é tipicamente um pacote que contém muitos arquivos e pastas individuais que compõem o aplicativo.
- Link de Aplicativos: Este é um atalho para a pasta Aplicativos no macOS. O objetivo disso é facilitar a instalação do aplicativo. Você pode arrastar o arquivo .app para este atalho para instalar o aplicativo.

## Privesc via abuso de pkg

### Execução de diretórios públicos

Se um script de pré ou pós-instalação estiver, por exemplo, sendo executado em **`/var/tmp/Installerutil`**, e um atacante puder controlar esse script, ele poderá elevar privilégios sempre que for executado. Ou outro exemplo semelhante:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta é uma [função pública](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que vários instaladores e atualizadores chamarão para **executar algo como root**. Esta função aceita o **caminho** do **arquivo** a **executar** como parâmetro, no entanto, se um atacante puder **modificar** este arquivo, ele poderá **abusar** de sua execução com root para **elevar privilégios**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### Execução por montagem

Se um instalador escreve em `/tmp/fixedname/bla/bla`, é possível **criar um ponto de montagem** sobre `/tmp/fixedname` sem proprietários para que você possa **modificar qualquer arquivo durante a instalação** para abusar do processo de instalação.

Um exemplo disso é o **CVE-2021-26089** que conseguiu **sobrescrever um script periódico** para obter execução como root. Para mais informações, confira a palestra: [**OBTS v4.0: "Montanha de Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg como malware

### Carga vazia

É possível simplesmente gerar um arquivo **`.pkg`** com **scripts de pré e pós-instalação** sem nenhuma carga útil.

### JS no xml de Distribuição

É possível adicionar tags **`<script>`** no arquivo **xml de distribuição** do pacote e esse código será executado e pode **executar comandos** usando **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Referências

* [**DEF CON 27 - Desempacotando Pkgs Uma Visão Interna dos Pacotes de Instalação do MacOS e Falhas Comuns de Segurança**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "O Mundo Selvagem dos Instaladores do macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
