# Abuso de Instaladores macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas do Pkg

Um **pacote instalador** macOS (também conhecido como arquivo `.pkg`) é um formato de arquivo usado pelo macOS para **distribuir software**. Esses arquivos são como uma **caixa que contém tudo o que um software** precisa para instalar e funcionar corretamente.

O próprio arquivo do pacote é um arquivo que contém uma **hierarquia de arquivos e diretórios que serão instalados no computador alvo**. Ele também pode incluir **scripts** para realizar tarefas antes e depois da instalação, como configurar arquivos de configuração ou limpar versões antigas do software.

### Hierarquia

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt=""><figcaption></figcaption></figure>

* **Distribuição (xml)**: Personalizações (título, texto de boas-vindas...) e verificações de script/instalação
* **PackageInfo (xml)**: Informações, requisitos de instalação, local de instalação, caminhos para scripts a serem executados
* **Lista de materiais (bom)**: Lista de arquivos para instalar, atualizar ou remover com permissões de arquivo
* **Carga (arquivo CPIO comprimido com gzip)**: Arquivos para instalar no `local de instalação` do PackageInfo
* **Scripts (arquivo CPIO comprimido com gzip)**: Scripts de pré e pós instalação e mais recursos extraídos para um diretório temporário para execução.

### Descomprimir
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
## Informações Básicas sobre DMG

Arquivos DMG, ou Imagens de Disco Apple, são um formato de arquivo usado pelo macOS da Apple para imagens de disco. Um arquivo DMG é essencialmente uma **imagem de disco montável** (contém seu próprio sistema de arquivos) que contém dados de blocos brutos tipicamente comprimidos e às vezes criptografados. Quando você abre um arquivo DMG, o macOS **o monta como se fosse um disco físico**, permitindo que você acesse seu conteúdo.

### Hierarquia

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

A hierarquia de um arquivo DMG pode ser diferente com base no conteúdo. No entanto, para DMGs de aplicativos, geralmente segue esta estrutura:

* Nível Superior: Esta é a raiz da imagem de disco. Frequentemente contém o aplicativo e possivelmente um link para a pasta Aplicações.
* Aplicativo (.app): Este é o aplicativo real. No macOS, um aplicativo é tipicamente um pacote que contém muitos arquivos e pastas individuais que compõem o aplicativo.
* Link para Aplicações: Este é um atalho para a pasta Aplicações no macOS. O propósito disso é facilitar a instalação do aplicativo. Você pode arrastar o arquivo .app para este atalho para instalar o app.

## Privesc via abuso de pkg

### Execução a partir de diretórios públicos

Se um script de pré ou pós instalação está, por exemplo, executando a partir de **`/var/tmp/Installerutil`**, um atacante poderia controlar esse script para escalar privilégios sempre que ele for executado. Ou outro exemplo similar:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta é uma [função pública](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que vários instaladores e atualizadores chamarão para **executar algo como root**. Esta função aceita o **caminho** do **arquivo** a **executar** como parâmetro, no entanto, se um atacante pudesse **modificar** este arquivo, ele poderá **abusar** de sua execução com root para **escalar privilégios**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Para mais informações, confira esta palestra: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Execução por montagem

Se um instalador escreve em `/tmp/fixedname/bla/bla`, é possível **criar uma montagem** sobre `/tmp/fixedname` com noowners para que você possa **modificar qualquer arquivo durante a instalação** para abusar do processo de instalação.

Um exemplo disso é o **CVE-2021-26089** que conseguiu **sobrescrever um script periódico** para obter execução como root. Para mais informações, dê uma olhada na palestra: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg como malware

### Payload Vazio

É possível apenas gerar um arquivo **`.pkg`** com **scripts de pré e pós-instalação** sem nenhum payload.

### JS no xml de Distribuição

É possível adicionar tags **`<script>`** no arquivo **xml de distribuição** do pacote e esse código será executado e pode **executar comandos** usando **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Referências

* [**DEF CON 27 - Desempacotando Pkgs Uma Olhada Dentro dos Pacotes de Instalador do MacOS e Falhas Comuns de Segurança**](https://www.youtube.com/watch?v=iASSG0_zobQ)
* [**OBTS v4.0: "O Mundo Selvagem dos Instaladores do macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
