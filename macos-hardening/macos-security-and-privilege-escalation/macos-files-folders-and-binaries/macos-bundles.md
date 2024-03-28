# Bundles do macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações Básicas

Os bundles no macOS servem como contêineres para uma variedade de recursos, incluindo aplicativos, bibliotecas e outros arquivos necessários, fazendo com que eles apareçam como objetos únicos no Finder, como os familiares arquivos `*.app`. O bundle mais comumente encontrado é o bundle `.app`, embora outros tipos como `.framework`, `.systemextension` e `.kext` também sejam prevalentes.

### Componentes Essenciais de um Bundle

Dentro de um bundle, especialmente dentro do diretório `<aplicativo>.app/Contents/`, uma variedade de recursos importantes são armazenados:

* **\_CodeSignature**: Este diretório armazena detalhes de assinatura de código vital para verificar a integridade do aplicativo. Você pode inspecionar as informações de assinatura de código usando comandos como: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Contém o binário executável do aplicativo que é executado após a interação do usuário.
* **Resources**: Um repositório para os componentes da interface do usuário do aplicativo, incluindo imagens, documentos e descrições de interface (arquivos nib/xib).
* **Info.plist**: Age como o arquivo de configuração principal do aplicativo, crucial para o sistema reconhecer e interagir com o aplicativo adequadamente.

#### Chaves Importantes em Info.plist

O arquivo `Info.plist` é fundamental para a configuração do aplicativo, contendo chaves como:

* **CFBundleExecutable**: Especifica o nome do arquivo executável principal localizado no diretório `Contents/MacOS`.
* **CFBundleIdentifier**: Fornece um identificador global para o aplicativo, amplamente utilizado pelo macOS para gerenciamento de aplicativos.
* **LSMinimumSystemVersion**: Indica a versão mínima do macOS necessária para que o aplicativo seja executado.

### Explorando Bundles

Para explorar o conteúdo de um bundle, como `Safari.app`, o seguinte comando pode ser usado: `bash ls -lR /Applications/Safari.app/Contents`

Essa exploração revela diretórios como `_CodeSignature`, `MacOS`, `Resources` e arquivos como `Info.plist`, cada um servindo a um propósito único, desde a segurança do aplicativo até a definição de sua interface do usuário e parâmetros operacionais.

#### Diretórios Adicionais de Bundles

Além dos diretórios comuns, os bundles também podem incluir:

* **Frameworks**: Contém frameworks agrupados usados pelo aplicativo. Frameworks são como dylibs com recursos extras.
* **PlugIns**: Um diretório para plug-ins e extensões que aprimoram as capacidades do aplicativo.
* **XPCServices**: Mantém serviços XPC usados pelo aplicativo para comunicação fora do processo.

Essa estrutura garante que todos os componentes necessários estejam encapsulados no bundle, facilitando um ambiente de aplicativo modular e seguro.

Para obter informações mais detalhadas sobre as chaves do `Info.plist` e seus significados, a documentação do desenvolvedor da Apple fornece recursos extensos: [Referência de Chaves Info.plist da Apple](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
