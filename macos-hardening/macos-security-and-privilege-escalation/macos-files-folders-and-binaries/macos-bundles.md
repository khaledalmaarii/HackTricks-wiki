# Bundles do macOS

{% hint style="success" %}
Aprenda e pratique Hacking na AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking na GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Informações Básicas

Os bundles no macOS servem como contêineres para uma variedade de recursos, incluindo aplicativos, bibliotecas e outros arquivos necessários, fazendo com que eles apareçam como objetos únicos no Finder, como os familiares arquivos `*.app`. O bundle mais comumente encontrado é o bundle `.app`, embora outros tipos como `.framework`, `.systemextension` e `.kext` também sejam prevalentes.

### Componentes Essenciais de um Bundle

Dentro de um bundle, especialmente dentro do diretório `<application>.app/Contents/`, uma variedade de recursos importantes são armazenados:

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

Para obter informações mais detalhadas sobre as chaves do `Info.plist` e seus significados, a documentação de desenvolvedor da Apple fornece recursos extensivos: [Referência de Chaves do Info.plist da Apple](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{% hint style="success" %}
Aprenda e pratique Hacking na AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking na GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
