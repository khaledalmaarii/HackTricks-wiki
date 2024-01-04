# Pacotes macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Basicamente, um pacote é uma **estrutura de diretórios** dentro do sistema de arquivos. Curiosamente, por padrão, este diretório **parece um único objeto no Finder**.&#x20;

O pacote **comum** e frequente com o qual nos deparamos é o **pacote `.app`**, mas muitos outros executáveis também são empacotados como pacotes, como **`.framework`** e **`.systemextension`** ou **`.kext`**.

Os tipos de recursos contidos dentro de um pacote podem consistir em aplicações, bibliotecas, imagens, documentação, arquivos de cabeçalho, etc. Todos esses arquivos estão dentro de `<application>.app/Contents/`
```bash
ls -lR /Applications/Safari.app/Contents
```
* `Contents/_CodeSignature` -> Contém **informações de assinatura de código** sobre o aplicativo (ou seja, hashes, etc.).
* `openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64`
* `Contents/MacOS` -> Contém o **binário do aplicativo** (que é executado quando o usuário clica duas vezes no ícone do aplicativo na UI).
* `Contents/Resources` -> Contém **elementos da UI do aplicativo**, como imagens, documentos e arquivos nib/xib (que descrevem várias interfaces de usuário).
* `Contents/Info.plist` -> O principal “**arquivo de configuração**” do aplicativo. A Apple observa que “o sistema depende da presença deste arquivo para identificar informações relevantes sobre \[o] aplicativo e quaisquer arquivos relacionados”.
* **Arquivos Plist** contêm informações de configuração. Você pode encontrar informações sobre o significado das chaves plist em [https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)
*   Pares que podem ser de interesse ao analisar um aplicativo incluem:\\

* **CFBundleExecutable**

Contém o **nome do binário do aplicativo** (encontrado em Contents/MacOS).

* **CFBundleIdentifier**

Contém o identificador de pacote do aplicativo (frequentemente usado pelo sistema para **identificar globalmente** o aplicativo).

* **LSMinimumSystemVersion**

Contém a **versão mais antiga** de **macOS** com a qual o aplicativo é compatível.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
