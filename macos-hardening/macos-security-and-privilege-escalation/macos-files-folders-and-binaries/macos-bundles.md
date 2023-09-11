# Pacotes do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Basicamente, um pacote é uma **estrutura de diretórios** dentro do sistema de arquivos. Curiosamente, por padrão, este diretório **parece ser um único objeto no Finder**.&#x20;

O pacote mais **comum** que encontraremos é o pacote **`.app`**, mas muitos outros executáveis também são empacotados como pacotes, como **`.framework`** e **`.systemextension`** ou **`.kext`**.

Os tipos de recursos contidos em um pacote podem consistir em aplicativos, bibliotecas, imagens, documentação, arquivos de cabeçalho, etc. Todos esses arquivos estão dentro de `<aplicativo>.app/Contents/`
```bash
ls -lR /Applications/Safari.app/Contents
```
* `Contents/_CodeSignature` -> Contém informações de **assinatura de código** sobre o aplicativo (ou seja, hashes, etc.).
* `openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64`
* `Contents/MacOS` -> Contém o **binário do aplicativo** (que é executado quando o usuário clica duas vezes no ícone do aplicativo na interface do usuário).
* `Contents/Resources` -> Contém **elementos da interface do usuário do aplicativo**, como imagens, documentos e arquivos nib/xib (que descrevem várias interfaces do usuário).
* `Contents/Info.plist` -> O principal "arquivo de **configuração do aplicativo**". A Apple observa que "o sistema depende da presença deste arquivo para identificar informações relevantes sobre o aplicativo e quaisquer arquivos relacionados".
* Os arquivos **Plist** contêm informações de configuração. Você pode encontrar informações sobre o significado das chaves plist em [https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)
*   Pares que podem ser de interesse ao analisar um aplicativo incluem:\\

* **CFBundleExecutable**

Contém o **nome do binário do aplicativo** (encontrado em Contents/MacOS).

* **CFBundleIdentifier**

Contém o identificador de pacote do aplicativo (frequentemente usado pelo sistema para **identificar globalmente** o aplicativo).

* **LSMinimumSystemVersion**

Contém a **versão mais antiga** do **macOS** com a qual o aplicativo é compatível.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
