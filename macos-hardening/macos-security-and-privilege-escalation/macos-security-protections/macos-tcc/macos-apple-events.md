# macOS Eventos da Apple

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

- Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
- Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações Básicas

**Eventos da Apple** são um recurso no macOS da Apple que permite que aplicativos se comuniquem entre si. Eles fazem parte do **Gerenciador de Eventos da Apple**, que é um componente do sistema operacional macOS responsável por lidar com a comunicação entre processos. Esse sistema permite que um aplicativo envie uma mensagem para outro aplicativo solicitando que ele execute uma operação específica, como abrir um arquivo, recuperar dados ou executar um comando.

O daemon mina é `/System/Library/CoreServices/appleeventsd` que registra o serviço `com.apple.coreservices.appleevents`.

Cada aplicativo que pode receber eventos verificará com esse daemon fornecendo sua Porta Mach de Evento da Apple. E quando um aplicativo deseja enviar um evento para ele, o aplicativo solicitará essa porta ao daemon.

Aplicativos com sandbox precisam de privilégios como `allow appleevent-send` e `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` para poder enviar eventos. Note que as autorizações como `com.apple.security.temporary-exception.apple-events` podem restringir quem tem acesso para enviar eventos, o que exigirá autorizações como `com.apple.private.appleevents`.

{% hint style="success" %}
É possível usar a variável de ambiente **`AEDebugSends`** para registrar informações sobre a mensagem enviada:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
