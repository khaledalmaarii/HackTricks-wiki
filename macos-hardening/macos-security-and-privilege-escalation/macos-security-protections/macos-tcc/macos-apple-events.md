# macOS Apple Events

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

**Apple Events** são um recurso no macOS da Apple que permite que aplicativos se comuniquem entre si. Eles fazem parte do **Apple Event Manager**, que é um componente do sistema operacional macOS responsável por gerenciar a comunicação entre processos. Este sistema permite que um aplicativo envie uma mensagem para outro aplicativo solicitando que ele execute uma operação específica, como abrir um arquivo, recuperar dados ou executar um comando.

O daemon mina é `/System/Library/CoreServices/appleeventsd`, que registra o serviço `com.apple.coreservices.appleevents`.

Todo aplicativo que pode receber eventos verificará com este daemon fornecendo seu Apple Event Mach Port. E quando um aplicativo deseja enviar um evento para ele, o aplicativo solicitará este porto ao daemon.

Aplicativos em sandbox requerem privilégios como `allow appleevent-send` e `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` para poder enviar eventos. Note que direitos como `com.apple.security.temporary-exception.apple-events` podem restringir quem tem acesso para enviar eventos, o que exigirá direitos como `com.apple.private.appleevents`.

{% hint style="success" %}
É possível usar a variável de ambiente **`AEDebugSends`** para registrar informações sobre a mensagem enviada:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporte o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
