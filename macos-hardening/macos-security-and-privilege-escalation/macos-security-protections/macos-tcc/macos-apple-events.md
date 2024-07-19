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

**Apple Events** sono una funzionalità nel macOS di Apple che consente alle applicazioni di comunicare tra loro. Fanno parte del **Apple Event Manager**, che è un componente del sistema operativo macOS responsabile della gestione della comunicazione interprocesso. Questo sistema consente a un'applicazione di inviare un messaggio a un'altra applicazione per richiedere di eseguire un'operazione particolare, come aprire un file, recuperare dati o eseguire un comando.

Il daemon mina è `/System/Library/CoreServices/appleeventsd` che registra il servizio `com.apple.coreservices.appleevents`.

Ogni applicazione che può ricevere eventi verificherà con questo daemon fornendo il suo Apple Event Mach Port. E quando un'app vuole inviare un evento a essa, l'app richiederà questo port dal daemon.

Le applicazioni sandboxed richiedono privilegi come `allow appleevent-send` e `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` per poter inviare eventi. Si noti che le autorizzazioni come `com.apple.security.temporary-exception.apple-events` potrebbero limitare chi ha accesso per inviare eventi, il che richiederà autorizzazioni come `com.apple.private.appleevents`.

{% hint style="success" %}
It's possible to use the env variable **`AEDebugSends`** in order to log informtion about the message sent:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
