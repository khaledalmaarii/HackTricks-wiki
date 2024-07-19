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

**Apple Events** son una característica en macOS de Apple que permite a las aplicaciones comunicarse entre sí. Son parte del **Apple Event Manager**, que es un componente del sistema operativo macOS responsable de manejar la comunicación entre procesos. Este sistema permite que una aplicación envíe un mensaje a otra aplicación para solicitar que realice una operación particular, como abrir un archivo, recuperar datos o ejecutar un comando.

El daemon mina es `/System/Library/CoreServices/appleeventsd` que registra el servicio `com.apple.coreservices.appleevents`.

Cada aplicación que puede recibir eventos verificará con este daemon proporcionando su Apple Event Mach Port. Y cuando una aplicación quiere enviar un evento a él, la aplicación solicitará este puerto al daemon.

Las aplicaciones en sandbox requieren privilegios como `allow appleevent-send` y `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` para poder enviar eventos. Noten que los derechos como `com.apple.security.temporary-exception.apple-events` podrían restringir quién tiene acceso para enviar eventos, lo que necesitará derechos como `com.apple.private.appleevents`.

{% hint style="success" %}
Es posible usar la variable de entorno **`AEDebugSends`** para registrar información sobre el mensaje enviado:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
