# macOS Chromium-Injektion

{% hint style="success" %}
Lernen und üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen und üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories einreichen.

</details>
{% endhint %}

## Grundlegende Informationen

Chromium-basierte Browser wie Google Chrome, Microsoft Edge, Brave und andere. Diese Browser basieren auf dem Open-Source-Projekt Chromium, was bedeutet, dass sie eine gemeinsame Basis teilen und daher ähnliche Funktionen und Entwickleroptionen haben.

#### `--load-extension` Flag

Das `--load-extension`-Flag wird verwendet, wenn ein Chromium-basierter Browser von der Befehlszeile oder einem Skript gestartet wird. Dieses Flag ermöglicht es, **automatisch eine oder mehrere Erweiterungen** beim Start des Browsers zu laden.

#### `--use-fake-ui-for-media-stream` Flag

Das `--use-fake-ui-for-media-stream`-Flag ist eine weitere Befehlszeilenoption, die zum Starten von Chromium-basierten Browsern verwendet werden kann. Dieses Flag ist dazu gedacht, **die normalen Benutzerabfragen zu umgehen, die um Erlaubnis zur Nutzung von Mediendaten aus Kamera und Mikrofon bitten**. Wenn dieses Flag verwendet wird, gewährt der Browser automatisch die Erlaubnis für jede Website oder Anwendung, die Zugriff auf Kamera oder Mikrofon anfordert.

### Tools

* [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
* [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Beispiel
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Finde mehr Beispiele in den Tools-Links

## Referenzen

* [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{% hint style="success" %}
Lerne und übe AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne und übe GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Trete der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories einreichst.

</details>
{% endhint %}
