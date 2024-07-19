# macOS Apple Events

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

## Grundinformationen

**Apple Events** sind eine Funktion in Apples macOS, die es Anwendungen ermöglicht, miteinander zu kommunizieren. Sie sind Teil des **Apple Event Managers**, der ein Bestandteil des macOS-Betriebssystems ist und für die Handhabung der interprozessualen Kommunikation verantwortlich ist. Dieses System ermöglicht es einer Anwendung, einer anderen Anwendung eine Nachricht zu senden, um zu verlangen, dass sie eine bestimmte Operation ausführt, wie das Öffnen einer Datei, das Abrufen von Daten oder das Ausführen eines Befehls.

Der mina-Daemon ist `/System/Library/CoreServices/appleeventsd`, der den Dienst `com.apple.coreservices.appleevents` registriert.

Jede Anwendung, die Ereignisse empfangen kann, wird mit diesem Daemon überprüfen, indem sie ihren Apple Event Mach Port bereitstellt. Und wenn eine App ein Ereignis an ihn senden möchte, wird die App diesen Port vom Daemon anfordern.

Sandboxed-Anwendungen benötigen Berechtigungen wie `allow appleevent-send` und `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`, um in der Lage zu sein, Ereignisse zu senden. Beachten Sie, dass Berechtigungen wie `com.apple.security.temporary-exception.apple-events` einschränken können, wer Zugriff auf das Senden von Ereignissen hat, was Berechtigungen wie `com.apple.private.appleevents` erfordert.

{% hint style="success" %}
Es ist möglich, die Umgebungsvariable **`AEDebugSends`** zu verwenden, um Informationen über die gesendete Nachricht zu protokollieren:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
