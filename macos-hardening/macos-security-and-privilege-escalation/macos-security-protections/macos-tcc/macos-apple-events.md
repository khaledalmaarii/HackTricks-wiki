# macOS Apple Events

<details>

<summary><strong>Erfahren Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Grundlegende Informationen

**Apple Events** sind eine Funktion in Apples macOS, die es Anwendungen ermöglicht, miteinander zu kommunizieren. Sie sind Teil des **Apple Event Managers**, der eine Komponente des macOS-Betriebssystems ist, die für die Behandlung der Interprozesskommunikation verantwortlich ist. Dieses System ermöglicht es einer Anwendung, einer anderen Anwendung eine Nachricht zu senden, um zu fordern, dass sie eine bestimmte Operation ausführt, wie das Öffnen einer Datei, das Abrufen von Daten oder das Ausführen eines Befehls.

Der mina-Daemon ist `/System/Library/CoreServices/appleeventsd`, der den Dienst `com.apple.coreservices.appleevents` registriert.

Jede Anwendung, die Ereignisse empfangen kann, überprüft dies mit diesem Daemon, indem sie ihren Apple Event Mach Port bereitstellt. Und wenn eine App ein Ereignis an diese senden möchte, fordert die App diesen Port vom Daemon an.

Sandbox-Anwendungen erfordern Berechtigungen wie `allow appleevent-send` und `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`, um Ereignisse senden zu können. Beachten Sie, dass Berechtigungen wie `com.apple.security.temporary-exception.apple-events` einschränken können, wer Zugriff auf das Senden von Ereignissen hat, was Berechtigungen wie `com.apple.private.appleevents` erfordern könnte.

{% hint style="success" %}
Es ist möglich, die Umgebungsvariable **`AEDebugSends`** zu verwenden, um Informationen über die gesendete Nachricht zu protokollieren:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
