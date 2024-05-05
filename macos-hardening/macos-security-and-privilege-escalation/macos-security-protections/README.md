# macOS Sicherheitsschutz

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Gatekeeper

Gatekeeper wird normalerweise verwendet, um auf die Kombination von **Quarantäne + Gatekeeper + XProtect** zu verweisen, 3 macOS-Sicherheitsmodule, die versuchen werden, **Benutzer daran zu hindern, potenziell bösartige heruntergeladene Software auszuführen**.

Weitere Informationen unter:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Prozessbeschränkungen

### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

Die macOS-Sandbox **beschränkt Anwendungen**, die innerhalb der Sandbox ausgeführt werden, auf die **zugelassenen Aktionen, die im Sandbox-Profil** festgelegt sind, mit dem die App ausgeführt wird. Dies hilft sicherzustellen, dass **die Anwendung nur auf erwartete Ressourcen zugreift**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparenz, Einwilligung und Kontrolle**

**TCC (Transparenz, Einwilligung und Kontrolle)** ist ein Sicherheitsframework. Es ist darauf ausgelegt, die Berechtigungen von Anwendungen zu **verwalten**, insbesondere durch die Regulierung ihres Zugriffs auf sensible Funktionen. Dazu gehören Elemente wie **Standortdienste, Kontakte, Fotos, Mikrofon, Kamera, Zugänglichkeit und voller Festplattenzugriff**. TCC stellt sicher, dass Apps nur nach ausdrücklicher Zustimmung des Benutzers auf diese Funktionen zugreifen können, wodurch der Datenschutz und die Kontrolle über persönliche Daten gestärkt werden.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Start-/Umgebungseinschränkungen & Trust Cache

Startbeschränkungen in macOS sind eine Sicherheitsfunktion zur **Regulierung der Prozessinitiierung**, indem definiert wird, **wer**, **wie** und **von wo aus** ein Prozess gestartet werden kann. Eingeführt in macOS Ventura, kategorisieren sie Systembinärdateien in Beschränkungskategorien innerhalb eines **Trust Cache**. Jede ausführbare Binärdatei hat festgelegte **Regeln** für ihren **Start**, einschließlich **Selbst**, **Eltern** und **verantwortliche** Beschränkungen. Erweitert auf Drittanbieter-Apps als **Umgebung**-Beschränkungen in macOS Sonoma, helfen diese Funktionen potenzielle Systemausnutzungen zu mildern, indem sie die Bedingungen für das Starten von Prozessen regeln.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malware Removal Tool

Das Malware Removal Tool (MRT) ist ein weiterer Bestandteil der Sicherheitsinfrastruktur von macOS. Wie der Name schon sagt, besteht die Hauptfunktion von MRT darin, **bekannte Malware von infizierten Systemen zu entfernen**.

Sobald Malware auf einem Mac erkannt wird (entweder durch XProtect oder auf andere Weise), kann MRT verwendet werden, um die Malware automatisch **zu entfernen**. MRT arbeitet im Hintergrund und wird in der Regel ausgeführt, wenn das System aktualisiert wird oder wenn eine neue Malware-Definition heruntergeladen wird (es sieht so aus, als ob die Regeln, die MRT zum Erkennen von Malware hat, innerhalb der Binärdatei enthalten sind).

Während sowohl XProtect als auch MRT Teil der Sicherheitsmaßnahmen von macOS sind, erfüllen sie unterschiedliche Funktionen:

* **XProtect** ist ein präventives Werkzeug. Es **überprüft Dateien beim Herunterladen** (über bestimmte Anwendungen) und wenn es bekannte Arten von Malware erkennt, **verhindert es das Öffnen der Datei**, wodurch verhindert wird, dass die Malware Ihr System infiziert.
* **MRT** hingegen ist ein **reaktives Werkzeug**. Es arbeitet, nachdem Malware auf einem System erkannt wurde, mit dem Ziel, die schädliche Software zu entfernen und das System zu säubern.

Die MRT-Anwendung befindet sich in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Verwaltung von Hintergrundaufgaben

**macOS** warnt jetzt jedes Mal, wenn ein Tool eine bekannte **Technik zur Aufrechterhaltung der Codeausführung** verwendet (wie Anmeldeobjekte, Daemons...), damit der Benutzer besser weiß, **welche Software bestehen bleibt**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Dies läuft mit einem **Daemon** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` und dem **Agenten** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Die Art und Weise, wie **`backgroundtaskmanagementd`** erkennt, dass etwas in einem persistenten Ordner installiert ist, erfolgt durch **Abrufen der FSEvents** und Erstellen einiger **Handler** dafür.

Darüber hinaus gibt es eine plist-Datei, die **bekannte Anwendungen** enthält, die häufig bestehen bleiben und von Apple gepflegt werden, die sich befindet in: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Auflistung

Es ist möglich, **alle konfigurierten Hintergrundelemente** mithilfe des Apple-CLI-Tools aufzulisten:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Darüber hinaus ist es auch möglich, diese Informationen mit [**DumpBTM**](https://github.com/objective-see/DumpBTM) aufzulisten.
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Diese Informationen werden in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** gespeichert und das Terminal benötigt FDA.

### Herumspielen mit BTM

Wenn eine neue Persistenz gefunden wird, erfolgt ein Ereignis vom Typ **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Daher kann jede Möglichkeit, dieses Ereignis zu **verhindern** oder den **Agenten daran zu hindern, den Benutzer zu benachrichtigen**, einem Angreifer helfen, BTM zu _**umgehen**_.

* **Zurücksetzen der Datenbank**: Durch Ausführen des folgenden Befehls wird die Datenbank zurückgesetzt (sollte sie von Grund auf neu aufbauen), jedoch werden aus irgendeinem Grund nach Ausführung dieses Befehls **keine neuen Persistenzen benachrichtigt, bis das System neu gestartet wird**.
* **root** ist erforderlich.
```bash
# Reset the database
sfltool resettbtm
```
* **Agent stoppen**: Es ist möglich, dem Agenten ein Stopp-Signal zu senden, damit er den Benutzer nicht benachrichtigt, wenn neue Erkennungen gefunden werden.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Fehler**: Wenn der **Prozess, der die Persistenz erstellt hat, kurz danach schnell beendet wird**, wird der Daemon versuchen, **Informationen darüber zu erhalten**, **scheitern** und **nicht in der Lage sein, das Ereignis zu senden**, das anzeigt, dass etwas Neues bestehen bleibt.

Verweise und **weitere Informationen zu BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
