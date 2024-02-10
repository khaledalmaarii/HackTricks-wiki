# macOS-Sicherheitsschutz

<details>

<summary><strong>Erlernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Gatekeeper

Gatekeeper bezieht sich in der Regel auf die Kombination aus **Quarantäne + Gatekeeper + XProtect**, drei macOS-Sicherheitsmodule, die versuchen, **Benutzer daran zu hindern, potenziell schädliche Software auszuführen**, die heruntergeladen wurde.

Weitere Informationen finden Sie unter:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Prozessbeschränkungen

### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

Die macOS-Sandbox **beschränkt Anwendungen**, die innerhalb der Sandbox ausgeführt werden, auf die in dem Sandbox-Profil festgelegten **zulässigen Aktionen**. Dadurch wird sichergestellt, dass die Anwendung nur auf erwartete Ressourcen zugreift.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparenz, Zustimmung und Kontrolle**

**TCC (Transparenz, Zustimmung und Kontrolle)** ist ein Sicherheitsframework. Es ist darauf ausgelegt, die Berechtigungen von Anwendungen zu **verwalten**, insbesondere durch die Regulierung ihres Zugriffs auf sensible Funktionen. Dies umfasst Elemente wie **Standortdienste, Kontakte, Fotos, Mikrofon, Kamera, Barrierefreiheit und vollständigen Festplattenzugriff**. TCC stellt sicher, dass Apps nur nach expliziter Zustimmung des Benutzers auf diese Funktionen zugreifen können, um die Privatsphäre und Kontrolle über persönliche Daten zu stärken.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Start-/Umgebungseinschränkungen und Trust Cache

Starteinschränkungen in macOS sind eine Sicherheitsfunktion zur **Regulierung der Prozessinitiierung**, indem definiert wird, **wer**, **wie** und **von wo aus** einen Prozess starten kann. Eingeführt in macOS Ventura, kategorisieren sie Systembinärdateien in Einschränkungskategorien innerhalb eines **Trust Cache**. Jede ausführbare Binärdatei hat festgelegte **Regeln** für ihren Start, einschließlich **Selbst**, **Eltern** und **Verantwortlicher** Einschränkungen. Diese Funktionen, die in macOS Sonoma als **Umgebungseinschränkungen** für Drittanbieter-Apps erweitert wurden, tragen dazu bei, potenzielle Systemausnutzungen durch die Steuerung der Startbedingungen von Prozessen zu mindern.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malware Removal Tool

Das Malware Removal Tool (MRT) ist ein weiterer Teil der Sicherheitsinfrastruktur von macOS. Wie der Name schon sagt, besteht die Hauptfunktion von MRT darin, **bekannte Malware von infizierten Systemen zu entfernen**.

Sobald Malware auf einem Mac erkannt wird (entweder durch XProtect oder auf andere Weise), kann MRT verwendet werden, um die Malware automatisch zu **entfernen**. MRT arbeitet im Hintergrund und wird in der Regel ausgeführt, wenn das System aktualisiert wird oder wenn eine neue Malware-Definition heruntergeladen wird (es sieht so aus, als ob die Regeln, die MRT zum Erkennen von Malware hat, in der Binärdatei enthalten sind).

Während sowohl XProtect als auch MRT Teil der Sicherheitsmaßnahmen von macOS sind, erfüllen sie unterschiedliche Funktionen:

* **XProtect** ist ein präventives Tool. Es **überprüft Dateien beim Herunterladen** (über bestimmte Anwendungen) und wenn es bekannte Arten von Malware erkennt, **verhindert es das Öffnen der Datei**, um die Infektion Ihres Systems von vornherein zu verhindern.
* **MRT** hingegen ist ein **reaktives Tool**. Es arbeitet nach der Erkennung von Malware auf einem System und hat das Ziel, die schädliche Software zu entfernen, um das System zu bereinigen.

Die MRT-Anwendung befindet sich in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Verwaltung von Hintergrundaufgaben

**macOS** gibt jetzt jedes Mal eine **Warnung aus**, wenn ein Tool eine bekannte **Technik zur dauerhaften Ausführung von Code** verwendet (wie z.B. Login-Elemente, Daemons...), damit der Benutzer besser weiß, **welche Software dauerhaft ist**.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

Dies geschieht mit einem **Daemon**, der sich in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` befindet, und dem **Agenten** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Die Art und Weise, wie **`backgroundtaskmanagementd`** erkennt, dass etwas in einem persistenten Ordner installiert ist, besteht darin, die **FSEvents abzurufen** und einige **Handler** dafür zu erstellen.

Darüber hinaus gibt es eine Plist-Datei, die **bekannte Anwendungen** enthält, die häufig von Apple beibehalten werden und sich unter: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist` befindet.
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
### Enumeration

Es ist möglich, **alle konfigurierten Hintergrundelemente** mithilfe des Apple CLI-Tools aufzulisten:
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

### Manipulation von BTM

Wenn eine neue Persistenz gefunden wird, wird ein Ereignis vom Typ **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** ausgelöst. Jeder Weg, um dieses Ereignis daran zu hindern, gesendet zu werden, oder um den Benutzer vor der Benachrichtigung des Agents zu warnen, hilft einem Angreifer dabei, BTM zu umgehen.

* **Zurücksetzen der Datenbank**: Das Ausführen des folgenden Befehls setzt die Datenbank zurück (sie sollte neu aufgebaut werden), jedoch wird aus irgendeinem Grund nach dem Ausführen dieses Befehls **keine neue Persistenz benachrichtigt, bis das System neu gestartet wird**.
* **root** ist erforderlich.
```bash
# Reset the database
sfltool resettbtm
```
* **Agent stoppen**: Es ist möglich, ein Stoppsignal an den Agenten zu senden, damit er den Benutzer nicht benachrichtigt, wenn neue Erkennungen gefunden werden.
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
* **Fehler**: Wenn der **Prozess, der die Persistenz erstellt hat, kurz danach beendet wird**, versucht der Daemon, **Informationen darüber zu erhalten**, **scheitert** jedoch und **kann das Ereignis nicht senden**, das anzeigt, dass etwas Neues persistiert wird.

Referenzen und **weitere Informationen zu BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
