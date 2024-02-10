<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>


# Integritätsstufen

In Windows Vista und späteren Versionen sind alle geschützten Objekte mit einem **Integritätsstufen**-Tag versehen. In der Regel wird die Integritätsstufe "Medium" für Dateien und Registrierungsschlüssel zugewiesen, mit Ausnahme bestimmter Ordner und Dateien, auf die Internet Explorer 7 mit niedriger Integritätsstufe schreiben kann. Das Standardverhalten besteht darin, dass Prozesse, die von Standardbenutzern gestartet werden, eine mittlere Integritätsstufe haben, während Dienste in der Regel mit einer Systemintegritätsstufe arbeiten. Ein Label mit hoher Integrität schützt das Stammverzeichnis.

Eine wichtige Regel besagt, dass Objekte nicht von Prozessen mit einer niedrigeren Integritätsstufe als der des Objekts geändert werden können. Die Integritätsstufen sind:

- **Untrusted**: Diese Stufe gilt für Prozesse mit anonymen Anmeldungen. %%%Beispiel: Chrome%%%
- **Low**: Hauptsächlich für Internetinteraktionen, insbesondere im geschützten Modus von Internet Explorer, der sich auf zugehörige Dateien und Prozesse sowie bestimmte Ordner wie den **Temporary Internet Folder** auswirkt. Prozesse mit niedriger Integrität unterliegen erheblichen Einschränkungen, einschließlich des Fehlens von Schreibzugriff auf die Registrierung und begrenztem Schreibzugriff auf Benutzerprofile.
- **Medium**: Die Standardstufe für die meisten Aktivitäten, zugewiesen an Standardbenutzer und Objekte ohne spezifische Integritätsstufen. Selbst Mitglieder der Administratorengruppe arbeiten standardmäßig auf dieser Stufe.
- **High**: Für Administratoren reserviert, ermöglicht es ihnen, Objekte auf niedrigeren Integritätsstufen zu ändern, einschließlich solcher auf der hohen Stufe selbst.
- **System**: Die höchste Betriebsstufe für den Windows-Kernel und Kernservices, selbst für Administratoren unerreichbar, um den Schutz wichtiger Systemfunktionen zu gewährleisten.
- **Installer**: Eine einzigartige Stufe, die über allen anderen steht und Objekten auf dieser Stufe ermöglicht, jedes andere Objekt zu deinstallieren.

Sie können die Integritätsstufe eines Prozesses mit **Process Explorer** von **Sysinternals** abrufen, indem Sie die **Eigenschaften** des Prozesses aufrufen und den Tab "**Sicherheit**" anzeigen:

![](<../../.gitbook/assets/image (318).png>)

Sie können auch Ihre **aktuelle Integritätsstufe** mit `whoami /groups` abrufen.

![](<../../.gitbook/assets/image (319).png>)

## Integritätsstufen im Dateisystem

Ein Objekt im Dateisystem kann eine **Mindestintegritätsstufenanforderung** haben, und wenn ein Prozess diese Integritätsstufe nicht hat, kann er nicht damit interagieren.\
Zum Beispiel erstellen wir eine **reguläre Datei aus einer regulären Benutzerkonsole und überprüfen die Berechtigungen**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Jetzt weisen wir der Datei ein Mindestintegritätslevel von **Hoch** zu. Dies **muss von einer Konsole** ausgeführt werden, die als **Administrator** läuft, da eine **normale Konsole** im Medium-Integritätslevel ausgeführt wird und **nicht berechtigt ist**, dem Objekt ein Hoch-Integritätslevel zuzuweisen:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Hier wird es interessant. Sie können sehen, dass der Benutzer `DESKTOP-IDJHTKP\user` **VOLLSTÄNDIGE Berechtigungen** für die Datei hat (tatsächlich hat dieser Benutzer die Datei erstellt). Aufgrund des implementierten Mindestintegritätslevels kann er die Datei jedoch nicht mehr ändern, es sei denn, er führt sie mit einem hohen Integritätslevel aus (beachten Sie, dass er sie weiterhin lesen kann):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Daher müssen Sie, um eine Datei mit einem Mindestintegritätslevel zu ändern, mindestens in diesem Integritätslevel ausgeführt werden.**
{% endhint %}

## Integritätslevel in Binärdateien

Ich habe eine Kopie von `cmd.exe` in `C:\Windows\System32\cmd-low.exe` erstellt und ihm einen **Integritätslevel von niedrig aus einer Administrator-Konsole zugewiesen:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Jetzt, wenn ich `cmd-low.exe` ausführe, wird es **unter einem niedrigen Integritätslevel** anstatt eines mittleren ausgeführt:

![](<../../.gitbook/assets/image (320).png>)

Für neugierige Menschen, wenn Sie einem Binärdatei einen hohen Integritätslevel zuweisen (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), wird es nicht automatisch mit hohem Integritätslevel ausgeführt (wenn Sie es aus einem mittleren Integritätslevel aufrufen - standardmäßig - wird es unter einem mittleren Integritätslevel ausgeführt).

## Integritätslevel in Prozessen

Nicht alle Dateien und Ordner haben einen Mindestintegritätslevel, **aber alle Prozesse laufen unter einem Integritätslevel**. Und ähnlich wie bei dem, was mit dem Dateisystem passiert ist, **muss ein Prozess, der in einen anderen Prozess schreiben möchte, mindestens den gleichen Integritätslevel haben**. Das bedeutet, dass ein Prozess mit niedrigem Integritätslevel keinen Handle mit vollem Zugriff auf einen Prozess mit mittlerem Integritätslevel öffnen kann.

Aufgrund der in diesem und im vorherigen Abschnitt genannten Einschränkungen wird aus Sicherheitsgründen immer empfohlen, einen Prozess mit dem niedrigsten möglichen Integritätslevel auszuführen.


<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
