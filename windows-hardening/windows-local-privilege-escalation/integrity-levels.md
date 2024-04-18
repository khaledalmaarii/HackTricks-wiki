# Integritätsstufen

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihre Engine **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

---

## Integritätsstufen

In Windows Vista und späteren Versionen sind alle geschützten Elemente mit einem **Integritätsstufen**-Tag versehen. Dieses Setup weist in der Regel Dateien und Registrierungsschlüsseln eine "mittlere" Integritätsstufe zu, mit Ausnahme bestimmter Ordner und Dateien, auf die Internet Explorer 7 auf einer niedrigen Integritätsstufe schreiben kann. Das Standardverhalten besteht darin, dass Prozesse, die von Standardbenutzern initiiert werden, eine mittlere Integritätsstufe haben, während Dienste in der Regel auf Systemintegritätsstufe arbeiten. Ein Label mit hoher Integrität schützt das Stammverzeichnis.

Eine wichtige Regel besagt, dass Objekte nicht von Prozessen mit einer niedrigeren Integritätsstufe als der des Objekts geändert werden können. Die Integritätsstufen sind:

* **Nicht vertrauenswürdig**: Diese Stufe ist für Prozesse mit anonymen Anmeldungen. %%%Beispiel: Chrome%%%
* **Niedrig**: Hauptsächlich für Internetinteraktionen, insbesondere im geschützten Modus des Internet Explorers, beeinflusst damit verbundene Dateien und Prozesse sowie bestimmte Ordner wie den **Temporären Internetordner**. Prozesse mit niedriger Integrität unterliegen erheblichen Einschränkungen, einschließlich keinem Schreibzugriff auf die Registrierung und begrenztem Schreibzugriff auf Benutzerprofile.
* **Mittel**: Die Standardstufe für die meisten Aktivitäten, zugewiesen an Standardbenutzer und Objekte ohne spezifische Integritätsstufen. Selbst Mitglieder der Administratorengruppe arbeiten standardmäßig auf dieser Stufe.
* **Hoch**: Reserviert für Administratoren, die es ihnen ermöglicht, Objekte auf niedrigeren Integritätsstufen zu ändern, einschließlich solcher auf der hohen Stufe selbst.
* **System**: Die höchste Betriebsstufe für den Windows-Kernel und Kernservices, selbst für Administratoren unerreichbar, um die wichtigen Systemfunktionen zu schützen.
* **Installer**: Eine einzigartige Stufe, die über allen anderen steht und es Objekten auf dieser Stufe ermöglicht, jedes andere Objekt zu deinstallieren.

Sie können die Integritätsstufe eines Prozesses mit **Process Explorer** von **Sysinternals** abrufen, indem Sie auf die **Eigenschaften** des Prozesses zugreifen und den Tab "**Sicherheit**" anzeigen:

![](<../../.gitbook/assets/image (821).png>)

Sie können auch Ihre **aktuelle Integritätsstufe** mit `whoami /groups` abrufen

![](<../../.gitbook/assets/image (322).png>)

### Integritätsstufen im Dateisystem

Ein Objekt im Dateisystem kann einen **mindestens erforderlichen Integritätsstufen** haben, und wenn ein Prozess diese Integritätsstufe nicht hat, kann er nicht damit interagieren.\
Zum Beispiel, lassen Sie uns **eine Datei aus einer regulären Benutzerkonsole erstellen und die Berechtigungen überprüfen**:
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
Jetzt weisen wir der Datei ein minimales Integritätsniveau von **Hoch** zu. Dies **muss von einer Konsole** ausgeführt werden, die als **Administrator** läuft, da eine **normale Konsole** im Medium-Integritätsniveau läuft und **nicht berechtigt ist**, das Hoch-Integritätsniveau einem Objekt zuzuweisen:
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
Das ist der interessante Teil. Sie können sehen, dass der Benutzer `DESKTOP-IDJHTKP\user` **VOLLE Berechtigungen** über die Datei hat (tatsächlich war dies der Benutzer, der die Datei erstellt hat), jedoch aufgrund des implementierten minimalen Integritätslevels wird er die Datei nicht mehr ändern können, es sei denn, er führt sie auf einem hohen Integritätslevel aus (beachten Sie, dass er sie weiterhin lesen kann):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Daher, wenn eine Datei ein minimales Integritätsniveau hat, müssen Sie mindestens auf diesem Integritätsniveau ausgeführt werden, um sie zu ändern.**
{% endhint %}

### Integritätsniveaus in Binärdateien

Ich habe eine Kopie von `cmd.exe` in `C:\Windows\System32\cmd-low.exe` erstellt und ihm ein **Integritätsniveau von niedrig aus einer Administrator-Konsole heraus zugewiesen:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Jetzt, wenn ich `cmd-low.exe` ausführe, wird es **unter einem niedrigen Integritätslevel** anstelle eines mittleren ausgeführt:

![](<../../.gitbook/assets/image (310).png>)

Für neugierige Personen, wenn Sie einem Binärdatei einen hohen Integritätslevel zuweisen (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), wird es nicht automatisch mit hohem Integritätslevel ausgeführt (wenn Sie es von einem mittleren Integritätslevel aus aufrufen - standardmäßig wird es unter einem mittleren Integritätslevel ausgeführt).

### Integritätslevel in Prozessen

Nicht alle Dateien und Ordner haben ein Mindestintegritätslevel, **aber alle Prozesse laufen unter einem Integritätslevel**. Und ähnlich wie bei dem, was mit dem Dateisystem passiert ist, **muss ein Prozess, der in einen anderen Prozess schreiben möchte, mindestens das gleiche Integritätslevel haben**. Das bedeutet, dass ein Prozess mit niedrigem Integritätslevel keinen Zugriff mit vollständigen Rechten auf einen Prozess mit mittlerem Integritätslevel öffnen kann.

Aufgrund der in diesem und im vorherigen Abschnitt kommentierten Einschränkungen wird aus Sicherheitssicht immer empfohlen, einen Prozess im niedrigsten möglichen Integritätslevel auszuführen.


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihre Engine **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}


<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
