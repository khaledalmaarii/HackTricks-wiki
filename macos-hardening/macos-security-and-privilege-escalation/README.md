# macOS Sicherheit & Privilege Escalation

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking-Einblicke**\
Beschäftigen Sie sich mit Inhalten, die sich mit dem Nervenkitzel und den Herausforderungen des Hackens befassen

**Echtzeit-Hack-News**\
Bleiben Sie mit der schnelllebigen Hacking-Welt durch Echtzeitnachrichten und Einblicke auf dem Laufenden

**Neueste Ankündigungen**\
Bleiben Sie über die neuesten Bug-Bounties und wichtige Plattformupdates informiert

**Treten Sie uns bei** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginnen Sie noch heute mit der Zusammenarbeit mit Top-Hackern!

## Grundlagen MacOS

Wenn Sie mit macOS nicht vertraut sind, sollten Sie mit den Grundlagen von macOS beginnen:

* Besondere macOS-**Dateien & Berechtigungen:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Übliche macOS-**Benutzer**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* Die **Architektur** des k**ernels**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Übliche macOS-N**etzwerkdienste & Protokolle**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Um ein `tar.gz` herunterzuladen, ändern Sie eine URL wie [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) in [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

In Unternehmen werden **macOS-Systeme höchstwahrscheinlich mit einem MDM verwaltet**. Daher ist es aus der Sicht eines Angreifers interessant zu wissen, **wie das funktioniert**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspektion, Debugging und Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS Sicherheitsschutz

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Angriffsfläche

### Dateiberechtigungen

Wenn ein **als Root ausgeführter Prozess eine Datei schreibt**, die von einem Benutzer kontrolliert werden kann, könnte der Benutzer dies missbrauchen, um **Berechtigungen zu eskalieren**.\
Dies könnte in folgenden Situationen auftreten:

* Die verwendete Datei wurde bereits von einem Benutzer erstellt (im Besitz des Benutzers)
* Die verwendete Datei ist aufgrund einer Gruppe vom Benutzer beschreibbar
* Die verwendete Datei befindet sich in einem Verzeichnis im Besitz des Benutzers (der Benutzer könnte die Datei erstellen)
* Die verwendete Datei befindet sich in einem Verzeichnis im Besitz von Root, aber der Benutzer hat Schreibzugriff darauf aufgrund einer Gruppe (der Benutzer könnte die Datei erstellen)

Die Möglichkeit, eine Datei zu erstellen, die von Root verwendet wird, ermöglicht es einem Benutzer, **den Inhalt zu nutzen** oder sogar **Symlinks/Hardlinks** zu erstellen, um sie an einen anderen Ort zu verweisen.

Vergessen Sie bei solchen Schwachstellen nicht, anfällige `.pkg`-Installationsprogramme zu überprüfen:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Dateierweiterung & URL-Schema-App-Handler

Seltsame Apps, die sich über Dateierweiterungen registrieren lassen, könnten missbraucht werden, und verschiedene Anwendungen können registriert werden, um bestimmte Protokolle zu öffnen

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Privilege Escalation

In macOS können **Anwendungen und Binärdateien Berechtigungen** haben, auf Ordner oder Einstellungen zuzugreifen, die sie privilegierter machen als andere.

Daher muss ein Angreifer, der erfolgreich eine macOS-Maschine kompromittieren möchte, seine **TCC-Berechtigungen eskalieren** (oder sogar **SIP umgehen**, je nach Bedarf).

Diese Berechtigungen werden normalerweise in Form von **Berechtigungen** vergeben, mit denen die Anwendung signiert ist, oder die Anwendung könnte einige Zugriffe angefordert haben und nachdem der **Benutzer sie genehmigt hat**, können sie in den **TCC-Datenbanken** gefunden werden. Ein anderer Weg, wie ein Prozess diese Berechtigungen erhalten kann, besteht darin, ein **Kind eines Prozesses** mit diesen **Berechtigungen** zu sein, da sie normalerweise **vererbt** werden.

Folgen Sie diesen Links, um verschiedene Möglichkeiten zu finden, [**Berechtigungen in TCC zu eskalieren**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), um **TCC zu umgehen**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) und wie in der Vergangenheit [**SIP umgangen wurde**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Traditionelle Privilege Escalation

Natürlich sollte man auch aus der Perspektive eines Red Teams daran interessiert sein, zu Root zu eskalieren. Überprüfen Sie den folgenden Beitrag für einige Hinweise:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Referenzen

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking-Einblicke**\
Beschäftigen Sie sich mit Inhalten, die sich mit dem Nervenkitzel und den Herausforderungen des Hackens befassen

**Echtzeit-Hack-News**\
Bleiben Sie mit der schnelllebigen Hacking-Welt durch Echtzeit-Nachrichten und Einblicke auf dem Laufenden

**Neueste Ankündigungen**\
Bleiben Sie über die neuesten Bug-Bounties und wichtige Plattformupdates informiert

**Treten Sie uns bei** [**Discord**](https://discord.com/invite/N3FrSbmwdy) und beginnen Sie noch heute mit der Zusammenarbeit mit Top-Hackern!

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
