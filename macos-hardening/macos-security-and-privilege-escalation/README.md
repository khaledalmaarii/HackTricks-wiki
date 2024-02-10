# macOS Sicherheit & Privilege Escalation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Insights**\
Beschäftigen Sie sich mit Inhalten, die sich mit dem Nervenkitzel und den Herausforderungen des Hackens befassen.

**Echtzeit-Hack-News**\
Bleiben Sie mit der schnelllebigen Hacking-Welt durch Echtzeit-Nachrichten und Einblicke auf dem Laufenden.

**Neueste Ankündigungen**\
Bleiben Sie über die neuesten Bug-Bounties und wichtige Plattformupdates informiert.

**Treten Sie uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginnen Sie noch heute mit Top-Hackern zusammenzuarbeiten!

## Grundlagen von MacOS

Wenn Sie mit macOS nicht vertraut sind, sollten Sie mit den Grundlagen von macOS beginnen:

* Besondere macOS-**Dateien & Berechtigungen:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Gemeinsame macOS-**Benutzer**

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

* Gemeinsame macOS-N**etzwerkdienste & Protokolle**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Um eine `tar.gz` herunterzuladen, ändern Sie eine URL wie [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) in [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

In Unternehmen werden **macOS**-Systeme höchstwahrscheinlich mit einem MDM verwaltet. Daher ist es aus der Sicht eines Angreifers interessant zu wissen, **wie das funktioniert**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspektion, Debugging und Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS-Sicherheitsschutzmaßnahmen

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Angriffsfläche

### Dateiberechtigungen

Wenn ein **Prozess, der als root ausgeführt wird**, eine Datei schreibt, die von einem Benutzer kontrolliert werden kann, könnte der Benutzer dies missbrauchen, um **Privilegien zu eskalieren**.\
Dies kann in folgenden Situationen auftreten:

* Die verwendete Datei wurde bereits von einem Benutzer erstellt (im Besitz des Benutzers)
* Die verwendete Datei ist aufgrund einer Gruppe schreibbar für den Benutzer
* Die verwendete Datei befindet sich in einem Verzeichnis, das dem Benutzer gehört (der Benutzer könnte die Datei erstellen)
* Die verwendete Datei befindet sich in einem Verzeichnis, das root gehört, aber der Benutzer hat Schreibzugriff darauf aufgrund einer Gruppe (der Benutzer könnte die Datei erstellen)

Die Möglichkeit, eine Datei zu erstellen, die von root verwendet wird, ermöglicht es einem Benutzer, deren Inhalt auszunutzen oder sogar **Symlinks/Hardlinks** zu erstellen, um sie an einen anderen Ort zu verweisen.

Vergessen Sie bei solchen Sicherheitslücken nicht, anfällige `.pkg`-Installationsprogramme zu überprüfen:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}



### Dateierweiterung & URL-Schema-App-Handler

Seltsame Apps, die durch Dateierweiterungen registriert sind, können missbraucht werden, und verschiedene Anwendungen können registriert werden, um bestimmte Protokolle zu öffnen.

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Privilege Escalation

In macOS können **Anwendungen und Binärdateien Berechtigungen** haben, auf Ordner oder Einstellungen zuzugreifen, die sie privilegierter machen als andere.

Daher muss ein Angreifer, der eine macOS-Maschine erfolgreich kompromittieren möchte, seine TCC-Berechtigungen (oder sogar SIP umgehen, je nach Bedarf) **eskaliert**.

Diese Berechtigungen werden normalerweise in Form von **Entitlements** vergeben, mit denen die Anwendung signiert ist, oder die Anwendung kann einige Zugriffe angefordert haben und nach der **Genehmigung durch den Benutzer** können sie in den **TCC-Datenbanken** gefunden werden. Eine andere Möglichkeit, dass ein Prozess diese Berechtigungen erhält, besteht darin, ein **Kindprozess eines Prozesses** mit diesen **Berechtigungen** zu sein, da sie normalerweise **vererbt** werden.

Folgen Sie diesen Links, um verschiedene Möglichkeiten zu finden, [**Berechtigungen in TCC zu eskalieren**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), TCC zu **umgehen**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) und wie in der Vergangenheit [**SIP umgangen wurde**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Traditionelle Privilege Escalation

Natürlich sollten Sie als Red Team auch daran interessiert sein, zu root zu eskalieren. Überprüfen Sie den folgenden Beitrag für einige Hinweise:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Referenzen

* [**OS X Incident Response: Scripting und Analyse**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Insights**\
Beschäftigen Sie sich mit Inhalten, die sich mit dem Nervenkitzel und den Herausforderungen des Hackens befassen.

**Echtzeit-Hack-News**\
Bleiben Sie mit den schnelllebigen Hacking-Welt durch Echtzeit-Nachrichten und Einblicke auf dem Laufenden.

**Neueste Ankündigungen**\
Bleiben Sie über die neuesten Bug-Bounties und wichtige Plattformupdates informiert.

**Treten Sie uns bei** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginnen Sie noch heute mit Top-Hackern zusammenzuarbeiten!

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
