# Zugriffstoken

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) bei oder der [**Telegram-Gruppe**](https://t.me/peass) oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **einreichen**.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihr Tool **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

---

## Zugriffstoken

Jeder **angemeldete Benutzer** im System **besitzt ein Zugriffstoken mit Sicherheitsinformationen** für diese Anmeldesitzung. Das System erstellt ein Zugriffstoken, wenn sich der Benutzer anmeldet. **Jeder im Namen des Benutzers ausgeführte Prozess** hat eine Kopie des Zugriffstokens. Das Token identifiziert den Benutzer, die Gruppen des Benutzers und die Berechtigungen des Benutzers. Ein Token enthält auch eine Anmeldesitzungs-SID (Sicherheitskennung), die die aktuelle Anmeldesitzung identifiziert.

Sie können diese Informationen anzeigen, indem Sie `whoami /all` ausführen.
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
oder mit _Process Explorer_ von Sysinternals (Prozess auswählen und auf die Registerkarte "Sicherheit" zugreifen):

![](<../../.gitbook/assets/image (769).png>)

### Lokaler Administrator

Wenn sich ein lokaler Administrator anmeldet, **werden zwei Zugriffstoken erstellt**: Eines mit Administratorrechten und das andere mit normalen Rechten. **Standardmäßig** wird bei der Ausführung eines Prozesses durch diesen Benutzer das mit **normalen** (nicht-Administrator) **Rechten verwendet**. Wenn dieser Benutzer versucht, **etwas als Administrator auszuführen** ("Als Administrator ausführen" zum Beispiel), wird die **UAC** verwendet, um um Erlaubnis zu bitten.\
Wenn Sie mehr über die UAC erfahren möchten, lesen Sie diese Seite [**hier**](../authentication-credentials-uac-and-efs/#uac)**.**

### Benutzerimitation von Anmeldeinformationen

Wenn Sie **gültige Anmeldeinformationen eines anderen Benutzers haben**, können Sie eine **neue Anmeldesitzung** mit diesen Anmeldeinformationen **erstellen**:
```
runas /user:domain\username cmd.exe
```
Das **Zugriffstoken** enthält auch eine **Referenz** der Anmeldesitzungen innerhalb des **LSASS**. Dies ist nützlich, wenn der Prozess auf Objekte im Netzwerk zugreifen muss.\
Sie können einen Prozess starten, der **verschiedene Anmeldeinformationen für den Zugriff auf Netzwerkdienste verwendet**, indem Sie:
```
runas /user:domain\username /netonly cmd.exe
```
### Arten von Tokens

Es gibt zwei Arten von verfügbaren Tokens:

- **Primäres Token**: Dient als Repräsentation der Sicherheitsanmeldeinformationen eines Prozesses. Die Erstellung und Zuordnung von primären Tokens zu Prozessen sind Aktionen, die erhöhte Berechtigungen erfordern und das Prinzip der Berechtigungstrennung betonen. Typischerweise ist ein Authentifizierungsdienst für die Token-Erstellung verantwortlich, während ein Anmeldedienst die Zuordnung mit der Betriebssystemshell des Benutzers behandelt. Es ist erwähnenswert, dass Prozesse das Primärtoken ihres übergeordneten Prozesses bei der Erstellung erben.
- **Imitierungs-Token**: Ermächtigt eine Serveranwendung, vorübergehend die Identität des Clients anzunehmen, um auf sichere Objekte zuzugreifen. Dieser Mechanismus ist in vier Betriebsstufen unterteilt:
  - **Anonym**: Gewährt dem Server Zugriff ähnlich wie einem nicht identifizierten Benutzer.
  - **Identifikation**: Ermöglicht es dem Server, die Identität des Clients zu überprüfen, ohne sie für den Objektzugriff zu verwenden.
  - **Imitierung**: Ermöglicht es dem Server, unter der Identität des Clients zu arbeiten.
  - **Delegation**: Ähnlich wie Imitierung, beinhaltet jedoch die Möglichkeit, diese Identitätsannahme auf entfernte Systeme auszudehnen, mit denen der Server interagiert, um die Aufrechterhaltung von Anmeldeinformationen sicherzustellen.

#### Imitieren von Tokens

Mit dem _**incognito**_ Modul von Metasploit können Sie bei ausreichenden Berechtigungen einfach **Liste** und **Imitieren** anderer **Tokens**. Dies könnte nützlich sein, um **Aktionen auszuführen, als wären Sie der andere Benutzer**. Sie könnten auch mit dieser Technik **Berechtigungen eskalieren**.

### Token-Berechtigungen

Erfahren Sie, welche **Token-Berechtigungen missbraucht werden können, um Berechtigungen zu eskalieren:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Werfen Sie einen Blick auf [**alle möglichen Token-Berechtigungen und einige Definitionen auf dieser externen Seite**](https://github.com/gtworek/Priv2Admin).

## Referenzen

Erfahren Sie mehr über Tokens in diesen Tutorials: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) und [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von Dark Web angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihre Engine **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Erfahren Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

- Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks in PDF** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
- Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
- Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
- **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**HackTricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**HackTricks-Cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **einreichen**.

</details>
