# Access Tokens

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Access Tokens

Jeder **Benutzer, der** im System **angemeldet ist, hält ein Zugriffstoken mit Sicherheitsinformationen** für diese Anmeldesitzung. Das System erstellt ein Zugriffstoken, wenn der Benutzer sich anmeldet. **Jeder Prozess, der** im Namen des Benutzers **ausgeführt wird, hat eine Kopie des Zugriffstokens**. Das Token identifiziert den Benutzer, die Gruppen des Benutzers und die Berechtigungen des Benutzers. Ein Token enthält auch eine Anmelde-SID (Security Identifier), die die aktuelle Anmeldesitzung identifiziert.

Sie können diese Informationen sehen, indem Sie `whoami /all` ausführen.
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
or using _Process Explorer_ von Sysinternals (Prozess auswählen und "Sicherheit" Tab zugreifen):

![](<../../.gitbook/assets/image (772).png>)

### Lokaler Administrator

Wenn sich ein lokaler Administrator anmeldet, **werden zwei Zugriffstoken erstellt**: Eines mit Administratorrechten und eines mit normalen Rechten. **Standardmäßig** wird, wenn dieser Benutzer einen Prozess ausführt, das mit **regulären** (nicht-Administrator) **Rechten verwendet**. Wenn dieser Benutzer versucht, **etwas** **als Administrator** auszuführen ("Als Administrator ausführen" zum Beispiel), wird die **UAC** verwendet, um um Erlaubnis zu bitten.\
Wenn Sie [**mehr über die UAC erfahren möchten, lesen Sie diese Seite**](../authentication-credentials-uac-and-efs/#uac)**.**

### Anmeldeinformationen Benutzerimitation

Wenn Sie **gültige Anmeldeinformationen eines anderen Benutzers** haben, können Sie **eine neue Anmeldesitzung** mit diesen Anmeldeinformationen **erstellen**:
```
runas /user:domain\username cmd.exe
```
Das **Zugriffs-Token** hat auch einen **Verweis** auf die Anmeldesitzungen innerhalb des **LSASS**, dies ist nützlich, wenn der Prozess auf einige Objekte des Netzwerks zugreifen muss.\
Sie können einen Prozess starten, der **verschiedene Anmeldeinformationen für den Zugriff auf Netzwerkdienste verwendet** mit:
```
runas /user:domain\username /netonly cmd.exe
```
Dies ist nützlich, wenn Sie nützliche Anmeldeinformationen haben, um auf Objekte im Netzwerk zuzugreifen, diese Anmeldeinformationen jedoch auf dem aktuellen Host nicht gültig sind, da sie nur im Netzwerk verwendet werden (auf dem aktuellen Host werden Ihre aktuellen Benutzerprivilegien verwendet).

### Arten von Tokens

Es gibt zwei Arten von Tokens:

* **Primäres Token**: Es dient als Darstellung der Sicherheitsanmeldeinformationen eines Prozesses. Die Erstellung und Zuordnung von primären Tokens zu Prozessen sind Aktionen, die erhöhte Privilegien erfordern, was das Prinzip der Privilegientrennung betont. Typischerweise ist ein Authentifizierungsdienst für die Token-Erstellung verantwortlich, während ein Anmeldedienst dessen Zuordnung zur Betriebssystem-Shell des Benutzers übernimmt. Es ist erwähnenswert, dass Prozesse das primäre Token ihres übergeordneten Prozesses bei der Erstellung erben.
* **Impersonation Token**: Ermöglicht einer Serveranwendung, vorübergehend die Identität des Clients anzunehmen, um auf sichere Objekte zuzugreifen. Dieser Mechanismus ist in vier Betriebsstufen unterteilt:
* **Anonym**: Gewährt dem Server Zugriff ähnlich dem eines nicht identifizierten Benutzers.
* **Identifikation**: Ermöglicht es dem Server, die Identität des Clients zu überprüfen, ohne sie für den Objektzugriff zu nutzen.
* **Impersonation**: Ermöglicht es dem Server, unter der Identität des Clients zu arbeiten.
* **Delegation**: Ähnlich wie Impersonation, umfasst jedoch die Fähigkeit, diese Identitätsübernahme auf entfernte Systeme auszudehnen, mit denen der Server interagiert, um die Anmeldeinformationen zu bewahren.

#### Impersonate Tokens

Mit dem _**incognito**_ Modul von Metasploit können Sie, wenn Sie über genügend Privilegien verfügen, andere **Tokens** leicht **auflisten** und **nachahmen**. Dies könnte nützlich sein, um **Aktionen auszuführen, als ob Sie der andere Benutzer wären**. Sie könnten auch mit dieser Technik **Privilegien erhöhen**.

### Token-Privilegien

Erfahren Sie, welche **Token-Privilegien missbraucht werden können, um Privilegien zu erhöhen:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Werfen Sie einen Blick auf [**alle möglichen Token-Privilegien und einige Definitionen auf dieser externen Seite**](https://github.com/gtworek/Priv2Admin).

## Referenzen

Erfahren Sie mehr über Tokens in diesen Tutorials: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) und [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)


{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
