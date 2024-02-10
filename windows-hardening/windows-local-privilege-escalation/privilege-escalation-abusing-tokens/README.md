# Missbrauch von Tokens

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF-Download** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>

## Tokens

Wenn Sie nicht wissen, was Windows Access Tokens sind, lesen Sie diese Seite, bevor Sie fortfahren:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Vielleicht können Sie Berechtigungen eskalieren, indem Sie die Tokens missbrauchen, die Sie bereits haben**

### SeImpersonatePrivilege

Dies ist ein Privileg, das von jedem Prozess gehalten wird und die Impersonation (aber nicht die Erstellung) eines beliebigen Tokens ermöglicht, sofern ein Handle dafür erhalten werden kann. Ein privilegiertes Token kann von einem Windows-Dienst (DCOM) erworben werden, indem man ihn dazu bringt, eine NTLM-Authentifizierung gegen einen Exploit durchzuführen, was anschließend die Ausführung eines Prozesses mit SYSTEM-Berechtigungen ermöglicht. Diese Schwachstelle kann mit verschiedenen Tools ausgenutzt werden, wie z.B. [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (das winrm deaktiviert erfordert), [SweetPotato](https://github.com/CCob/SweetPotato) und [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Es ist sehr ähnlich wie **SeImpersonatePrivilege**, es wird die **gleiche Methode** verwendet, um ein privilegiertes Token zu erhalten.\
Dann ermöglicht dieses Privileg, einem neuen/ausgesetzten Prozess ein **primäres Token zuzuweisen**. Mit dem privilegierten Impersonation-Token können Sie ein primäres Token ableiten (DuplicateTokenEx).\
Mit dem Token können Sie einen **neuen Prozess** mit 'CreateProcessAsUser' erstellen oder einen Prozess im Ruhezustand erstellen und das Token setzen (im Allgemeinen können Sie das primäre Token eines laufenden Prozesses nicht ändern).

### SeTcbPrivilege

Wenn Sie dieses Token aktiviert haben, können Sie **KERB\_S4U\_LOGON** verwenden, um ein **Impersonation-Token** für einen beliebigen anderen Benutzer ohne Kenntnis der Anmeldeinformationen zu erhalten, eine **beliebige Gruppe** (Administratoren) dem Token hinzufügen, das **Integritätsniveau** des Tokens auf "**medium**" setzen und dieses Token dem **aktuellen Thread** zuweisen (SetThreadToken).

### SeBackupPrivilege

Das System gewährt durch dieses Privileg **Lesezugriff** auf jede Datei (beschränkt auf Lesevorgänge). Es wird verwendet, um die Passworthashes der lokalen Administrator-Konten aus der Registrierung zu lesen, wonach Tools wie "**psexec**" oder "**wmicexec**" mit dem Hash (Pass-the-Hash-Technik) verwendet werden können. Diese Technik funktioniert jedoch unter zwei Bedingungen nicht: wenn das lokale Administrator-Konto deaktiviert ist oder wenn eine Richtlinie vorhanden ist, die Administratoren, die sich remote verbinden, die administrativen Rechte entzieht.\
Sie können dieses Privileg missbrauchen mit:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* folgen Sie **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Oder wie im Abschnitt **Berechtigungen eskalieren mit Backup-Operatoren** erklärt in:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Dieses Privileg ermöglicht **Schreibzugriff** auf jede Systemdatei, unabhängig von der Zugriffssteuerungsliste (ACL) der Datei. Es eröffnet zahlreiche Möglichkeiten zur Eskalation, einschließlich der Möglichkeit, **Dienste zu modifizieren**, DLL-Hijacking durchzuführen und **Debugger** über Image File Execution Options zu setzen, sowie verschiedene andere Techniken.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ist eine leistungsstarke Berechtigung, die besonders nützlich ist, wenn ein Benutzer die Fähigkeit besitzt, Tokens zu impersonieren, aber auch in Abwesenheit von SeImpersonatePrivilege. Diese Fähigkeit hängt von der Fähigkeit ab, ein Token zu impersonieren, das denselben Benutzer repräsentiert und dessen Integritätsniveau das des aktuellen Prozesses nicht übersteigt.

**Wichtige Punkte:**
- **Impersonation ohne SeImpersonatePrivilege:** Es ist möglich, SeCreateTokenPrivilege für EoP zu nutzen, indem Tokens unter bestimmten Bedingungen impersoniert werden.
- **Bedingungen für Token-Impersonation:** Die erfolgreiche Impersonation erfordert, dass das Ziel-Token demselben Benutzer gehört und ein Integritätsniveau hat, das kleiner oder gleich dem Integritätsniveau des Prozesses ist, der die Impersonation versucht.
- **Erstellung und Änderung von Impersonation-Tokens:** Benutzer können ein Impersonation-Token erstellen und es verbessern, indem sie die SID (Security Identifier) einer privilegierten Gruppe hinzufügen.


### SeLoadDriverPrivilege

Dieses Privileg ermöglicht das **Laden und Entladen von Gerätetreibern** durch das Erstellen eines Registrierungseintrags mit spezifischen Werten für `ImagePath` und `Type`. Da der direkte Schreibzugriff auf `HKLM` (HKEY_LOCAL_MACHINE) eingeschränkt ist, muss stattdessen `HKCU` (HKEY_CURRENT_USER) verwendet werden. Um jedoch `HKCU` für den Kernel zur Treiberkonfiguration erkennbar zu machen, muss ein bestimmter Pfad befolgt werden.

Dieser Pfad lautet `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, wobei `<RID>` die Relative Identifier des aktuellen Benutzers ist. Innerhalb von `HKCU` muss dieser gesamte Pfad erstellt und zwei Werte festgelegt werden:
- `ImagePath`, der Pfad zur auszuführenden Binärdatei
- `Type` mit einem Wert von
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Weitere Möglichkeiten, dieses Privileg zu missbrauchen, finden Sie unter [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dies ist ähnlich wie **SeRestorePrivilege**. Seine Hauptfunktion ermöglicht es einem Prozess, **Eigentum an einem Objekt zu übernehmen**, um die Notwendigkeit expliziter diskretionärer Zugriffsrechte durch die Bereitstellung von WRITE_OWNER-Zugriffsrechten zu umgehen. Der Prozess besteht darin, zunächst das Eigentum am beabsichtigten Registrierungsschlüssel für Schreibzwecke zu sichern und dann die DACL zu ändern, um Schreiboperationen zu ermöglichen.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Dieses Privileg erlaubt das **Debuggen anderer Prozesse**, einschließlich des Lesens und Schreibens im Speicher. Mit diesem Privileg können verschiedene Strategien für die Speicherinjektion verwendet werden, die die meisten Antiviren- und Host-Intrusion-Prevention-Lösungen umgehen können.

#### Speicher dumpen

Sie können [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aus der [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) verwenden, um den Speicher eines Prozesses zu **erfassen**. Dies gilt insbesondere für den **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**-Prozess, der für die Speicherung von Benutzeranmeldeinformationen nach erfolgreicher Anmeldung eines Benutzers an einem System verantwortlich ist.

Sie können dann diesen Dump in mimikatz laden, um Passwörter zu erhalten:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Wenn Sie eine `NT SYSTEM`-Shell erhalten möchten, können Sie Folgendes verwenden:

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Überprüfen von Berechtigungen

To check the privileges of a user or process in Windows, you can use the following methods:

### 1. Using the Command Prompt

Open the Command Prompt as an administrator and run the following command:

```bash
whoami /priv
```

This command will display the privileges assigned to the current user.

### 2. Using PowerShell

Open PowerShell as an administrator and run the following command:

```powershell
(Get-Process -Id $pid).StartInfo.EnvironmentVariables
```

This command will display the environment variables, including the privileges, of the current process.

### 3. Using the Windows Management Instrumentation Command-line (WMIC)

Open the Command Prompt as an administrator and run the following command:

```bash
wmic process where name="explorer.exe" get name, elevatedtoken
```

Replace "explorer.exe" with the name of the process you want to check. This command will display the name and the status of the elevated token for the specified process.

### 4. Using the Sysinternals Suite

Download and install the Sysinternals Suite from the Microsoft website. Once installed, open the Command Prompt as an administrator and navigate to the directory where the suite is installed (usually `C:\Sysinternals`). Run the following command:

```bash
psexec -i -s cmd.exe
```

This command will open a new Command Prompt window with system privileges. You can then run the `whoami /priv` command to check the privileges.

By using these methods, you can easily check the privileges of a user or process in Windows. This information can be useful for identifying potential privilege escalation opportunities.
```
whoami /priv
```
Die **deaktivierten Tokens** können aktiviert werden und es ist möglich, sowohl _aktivierte_ als auch _deaktivierte_ Tokens zu missbrauchen.

### Aktiviere alle Tokens

Wenn du deaktivierte Tokens hast, kannst du das Skript [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) verwenden, um alle Tokens zu aktivieren:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oder das **Skript**, das in diesem [**Beitrag**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) eingebettet ist.

## Tabelle

Vollständige Übersicht über Token-Privilegien unter [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin). Die folgende Zusammenfassung listet nur direkte Möglichkeiten auf, um das Privileg auszunutzen und eine Administrator-Sitzung zu erlangen oder auf sensible Dateien zuzugreifen.

| Privileg                   | Auswirkung  | Tool                    | Ausführungspfad                                                                                                                                                                                                                                                                                                                                   | Bemerkungen                                                                                                                                                                                                                                                                                                                    |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Drittanbieter-Tool      | _"Es würde einem Benutzer ermöglichen, Tokens zu übernehmen und mit Tools wie potato.exe, rottenpotato.exe und juicypotato.exe zu nt system zu eskalieren."_                                                                                                                                                                                         | Danke an [Aurélien Chalot](https://twitter.com/Defte\_) für das Update. Ich werde versuchen, es bald in eine Art Rezept umzuformulieren.                                                                                                                                                                                        |
| **`SeBackup`**             | **Bedrohung** | _**Integrierte Befehle**_ | Lesen Sie sensible Dateien mit `robocopy /b`                                                                                                                                                                                                                                                                                                      | <p>- Möglicherweise interessanter, wenn Sie %WINDIR%\MEMORY.DMP lesen können<br><br>- <code>SeBackupPrivilege</code> (und robocopy) ist nicht hilfreich, wenn es um das Öffnen von Dateien geht.<br><br>- Robocopy erfordert sowohl SeBackup als auch SeRestore, um mit dem /b-Parameter zu funktionieren.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Drittanbieter-Tool      | Erstellen Sie einen beliebigen Token, einschließlich lokaler Administratorrechte, mit `NtCreateToken`.                                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplizieren Sie das `lsass.exe`-Token.                                                                                                                                                                                                                                                                                                            | Das Skript finden Sie unter [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Drittanbieter-Tool      | <p>1. Laden Sie einen fehlerhaften Kernel-Treiber wie <code>szkg64.sys</code><br>2. Nutzen Sie die Schwachstelle des Treibers aus<br><br>Alternativ kann das Privileg verwendet werden, um sicherheitsrelevante Treiber mit dem integrierten Befehl <code>ftlMC</code> zu entladen. z.B.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Die Schwachstelle <code>szkg64</code> ist als <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> aufgeführt<br>2. Der Exploit-Code für <code>szkg64</code> wurde von <a href="https://twitter.com/parvezghh">Parvez Anwar</a> erstellt</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Starten Sie PowerShell/ISE mit dem vorhandenen SeRestore-Privileg.<br>2. Aktivieren Sie das Privileg mit <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Benennen Sie utilman.exe in utilman.old um<br>4. Benennen Sie cmd.exe in utilman.exe um<br>5. Sperren Sie die Konsole und drücken Sie Win+U</p> | <p>Der Angriff kann von einigen AV-Programmen erkannt werden.</p><p>Alternative Methode basiert auf dem Ersetzen von Dienst-Binärdateien, die mit demselben Privileg in "Program Files" gespeichert sind</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Integrierte Befehle**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Benennen Sie cmd.exe in utilman.exe um<br>4. Sperren Sie die Konsole und drücken Sie Win+U</p>                                                                                                                                       | <p>Der Angriff kann von einigen AV-Programmen erkannt werden.</p><p>Alternative Methode basiert auf dem Ersetzen von Dienst-Binärdateien, die mit demselben Privileg in "Program Files" gespeichert sind.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Drittanbieter-Tool      | <p>Manipulieren Sie Tokens, um lokale Administratorrechte einzuschließen. Möglicherweise ist SeImpersonate erforderlich.</p><p>Zu überprüfen.</p>                                                                                                                                                                                                 |                                                                                                                                                                                                                                                                                                                                |

## Referenz

* Werfen Sie einen Blick auf diese Tabelle, die Windows-Tokens definiert: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Lesen Sie [**diesen Artikel**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) über Privilege Escalation mit Tokens.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersecurity-Unternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repo](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>
