# Ausnutzung von Tokens

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) bei oder der [**Telegram-Gruppe**](https://t.me/peass) oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zum** [**HackTricks-Repo**](https://github.com/carlospolop/hacktricks) **und zum** [**HackTricks-Cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **einreichen**.

</details>

## Tokens

Wenn Sie **nicht wissen, was Windows-Zugriffstoken sind**, lesen Sie diese Seite, bevor Sie fortfahren:

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

**Möglicherweise können Sie Berechtigungen eskalieren, indem Sie die Tokens missbrauchen, die Sie bereits haben**

### SeImpersonatePrivilege

Dies ist ein Privileg, das von jedem Prozess gehalten wird und die Übernahme (aber nicht die Erstellung) eines beliebigen Tokens ermöglicht, sofern ein Handle dafür erhalten werden kann. Ein privilegiertes Token kann von einem Windows-Dienst (DCOM) erworben werden, indem er zur Durchführung einer NTLM-Authentifizierung gegen einen Exploit veranlasst wird, was anschließend die Ausführung eines Prozesses mit SYSTEM-Berechtigungen ermöglicht. Diese Schwachstelle kann mit verschiedenen Tools ausgenutzt werden, wie [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (der die Deaktivierung von WinRM erfordert), [SweetPotato](https://github.com/CCob/SweetPotato) und [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="juicypotato.md" %}
[juicypotato.md](juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Es ist sehr ähnlich wie **SeImpersonatePrivilege**, es wird die **gleiche Methode** verwendet, um ein privilegiertes Token zu erhalten.\
Dann ermöglicht dieses Privileg, einem neuen/ausgesetzten Prozess **ein primäres Token zuzuweisen**. Mit dem privilegierten Übernahme-Token können Sie ein primäres Token ableiten (DuplicateTokenEx).\
Mit dem Token können Sie einen **neuen Prozess** mit 'CreateProcessAsUser' erstellen oder einen Prozess suspendieren und das Token **festlegen** (im Allgemeinen können Sie das primäre Token eines laufenden Prozesses nicht ändern).

### SeTcbPrivilege

Wenn Sie dieses Token aktiviert haben, können Sie **KERB\_S4U\_LOGON** verwenden, um ein **Übernahme-Token** für einen anderen Benutzer zu erhalten, ohne die Anmeldeinformationen zu kennen, eine **beliebige Gruppe** (Administratoren) dem Token hinzufügen, den **Integritätslevel** des Tokens auf "**mittel**" setzen und dieses Token dem **aktuellen Thread** zuweisen (SetThreadToken).

### SeBackupPrivilege

Das System wird veranlasst, allen Dateien (auf Lesevorgänge beschränkt) durch dieses Privileg **vollen Lesezugriff** zu gewähren. Es wird verwendet, um die Passworthashes der lokalen Administratorkonten aus der Registrierung zu lesen, wonach Tools wie "**psexec**" oder "**wmicexec**" mit dem Hash verwendet werden können (Pass-the-Hash-Technik). Diese Technik scheitert jedoch unter zwei Bedingungen: wenn das lokale Administrator-Konto deaktiviert ist oder wenn eine Richtlinie besteht, die administrativen Rechten von lokalen Administratoren, die sich remote verbinden, entfernt.\
Sie können dieses Privileg **missbrauchen** mit:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* folgen Sie **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Oder wie im Abschnitt **Berechtigungen eskalieren mit Backup-Operatoren** erklärt in:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Dieses Privileg ermöglicht **Schreibzugriff** auf jede Systemdatei, unabhängig von der Zugriffssteuerungsliste (ACL) der Datei. Es eröffnet zahlreiche Möglichkeiten zur Eskalation, einschließlich der Möglichkeit, **Dienste zu ändern**, DLL-Hijacking durchzuführen und **Debugger** über Image File Execution Options einzurichten, unter verschiedenen anderen Techniken.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ist eine leistungsstarke Berechtigung, besonders nützlich, wenn ein Benutzer die Fähigkeit besitzt, Tokens zu übernehmen, aber auch in Abwesenheit von SeImpersonatePrivilege. Diese Fähigkeit hängt davon ab, ein Token zu übernehmen, das denselben Benutzer repräsentiert und dessen Integritätslevel nicht höher ist als der des aktuellen Prozesses.

**Hauptpunkte:**

* **Übernahme ohne SeImpersonatePrivilege:** Es ist möglich, SeCreateTokenPrivilege für EoP zu nutzen, indem Tokens unter bestimmten Bedingungen übernommen werden.
* **Bedingungen für Token-Übernahme:** Eine erfolgreiche Übernahme erfordert, dass das Ziel-Token demselben Benutzer gehört und ein Integritätslevel hat, das kleiner oder gleich dem Integritätslevel des Prozesses ist, der die Übernahme versucht.
* **Erstellung und Änderung von Übernahme-Tokens:** Benutzer können ein Übernahme-Token erstellen und es verbessern, indem sie die SID (Sicherheitskennung) einer privilegierten Gruppe hinzufügen.

### SeLoadDriverPrivilege

Dieses Privileg erlaubt es, **Gerätetreiber zu laden und zu entladen**, indem ein Registrierungseintrag mit spezifischen Werten für `ImagePath` und `Type` erstellt wird. Da der direkte Schreibzugriff auf `HKLM` (HKEY\_LOCAL\_MACHINE) eingeschränkt ist, muss stattdessen `HKCU` (HKEY\_CURRENT\_USER) verwendet werden. Um `HKCU` jedoch für die Kernelkonfiguration von Treibern erkennbar zu machen, muss ein spezifischer Pfad befolgt werden.

Dieser Pfad lautet `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, wobei `<RID>` die Relative Kennung des aktuellen Benutzers ist. Innerhalb von `HKCU` muss dieser gesamte Pfad erstellt und zwei Werte festgelegt werden:

* `ImagePath`, der Pfad zur auszuführenden Binärdatei
* `Type`, mit einem Wert von `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Zu befolgende Schritte:**

1. Greifen Sie auf `HKCU` anstelle von `HKLM` aufgrund des eingeschränkten Schreibzugriffs zu.
2. Erstellen Sie den Pfad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` innerhalb von `HKCU`, wobei `<RID>` die Relative Kennung des aktuellen Benutzers darstellt.
3. Legen Sie den `ImagePath` auf den Ausführungspfad der Binärdatei fest.
4. Weisen Sie den `Type` als `SERVICE_KERNEL_DRIVER` (`0x00000001`) zu.
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

Dies ist ähnlich wie **SeRestorePrivilege**. Seine Hauptfunktion ermöglicht es einem Prozess, **Eigentum an einem Objekt zu übernehmen**, indem die Anforderung nach explizitem diskretionärem Zugriff durch die Bereitstellung von WRITE\_OWNER-Zugriffsrechten umgangen wird. Der Prozess beinhaltet zunächst die Sicherung des Eigentums am beabsichtigten Registrierungsschlüssel für Schreibzwecke und anschließend die Änderung des DACL, um Schreiboperationen zu ermöglichen.
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

Diese Berechtigung erlaubt es, **andere Prozesse zu debuggen**, einschließlich Lesen und Schreiben im Speicher. Verschiedene Strategien für Speicherinjektionen, die in der Lage sind, die meisten Antiviren- und Host-Eindringungsschutzlösungen zu umgehen, können mit dieser Berechtigung verwendet werden.

#### Speicher dumpen

Sie könnten [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aus der [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) verwenden, um **den Speicher eines Prozesses zu erfassen**. Dies gilt insbesondere für den **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)**-Prozess, der für die Speicherung von Benutzeranmeldeinformationen verantwortlich ist, sobald sich ein Benutzer erfolgreich bei einem System angemeldet hat.

Anschließend können Sie diesen Dump in mimikatz laden, um Passwörter zu erhalten:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Wenn Sie eine `NT SYSTEM`-Shell erhalten möchten, könnten Sie Folgendes verwenden:

* [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
* [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
* [**psgetsys.ps1 (Powershell-Skript)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Überprüfen von Berechtigungen
```
whoami /priv
```
Die **Tokens, die als Deaktiviert erscheinen**, können aktiviert werden, sodass Sie tatsächlich _Aktivierte_ und _Deaktivierte_ Tokens missbrauchen können.

### Aktivieren Sie alle Tokens

Wenn Sie deaktivierte Tokens haben, können Sie das Skript [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) verwenden, um alle Tokens zu aktivieren:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oder das **Skript** in diesem [**Beitrag**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabelle

Vollständige Token-Privilegien-Cheatsheet unter [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), die folgende Zusammenfassung listet nur direkte Möglichkeiten auf, das Privileg auszunutzen, um eine Admin-Sitzung zu erhalten oder sensible Dateien zu lesen.

| Privileg                  | Auswirkung   | Tool                    | Ausführungspfad                                                                                                                                                                                                                                                                                                                                     | Bemerkungen                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Drittanbieter-Tool          | _"Es würde einem Benutzer ermöglichen, Tokens zu übernehmen und mit Tools wie potato.exe, rottenpotato.exe und juicypotato.exe zu nt-Systemen zu eskalieren"_                                                                                                                                                                                                      | Danke an [Aurélien Chalot](https://twitter.com/Defte\_) für das Update. Ich werde versuchen, es bald etwas mehr rezeptartig umzuformulieren.                                                                                                                                                                                        |
| **`SeBackup`**             | **Bedrohung**  | _**Eingebaute Befehle**_ | Lesen sensibler Dateien mit `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Möglicherweise interessanter, wenn Sie %WINDIR%\MEMORY.DMP lesen können<br><br>- <code>SeBackupPrivilege</code> (und robocopy) sind nicht hilfreich, wenn es um geöffnete Dateien geht.<br><br>- Robocopy erfordert sowohl SeBackup als auch SeRestore, um mit dem /b-Parameter zu arbeiten.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Drittanbieter-Tool          | Erstellen eines beliebigen Tokens einschließlich lokaler Admin-Rechte mit `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplizieren des `lsass.exe`-Tokens.                                                                                                                                                                                                                                                                                                                   | Skript zu finden unter [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Drittanbieter-Tool          | <p>1. Laden eines fehlerhaften Kernel-Treibers wie <code>szkg64.sys</code><br>2. Ausnutzen der Treiberschwachstelle<br><br>Alternativ kann das Privileg verwendet werden, um sicherheitsrelevante Treiber mit dem integrierten Befehl <code>ftlMC</code> zu entladen. z.B.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Die Schwachstelle von <code>szkg64</code> ist als <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> aufgeführt<br>2. Der <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">Exploit-Code</a> wurde von <a href="https://twitter.com/parvezghh">Parvez Anwar</a> erstellt</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Starten von PowerShell/ISE mit dem vorhandenen SeRestore-Privileg.<br>2. Aktivieren des Privilegs mit <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Umbenennen von utilman.exe in utilman.old<br>4. Umbenennen von cmd.exe in utilman.exe<br>5. Sperren der Konsole und Drücken von Win+U</p> | <p>Der Angriff kann von einigen AV-Software erkannt werden.</p><p>Alternative Methode beruht auf dem Ersetzen von Service-Binärdateien, die in "Program Files" gespeichert sind, mit demselben Privileg</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Eingebaute Befehle**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Umbenennen von cmd.exe in utilman.exe<br>4. Sperren der Konsole und Drücken von Win+U</p>                                                                                                                                       | <p>Der Angriff kann von einigen AV-Software erkannt werden.</p><p>Alternative Methode beruht auf dem Ersetzen von Service-Binärdateien, die in "Program Files" gespeichert sind, mit demselben Privileg.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Drittanbieter-Tool          | <p>Manipulation von Tokens, um lokale Admin-Rechte einzuschließen. Möglicherweise erfordert SeImpersonate.</p><p>Zu überprüfen.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Referenz

* Werfen Sie einen Blick auf diese Tabelle, die Windows-Token definiert: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Werfen Sie einen Blick auf [**dieses Papier**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) über Privilege Escalation mit Tokens.

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Heldenniveau mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) bei oder der [**Telegram-Gruppe**](https://t.me/peass) oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**HackTricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**HackTricks-Cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **einreichen**.

</details>
