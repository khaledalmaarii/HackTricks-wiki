# Anti-Forensic Techniken

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

## Zeitstempel

Ein Angreifer könnte daran interessiert sein, **die Zeitstempel von Dateien zu ändern**, um nicht entdeckt zu werden.\
Es ist möglich, die Zeitstempel im MFT in den Attributen `$STANDARD_INFORMATION` \_\_ und \_\_ `$FILE_NAME` zu finden.

Beide Attribute haben 4 Zeitstempel: **Änderung**, **Zugriff**, **Erstellung** und **MFT-Registrierungsänderung** (MACE oder MACB).

**Windows-Explorer** und andere Tools zeigen die Informationen von **`$STANDARD_INFORMATION`** an.

### TimeStomp - Anti-Forensisches Tool

Dieses Tool **modifiziert** die Zeitstempelinformationen innerhalb von **`$STANDARD_INFORMATION`**, **aber** **nicht** die Informationen innerhalb von **`$FILE_NAME`**. Daher ist es möglich, **verdächtige** **Aktivitäten** zu **identifizieren**.

### Usnjrnl

Das **USN Journal** (Update Sequence Number Journal) ist eine Funktion des NTFS (Windows NT-Dateisystem), die Änderungen am Volume verfolgt. Das [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) Tool ermöglicht die Untersuchung dieser Änderungen.

![](<../../.gitbook/assets/image (801).png>)

Das vorherige Bild ist die **Ausgabe**, die von dem **Tool** angezeigt wird, wo zu beobachten ist, dass einige **Änderungen vorgenommen wurden**.

### $LogFile

**Alle Metadatenänderungen an einem Dateisystem werden** in einem Prozess protokolliert, der als [Write-Ahead Logging](https://en.wikipedia.org/wiki/Write-ahead_logging) bekannt ist. Die protokollierten Metadaten werden in einer Datei namens `**$LogFile**` gespeichert, die sich im Stammverzeichnis eines NTFS-Dateisystems befindet. Tools wie [LogFileParser](https://github.com/jschicht/LogFileParser) können verwendet werden, um diese Datei zu analysieren und Änderungen zu identifizieren.

![](<../../.gitbook/assets/image (137).png>)

Wiederum ist es in der Ausgabe des Tools möglich zu sehen, dass **einige Änderungen vorgenommen wurden**.

Mit demselben Tool ist es möglich zu identifizieren, **zu welchem Zeitpunkt die Zeitstempel geändert wurden**:

![](<../../.gitbook/assets/image (1089).png>)

* CTIME: Erstellungszeit der Datei
* ATIME: Änderungszeit der Datei
* MTIME: MFT-Registrierungsänderung der Datei
* RTIME: Zugriffszeit der Datei

### Vergleich von `$STANDARD_INFORMATION` und `$FILE_NAME`

Eine weitere Möglichkeit, verdächtig modifizierte Dateien zu identifizieren, wäre der Vergleich der Zeit auf beiden Attributen auf **Unstimmigkeiten** zu überprüfen.

### Nanosekunden

**NTFS** Zeitstempel haben eine **Präzision** von **100 Nanosekunden**. Daher ist es sehr **verdächtig**, Dateien mit Zeitstempeln wie 2010-10-10 10:10:**00.000:0000 zu finden.

### SetMace - Anti-Forensisches Tool

Dieses Tool kann beide Attribute `$STANDARD_INFORMATION` und `$FILE_NAME` modifizieren. Allerdings ist es ab Windows Vista notwendig, dass ein Live-OS diese Informationen ändert.

## Datenversteckung

NFTS verwendet einen Cluster und die minimale Informationsgröße. Das bedeutet, dass, wenn eine Datei einen Cluster und einen halben Cluster belegt, die **verbleibende Hälfte niemals verwendet wird**, bis die Datei gelöscht wird. Daher ist es möglich, **Daten in diesem Slack-Space zu verstecken**.

Es gibt Tools wie Slacker, die es ermöglichen, Daten in diesem "versteckten" Raum zu verbergen. Eine Analyse des `$logfile` und `$usnjrnl` kann jedoch zeigen, dass einige Daten hinzugefügt wurden:

![](<../../.gitbook/assets/image (1060).png>)

Dann ist es möglich, den Slack-Space mit Tools wie FTK Imager abzurufen. Beachte, dass diese Art von Tool den Inhalt obfuskiert oder sogar verschlüsselt speichern kann.

## UsbKill

Dies ist ein Tool, das den Computer **ausschaltet, wenn eine Änderung an den USB**-Ports erkannt wird.\
Eine Möglichkeit, dies zu entdecken, wäre, die laufenden Prozesse zu inspizieren und **jedes laufende Python-Skript zu überprüfen**.

## Live Linux-Distributionen

Diese Distributionen werden **im RAM** ausgeführt. Die einzige Möglichkeit, sie zu erkennen, besteht darin, **wenn das NTFS-Dateisystem mit Schreibberechtigungen gemountet ist**. Wenn es nur mit Lesezugriff gemountet ist, wird es nicht möglich sein, die Eindringung zu erkennen.

## Sichere Löschung

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows-Konfiguration

Es ist möglich, mehrere Windows-Protokollierungsmethoden zu deaktivieren, um die forensische Untersuchung erheblich zu erschweren.

### Zeitstempel deaktivieren - UserAssist

Dies ist ein Registrierungsschlüssel, der Daten und Uhrzeiten speichert, wann jede ausführbare Datei vom Benutzer ausgeführt wurde.

Die Deaktivierung von UserAssist erfordert zwei Schritte:

1. Setze zwei Registrierungsschlüssel, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` und `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, beide auf null, um anzuzeigen, dass wir UserAssist deaktivieren möchten.
2. Lösche deine Registrierungssubbäume, die wie `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` aussehen.

### Zeitstempel deaktivieren - Prefetch

Dies speichert Informationen über die ausgeführten Anwendungen mit dem Ziel, die Leistung des Windows-Systems zu verbessern. Dies kann jedoch auch für forensische Praktiken nützlich sein.

* Führe `regedit` aus
* Wähle den Dateipfad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Klicke mit der rechten Maustaste auf `EnablePrefetcher` und `EnableSuperfetch`
* Wähle Ändern bei jedem dieser, um den Wert von 1 (oder 3) auf 0 zu ändern
* Starte neu

### Zeitstempel deaktivieren - Letzter Zugriffszeit

Immer wenn ein Ordner von einem NTFS-Volume auf einem Windows NT-Server geöffnet wird, nimmt das System sich die Zeit, um **ein Zeitstempelfeld für jeden aufgelisteten Ordner zu aktualisieren**, das als letzte Zugriffszeit bezeichnet wird. Bei einem stark genutzten NTFS-Volume kann dies die Leistung beeinträchtigen.

1. Öffne den Registrierungs-Editor (Regedit.exe).
2. Navigiere zu `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Suche nach `NtfsDisableLastAccessUpdate`. Wenn es nicht existiert, füge dieses DWORD hinzu und setze seinen Wert auf 1, um den Prozess zu deaktivieren.
4. Schließe den Registrierungs-Editor und starte den Server neu.

### USB-Historie löschen

Alle **USB-Geräteeinträge** werden in der Windows-Registrierung unter dem **USBSTOR**-Registrierungsschlüssel gespeichert, der Unterkeys enthält, die erstellt werden, wann immer du ein USB-Gerät an deinen PC oder Laptop anschließt. Du kannst diesen Schlüssel hier finden: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Wenn du dies löschst**, wirst du die USB-Historie löschen.\
Du kannst auch das Tool [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) verwenden, um sicherzustellen, dass du sie gelöscht hast (und um sie zu löschen).

Eine weitere Datei, die Informationen über die USBs speichert, ist die Datei `setupapi.dev.log` im Verzeichnis `C:\Windows\INF`. Diese sollte ebenfalls gelöscht werden.

### Schattenkopien deaktivieren

**Liste** Schattenkopien mit `vssadmin list shadowstorage`\
**Lösche** sie, indem du `vssadmin delete shadow` ausführst.

Du kannst sie auch über die GUI löschen, indem du die Schritte in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) befolgst.

Um Schattenkopien zu deaktivieren, [folgen die Schritte hier](https://support.waters.com/KB\_Inf/Other/WKB15560\_How\_to\_disable\_Volume\_Shadow\_Copy\_Service\_VSS\_in\_Windows):

1. Öffne das Dienstprogramm, indem du "services" in das Textsuchfeld eingibst, nachdem du auf die Windows-Starttaste geklickt hast.
2. Finde in der Liste "Volume Shadow Copy", wähle es aus und greife dann mit einem Rechtsklick auf die Eigenschaften zu.
3. Wähle Deaktiviert aus dem Dropdown-Menü "Starttyp" und bestätige die Änderung, indem du auf Übernehmen und OK klickst.

Es ist auch möglich, die Konfiguration zu ändern, welche Dateien in der Schattenkopie kopiert werden, in der Registrierung `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`.

### Gelöschte Dateien überschreiben

* Du kannst ein **Windows-Tool** verwenden: `cipher /w:C`. Dies wird dem Cipher anweisen, alle Daten aus dem verfügbaren ungenutzten Speicherplatz auf dem C-Laufwerk zu entfernen.
* Du kannst auch Tools wie [**Eraser**](https://eraser.heidi.ie) verwenden.

### Windows-Ereignisprotokolle löschen

* Windows + R --> eventvwr.msc --> Erweitere "Windows-Protokolle" --> Klicke mit der rechten Maustaste auf jede Kategorie und wähle "Protokoll löschen"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows-Ereignisprotokolle deaktivieren

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Deaktiviere im Dienstebereich den Dienst "Windows-Ereignisprotokoll"
* `WEvtUtil.exec clear-log` oder `WEvtUtil.exe cl`

### $UsnJrnl deaktivieren

* `fsutil usn deletejournal /d c:`

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
