<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


# Zeitstempel

Ein Angreifer kann daran interessiert sein, **die Zeitstempel von Dateien zu ändern**, um nicht erkannt zu werden.\
Es ist möglich, die Zeitstempel im MFT in den Attributen `$STANDARD_INFORMATION` __ und __ `$FILE_NAME` zu finden.

Beide Attribute haben 4 Zeitstempel: **Änderung**, **Zugriff**, **Erstellung** und **MFT-Registrierungsänderung** (MACE oder MACB).

**Windows Explorer** und andere Tools zeigen die Informationen aus **`$STANDARD_INFORMATION`** an.

## TimeStomp - Anti-Forensik-Tool

Dieses Tool **ändert** die Zeitstempelinformationen in **`$STANDARD_INFORMATION`**, **nicht jedoch** die Informationen in **`$FILE_NAME`**. Daher ist es möglich, **verdächtige Aktivitäten** zu **identifizieren**.

## Usnjrnl

Das **USN Journal** (Update Sequence Number Journal) ist eine Funktion des NTFS (Windows NT-Dateisystems), das Änderungen am Volume verfolgt. Das Tool [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) ermöglicht die Untersuchung dieser Änderungen.

![](<../../.gitbook/assets/image (449).png>)

Das vorherige Bild zeigt die **Ausgabe**, die vom **Tool** angezeigt wird, in der einige **Änderungen an der Datei** vorgenommen wurden.

## $LogFile

**Alle Metadatenänderungen an einem Dateisystem werden protokolliert** in einem Prozess, der als [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) bekannt ist. Die protokollierten Metadaten werden in einer Datei namens `**$LogFile**` gespeichert, die sich im Stammverzeichnis eines NTFS-Dateisystems befindet. Tools wie [LogFileParser](https://github.com/jschicht/LogFileParser) können verwendet werden, um diese Datei zu analysieren und Änderungen zu identifizieren.

![](<../../.gitbook/assets/image (450).png>)

Auch hier ist in der Ausgabe des Tools zu sehen, dass **einige Änderungen vorgenommen wurden**.

Mit demselben Tool ist es möglich, zu **welcher Zeit die Zeitstempel geändert wurden**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Erstellungszeit der Datei
* ATIME: Änderungszeit der Datei
* MTIME: MFT-Registrierungsänderungszeit der Datei
* RTIME: Zugriffszeit der Datei

## Vergleich von `$STANDARD_INFORMATION` und `$FILE_NAME`

Eine andere Möglichkeit, verdächtig geänderte Dateien zu identifizieren, besteht darin, die Zeit in beiden Attributen zu vergleichen und nach **Abweichungen** zu suchen.

## Nanosekunden

**NTFS**-Zeitstempel haben eine **Genauigkeit** von **100 Nanosekunden**. Daher ist es sehr verdächtig, Dateien mit Zeitstempeln wie 2010-10-10 10:10:**00.000:0000** zu finden.

## SetMace - Anti-Forensik-Tool

Dieses Tool kann sowohl die Attribute `$STARNDAR_INFORMATION` als auch `$FILE_NAME` ändern. Ab Windows Vista ist jedoch ein Live-Betriebssystem erforderlich, um diese Informationen zu ändern.

# Datenversteckung

NFTS verwendet einen Cluster und die minimale Informationsgröße. Das bedeutet, dass, wenn eine Datei einen Cluster und eine Hälfte belegt, der **verbleibende halbe Teil niemals verwendet wird**, bis die Datei gelöscht wird. Daher ist es möglich, Daten in diesem "versteckten" Bereich zu **verstecken**.

Es gibt Tools wie Slacker, die das Verstecken von Daten in diesem "versteckten" Bereich ermöglichen. Eine Analyse des `$logfile` und `$usnjrnl` kann jedoch zeigen, dass Daten hinzugefügt wurden:

![](<../../.gitbook/assets/image (452).png>)

Daher ist es möglich, den Slack-Space mithilfe von Tools wie FTK Imager abzurufen. Beachten Sie, dass diese Art von Tool den Inhalt verschleiert oder sogar verschlüsselt speichern kann.

# UsbKill

Dies ist ein Tool, das den Computer ausschaltet, wenn eine Änderung an den USB-Anschlüssen erkannt wird.\
Eine Möglichkeit, dies zu entdecken, besteht darin, die laufenden Prozesse zu inspizieren und **jedes ausgeführte Python-Skript zu überprüfen**.

# Live-Linux-Distributionen

Diese Distributionen werden **im RAM-Speicher** ausgeführt. Die einzige Möglichkeit, sie zu erkennen, besteht darin, **wenn das NTFS-Dateisystem mit Schreibberechtigungen eingebunden ist**. Wenn es nur mit Leseberechtigungen eingebunden ist, ist es nicht möglich, den Eindringling zu erkennen.

# Sicheres Löschen

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows-Konfiguration

Es ist möglich, mehrere Windows-Protokollierungsmethoden zu deaktivieren, um die forensische Untersuchung zu erschweren.

## Deaktivieren von Zeitstempeln - UserAssist

Dies ist ein Registrierungsschlüssel, der Datum und Uhrzeit speichert, wann jede ausführbare Datei vom Benutzer ausgeführt wurde.

Das Deaktivieren von UserAssist erfordert zwei Schritte:

1. Setzen Sie zwei Registrierungsschlüssel, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` und `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, beide auf Null, um anzuzeigen, dass UserAssist deaktiviert werden soll.
2. Löschen Sie Ihre Registrierungsunterbäume, die wie `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` aussehen.

## Deaktivieren von Zeitstempeln - Prefetch

Hier werden Informationen über die ausgeführten Anwendungen gespeichert, um die Leistung des Windows-Systems zu verbessern. Dies kann jedoch auch für forensische Zwecke nützlich sein.

* Führen Sie `regedit` aus.
* Wählen Sie den Dateipfad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`.
* Klicken Sie mit der rechten Maustaste auf `EnablePrefetcher` und `EnableSuperfetch`.
* Wählen Sie bei beiden "Ändern" aus, um den Wert von 1 (oder 3) auf 0 zu ändern.
* Starten Sie den Computer neu.

## Deaktivieren von Zeitstempeln - Letzter Zugriffszeit

Wenn ein Ordner von einem NTFS-Volume auf einem Windows NT-Server geöffnet wird, nimmt sich das System Zeit, um ein Zeitstempelfeld in jedem aufgelisteten Ordner zu **aktualisieren**, das als letzte Zugriffszeit bezeichnet wird. Auf einem stark genutzten NTFS-Volume kann dies die Leistung beeinträchtigen.

1. Öffnen Sie den Registrierungseditor (Regedit.exe).
2. Navigieren Sie zu `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Suchen Sie nach `NtfsDisableLastAccessUpdate`. Wenn es nicht vorhanden ist, fügen Sie dieses DWORD hinzu und setzen Sie seinen Wert auf 1, um den Vorgang zu deaktivieren.
4. Schließen Sie den Registrierungseditor und starten Sie den Server neu.
## USB-Verlauf löschen

Alle **USB-Geräteeinträge** werden in der Windows-Registrierung unter dem Registrierungsschlüssel **USBSTOR** gespeichert, der Unterkeys enthält, die jedes Mal erstellt werden, wenn Sie ein USB-Gerät in Ihren PC oder Laptop stecken. Sie können diesen Schlüssel hier finden: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Durch das Löschen** dieses Schlüssels wird der USB-Verlauf gelöscht.\
Sie können auch das Tool [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) verwenden, um sicherzustellen, dass Sie sie gelöscht haben (und um sie zu löschen).

Eine weitere Datei, die Informationen über die USB-Geräte speichert, ist die Datei `setupapi.dev.log` im Ordner `C:\Windows\INF`. Diese sollte ebenfalls gelöscht werden.

## Schattenkopien deaktivieren

**Liste** Schattenkopien mit `vssadmin list shadowstorage`\
**Löschen** Sie sie, indem Sie `vssadmin delete shadow` ausführen.

Sie können sie auch über die GUI löschen, indem Sie den Schritten auf [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) folgen.

Um Schattenkopien zu deaktivieren [Schritte von hier](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Öffnen Sie das Dienstprogramm "Dienste", indem Sie nach dem Klicken auf die Windows-Startschaltfläche "Dienste" in das Textsuchfeld eingeben.
2. Suchen Sie in der Liste "Volume Shadow Copy", wählen Sie es aus und greifen Sie dann durch einen Rechtsklick auf Eigenschaften zu.
3. Wählen Sie "Deaktiviert" aus dem Dropdown-Menü "Starttyp" und bestätigen Sie die Änderung, indem Sie auf "Übernehmen" und "OK" klicken.

Es ist auch möglich, die Konfiguration zu ändern, welche Dateien in der Schattenkopie kopiert werden sollen, in der Registrierung `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`.

## Überschreiben gelöschter Dateien

* Sie können ein **Windows-Tool** verwenden: `cipher /w:C`. Dadurch wird Cipher angewiesen, alle Daten aus dem verfügbaren ungenutzten Festplattenspeicherplatz auf Laufwerk C zu entfernen.
* Sie können auch Tools wie [**Eraser**](https://eraser.heidi.ie) verwenden.

## Windows-Ereignisprotokolle löschen

* Windows + R --> eventvwr.msc --> Erweitern Sie "Windows-Protokolle" --> Klicken Sie mit der rechten Maustaste auf jede Kategorie und wählen Sie "Protokoll löschen".
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Windows-Ereignisprotokolle deaktivieren

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Deaktivieren Sie den Dienst "Windows-Ereignisprotokoll" im Abschnitt "Dienste".
* `WEvtUtil.exec clear-log` oder `WEvtUtil.exe cl`

## $UsnJrnl deaktivieren

* `fsutil usn deletejournal /d c:`


<details>

<summary><strong>Lernen Sie das Hacken von AWS von Null bis zum Experten mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
