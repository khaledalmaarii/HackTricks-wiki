<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** möchten oder **HackTricks in PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


# Zeitstempel

Ein Angreifer könnte daran interessiert sein, **die Zeitstempel von Dateien zu ändern**, um nicht entdeckt zu werden.\
Es ist möglich, die Zeitstempel im MFT in den Attributen `$STANDARD_INFORMATION` __ und __ `$FILE_NAME` zu finden.

Beide Attribute haben 4 Zeitstempel: **Änderung**, **Zugriff**, **Erstellung** und **MFT-Registrierungsänderung** (MACE oder MACB).

**Windows Explorer** und andere Tools zeigen die Informationen aus **`$STANDARD_INFORMATION`**.

## TimeStomp - Anti-Forensik-Tool

Dieses Tool **ändert** die Zeitstempelinformationen innerhalb von **`$STANDARD_INFORMATION`** **aber** **nicht** die Informationen innerhalb von **`$FILE_NAME`**. Daher ist es möglich, **verdächtige Aktivitäten zu identifizieren**.

## Usnjrnl

Das **USN Journal** (Update Sequence Number Journal) ist eine Funktion des NTFS (Windows NT-Dateisystems), die Änderungen am Volume verfolgt. Das [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)-Tool ermöglicht die Untersuchung dieser Änderungen.

![](<../../.gitbook/assets/image (449).png>)

Das vorherige Bild zeigt die **Ausgabe**, die vom **Tool** angezeigt wird, in der einige **Änderungen an der Datei durchgeführt wurden**.

## $LogFile

**Alle Metadatenänderungen an einem Dateisystem werden protokolliert** in einem Prozess, der als [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) bekannt ist. Die protokollierten Metadaten werden in einer Datei namens `**$LogFile**` gespeichert, die sich im Stammverzeichnis eines NTFS-Dateisystems befindet. Tools wie [LogFileParser](https://github.com/jschicht/LogFileParser) können verwendet werden, um diese Datei zu analysieren und Änderungen zu identifizieren.

![](<../../.gitbook/assets/image (450).png>)

Erneut ist es in der Ausgabe des Tools möglich zu sehen, dass **einige Änderungen durchgeführt wurden**.

Mit demselben Tool ist es möglich zu identifizieren, **zu welcher Zeit die Zeitstempel geändert wurden**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Erstellungszeit der Datei
* ATIME: Änderungszeit der Datei
* MTIME: MFT-Registrierungsänderung der Datei
* RTIME: Zugriffszeit der Datei

## Vergleich von `$STANDARD_INFORMATION` und `$FILE_NAME`

Eine weitere Möglichkeit, verdächtig modifizierte Dateien zu identifizieren, wäre der Vergleich der Zeit in beiden Attributen auf der Suche nach **Unstimmigkeiten**.

## Nanosekunden

**NTFS**-Zeitstempel haben eine **Genauigkeit** von **100 Nanosekunden**. Daher ist es sehr verdächtig, Dateien mit Zeitstempeln wie 2010-10-10 10:10:**00.000:0000 zu finden**.

## SetMace - Anti-Forensik-Tool

Dieses Tool kann beide Attribute `$STARNDAR_INFORMATION` und `$FILE_NAME` ändern. Ab Windows Vista ist es jedoch erforderlich, ein Live-Betriebssystem zu haben, um diese Informationen zu ändern.

# Datenversteckung

NFTS verwendet einen Cluster und die minimale Informationsgröße. Das bedeutet, dass, wenn eine Datei einen Cluster und eine Hälfte belegt, die **verbleibende Hälfte niemals verwendet wird**, bis die Datei gelöscht wird. Daher ist es möglich, **Daten in diesem Slack-Space zu verstecken**.

Es gibt Tools wie Slacker, die das Verstecken von Daten in diesem "versteckten" Speicherplatz ermöglichen. Eine Analyse des `$logfile` und `$usnjrnl` kann jedoch zeigen, dass Daten hinzugefügt wurden:

![](<../../.gitbook/assets/image (452).png>)

Dann ist es möglich, den Slack-Space mithilfe von Tools wie FTK Imager abzurufen. Beachten Sie, dass diese Art von Tool den Inhalt verschleiert oder sogar verschlüsselt speichern kann.

# UsbKill

Dies ist ein Tool, das den Computer **ausschaltet, wenn eine Änderung an den USB-Anschlüssen erkannt wird**.\
Eine Möglichkeit, dies zu entdecken, wäre die Überprüfung der laufenden Prozesse und das **Überprüfen jedes ausgeführten Python-Skripts**.

# Live-Linux-Distributionen

Diese Distributionen werden **im RAM-Speicher ausgeführt**. Der einzige Weg, sie zu entdecken, besteht darin, **falls das NTFS-Dateisystem mit Schreibberechtigungen eingebunden ist**. Wenn es nur mit Leseberechtigungen eingebunden ist, wird es nicht möglich sein, den Eindringling zu entdecken.

# Sicheres Löschen

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows-Konfiguration

Es ist möglich, mehrere Windows-Protokollierungsmethoden zu deaktivieren, um die forensische Untersuchung deutlich zu erschweren.

## Deaktivieren von Zeitstempeln - UserAssist

Dies ist ein Registrierungsschlüssel, der Datum und Uhrzeit speichert, wann jede ausführbare Datei vom Benutzer ausgeführt wurde.

Die Deaktivierung von UserAssist erfordert zwei Schritte:

1. Setzen Sie zwei Registrierungsschlüssel, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` und `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, beide auf Null, um anzuzeigen, dass wir UserAssist deaktivieren möchten.
2. Löschen Sie Ihre Registrierungsunterbäume, die wie `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` aussehen.

## Deaktivieren von Zeitstempeln - Prefetch

Dies speichert Informationen über die ausgeführten Anwendungen mit dem Ziel, die Leistung des Windows-Systems zu verbessern. Dies kann jedoch auch für forensische Praktiken nützlich sein.

* Führen Sie `regedit` aus
* Wählen Sie den Dateipfad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Klicken Sie mit der rechten Maustaste auf sowohl `EnablePrefetcher` als auch `EnableSuperfetch`
* Wählen Sie bei jedem von ihnen "Ändern", um den Wert von 1 (oder 3) auf 0 zu ändern
* Neustart

## Deaktivieren von Zeitstempeln - Letzter Zugriffszeit

Immer wenn ein Ordner von einem NTFS-Volume auf einem Windows NT-Server geöffnet wird, nimmt sich das System Zeit, um **ein Zeitstempelfeld auf jedem aufgelisteten Ordner zu aktualisieren**, genannt die letzte Zugriffszeit. Auf einem stark genutzten NTFS-Volume kann dies die Leistung beeinträchtigen.

1. Öffnen Sie den Registrierungseditor (Regedit.exe).
2. Navigieren Sie zu `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Suchen Sie nach `NtfsDisableLastAccessUpdate`. Wenn es nicht existiert, fügen Sie dieses DWORD hinzu und setzen Sie seinen Wert auf 1, um den Prozess zu deaktivieren.
4. Schließen Sie den Registrierungseditor und starten Sie den Server neu.
## Löschen des USB-Verlaufs

Alle **USB-Geräteeinträge** werden im Windows-Registrierungsschlüssel **USBSTOR** gespeichert, der Unterordnungen enthält, die jedes Mal erstellt werden, wenn Sie ein USB-Gerät in Ihren PC oder Laptop stecken. Sie finden diesen Schlüssel hier H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Durch das Löschen** dieses Schlüssels wird der USB-Verlauf gelöscht.\
Sie können auch das Tool [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) verwenden, um sicherzustellen, dass Sie sie gelöscht haben (und um sie zu löschen).

Eine weitere Datei, die Informationen über die USB-Geräte speichert, ist die Datei `setupapi.dev.log` im Ordner `C:\Windows\INF`. Diese sollte ebenfalls gelöscht werden.

## Deaktivieren von Schattenkopien

**Liste** Schattenkopien mit `vssadmin list shadowstorage`\
**Löschen** Sie sie, indem Sie `vssadmin delete shadow` ausführen

Sie können sie auch über die GUI löschen, indem Sie den auf [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) vorgeschlagenen Schritten folgen.

Um Schattenkopien zu deaktivieren [Schritte von hier](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Öffnen Sie das Dienstprogramm "Dienste", indem Sie nach dem Klicken auf die Windows-Startschaltfläche "Dienste" in das Textsuchfeld eingeben.
2. Suchen Sie aus der Liste "Volume Shadow Copy", wählen Sie es aus und greifen Sie dann durch einen Rechtsklick auf Eigenschaften zu.
3. Wählen Sie "Deaktiviert" aus dem Dropdown-Menü "Starttyp" und bestätigen Sie die Änderung, indem Sie auf Übernehmen und OK klicken.

Es ist auch möglich, die Konfiguration zu ändern, welche Dateien im Schattenkopie im Registrierungsschlüssel `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` kopiert werden sollen.

## Überschreiben gelöschter Dateien

* Sie können ein **Windows-Tool** verwenden: `cipher /w:C` Dies gibt Cipher an, alle Daten aus dem verfügbaren ungenutzten Festplattenspeicher im Laufwerk C zu entfernen.
* Sie können auch Tools wie [**Eraser**](https://eraser.heidi.ie) verwenden

## Löschen von Windows-Ereignisprotokollen

* Windows + R --> eventvwr.msc --> Erweitern Sie "Windows-Protokolle" --> Klicken Sie mit der rechten Maustaste auf jede Kategorie und wählen Sie "Protokoll löschen"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Deaktivieren von Windows-Ereignisprotokollen

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Deaktivieren Sie im Dienstabschnitt den Dienst "Windows-Ereignisprotokoll"
* `WEvtUtil.exec clear-log` oder `WEvtUtil.exe cl`

## Deaktivieren von $UsnJrnl

* `fsutil usn deletejournal /d c:`

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
