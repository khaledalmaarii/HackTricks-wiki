# Windows Artefakte

## Windows Artefakte

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys einreichen.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Generische Windows Artefakte

### Windows 10 Benachrichtigungen

Im Pfad `\Users\<Benutzername>\AppData\Local\Microsoft\Windows\Notifications` finden Sie die Datenbank `appdb.dat` (vor Windows-Update) oder `wpndatabase.db` (nach Windows-Update).

In dieser SQLite-Datenbank finden Sie die Tabelle `Notification` mit allen Benachrichtigungen (im XML-Format), die interessante Daten enthalten können.

### Zeitachse

Die Zeitachse ist eine Windows-Funktion, die eine **chronologische Historie** der besuchten Webseiten, bearbeiteten Dokumente und ausgeführten Anwendungen bereitstellt.

Die Datenbank befindet sich im Pfad `\Users\<Benutzername>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Diese Datenbank kann mit einem SQLite-Tool oder mit dem Tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) geöffnet werden, **das 2 Dateien generiert, die mit dem Tool** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **geöffnet werden können**.

### ADS (Alternative Datenströme)

Heruntergeladene Dateien können die **ADS Zone.Identifier** enthalten, die anzeigt, **wie** sie aus dem Intranet, Internet usw. heruntergeladen wurden. Einige Software (wie Browser) geben in der Regel sogar **mehr** **Informationen** wie die **URL** an, von der die Datei heruntergeladen wurde.

## **Dateisicherungen**

### Papierkorb

Im Vista/Win7/Win8/Win10 befindet sich der **Papierkorb** im Ordner **`$Recycle.bin`** im Stammverzeichnis des Laufwerks (`C:\$Recycle.bin`).\
Wenn eine Datei in diesem Ordner gelöscht wird, werden 2 spezifische Dateien erstellt:

* `$I{id}`: Dateiinformationen (Datum des Löschens}
* `$R{id}`: Inhalt der Datei

![](<../../../.gitbook/assets/image (486).png>)

Mit diesen Dateien können Sie das Tool [**Rifiuti**](https://github.com/abelcheung/rifiuti2) verwenden, um die ursprüngliche Adresse der gelöschten Dateien und das Löschdatum zu erhalten (verwenden Sie `rifiuti-vista.exe` für Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy ist eine Technologie, die in Microsoft Windows enthalten ist und **Sicherungskopien** oder Snapshots von Computerdateien oder Volumes erstellen kann, auch wenn sie verwendet werden.

Diese Backups befinden sich normalerweise im Verzeichnis `\System Volume Information` im Stammverzeichnis des Dateisystems und der Name setzt sich aus **UIDs** zusammen, wie im folgenden Bild gezeigt:

![](<../../../.gitbook/assets/image (520).png>)

Durch das Einhängen des forensischen Abbilds mit dem **ArsenalImageMounter** kann das Tool [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) verwendet werden, um eine Schattenkopie zu inspizieren und sogar die Dateien aus den Sicherungskopien der Schattenkopie zu **extrahieren**.

![](<../../../.gitbook/assets/image (521).png>)

Der Registrierungseintrag `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` enthält die Dateien und Schlüssel, die **nicht gesichert werden sollen**:

![](<../../../.gitbook/assets/image (522).png>)

Die Registrierung `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` enthält auch Konfigurationsinformationen über die `Volume Shadow Copies`.

### Office AutoSaved-Dateien

Sie können die automatisch gespeicherten Office-Dateien unter folgendem Pfad finden: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell-Elemente

Ein Shell-Element ist ein Element, das Informationen darüber enthält, wie auf eine andere Datei zugegriffen werden kann.

### Zuletzt verwendete Dokumente (LNK)

Windows erstellt diese **Verknüpfungen** **automatisch**, wenn der Benutzer eine Datei **öffnet, verwendet oder erstellt** in:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Wenn ein Ordner erstellt wird, wird auch eine Verknüpfung zum Ordner, zum übergeordneten Ordner und zum Großelterordner erstellt.

Diese automatisch erstellten Verknüpfungsdateien enthalten Informationen über die Herkunft, ob es sich um eine **Datei** oder einen **Ordner** handelt, **MAC-Zeiten** dieser Datei, **Volumeninformationen**, wo die Datei gespeichert ist, und **Ordner der Zieldatei**. Diese Informationen können nützlich sein, um diese Dateien wiederherzustellen, falls sie entfernt wurden.

Außerdem ist das **Erstelldatum der Verknüpfung** die erste **Zeit**, zu der die Originaldatei **erstmalig verwendet** wurde, und das **Änderungsdatum** der Verknüpfungsdatei ist die **letzte Zeit**, zu der die Ursprungsdatei verwendet wurde.

Zur Inspektion dieser Dateien können Sie [**LinkParser**](http://4discovery.com/our-tools/) verwenden.

In diesem Tool finden Sie **2 Sets** von Zeitstempeln:

* **Erstes Set:**
1. Dateiänderungsdatum
2. Dateizugriffsdatum
3. Dateierstellungsdatum
* **Zweites Set:**
1. Verknüpfungsänderungsdatum
2. Verknüpfungszugriffsdatum
3. Verknüpfungserstellungsdatum.

Das erste Set von Zeitstempeln bezieht sich auf die **Zeitstempel der Datei selbst**. Das zweite Set bezieht sich auf die **Zeitstempel der verknüpften Datei**.

Sie können dieselben Informationen erhalten, indem Sie das Windows CLI-Tool ausführen: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
### Jumplists

Dies sind die zuletzt verwendeten Dateien pro Anwendung. Es handelt sich um eine Liste der **zuletzt verwendeten Dateien einer Anwendung**, auf die Sie in jeder Anwendung zugreifen können. Sie können **automatisch erstellt oder benutzerdefiniert sein**.

Die **automatisch erstellten Jumplists** werden unter `C:\Users\{Benutzername}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` gespeichert. Die Jumplists sind nach dem Format `{ID}.automaticDestinations-ms` benannt, wobei die anfängliche ID die ID der Anwendung ist.

Die benutzerdefinierten Jumplists werden unter `C:\Users\{Benutzername}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` gespeichert und werden in der Regel von der Anwendung erstellt, weil etwas **Wichtiges** mit der Datei passiert ist (vielleicht als Favorit markiert).

Die **Erstellungszeit** einer Jumplist gibt an, **wann die Datei zum ersten Mal zugegriffen wurde**, und die **Änderungszeit das letzte Mal**.

Sie können die Jumplists mit [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) überprüfen.

![](<../../../.gitbook/assets/image (474).png>)

(Bitte beachten Sie, dass die von JumplistExplorer bereitgestellten Zeitstempel mit der Jumplist-Datei selbst zusammenhängen.)

### Shellbags

[Folgen Sie diesem Link, um zu erfahren, was Shellbags sind.](interesting-windows-registry-keys.md#shellbags)

## Verwendung von Windows-USBs

Es ist möglich festzustellen, dass ein USB-Gerät verwendet wurde, dank der Erstellung von:

* Windows Recent-Ordner
* Microsoft Office Recent-Ordner
* Jumplists

Beachten Sie, dass einige LNK-Dateien anstelle des ursprünglichen Pfads auf den WPDNSE-Ordner verweisen:

![](<../../../.gitbook/assets/image (476).png>)

Die Dateien im WPDNSE-Ordner sind Kopien der Originaldateien, daher überleben sie keinen Neustart des PCs und die GUID wird aus einem Shellbag übernommen.

### Registrierungsinformationen

[Überprüfen Sie diese Seite, um zu erfahren](interesting-windows-registry-keys.md#usb-information), welche Registrierungsschlüssel interessante Informationen über angeschlossene USB-Geräte enthalten.

### setupapi

Überprüfen Sie die Datei `C:\Windows\inf\setupapi.dev.log`, um die Zeitstempel darüber zu erhalten, wann die USB-Verbindung hergestellt wurde (suchen Sie nach `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kann verwendet werden, um Informationen über die an ein Bild angeschlossenen USB-Geräte zu erhalten.

![](<../../../.gitbook/assets/image (483).png>)

### Plug and Play Cleanup

Die geplante Aufgabe namens 'Plug and Play Cleanup' ist hauptsächlich für die Entfernung veralteter Treiberversionen konzipiert. Entgegen ihrem angegebenen Zweck, die neueste Treiberversion beizubehalten, deuten Online-Quellen darauf hin, dass sie auch Treiber löscht, die seit 30 Tagen inaktiv sind. Folglich können Treiber für entfernbare Geräte, die in den letzten 30 Tagen nicht angeschlossen wurden, gelöscht werden.

Die Aufgabe befindet sich unter dem folgenden Pfad:
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Ein Screenshot des Inhalts der Aufgabe wird bereitgestellt:
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Wichtige Komponenten und Einstellungen der Aufgabe:**
- **pnpclean.dll**: Diese DLL ist für den eigentlichen Bereinigungsvorgang verantwortlich.
- **UseUnifiedSchedulingEngine**: Auf `TRUE` gesetzt, was auf die Verwendung des generischen Taskplanungsmotors hinweist.
- **MaintenanceSettings**:
- **Periode ('P1M')**: Weist den Taskplaner an, die Bereinigungsaufgabe monatlich während der regulären automatischen Wartung zu starten.
- **Frist ('P2M')**: Weist den Taskplaner an, die Aufgabe bei zwei aufeinanderfolgenden Monaten des Scheiterns während der Notfallautomatisierung durchzuführen.

Diese Konfiguration gewährleistet eine regelmäßige Wartung und Bereinigung von Treibern mit Vorkehrungen für einen erneuten Versuch der Aufgabe bei aufeinanderfolgenden Fehlern.

**Weitere Informationen finden Sie unter:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-Mails

E-Mails enthalten **2 interessante Teile: Die Header und den Inhalt** der E-Mail. In den **Headern** finden Sie Informationen wie:

* **Wer** die E-Mails gesendet hat (E-Mail-Adresse, IP, Mailserver, die die E-Mail weitergeleitet haben)
* **Wann** die E-Mail gesendet wurde

Außerdem finden Sie in den Headern `References` und `In-Reply-To` die ID der Nachrichten:

![](<../../../.gitbook/assets/image (484).png>)

### Windows Mail App

Diese Anwendung speichert E-Mails in HTML oder Text. Sie finden die E-Mails in Unterordnern unter `\Users\<Benutzername>\AppData\Local\Comms\Unistore\data\3\`. Die E-Mails werden mit der Erweiterung `.dat` gespeichert.

Die **Metadaten** der E-Mails und die **Kontakte** finden Sie in der **EDB-Datenbank**: `\Users\<Benutzername>\AppData\Local\Comms\UnistoreDB\store.vol`

**Ändern Sie die Erweiterung** der Datei von `.vol` in `.edb` und Sie können das Tool [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) verwenden, um sie zu öffnen. In der Tabelle `Message` können Sie die E-Mails sehen.

### Microsoft Outlook

Wenn Exchange-Server oder Outlook-Clients verwendet werden, gibt es einige MAPI-Header:

* `Mapi-Client-Submit-Time`: Zeit des Systems, als die E-Mail gesendet wurde
* `Mapi-Conversation-Index`: Anzahl der Kindernachrichten des Threads und Zeitstempel jeder Nachricht des Threads
* `Mapi-Entry-ID`: Nachrichtenidentifikator.
* `Mappi-Message-Flags` und `Pr_last_Verb-Executed`: Informationen über den MAPI-Client (Nachricht gelesen? Nicht gelesen? Beantwortet? Weitergeleitet? Abwesend?)

Im Microsoft Outlook-Client werden alle gesendeten/empfangenen Nachrichten, Kontaktdaten und Kalenderdaten in einer PST-Datei gespeichert unter:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Der Registrierungspfad `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` gibt an, welche Datei verwendet wird.

Sie können die PST-Datei mit dem Tool [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) öffnen.

![](<../../../.gitbook/assets/image (485).png>)
### Microsoft Outlook OST-Dateien

Eine **OST-Datei** wird von Microsoft Outlook generiert, wenn es mit einem **IMAP**- oder einem **Exchange**-Server konfiguriert ist und ähnliche Informationen wie eine PST-Datei speichert. Diese Datei wird mit dem Server synchronisiert, behält Daten für **die letzten 12 Monate** bis zu einer **maximalen Größe von 50 GB** bei und befindet sich im selben Verzeichnis wie die PST-Datei. Um eine OST-Datei anzuzeigen, kann der [**Kernel OST-Viewer**](https://www.nucleustechnologies.com/ost-viewer.html) verwendet werden.

### Abrufen von Anhängen

Verlorene Anhänge können aus folgenden Orten wiederhergestellt werden:

- Für **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Für **IE11 und höher**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX-Dateien

**Thunderbird** verwendet **MBOX-Dateien** zur Speicherung von Daten, die sich unter `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles` befinden.

### Bildvorschauen

- **Windows XP und 8-8.1**: Der Zugriff auf einen Ordner mit Miniaturansichten erzeugt eine `thumbs.db`-Datei, die Bildvorschauen speichert, auch nach dem Löschen.
- **Windows 7/10**: `thumbs.db` wird erstellt, wenn über einen Netzwerkpfad über UNC zugegriffen wird.
- **Windows Vista und neuere Versionen**: Miniaturansichten sind zentralisiert in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` mit Dateien namens **thumbcache\_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) und [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sind Tools zum Anzeigen dieser Dateien.

### Windows-Registrierungsinformationen

Die Windows-Registrierung, die umfangreiche System- und Benutzeraktivitätsdaten speichert, ist in Dateien enthalten, die sich befinden in:

- `%windir%\System32\Config` für verschiedene `HKEY_LOCAL_MACHINE`-Unterschlüssel.
- `%UserProfile%{Benutzer}\NTUSER.DAT` für `HKEY_CURRENT_USER`.
- Windows Vista und neuere Versionen sichern die Registrierungsdateien von `HKEY_LOCAL_MACHINE` zusätzlich in `%Windir%\System32\Config\RegBack\`.
- Darüber hinaus werden Informationen zur Programmausführung in `%UserProfile%\{Benutzer}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` ab Windows Vista und Windows 2008 Server gespeichert.

### Tools

Einige Tools sind nützlich zur Analyse der Registrierungsdateien:

* **Registrierungseditor**: Er ist in Windows installiert. Es ist eine grafische Benutzeroberfläche zum Navigieren durch die Windows-Registrierung der aktuellen Sitzung.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Es ermöglicht das Laden der Registrierungsdatei und das Navigieren durch sie mit einer grafischen Benutzeroberfläche. Es enthält auch Lesezeichen, die Schlüssel mit interessanten Informationen hervorheben.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Auch hier gibt es eine grafische Benutzeroberfläche, die es ermöglicht, durch die geladene Registrierung zu navigieren und enthält auch Plugins, die interessante Informationen in der geladenen Registrierung hervorheben.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Eine weitere GUI-Anwendung, die in der Lage ist, wichtige Informationen aus der geladenen Registrierung zu extrahieren.

### Wiederherstellen eines gelöschten Elements

Wenn ein Schlüssel gelöscht wird, wird er als solcher markiert, aber bis der Platz, den er einnimmt, benötigt wird, wird er nicht entfernt. Daher ist es mit Tools wie **Registry Explorer** möglich, diese gelöschten Schlüssel wiederherzustellen.

### Letztes Änderungsdatum

Jeder Schlüssel-Wert enthält einen **Zeitstempel**, der angibt, wann er zuletzt geändert wurde.

### SAM

Die Datei/Hive **SAM** enthält die **Benutzer-, Gruppen- und Benutzerpasswort-Hashes** des Systems.

In `SAM\Domains\Account\Users` können Sie den Benutzernamen, die RID, den letzten Login, den letzten fehlgeschlagenen Login, den Login-Zähler, die Passwortrichtlinie und das Erstellungsdatum des Kontos erhalten. Um die **Hashes** zu erhalten, benötigen Sie auch die Datei/Hive **SYSTEM**.

### Interessante Einträge in der Windows-Registrierung

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Ausgeführte Programme

### Grundlegende Windows-Prozesse

In [diesem Beitrag](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) können Sie mehr über die gängigen Windows-Prozesse erfahren, um verdächtige Verhaltensweisen zu erkennen.

### Kürzlich verwendete Windows-Apps

In der Registrierung `NTUSER.DAT` im Pfad `Software\Microsoft\Current Version\Search\RecentApps` finden Sie Unterschlüssel mit Informationen über die **ausgeführte Anwendung**, den **letzten Ausführungszeitpunkt** und die **Anzahl der Ausführungen**.

### BAM (Background Activity Moderator)

Sie können die Datei `SYSTEM` mit einem Registrierungseditor öffnen und im Pfad `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` Informationen über die **von jedem Benutzer ausgeführten Anwendungen** finden (beachten Sie die `{SID}` im Pfad) und zu **welcher Zeit** sie ausgeführt wurden (die Zeit befindet sich im Datenwert der Registrierung).

### Windows Prefetch

Prefetching ist eine Technik, die es einem Computer ermöglicht, stillschweigend die **notwendigen Ressourcen abzurufen, die benötigt werden, um Inhalte anzuzeigen**, auf die ein Benutzer **möglicherweise in naher Zukunft zugreifen wird**, damit Ressourcen schneller abgerufen werden können.

Windows Prefetch besteht darin, **Caches der ausgeführten Programme** zu erstellen, um sie schneller laden zu können. Diese Caches werden als `.pf`-Dateien im Pfad erstellt: `C:\Windows\Prefetch`. Es gibt eine Begrenzung von 128 Dateien in XP/VISTA/WIN7 und 1024 Dateien in Win8/Win10.

Der Dateiname wird als `{Programmname}-{Hash}.pf` erstellt (der Hash basiert auf dem Pfad und den Argumenten der ausführbaren Datei). In W10 sind diese Dateien komprimiert. Beachten Sie, dass allein das Vorhandensein der Datei darauf hinweist, dass **das Programm** zu einem bestimmten Zeitpunkt **ausgeführt wurde**.

Die Datei `C:\Windows\Prefetch\Layout.ini` enthält die **Namen der Ordner der vorausgeholten Dateien**. Diese Datei enthält **Informationen über die Anzahl der Ausführungen**, **Datum** der Ausführung und **Dateien**, die vom Programm **geöffnet** wurden.

Um diese Dateien zu inspizieren, können Sie das Tool [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) verwenden:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** hat das gleiche Ziel wie prefetch, **Programme schneller laden**, indem vorhergesagt wird, was als nächstes geladen wird. Es ersetzt jedoch nicht den prefetch-Dienst.\
Dieser Dienst generiert Datenbankdateien in `C:\Windows\Prefetch\Ag*.db`.

In diesen Datenbanken finden Sie den **Namen des Programms**, die **Anzahl der Ausführungen**, die **geöffneten Dateien**, den **zugriffenen Speicher**, den **vollständigen Pfad**, die **Zeitrahmen** und die **Zeitstempel**.

Sie können auf diese Informationen mit dem Tool [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) zugreifen.

### SRUM

Der **System Resource Usage Monitor** (SRUM) **überwacht** die **Ressourcen**, die von einem Prozess **verbraucht** werden. Er erschien in W8 und speichert die Daten in einer ESE-Datenbank, die sich in `C:\Windows\System32\sru\SRUDB.dat` befindet.

Er gibt folgende Informationen:

* AppID und Pfad
* Benutzer, der den Prozess ausgeführt hat
* Gesendete Bytes
* Empfangene Bytes
* Netzwerkschnittstelle
* Verbindungsdauer
* Prozessdauer

Diese Informationen werden alle 60 Minuten aktualisiert.

Sie können die Daten aus dieser Datei mit dem Tool [**srum\_dump**](https://github.com/MarkBaggett/srum-dump) erhalten.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Der **AppCompatCache**, auch bekannt als **ShimCache**, bildet einen Teil der von **Microsoft** entwickelten **Application Compatibility Database**, um Probleme mit der Anwendungskompatibilität zu lösen. Dieses Systemkomponente zeichnet verschiedene Dateimetadaten auf, die Folgendes beinhalten:

- Vollständiger Pfad der Datei
- Größe der Datei
- Letzte Änderungszeit unter **$Standard\_Information** (SI)
- Letzte Aktualisierungszeit des ShimCache
- Prozessausführungsflag

Diese Daten werden in der Registrierung an spezifischen Standorten basierend auf der Version des Betriebssystems gespeichert:

- Für XP werden die Daten unter `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` mit einer Kapazität von 96 Einträgen gespeichert.
- Für Server 2003 sowie für Windows-Versionen 2008, 2012, 2016, 7, 8 und 10 lautet der Speicherpfad `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, wobei jeweils 512 bzw. 1024 Einträge Platz finden.

Zur Analyse der gespeicherten Informationen wird die Verwendung des [**AppCompatCacheParser**-Tools](https://github.com/EricZimmerman/AppCompatCacheParser) empfohlen.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

Die Datei **Amcache.hve** ist im Wesentlichen eine Registrierungshive, die Details über auf einem System ausgeführte Anwendungen protokolliert. Sie wird typischerweise unter `C:\Windows\AppCompat\Programas\Amcache.hve` gefunden.

Diese Datei ist bemerkenswert, da sie Aufzeichnungen über kürzlich ausgeführte Prozesse speichert, einschließlich der Pfade zu den ausführbaren Dateien und ihrer SHA1-Hashes. Diese Informationen sind von unschätzbarem Wert, um die Aktivität von Anwendungen auf einem System zu verfolgen.

Zur Extraktion und Analyse der Daten aus **Amcache.hve** kann das [**AmcacheParser**-Tool](https://github.com/EricZimmerman/AmcacheParser) verwendet werden. Das folgende Beispiel zeigt, wie AmcacheParser verwendet wird, um den Inhalt der **Amcache.hve**-Datei zu analysieren und die Ergebnisse im CSV-Format auszugeben:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Unter den generierten CSV-Dateien ist besonders die `Amcache_Unassociated file entries` aufgrund der umfangreichen Informationen über nicht zugeordnete Dateieinträge hervorzuheben.

Die interessanteste generierte CVS-Datei ist die `Amcache_Unassociated file entries`.

### RecentFileCache

Dieses Artefakt kann nur in W7 unter `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` gefunden werden und enthält Informationen über die kürzliche Ausführung einiger Binärdateien.

Sie können das Tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) verwenden, um die Datei zu analysieren.

### Geplante Aufgaben

Sie können sie aus `C:\Windows\Tasks` oder `C:\Windows\System32\Tasks` extrahieren und als XML lesen.

### Dienste

Sie finden sie in der Registrierung unter `SYSTEM\ControlSet001\Services`. Sie können sehen, was ausgeführt wird und wann.

### **Windows Store**

Die installierten Anwendungen finden Sie in `\ProgramData\Microsoft\Windows\AppRepository\`\
Dieses Repository enthält ein **Protokoll** mit **jeder installierten Anwendung** im System innerhalb der Datenbank **`StateRepository-Machine.srd`**.

In der Anwendungstabelle dieser Datenbank können die Spalten "Anwendungs-ID", "PackageNumber" und "Anzeigename" gefunden werden. Diese Spalten enthalten Informationen über vorinstallierte und installierte Anwendungen, und es kann festgestellt werden, ob einige Anwendungen deinstalliert wurden, da die IDs der installierten Anwendungen sequenziell sein sollten.

Es ist auch möglich, **installierte Anwendungen** im Registrierungspfad zu finden: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Und **deinstallierte Anwendungen** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows-Ereignisse

Informationen, die in Windows-Ereignissen erscheinen, sind:

* Was passiert ist
* Zeitstempel (UTC + 0)
* Beteiligte Benutzer
* Beteiligte Hosts (Hostname, IP)
* Zugriff auf Assets (Dateien, Ordner, Drucker, Dienste)

Die Protokolle befinden sich in `C:\Windows\System32\config` vor Windows Vista und in `C:\Windows\System32\winevt\Logs` nach Windows Vista. Vor Windows Vista waren die Ereignisprotokolle im Binärformat und danach sind sie im **XML-Format** und verwenden die **.evtx**-Erweiterung.

Der Speicherort der Ereignisdateien kann in der SYSTEM-Registrierung unter **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Anwendung|System|Sicherheit}`** gefunden werden.

Sie können sie mit dem Windows-Ereignisbetrachter (**`eventvwr.msc`**) oder mit anderen Tools wie [**Event Log Explorer**](https://eventlogxp.com) **oder** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** visualisieren.**

## Verständnis der Protokollierung von Windows-Sicherheitsereignissen

Zugriffsereignisse werden in der Sicherheitskonfigurationsdatei aufgezeichnet, die sich unter `C:\Windows\System32\winevt\Security.evtx` befindet. Die Größe dieser Datei ist anpassbar, und wenn ihre Kapazität erreicht ist, werden ältere Ereignisse überschrieben. Aufgezeichnete Ereignisse umfassen Benutzeranmeldungen und -abmeldungen, Benutzeraktionen und Änderungen an Sicherheitseinstellungen sowie den Zugriff auf Dateien, Ordner und freigegebene Assets.

### Schlüsselereignis-IDs für die Benutzerauthentifizierung:

- **EventID 4624**: Zeigt eine erfolgreiche Benutzerauthentifizierung an.
- **EventID 4625**: Signalisiert ein Authentifizierungsfehler.
- **EventIDs 4634/4647**: Stellen Benutzerabmeldeereignisse dar.
- **EventID 4672**: Kennzeichnet die Anmeldung mit administrativen Berechtigungen.

#### Untertypen innerhalb von EventID 4634/4647:

- **Interaktiv (2)**: Direkte Benutzeranmeldung.
- **Netzwerk (3)**: Zugriff auf freigegebene Ordner.
- **Batch (4)**: Ausführung von Stapelprozessen.
- **Dienst (5)**: Dienststarts.
- **Proxy (6)**: Proxy-Authentifizierung.
- **Entsperren (7)**: Bildschirm mit einem Passwort entsperrt.
- **Netzwerk im Klartext (8)**: Übertragung von Klartextpasswörtern, oft von IIS.
- **Neue Anmeldeinformationen (9)**: Verwendung unterschiedlicher Anmeldeinformationen für den Zugriff.
- **Remote-Interaktiv (10)**: Anmeldung über Remote-Desktop oder Terminaldienste.
- **Zwischengespeichert interaktiv (11)**: Anmeldung mit zwischengespeicherten Anmeldeinformationen ohne Kontakt zum Domänencontroller.
- **Zwischengespeichert remote-interaktiv (12)**: Remote-Anmeldung mit zwischengespeicherten Anmeldeinformationen.
- **Zwischengespeichert entsperren (13)**: Entsperren mit zwischengespeicherten Anmeldeinformationen.

#### Status- und Untertypencodes für EventID 4625:

- **0xC0000064**: Benutzername existiert nicht - Könnte auf einen Benutzernamensenumerationsangriff hinweisen.
- **0xC000006A**: Richtiger Benutzername, aber falsches Passwort - Möglicherweise ein Versuch zum Erraten oder Brute-Forcen von Passwörtern.
- **0xC0000234**: Benutzerkonto gesperrt - Kann auf einen Brute-Force-Angriff mit mehreren fehlgeschlagenen Anmeldungen folgen.
- **0xC0000072**: Konto deaktiviert - Nicht autorisierte Versuche, auf deaktivierte Konten zuzugreifen.
- **0xC000006F**: Anmeldung außerhalb der erlaubten Zeit - Deutet auf Versuche hin, außerhalb der festgelegten Anmeldezeiten zuzugreifen, ein mögliches Zeichen für unbefugten Zugriff.
- **0xC0000070**: Verstoß gegen die Arbeitsstationseinschränkungen - Könnte ein Versuch sein, sich von einem nicht autorisierten Ort aus anzumelden.
- **0xC0000193**: Ablauf des Kontos - Zugriffsversuche mit abgelaufenen Benutzerkonten.
- **0xC0000071**: Abgelaufenes Passwort - Anmeldeversuche mit veralteten Passwörtern.
- **0xC0000133**: Zeit-Synchronisierungsprobleme - Große Zeitunterschiede zwischen Client und Server können auf anspruchsvollere Angriffe wie Pass-the-Ticket hinweisen.
- **0xC0000224**: Erforderliche obligatorische Passwortänderung - Häufige obligatorische Änderungen könnten auf einen Versuch hindeuten, die Kontosicherheit zu destabilisieren.
- **0xC0000225**: Deutet auf einen Systemfehler hin, nicht auf ein Sicherheitsproblem.
- **0xC000015b**: Verweigerte Anmeldetyp - Zugriffsversuch mit nicht autorisiertem Anmeldetyp, z. B. ein Benutzer, der versucht, eine Dienstanmeldung auszuführen.

#### EventID 4616:
- **Zeitänderung**: Änderung der Systemzeit, könnte die zeitliche Abfolge von Ereignissen verschleiern.

#### EventID 6005 und 6006:
- **Systemstart und -abschaltung**: EventID 6005 zeigt den Systemstart an, während EventID 6006 das Herunterfahren markiert.

#### EventID 1102:
- **Protokolllöschung**: Sicherheitsprotokolle werden gelöscht, was oft ein Hinweis auf das Vertuschen von illegalen Aktivitäten ist.

#### EventIDs für die Verfolgung von USB-Geräten:
- **20001 / 20003 / 10000**: Erstverbindung des USB-Geräts.
- **10100**: USB-Treiberupdate.
- **EventID 112**: Zeitpunkt des Einsteckens des USB-Geräts.

Für praktische Beispiele zur Simulation dieser Anmeldetypen und Möglichkeiten zum Auslesen von Anmeldeinformationen siehe [Altered Security's detaillierten Leitfaden](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Ereignisdetails, einschließlich Status- und Untertypencodes, liefern weitere Einblicke in die Ereignisursachen, insbesondere bei Ereignis-ID 4625.

### Wiederherstellung von Windows-Ereignissen

Um die Chancen auf die Wiederherstellung gelöschter Windows-Ereignisse zu erhöhen, ist es ratsam, den verdächtigen Computer durch direktes Abziehen des Netzsteckers auszuschalten. **Bulk_extractor**, ein Wiederherstellungstool, das die Erweiterung `.evtx` angibt, wird empfohlen, um solche Ereignisse wiederherzustellen.

### Identifizierung von häufigen Angriffen über Windows-Ereignisse

Für einen umfassenden Leitfaden zur Verwendung von Windows-Ereignis-IDs zur Identifizierung häufiger Cyberangriffe besuchen Sie [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute-Force-Angriffe

Identifizierbar durch mehrere EventID 4625-Einträge, gefolgt von einem EventID 4624, wenn der Angriff erfolgreich ist.

#### Zeitänderung

Aufgezeichnet durch EventID 4616, können Änderungen an der Systemzeit die forensische Analyse erschweren.

#### Verfolgung von USB-Geräten

Nützliche System-EventIDs für die Verfolgung von USB-Geräten sind 20001/20003/10000 für die Erstnutzung, 10100 für Treiberupdates und EventID 112 von DeviceSetupManager für Einsteckzeitstempel.
#### System Power Events

EventID 6005 zeigt den Systemstart an, während EventID 6006 den Shutdown markiert.

#### Log Deletion

Sicherheits-EventID 1102 signalisiert die Löschung von Logs, ein kritisches Ereignis für forensische Analysen.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
