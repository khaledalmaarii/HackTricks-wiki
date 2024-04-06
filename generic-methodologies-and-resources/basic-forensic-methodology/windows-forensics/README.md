# Windows Artifacts

## Windows-Artefakte

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Generische Windows-Artefakte

### Windows 10-Benachrichtigungen

Im Pfad `\Users\<Benutzername>\AppData\Local\Microsoft\Windows\Notifications` finden Sie die Datenbank `appdb.dat` (vor dem Windows-Jubiläum) oder `wpndatabase.db` (nach dem Windows-Jubiläum).

In dieser SQLite-Datenbank finden Sie die Tabelle `Notification` mit allen Benachrichtigungen (im XML-Format), die möglicherweise interessante Daten enthalten.

### Zeitachse

Die Zeitachse ist eine Windows-Funktion, die einen **chronologischen Verlauf** der besuchten Webseiten, bearbeiteten Dokumente und ausgeführten Anwendungen bietet.

Die Datenbank befindet sich im Pfad `\Users\<Benutzername>\AppData\Local\ConnectedDevicesPlatform\<ID>\ActivitiesCache.db`. Diese Datenbank kann mit einem SQLite-Tool oder mit dem Tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) geöffnet werden, **das 2 Dateien generiert, die mit dem Tool** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **geöffnet werden können**.

### ADS (Alternate Data Streams)

Heruntergeladene Dateien können die **ADS Zone.Identifier** enthalten, die anzeigen, **wie** sie aus dem Intranet, Internet usw. heruntergeladen wurden. Einige Software (wie Browser) geben in der Regel sogar **weitere Informationen** wie die **URL** an, von der die Datei heruntergeladen wurde.

## **Dateisicherungen**

### Papierkorb

In Vista/Win7/Win8/Win10 befindet sich der **Papierkorb** im Ordner **`$Recycle.bin`** im Stammverzeichnis des Laufwerks (`C:\$Recycle.bin`).\
Wenn eine Datei in diesem Ordner gelöscht wird, werden 2 spezifische Dateien erstellt:

* `$I{id}`: Dateiinformationen (Datum des Löschens)
* `$R{id}`: Inhalt der Datei

![](<../../../.gitbook/assets/image (486).png>)

Mit diesen Dateien können Sie das Tool [**Rifiuti**](https://github.com/abelcheung/rifiuti2) verwenden, um die ursprüngliche Adresse der gelöschten Dateien und das Löschdatum zu erhalten (verwenden Sie `rifiuti-vista.exe` für Vista - Win10).

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy ist eine Technologie, die in Microsoft Windows enthalten ist und **Sicherungskopien** oder Snapshots von Computerdateien oder -volumes erstellen kann, auch wenn sie verwendet werden.

Diese Backups befinden sich normalerweise im Verzeichnis `\System Volume Information` im Stammverzeichnis des Dateisystems und der Name setzt sich aus **UIDs** zusammen, wie im folgenden Bild gezeigt:

![](<../../../.gitbook/assets/image (520).png>)

Durch das Einbinden des forensischen Abbilds mit dem Tool **ArsenalImageMounter** kann das Tool [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) verwendet werden, um eine Schattenkopie zu inspizieren und sogar **Dateien aus den Sicherungskopien** der Schattenkopie zu extrahieren.

![](<../../../.gitbook/assets/image (521).png>)

Der Registrierungseintrag `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` enthält die Dateien und Schlüssel, die **nicht gesichert** werden sollen:

![](<../../../.gitbook/assets/image (522).png>)

Die Registrierung `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` enthält auch Konfigurationsinformationen zu den `Volume Shadow Copies`.

### Office AutoSaved Files

Sie können die automatisch gespeicherten Office-Dateien unter `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\` finden.

## Shell Items

Ein Shell-Element ist ein Element, das Informationen darüber enthält, wie auf eine andere Datei zugegriffen werden kann.

### Zuletzt verwendete Dokumente (LNK)

Windows erstellt diese **Verknüpfungen** automatisch, wenn der Benutzer eine Datei **öffnet, verwendet oder erstellt** in:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Beim Erstellen eines Ordners wird auch eine Verknüpfung zum Ordner, zum übergeordneten Ordner und zum Großelterndateiordner erstellt.

Diese automatisch erstellten Verknüpfungsdateien **enthalten Informationen über die Herkunft** wie z.B. ob es sich um eine **Datei** oder einen **Ordner** handelt, **MAC-Zeiten** dieser Datei, **Volumeninformationen**, wo die Datei gespeichert ist, und **Ordner der Zieldatei**. Diese Informationen können nützlich sein, um diese Dateien wiederherzustellen, falls sie entfernt wurden.

Außerdem ist das **Erstellungsdatum der Verknüpfungsdatei** die erste **Zeit**, zu der die Originaldatei **erstmalig verwendet** wurde, und das **Änderungsdatum** der Verknüpfungsdatei ist die **letzte Zeit**, zu der die Ursprungsdatei verwendet wurde.

Um diese Dateien zu inspizieren, können Sie das Tool [**LinkParser**](http://4discovery.com/our-tools/) verwenden.

In diesem Tool finden Sie **2 Sätze** von Zeitstempeln:

* **Erster Satz:**

1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate

* **Zweiter Satz:**

1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Der erste Satz von Zeitstempeln bezieht sich auf die **Zeitstempel der Datei selbst**. Der zweite Satz bezieht sich auf die **Zeitstempel der verknüpften Datei**.

Sie können dieselben Informationen mit dem Windows CLI-Tool [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) erhalten.

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

In diesem Fall werden die Informationen in einer CSV-Datei gespeichert.

### Jumplists

Dies sind die zuletzt verwendeten Dateien pro Anwendung. Es handelt sich um eine Liste der **zuletzt von einer Anwendung verwendeten Dateien**, auf die Sie in jeder Anwendung zugreifen können. Sie können automatisch erstellt oder benutzerdefiniert sein.

Die automatisch erstellten **Jumplists** werden unter `C:\Users\{Benutzername}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` gespeichert. Die Jumplists haben das Format `{ID}.autmaticDestinations-ms`, wobei die anfängliche ID die ID der Anwendung ist.

Die benutzerdefinierten Jumplists werden unter `C:\Users\{Benutzername}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` gespeichert und werden in der Regel von der Anwendung erstellt, weil etwas **Wichtiges** mit der Datei passiert ist (vielleicht als Favorit markiert).

Die **Erstellungszeit** einer Jumplist gibt an, **wann die Datei zum ersten Mal zugegriffen wurde**, und die **Änderungszeit das letzte Mal**.

Sie können die Jumplists mit [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) überprüfen.

![](<../../../.gitbook/assets/image (474).png>)

(_Beachten Sie, dass die von JumplistExplorer bereitgestellten Zeitstempel sich auf die Jumplist-Datei selbst beziehen_)

### Shellbags

[**Folgen Sie diesem Link**, um herauszufinden, was Shellbags sind.](interesting-windows-registry-keys.md#shellbags)

## Verwendung von Windows-USBs

Es ist möglich festzustellen, dass ein USB-Gerät verwendet wurde, dank der Erstellung von:

* Windows Recent Folder
* Microsoft Office Recent Folder
* Jumplists

Beachten Sie, dass einige LNK-Dateien anstelle auf den Originalpfad auf den WPDNSE-Ordner verweisen:

![](<../../../.gitbook/assets/image (476).png>)

Die Dateien im WPDNSE-Ordner sind Kopien der Originaldateien und überleben daher nicht einen Neustart des PCs. Die GUID wird aus einer Shellbag entnommen.

### Registrierungsinformationen

[Überprüfen Sie diese Seite, um herauszufinden](interesting-windows-registry-keys.md#usb-information), welche Registrierungsschlüssel interessante Informationen über angeschlossene USB-Geräte enthalten.

### setupapi

Überprüfen Sie die Datei `C:\Windows\inf\setupapi.dev.log`, um die Zeitstempel darüber zu erhalten, wann die USB-Verbindung hergestellt wurde (suchen Sie nach `Section start`).

![](https://github.com/carlospolop/hacktricks/blob/de/.gitbook/assets/image%20\(477\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(3\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(14\).png)

### USB Detective

[**USBDetective**](https://usbdetective.com) kann verwendet werden, um Informationen über die USB-Geräte zu erhalten, die mit einem Image verbunden waren.

![](<../../../.gitbook/assets/image (483).png>)

### Plug and Play Cleanup

Die geplante Aufgabe mit dem Namen "Plug and Play Cleanup" ist hauptsächlich für die Entfernung veralteter Treiberversionen vorgesehen. Entgegen ihrem angegebenen Zweck, die neueste Treiberversion beizubehalten, zielen Online-Quellen darauf hin, dass sie auch Treiber löscht, die seit 30 Tagen inaktiv waren. Folglich können Treiber für abnehmbare Geräte, die in den letzten 30 Tagen nicht angeschlossen waren, gelöscht werden.

Die Aufgabe befindet sich unter folgendem Pfad: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Ein Screenshot des Inhalts der Aufgabe wird bereitgestellt: ![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Wichtige Komponenten und Einstellungen der Aufgabe:**

* **pnpclean.dll**: Diese DLL ist für den eigentlichen Bereinigungsprozess verantwortlich.
* **UseUnifiedSchedulingEngine**: Auf `TRUE` gesetzt, was auf die Verwendung des generischen Taskplanungsmotors hinweist.
* **MaintenanceSettings**:
* **Period ('P1M')**: Weist den Taskplaner an, den Bereinigungsvorgang monatlich während der regulären automatischen Wartung durchzuführen.
* **Deadline ('P2M')**: Weist den Taskplaner an, den Task bei zwei aufeinanderfolgenden Monaten, in denen der Task fehlschlägt, während der Notfallautomatisierung durchzuführen.

Diese Konfiguration gewährleistet eine regelmäßige Wartung und Bereinigung der Treiber und bietet die Möglichkeit, den Task bei aufeinanderfolgenden Fehlern erneut auszuführen.

**Weitere Informationen finden Sie unter:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-Mails

E-Mails enthalten **2 interessante Teile: Die Header und den Inhalt** der E-Mail. In den **Headern** finden Sie Informationen wie:

* **Wer** die E-Mails gesendet hat (E-Mail-Adresse, IP, Mailserver, die die E-Mail umgeleitet haben)
* **Wann** wurde die E-Mail gesendet

Außerdem finden Sie in den Headern "References" und "In-Reply-To" die ID der Nachrichten:

![](<../../../.gitbook/assets/image (484).png>)

### Windows Mail App

Diese Anwendung speichert E-Mails in HTML oder Text. Sie finden die E-Mails in Unterordnern unter `\Users\<Benutzername>\AppData\Local\Comms\Unistore\data\3\`. Die E-Mails werden mit der Erweiterung `.dat` gespeichert.

Die **Metadaten** der E-Mails und die **Kontakte** finden Sie in der **EDB-Datenbank**: `\Users\<Benutzername>\AppData\Local\Comms\UnistoreDB\store.vol`

**Ändern Sie die Erweiterung** der Datei von `.vol` in `.edb` und Sie können das Tool [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) verwenden, um es zu öffnen. In der Tabelle "Message" können Sie die E-Mails sehen.

### Microsoft Outlook

Wenn Exchange-Server oder Outlook-Clients verwendet werden, gibt es einige MAPI-Header:

* `Mapi-Client-Submit-Time`: Zeit des Systems, als die E-Mail gesendet wurde
* `Mapi-Conversation-Index`: Anzahl der Kindernachrichten des Threads und Zeitstempel jeder Nachricht des Threads
* `Mapi-Entry-ID`: Nachrichtenidentifikator.
* `Mappi-Message-Flags` und `Pr_last_Verb-Executed`: Informationen über den MAPI-Client (wurde die Nachricht gelesen? nicht gelesen? beantwortet? umgeleitet? Abwesenheitsnotiz?)

Im Microsoft Outlook-Client werden alle gesendeten/empfangenen Nachrichten, Kontaktdaten und Kalenderdaten in einer PST-Datei gespeichert, und zwar unter:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Der Registrierungspfad `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` gibt an, welche Datei verwendet wird.

Sie können die PST-Datei mit dem Tool [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) öffnen.

![](<../../../.gitbook/assets/image (485).png>)

### Microsoft Outlook OST-Dateien

Eine **OST-Datei** wird von Microsoft Outlook generiert, wenn es mit einem **IMAP**- oder einem **Exchange**-Server konfiguriert ist und ähnliche Informationen wie eine PST-Datei speichert. Diese Datei wird mit dem Server synchronisiert und speichert Daten für **die letzten 12 Monate** mit einer **maximalen Größe von 50 GB**. Sie befindet sich im selben Verzeichnis wie die PST-Datei. Um eine OST-Datei anzuzeigen, kann der [**Kernel OST Viewer**](https://www.nucleustechnologies.com/ost-viewer.html) verwendet werden.

### Abrufen von Anhängen

Verlorene Anhänge können möglicherweise aus folgenden Ordnern wiederhergestellt werden:

* Für **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
* Für **IE11 und höher**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX-Dateien

**Thunderbird** verwendet **MBOX-Dateien**, um Daten zu speichern. Diese befinden sich unter `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Bildvorschauen

* **Windows XP und 8-8.1**: Beim Zugriff auf einen Ordner mit Bildvorschauen wird eine `thumbs.db`-Datei generiert, die auch nach dem Löschen die Bildvorschauen speichert.
* **Windows 7/10**: `thumbs.db` wird erstellt, wenn über einen Netzwerkpfad über UNC darauf zugegriffen wird.
* **Windows Vista und neuere Versionen**: Die Miniaturansichten werden zentral in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` mit Dateien namens **thumbcache\_xxx.db** gespeichert. [**Thumbsviewer**](https://thumbsviewer.github.io) und [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sind Tools zum Anzeigen dieser Dateien.

### Informationen in der Windows-Registrierung

Die Windows-Registrierung, die umfangreiche System- und Benutzeraktivitätsdaten speichert, befindet sich in Dateien unter:

* `%windir%\System32\Config` für verschiedene `HKEY_LOCAL_MACHINE`-Unterschlüssel.
* `%UserProfile%{Benutzer}\NTUSER.DAT` für `HKEY_CURRENT_USER`.
* Windows Vista und neuere Versionen sichern die `HKEY_LOCAL_MACHINE`-Registrierungsdateien in `%Windir%\System32\Config\RegBack\`.
* Zusätzlich werden Informationen zur Programmausführung ab Windows Vista und Windows 2008 Server in `%UserProfile%\{Benutzer}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` gespeichert.

### Tools

Einige Tools sind nützlich zur Analyse der Registrierungsdateien:

* **Registry Editor**: Es ist in Windows installiert und ermöglicht die Navigation durch die Windows-Registrierung der aktuellen Sitzung über eine grafische Benutzeroberfläche.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Es ermöglicht das Laden der Registrierungsdatei und die Navigation durch sie mit einer grafischen Benutzeroberfläche. Es enthält auch Lesezeichen, die Schlüssel mit interessanten Informationen hervorheben.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Auch dieses Tool verfügt über eine grafische Benutzeroberfläche, mit der man durch die geladene Registrierung navigieren kann. Es enthält auch Plugins, die interessante Informationen in der geladenen Registrierung hervorheben.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Eine weitere GUI-Anwendung, die in der Lage ist, wichtige Informationen aus der geladenen Registrierung zu extrahieren.

### Wiederherstellen gelöschter Elemente

Wenn ein Schlüssel gelöscht wird, wird er als solcher markiert, aber solange der Speicherplatz, den er einnimmt, nicht benötigt wird, wird er nicht entfernt. Daher ist es mit Tools wie **Registry Explorer** möglich, diese gelöschten Schlüssel wiederherzustellen.

### Zeitpunkt der letzten Änderung

Jeder Schlüssel-Wert enthält einen **Zeitstempel**, der den letzten Zeitpunkt angibt, an dem er geändert wurde.

### SAM

Die Datei/Hive **SAM** enthält die Hashes der **Benutzer, Gruppen und Benutzerpasswörter** des Systems.

In `SAM\Domains\Account\Users` können Sie den Benutzernamen, die RID, den letzten Login, den letzten fehlgeschlagenen Login, den Login-Zähler, die Passwortrichtlinie und den Zeitpunkt der Kontoerstellung abrufen. Um die **Hashes** zu erhalten, benötigen Sie auch die Datei/Hive **SYSTEM**.

### Interessante Einträge in der Windows-Registrierung

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Ausgeführte Programme

### Grundlegende Windows-Prozesse

In [diesem Beitrag](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) können Sie mehr über die gängigen Windows-Prozesse erfahren, um verdächtiges Verhalten zu erkennen.

### Zuletzt verwendete Windows-Apps

In der Registrierung `NTUSER.DAT` im Pfad `Software\Microsoft\Current Version\Search\RecentApps` finden Sie Unterschlüssel mit Informationen über die **ausgeführte Anwendung**, den **letzten Ausführungszeitpunkt** und die **Anzahl der Ausführungen**.

### BAM (Background Activity Moderator)

Sie können die Datei `SYSTEM` mit einem Registrierungseditor öffnen und im Pfad `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` Informationen über die **von jedem Benutzer ausgeführten Anwendungen** finden (beachten Sie die `{SID}` im Pfad) und zu welcher Zeit sie ausgeführt wurden (die Zeit befindet sich im Datenwert der Registrierung).

### Windows Prefetch

Prefetching ist eine Technik, die es einem Computer ermöglicht, stillschweigend die **notwendigen Ressourcen abzurufen, die benötigt werden, um Inhalte anzuzeigen**, auf die ein Benutzer **möglicherweise in naher Zukunft zugreifen wird**, damit Ressourcen schneller abgerufen werden können.

Windows Prefetch besteht darin, **Caches der ausgeführten Programme** zu erstellen, um sie schneller laden zu können. Diese Caches werden als `.pf`-Dateien im Pfad `C:\Windows\Prefetch` erstellt. Es gibt eine Begrenzung von 128 Dateien in XP/VISTA/WIN7 und 1024 Dateien in Win8/Win10.

Der Dateiname wird als `{Programmname}-{Hash}.pf` erstellt (der Hash basiert auf dem Pfad und den Argumenten der ausführbaren Datei). In W10 sind diese Dateien komprimiert. Beachten Sie, dass allein das Vorhandensein der Datei darauf hinweist, dass **das Programm** zu einem bestimmten Zeitpunkt **ausgeführt wurde**.

Die Datei `C:\Windows\Prefetch\Layout.ini` enthält die **Namen der Ordner der vorgepufferten Dateien**. Diese Datei enthält **Informationen über die Anzahl der Ausführungen**, **Datum** der Ausführung und **geöffnete Dateien** des Programms.

Um diese Dateien zu untersuchen, können Sie das Tool [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) verwenden.

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** hat das gleiche Ziel wie Prefetch, nämlich Programme schneller zu laden, indem vorhergesagt wird, was als nächstes geladen wird. Es ersetzt jedoch nicht den Prefetch-Dienst.\
Dieser Dienst generiert Datenbankdateien in `C:\Windows\Prefetch\Ag*.db`.

In diesen Datenbanken finden Sie den **Namen** des **Programms**, die **Anzahl** der **Ausführungen**, die **geöffneten** **Dateien**, den **zugriffenen** **Speicherplatz**, den **vollständigen** **Pfad**, die **Zeitrahmen** und die **Zeitstempel**.

Sie können auf diese Informationen mit dem Tool [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) zugreifen.

### SRUM

**System Resource Usage Monitor** (SRUM) **überwacht** die **Ressourcen**, die von einem Prozess **verbraucht** werden. Es erschien in W8 und speichert die Daten in einer ESE-Datenbank, die sich in `C:\Windows\System32\sru\SRUDB.dat` befindet.

Es liefert folgende Informationen:

* AppID und Pfad
* Benutzer, der den Prozess ausgeführt hat
* Gesendete Bytes
* Empfangene Bytes
* Netzwerkschnittstelle
* Verbindungsdauer
* Prozessdauer

Diese Informationen werden alle 60 Minuten aktualisiert.

Sie können die Daten aus dieser Datei mit dem Tool [**srum\_dump**](https://github.com/MarkBaggett/srum-dump) abrufen.

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```

### AppCompatCache (ShimCache)

Die **AppCompatCache**, auch bekannt als **ShimCache**, ist Teil der von **Microsoft** entwickelten **Application Compatibility Database**, um Probleme mit der Anwendungskompatibilität zu lösen. Diese Systemkomponente erfasst verschiedene Dateimetadaten, darunter:

* Vollständiger Pfad der Datei
* Dateigröße
* Zuletzt geänderte Zeit unter **$Standard\_Information** (SI)
* Zuletzt aktualisierte Zeit des ShimCache
* Prozessausführungsflag

Diese Daten werden in der Registrierung an bestimmten Speicherorten basierend auf der Version des Betriebssystems gespeichert:

* Für XP werden die Daten unter `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` mit einer Kapazität von 96 Einträgen gespeichert.
* Für Server 2003 sowie für Windows-Versionen 2008, 2012, 2016, 7, 8 und 10 befindet sich der Speicherpfad unter `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache` und bietet Platz für 512 bzw. 1024 Einträge.

Zur Analyse der gespeicherten Informationen wird die Verwendung des Tools [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) empfohlen.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

Die Datei **Amcache.hve** ist im Wesentlichen eine Registrierungshive, die Details über auf einem System ausgeführte Anwendungen protokolliert. Sie befindet sich normalerweise unter `C:\Windows\AppCompat\Programas\Amcache.hve`.

Diese Datei speichert Aufzeichnungen über kürzlich ausgeführte Prozesse, einschließlich der Pfade zu den ausführbaren Dateien und ihrer SHA1-Hashes. Diese Informationen sind von unschätzbarem Wert, um die Aktivität von Anwendungen auf einem System zu verfolgen.

Um die Daten aus **Amcache.hve** zu extrahieren und zu analysieren, kann das Tool [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) verwendet werden. Das folgende Beispiel zeigt, wie AmcacheParser verwendet wird, um den Inhalt der Datei **Amcache.hve** zu analysieren und die Ergebnisse im CSV-Format auszugeben:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Unter den generierten CSV-Dateien ist besonders die Datei "Amcache\_Unassociated file entries" hervorzuheben, da sie umfangreiche Informationen über nicht zugeordnete Dateieinträge liefert.

Die interessanteste CSV-Datei, die generiert wird, ist "Amcache\_Unassociated file entries".

### RecentFileCache

Dieser Artefakt kann nur in W7 unter `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` gefunden werden und enthält Informationen über die kürzliche Ausführung einiger Binärdateien.

Sie können das Tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) verwenden, um die Datei zu analysieren.

### Geplante Aufgaben

Sie können sie aus `C:\Windows\Tasks` oder `C:\Windows\System32\Tasks` extrahieren und als XML lesen.

### Dienste

Sie können sie in der Registrierung unter `SYSTEM\ControlSet001\Services` finden. Sie können sehen, was ausgeführt wird und wann.

### **Windows Store**

Die installierten Anwendungen finden Sie in `\ProgramData\Microsoft\Windows\AppRepository\`.\
Dieses Repository enthält ein **Protokoll** mit **jeder installierten Anwendung** im System in der Datenbank **`StateRepository-Machine.srd`**.

In der Tabelle "Application" dieser Datenbank können die Spalten "Application ID", "PackageNumber" und "Display Name" gefunden werden. Diese Spalten enthalten Informationen über vorinstallierte und installierte Anwendungen, und es kann festgestellt werden, ob einige Anwendungen deinstalliert wurden, da die IDs der installierten Anwendungen sequenziell sein sollten.

Es ist auch möglich, **installierte Anwendungen** im Registrierungspfad zu finden: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Und **deinstallierte Anwendungen** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows-Ereignisse

Informationen, die in Windows-Ereignissen angezeigt werden, sind:

* Was ist passiert
* Zeitstempel (UTC + 0)
* Beteiligte Benutzer
* Beteiligte Hosts (Hostname, IP)
* Zugriff auf Ressourcen (Dateien, Ordner, Drucker, Dienste)

Die Protokolle befinden sich in `C:\Windows\System32\config` vor Windows Vista und in `C:\Windows\System32\winevt\Logs` nach Windows Vista. Vor Windows Vista waren die Ereignisprotokolle im Binärformat und danach im **XML-Format** und verwenden die **.evtx**-Erweiterung.

Der Speicherort der Ereignisdateien kann in der SYSTEM-Registrierung unter **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Anwendung|System|Sicherheit}`** gefunden werden.

Sie können mit dem Windows-Ereignis-Viewer (**`eventvwr.msc`**) oder mit anderen Tools wie [**Event Log Explorer**](https://eventlogxp.com) **oder** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.** angezeigt werden.

## Verständnis der Windows-Sicherheitsereignisprotokollierung

Zugriffsereignisse werden in der Sicherheitskonfigurationsdatei aufgezeichnet, die sich unter `C:\Windows\System32\winevt\Security.evtx` befindet. Die Größe dieser Datei ist einstellbar, und wenn ihre Kapazität erreicht ist, werden ältere Ereignisse überschrieben. Aufgezeichnete Ereignisse umfassen Benutzeranmeldungen und -abmeldungen, Benutzeraktionen und Änderungen an Sicherheitseinstellungen sowie den Zugriff auf Dateien, Ordner und freigegebene Ressourcen.

### Wichtige Ereignis-IDs für die Benutzerauthentifizierung:

* **Ereignis-ID 4624**: Zeigt eine erfolgreiche Benutzerauthentifizierung an.
* **Ereignis-ID 4625**: Signalisiert einen Authentifizierungsfehler.
* **Ereignis-IDs 4634/4647**: Stellen Benutzerabmeldeereignisse dar.
* **Ereignis-ID 4672**: Bezeichnet die Anmeldung mit administrativen Berechtigungen.

#### Untertypen innerhalb von Ereignis-ID 4634/4647:

* **Interaktiv (2)**: Direkte Benutzeranmeldung.
* **Netzwerk (3)**: Zugriff auf freigegebene Ordner.
* **Batch (4)**: Ausführung von Stapelprozessen.
* **Dienst (5)**: Start von Diensten.
* **Proxy (6)**: Proxy-Authentifizierung.
* **Entsperrung (7)**: Bildschirm mit einem Passwort entsperrt.
* **Netzwerk im Klartext (8)**: Klartext-Passwortübertragung, oft von IIS.
* **Neue Anmeldeinformationen (9)**: Verwendung anderer Anmeldeinformationen für den Zugriff.
* **Remote-Interaktiv (10)**: Remote-Desktop- oder Terminaldienste-Anmeldung.
* **Cache-Interaktiv (11)**: Anmeldung mit zwischengespeicherten Anmeldeinformationen ohne Kontakt zum Domänencontroller.
* **Cache-Remote-Interaktiv (12)**: Remote-Anmeldung mit zwischengespeicherten Anmeldeinformationen.
* **Zwischengespeichert entsperrt (13)**: Entsperren mit zwischengespeicherten Anmeldeinformationen.

#### Status- und Untertstatuscodes für Ereignis-ID 4625:

* **0xC0000064**: Benutzername existiert nicht - könnte auf einen Benutzernamen-Enumeration-Angriff hinweisen.
* **0xC000006A**: Richtiger Benutzername, aber falsches Passwort - Möglicherweise ein Versuch zum Erraten oder Brute-Force des Passworts.
* **0xC0000234**: Benutzerkonto gesperrt - Kann auf einen Brute-Force-Angriff mit mehreren fehlgeschlagenen Anmeldungen folgen.
* **0xC0000072**: Konto deaktiviert - Nicht autorisierte Versuche, auf deaktivierte Konten zuzugreifen.
* **0xC000006F**: Anmeldung außerhalb der erlaubten Zeit - Deutet auf Versuche hin, außerhalb der festgelegten Anmeldezeiten zuzugreifen, ein möglicher Hinweis auf unbefugten Zugriff.
* **0xC0000070**: Verstoß gegen die Einschränkungen des Arbeitsplatzes - Könnte ein Versuch sein, sich von einem nicht autorisierten Ort aus anzumelden.
* **0xC0000193**: Kontoablauf - Zugriffsversuche mit abgelaufenen Benutzerkonten.
* **0xC0000071**: Abgelaufenes Passwort - Anmeldeversuche mit veralteten Passwörtern.
* **0xC0000133**: Zeitabgleichsprobleme - Große Zeitunterschiede zwischen Client und Server können auf komplexere Angriffe wie Pass-the-Ticket hinweisen.
* **0xC0000224**: Erforderliche obligatorische Passwortänderung - Häufige obligatorische Änderungen können auf einen Versuch hindeuten, die Kontosicherheit zu destabilisieren.
* **0xC0000225**: Deutet auf einen Systemfehler hin, nicht auf ein Sicherheitsproblem.
* **0xC000015b**: Verweigerte Anmeldetyp - Zugriffsversuch mit nicht autorisiertem Anmeldetyp, z. B. ein Benutzer, der versucht, eine Dienstanmeldung auszuführen.

#### Ereignis-ID 4616:

* **Zeitänderung**: Änderung der Systemzeit, kann die zeitliche Abfolge von Ereignissen verschleiern.

#### Ereignis-ID 6005 und 6006:

* **Systemstart und -abschaltung**: Ereignis-ID 6005 zeigt den Systemstart an, während Ereignis-ID 6006 das Herunterfahren markiert.

#### Ereignis-ID 1102:

* **Protokolllöschung**: Sicherheitsprotokolle werden gelöscht, was oft ein Warnsignal für das Vertuschen von illegalen Aktivitäten ist.

#### Ereignis-IDs für die Verfolgung von USB-Geräten:

* **20001 / 20003 / 10000**: Erstmalige Verbindung eines USB-Geräts.
* **10100**: USB-Treiberupdate.
* **Ereignis-ID 112**: Zeitpunkt des Einsteckens des USB-Geräts.

Für praktische Beispiele zur Simulation dieser Anmeldetypen und zum Ausnutzen von Möglichkeiten zum Auslesen von Anmeldeinformationen siehe [Altered Security's detaillierten Leitfaden](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Ereignisdetails, einschließlich Status- und Untertstatuscodes, liefern weitere Einblicke in die Ursachen von Ereignissen, insbesondere bei Ereignis-ID 4625.

### Wiederherstellung von Windows-Ereignissen

Um die Chancen auf die Wiederherstellung gelöschter Windows-Ereignisse zu erhöhen, wird empfohlen, den verdächtigen Computer durch direktes Ausstecken vom Stromnetz zu trennen. Das Wiederherstellungstool **Bulk\_extractor**, das die Erweiterung `.evtx` angibt, wird empfohlen, um solche Ereignisse wiederherzustellen.

### Identifizierung häufiger Angriffe über Windows-Ereignisse

Für einen umfassenden Leitfaden zur Verwendung von Windows-Ereignis-IDs zur Identifizierung häufiger Cyberangriffe besuchen Sie \[Red Team Recipe]\(https://redteamrecipe.com/event-codes/

#### System Power Events

EventID 6005 zeigt den Systemstart an, während EventID 6006 den Shutdown markiert.

#### Log-Löschung

Sicherheits-EventID 1102 signalisiert die Löschung von Logs, ein kritisches Ereignis für die forensische Analyse.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
