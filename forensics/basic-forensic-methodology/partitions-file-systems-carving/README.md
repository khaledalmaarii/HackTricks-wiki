# Partitionen/Dateisysteme/Carving

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Partitionen

Eine Festplatte oder eine **SSD-Festplatte kann verschiedene Partitionen** enthalten, um Daten physisch zu trennen.\
Die **minimale** Einheit einer Festplatte ist der **Sektor** (normalerweise bestehend aus 512B). Daher muss die Größe jeder Partition ein Vielfaches dieser Größe sein.

### MBR (Master Boot Record)

Es ist im **ersten Sektor der Festplatte nach den 446B des Bootcodes** allokiert. Dieser Sektor ist entscheidend, um dem PC anzuzeigen, was und von wo aus eine Partition eingehängt werden soll.\
Es erlaubt bis zu **4 Partitionen** (höchstens **nur 1** kann aktiv/**bootfähig** sein). Wenn jedoch mehr Partitionen benötigt werden, können **erweiterte Partitionen** verwendet werden. Das **letzte Byte** dieses ersten Sektors ist die Boot-Record-Signatur **0x55AA**. Nur eine Partition kann als aktiv markiert sein.\
MBR erlaubt **maximal 2,2 TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Von den **Bytes 440 bis 443** des MBR aus können Sie die **Windows-Disk-Signatur** finden (wenn Windows verwendet wird). Der logische Laufwerksbuchstabe der Festplatte hängt von der Windows-Disk-Signatur ab. Eine Änderung dieser Signatur könnte verhindern, dass Windows startet (Tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Format**

| Offset      | Länge      | Element             |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Bootcode            |
| 446 (0x1BE) | 16 (0x10)  | Erste Partition     |
| 462 (0x1CE) | 16 (0x10)  | Zweite Partition    |
| 478 (0x1DE) | 16 (0x10)  | Dritte Partition    |
| 494 (0x1EE) | 16 (0x10)  | Vierte Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signatur 0x55 0xAA  |

**Format des Partitionsdatensatzes**

| Offset    | Länge    | Element                                                  |
| --------- | -------- | -------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Aktiv-Flagge (0x80 = bootfähig)                          |
| 1 (0x01)  | 1 (0x01) | Start-Head                                               |
| 2 (0x02)  | 1 (0x01) | Start-Sektor (Bits 0-5); obere Bits des Zylinders (6-7) |
| 3 (0x03)  | 1 (0x01) | Niedrigste 8 Bits des Startzylinders                     |
| 4 (0x04)  | 1 (0x01) | Partitions-Typcode (0x83 = Linux)                        |
| 5 (0x05)  | 1 (0x01) | End-Head                                                 |
| 6 (0x06)  | 1 (0x01) | End-Sektor (Bits 0-5); obere Bits des Zylinders (6-7)    |
| 7 (0x07)  | 1 (0x01) | Niedrigste 8 Bits des Endzylinders                       |
| 8 (0x08)  | 4 (0x04) | Sektoren vor der Partition (Little Endian)               |
| 12 (0x0C) | 4 (0x04) | Sektoren in der Partition                                |

Um ein MBR in Linux einzuhängen, müssen Sie zuerst den Startoffset erhalten (Sie können `fdisk` und den Befehl `p` verwenden)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

Und dann verwenden Sie den folgenden Code
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logische Blockadressierung** (**LBA**) ist ein gängiges Schema zur **Spezifizierung des Speicherorts von Datenblöcken**, die auf Computerspeichergeräten gespeichert sind, in der Regel auf sekundären Speichersystemen wie Festplattenlaufwerken. LBA ist ein besonders einfaches lineares Adressierungsschema; **Blöcke werden durch einen ganzzahligen Index** lokalisiert, wobei der erste Block LBA 0, der zweite LBA 1 usw. ist.

### GPT (GUID-Partitionstabelle)

Die GUID-Partitionstabelle, bekannt als GPT, wird aufgrund ihrer erweiterten Funktionen im Vergleich zu MBR (Master Boot Record) bevorzugt. Ausgezeichnet durch seine **global eindeutige Kennung** für Partitionen, hebt sich GPT auf mehrere Arten hervor:

* **Ort und Größe**: Sowohl GPT als auch MBR beginnen bei **Sektor 0**. GPT arbeitet jedoch mit **64 Bits**, im Gegensatz zu MBR mit 32 Bits.
* **Partitionsbegrenzungen**: GPT unterstützt bis zu **128 Partitionen** auf Windows-Systemen und kann bis zu **9,4 ZB** an Daten aufnehmen.
* **Partitionsnamen**: Bietet die Möglichkeit, Partitionen mit bis zu 36 Unicode-Zeichen zu benennen.

**Datenresilienz und Wiederherstellung**:

* **Redundanz**: Im Gegensatz zu MBR beschränkt GPT die Partitionierung und Bootdaten nicht auf einen einzigen Ort. Es repliziert diese Daten über die Festplatte, was die Datenintegrität und -resilienz verbessert.
* **Zyklische Redundanzprüfung (CRC)**: GPT verwendet CRC, um die Datenintegrität sicherzustellen. Es überwacht aktiv auf Datenkorruption und versucht, bei Erkennung beschädigte Daten von einem anderen Speicherort auf der Festplatte wiederherzustellen.

**Schützender MBR (LBA0)**:

* GPT gewährleistet die Abwärtskompatibilität durch einen schützenden MBR. Diese Funktion befindet sich im Legacy-MBR-Bereich, ist jedoch so konzipiert, dass ältere MBR-basierte Dienstprogramme nicht versehentlich GPT-Festplatten überschreiben und somit die Datenintegrität auf GPT-formatierten Festplatten schützen.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**Hybrider MBR (LBA 0 + GPT)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

In Betriebssystemen, die **GPT-basiertes Booten über BIOS**-Dienste anstelle von EFI unterstützen, kann der erste Sektor auch weiterhin verwendet werden, um den ersten Abschnitt des **Bootloader**-Codes zu speichern, jedoch **modifiziert**, um **GPT-Partitionen** zu erkennen. Der Bootloader im MBR darf nicht von einer Sektorengröße von 512 Bytes ausgehen.

**Partitionstabelle-Header (LBA 1)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

Der Partitionstabellen-Header definiert die verwendbaren Blöcke auf der Festplatte. Er definiert auch die Anzahl und Größe der Partitionseinträge, aus denen die Partitionstabelle besteht (Offsets 80 und 84 in der Tabelle).

| Offset    | Länge    | Inhalt                                                                                                                                                                         |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0 (0x00)  | 8 Bytes  | Signatur ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h oder 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)bei Little-Endian-Maschinen) |
| 8 (0x08)  | 4 Bytes  | Revision 1.0 (00h 00h 01h 00h) für UEFI 2.8                                                                                                                                    |
| 12 (0x0C) | 4 Bytes  | Headergröße in Little-Endian (in Bytes, normalerweise 5Ch 00h 00h 00h oder 92 Bytes)                                                                                           |
| 16 (0x10) | 4 Bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) des Headers (Offset +0 bis zur Headergröße) in Little-Endian, wobei dieses Feld während der Berechnung auf Null gesetzt wird         |
| 20 (0x14) | 4 Bytes  | Reserviert; muss Null sein                                                                                                                                                     |
| 24 (0x18) | 8 Bytes  | Aktuelles LBA (Speicherort dieser Headerkopie)                                                                                                                                |
| 32 (0x20) | 8 Bytes  | Backup-LBA (Speicherort der anderen Headerkopie)                                                                                                                               |
| 40 (0x28) | 8 Bytes  | Erstes verwendbares LBA für Partitionen (letztes LBA der primären Partitionstabelle + 1)                                                                                       |
| 48 (0x30) | 8 Bytes  | Letztes verwendbares LBA (erstes LBA der sekundären Partitionstabelle − 1)                                                                                                      |
| 56 (0x38) | 16 Bytes | Disk-GUID in gemischter Endianität                                                                                                                                              |
| 72 (0x48) | 8 Bytes  | Start-LBA eines Arrays von Partitionseinträgen (immer 2 in der primären Kopie)                                                                                                 |
| 80 (0x50) | 4 Bytes  | Anzahl der Partitionseinträge im Array                                                                                                                                          |
| 84 (0x54) | 4 Bytes  | Größe eines einzelnen Partitionseintrags (normalerweise 80h oder 128)                                                                                                          |
| 88 (0x58) | 4 Bytes  | CRC32 des Partitionseintrags-Arrays in Little-Endian                                                                                                                            |
| 92 (0x5C) | \*       | Reserviert; muss für den Rest des Blocks Nullen sein (420 Bytes für eine Sektorengröße von 512 Bytes; kann jedoch bei größeren Sektorengrößen mehr sein)                       |

**Partitionseinträge (LBA 2–33)**

| Format des GUID-Partitionseintrags |          |                                                                                                                  |
| ---------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------- |
| Offset                             | Länge    | Inhalt                                                                                                           |
| 0 (0x00)                           | 16 Bytes | [Partitionstyp-GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (gemischte Endianität) |
| 16 (0x10)                          | 16 Bytes | Eindeutige Partition-GUID (gemischte Endianität)                                                                 |
| 32 (0x20)                          | 8 Bytes  | Erstes LBA ([Little-Endian](https://en.wikipedia.org/wiki/Little\_endian))                                       |
| 40 (0x28)                          | 8 Bytes  | Letztes LBA (einschließlich, normalerweise ungerade)                                                              |
| 48 (0x30)                          | 8 Bytes  | Attributflags (z. B. Bit 60 kennzeichnet schreibgeschützt)                                                       |
| 56 (0x38)                          | 72 Bytes | Partitionsname (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE-Codeeinheiten)                                |

**Partitionstypen**

![](<../../../.gitbook/assets/image (492).png>)

Weitere Partitionstypen unter [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspektion

Nach dem Einhängen des forensischen Abbilds mit [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) können Sie den ersten Sektor mit dem Windows-Tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)** inspizieren**. Im folgenden Bild wurde ein **MBR** im **Sektor 0** erkannt und interpretiert:

![](<../../../.gitbook/assets/image (494).png>)

Wenn es sich um eine **GPT-Tabelle anstelle eines MBR** handeln würde, sollte die Signatur _EFI PART_ im **Sektor 1** erscheinen (der in dem vorherigen Bild leer ist).
## Dateisysteme

### Liste der Windows-Dateisysteme

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

Das **FAT (File Allocation Table)**-Dateisystem ist um seine Kernkomponente, die Dateizuordnungstabelle, herum konzipiert, die sich am Anfang des Volumes befindet. Dieses System schützt Daten, indem es **zwei Kopien** der Tabelle aufrechterhält, um die Datenintegrität auch bei Beschädigung einer Kopie zu gewährleisten. Die Tabelle sowie der Stammordner müssen an einem **festen Ort** sein, der für den Startvorgang des Systems entscheidend ist.

Die grundlegende Speichereinheit des Dateisystems ist ein **Cluster, normalerweise 512B** groß und besteht aus mehreren Sektoren. FAT hat sich im Laufe der Versionen weiterentwickelt:

* **FAT12**, unterstützt 12-Bit-Clusteradressen und kann bis zu 4078 Cluster verwalten (4084 mit UNIX).
* **FAT16**, erweitert auf 16-Bit-Adressen und kann somit bis zu 65.517 Cluster aufnehmen.
* **FAT32**, weiterentwickelt mit 32-Bit-Adressen, was beeindruckende 268.435.456 Cluster pro Volume ermöglicht.

Eine wesentliche Einschränkung bei allen FAT-Versionen ist die **maximale Dateigröße von 4 GB**, die durch das 32-Bit-Feld für die Speicherung der Dateigröße festgelegt ist.

Wichtige Bestandteile des Stammverzeichnisses, insbesondere für FAT12 und FAT16, sind:

* **Datei/Ordnername** (bis zu 8 Zeichen)
* **Attribute**
* **Erstellungs-, Änderungs- und Letzter-Zugriff-Datum**
* **FAT-Tabellenadresse** (zeigt den Startcluster der Datei an)
* **Dateigröße**

### EXT

**Ext2** ist das häufigste Dateisystem für **nicht journaling** Partitionen (**Partitionen, die sich nicht viel ändern**), wie die Boot-Partition. **Ext3/4** sind **journaling** und werden normalerweise für die **restlichen Partitionen** verwendet.

## **Metadaten**

Einige Dateien enthalten Metadaten. Diese Informationen beziehen sich auf den Inhalt der Datei, der für einen Analysten manchmal interessant sein könnte, da je nach Dateityp Informationen wie:

* Titel
* Verwendete MS Office-Version
* Autor
* Erstellungs- und letztes Änderungsdatum
* Kameramodell
* GPS-Koordinaten
* Bildinformationen

Sie können Tools wie [**exiftool**](https://exiftool.org) und [**Metadiver**](https://www.easymetadata.com/metadiver-2/) verwenden, um die Metadaten einer Datei zu erhalten.

## **Wiederherstellung gelöschter Dateien**

### Protokollierte gelöschte Dateien

Wie bereits erwähnt, gibt es mehrere Orte, an denen die Datei auch nach dem "Löschen" noch gespeichert ist. Dies liegt daran, dass das Löschen einer Datei aus einem Dateisystem sie in der Regel nur als gelöscht markiert, aber die Daten nicht berührt. Anschließend ist es möglich, die Registrierungen der Dateien (wie die MFT) zu überprüfen und die gelöschten Dateien zu finden.

Außerdem speichert das Betriebssystem in der Regel viele Informationen über Dateisystemänderungen und Backups, sodass versucht werden kann, sie zur Wiederherstellung der Datei oder so vieler Informationen wie möglich zu verwenden.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Dateischnitzerei**

**Dateischnitzerei** ist eine Technik, die versucht, **Dateien in der Masse von Daten zu finden**. Tools wie diese arbeiten auf 3 Hauptwegen: **Basierend auf Dateityp-Headern und Footern**, basierend auf Dateityp-**Strukturen** und basierend auf dem **Inhalt** selbst.

Beachten Sie, dass diese Technik **nicht funktioniert, um fragmentierte Dateien wiederherzustellen**. Wenn eine Datei **nicht in aufeinanderfolgenden Sektoren gespeichert ist**, kann diese Technik sie nicht finden oder zumindest nicht vollständig.

Es gibt mehrere Tools, die Sie für die Dateischnitzerei verwenden können, um die Dateitypen zu suchen, die Sie suchen möchten.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Datenstromschnitzerei

Die Datenstromschnitzerei ähnelt der Dateischnitzerei, **sucht jedoch nicht nach vollständigen Dateien, sondern nach interessanten Fragmenten** von Informationen.\
Anstatt beispielsweise nach einer vollständigen Datei mit protokollierten URLs zu suchen, sucht diese Technik nach URLs.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Sicheres Löschen

Offensichtlich gibt es Möglichkeiten, Dateien und Teile von Protokollen darüber **"sicher" zu löschen**. Es ist beispielsweise möglich, den Inhalt einer Datei mehrmals mit Junk-Daten zu überschreiben und dann die **Protokolle** aus der **$MFT** und **$LOGFILE** über die Datei zu **entfernen** und die **Volume Shadow Copies zu löschen**.\
Es ist möglich, dass selbst nach dieser Aktion noch **andere Teile vorhanden sind, in denen das Vorhandensein der Datei protokolliert ist**, und es ist Aufgabe des Forensik-Profis, sie zu finden.

## Referenzen

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**
