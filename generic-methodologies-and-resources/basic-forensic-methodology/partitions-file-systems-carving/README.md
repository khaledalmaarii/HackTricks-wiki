# Partitions/Dateisysteme/Carving

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

## Partitionen

Eine Festplatte oder eine **SSD kann verschiedene Partitionen enthalten**, um Daten physisch zu trennen.\
Die **minimale** Einheit einer Festplatte ist der **Sektor** (normalerweise aus 512B). Daher muss die Größe jeder Partition ein Vielfaches dieser Größe sein.

### MBR (Master Boot Record)

Es wird im **ersten Sektor der Festplatte nach den 446B des Bootcodes** zugewiesen. Dieser Sektor ist entscheidend, um dem PC anzuzeigen, was und von wo eine Partition gemountet werden soll.\
Es erlaubt bis zu **4 Partitionen** (höchstens **nur 1** kann aktiv/**bootfähig** sein). Wenn Sie jedoch mehr Partitionen benötigen, können Sie **erweiterte Partitionen** verwenden. Das **letzte Byte** dieses ersten Sektors ist die Bootrecord-Signatur **0x55AA**. Nur eine Partition kann als aktiv markiert werden.\
MBR erlaubt **max 2,2TB**.

![](<../../../.gitbook/assets/image (350).png>)

![](<../../../.gitbook/assets/image (304).png>)

Von den **Bytes 440 bis 443** des MBR finden Sie die **Windows-Disk-Signatur** (wenn Windows verwendet wird). Der logische Laufwerksbuchstabe der Festplatte hängt von der Windows-Disk-Signatur ab. Das Ändern dieser Signatur könnte verhindern, dass Windows bootet (Tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (310).png>)

**Format**

| Offset      | Länge      | Element             |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Bootcode            |
| 446 (0x1BE) | 16 (0x10)  | Erste Partition     |
| 462 (0x1CE) | 16 (0x10)  | Zweite Partition    |
| 478 (0x1DE) | 16 (0x10)  | Dritte Partition     |
| 494 (0x1EE) | 16 (0x10)  | Vierte Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signatur 0x55 0xAA |

**Partition Record Format**

| Offset    | Länge    | Element                                               |
| --------- | -------- | ---------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Aktives Flag (0x80 = bootfähig)                      |
| 1 (0x01)  | 1 (0x01) | Startkopf                                             |
| 2 (0x02)  | 1 (0x01) | Startsektor (Bits 0-5); obere Bits des Zylinders (6-7) |
| 3 (0x03)  | 1 (0x01) | Startzylinder niedrigste 8 Bits                      |
| 4 (0x04)  | 1 (0x01) | Partitionstyp-Code (0x83 = Linux)                   |
| 5 (0x05)  | 1 (0x01) | Endkopf                                               |
| 6 (0x06)  | 1 (0x01) | Endsektor (Bits 0-5); obere Bits des Zylinders (6-7) |
| 7 (0x07)  | 1 (0x01) | Endzylinder niedrigste 8 Bits                        |
| 8 (0x08)  | 4 (0x04) | Sektoren vor der Partition (little endian)           |
| 12 (0x0C) | 4 (0x04) | Sektoren in der Partition                             |

Um ein MBR in Linux zu mounten, müssen Sie zuerst den Start-Offset ermitteln (Sie können `fdisk` und den `p`-Befehl verwenden)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Und dann verwenden Sie den folgenden Code
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logische Blockadressierung)**

**Logische Blockadressierung** (**LBA**) ist ein gängiges Schema zur **Spezifizierung des Standorts von Blöcken** von Daten, die auf Computer-Speichergeräten gespeichert sind, in der Regel auf sekundären Speichersystemen wie Festplatten. LBA ist ein besonders einfaches lineares Adressierungsschema; **Blöcke werden durch einen ganzzahligen Index lokalisiert**, wobei der erste Block LBA 0, der zweite LBA 1 und so weiter ist.

### GPT (GUID-Partitionstabelle)

Die GUID-Partitionstabelle, bekannt als GPT, wird aufgrund ihrer erweiterten Funktionen im Vergleich zu MBR (Master Boot Record) bevorzugt. Auffällig ist ihr **global eindeutiger Identifikator** für Partitionen, GPT hebt sich in mehreren Aspekten hervor:

* **Standort und Größe**: Sowohl GPT als auch MBR beginnen bei **Sektor 0**. GPT arbeitet jedoch mit **64 Bit**, im Gegensatz zu MBRs 32 Bit.
* **Partitionsgrenzen**: GPT unterstützt bis zu **128 Partitionen** auf Windows-Systemen und kann bis zu **9,4 ZB** an Daten aufnehmen.
* **Partitionsnamen**: Bietet die Möglichkeit, Partitionen mit bis zu 36 Unicode-Zeichen zu benennen.

**Datenresilienz und Wiederherstellung**:

* **Redundanz**: Im Gegensatz zu MBR beschränkt GPT die Partitionierung und Bootdaten nicht auf einen einzigen Ort. Es repliziert diese Daten über die gesamte Festplatte, was die Datenintegrität und Resilienz erhöht.
* **Zyklische Redundanzprüfung (CRC)**: GPT verwendet CRC, um die Datenintegrität sicherzustellen. Es überwacht aktiv auf Datenkorruption, und wenn diese erkannt wird, versucht GPT, die beschädigten Daten von einem anderen Speicherort auf der Festplatte wiederherzustellen.

**Schützendes MBR (LBA0)**:

* GPT erhält die Abwärtskompatibilität durch ein schützendes MBR. Diese Funktion befindet sich im Legacy-MBR-Bereich, ist jedoch so konzipiert, dass sie verhindert, dass ältere MBR-basierte Dienstprogramme versehentlich GPT-Festplatten überschreiben, wodurch die Datenintegrität auf GPT-formatierten Festplatten geschützt wird.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (1062).png>)

**Hybrides MBR (LBA 0 + GPT)**

[Von Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

In Betriebssystemen, die **GPT-basiertes Booten über BIOS**-Dienste anstelle von EFI unterstützen, kann der erste Sektor auch weiterhin verwendet werden, um die erste Stufe des **Bootloader**-Codes zu speichern, jedoch **modifiziert**, um **GPT**-**Partitionen** zu erkennen. Der Bootloader im MBR darf nicht von einer Sektorgröße von 512 Bytes ausgehen.

**Partitionstabelle-Header (LBA 1)**

[Von Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

Der Partitionstabelle-Header definiert die verwendbaren Blöcke auf der Festplatte. Er definiert auch die Anzahl und Größe der Partitionseinträge, die die Partitionstabelle bilden (Offsets 80 und 84 in der Tabelle).

| Offset    | Länge   | Inhalt                                                                                                                                                                        |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 Bytes  | Signatur ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h oder 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)auf Little-Endian-Maschinen) |
| 8 (0x08)  | 4 Bytes  | Revision 1.0 (00h 00h 01h 00h) für UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 Bytes  | Headergröße in Little Endian (in Bytes, normalerweise 5Ch 00h 00h 00h oder 92 Bytes)                                                                                                    |
| 16 (0x10) | 4 Bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) des Headers (Offset +0 bis Headergröße) in Little Endian, wobei dieses Feld während der Berechnung auf Null gesetzt wird                                |
| 20 (0x14) | 4 Bytes  | Reserviert; muss Null sein                                                                                                                                                          |
| 24 (0x18) | 8 Bytes  | Aktuelles LBA (Standort dieser Headerkopie)                                                                                                                                      |
| 32 (0x20) | 8 Bytes  | Backup LBA (Standort der anderen Headerkopie)                                                                                                                                  |
| 40 (0x28) | 8 Bytes  | Erstes verwendbares LBA für Partitionen (letztes LBA der primären Partitionstabelle + 1)                                                                                                          |
| 48 (0x30) | 8 Bytes  | Letztes verwendbares LBA (erstes LBA der sekundären Partitionstabelle − 1)                                                                                                                       |
| 56 (0x38) | 16 Bytes | Festplattenguid in gemischtem Endian                                                                                                                                                       |
| 72 (0x48) | 8 Bytes  | Start-LBA eines Arrays von Partitionseinträgen (immer 2 in der primären Kopie)                                                                                                        |
| 80 (0x50) | 4 Bytes  | Anzahl der Partitionseinträge im Array                                                                                                                                            |
| 84 (0x54) | 4 Bytes  | Größe eines einzelnen Partitionseintrags (normalerweise 80h oder 128)                                                                                                                           |
| 88 (0x58) | 4 Bytes  | CRC32 des Arrays der Partitionseinträge in Little Endian                                                                                                                               |
| 92 (0x5C) | \*       | Reserviert; muss für den Rest des Blocks Nullen sein (420 Bytes für eine Sektorgröße von 512 Bytes; kann jedoch mehr sein bei größeren Sektorgrößen)                                         |

**Partitionseinträge (LBA 2–33)**

| GUID-Partitionseintragsformat |          |                                                                                                                   |
| ----------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Offset                        | Länge   | Inhalt                                                                                                          |
| 0 (0x00)                      | 16 Bytes | [Partitionstyp-GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (gemischtes Endian) |
| 16 (0x10)                     | 16 Bytes | Eindeutige Partition-GUID (gemischtes Endian)                                                                              |
| 32 (0x20)                     | 8 Bytes  | Erstes LBA ([Little Endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                     | 8 Bytes  | Letztes LBA (einschließlich, normalerweise ungerade)                                                                                 |
| 48 (0x30)                     | 8 Bytes  | Attribut-Flags (z. B. Bit 60 bezeichnet schreibgeschützt)                                                                   |
| 56 (0x38)                     | 72 Bytes | Partitionsname (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE-Codeeinheiten)                                   |

**Partitionstypen**

![](<../../../.gitbook/assets/image (83).png>)

Weitere Partitionstypen unter [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspektion

Nach dem Einbinden des forensischen Images mit [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) können Sie den ersten Sektor mit dem Windows-Tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Im folgenden Bild wurde ein **MBR** im **Sektor 0** erkannt und interpretiert:

![](<../../../.gitbook/assets/image (354).png>)

Wenn es sich um eine **GPT-Tabelle anstelle eines MBR** handelte, sollte die Signatur _EFI PART_ im **Sektor 1** erscheinen (der im vorherigen Bild leer ist).

## Dateisysteme

### Liste der Windows-Dateisysteme

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

Das **FAT (File Allocation Table)**-Dateisystem ist um seine Kernkomponente, die Dateizuordnungstabelle, herum gestaltet, die sich am Anfang des Volumes befindet. Dieses System schützt Daten, indem es **zwei Kopien** der Tabelle aufrechterhält, um die Datenintegrität auch dann zu gewährleisten, wenn eine beschädigt ist. Die Tabelle sowie der Stammordner müssen sich an einem **festen Standort** befinden, was für den Startprozess des Systems entscheidend ist.

Die grundlegende Speichereinheit des Dateisystems ist ein **Cluster, normalerweise 512B**, der aus mehreren Sektoren besteht. FAT hat sich durch verschiedene Versionen weiterentwickelt:

* **FAT12**, unterstützt 12-Bit-Clusteradressen und verarbeitet bis zu 4078 Cluster (4084 mit UNIX).
* **FAT16**, verbessert auf 16-Bit-Adressen, wodurch bis zu 65.517 Cluster untergebracht werden können.
* **FAT32**, weiter fortgeschritten mit 32-Bit-Adressen, was beeindruckende 268.435.456 Cluster pro Volume ermöglicht.

Eine wesentliche Einschränkung über alle FAT-Versionen hinweg ist die **maximale Dateigröße von 4 GB**, die durch das 32-Bit-Feld für die Speicherung der Dateigröße auferlegt wird.

Wichtige Komponenten des Stammverzeichnisses, insbesondere für FAT12 und FAT16, umfassen:

* **Datei-/Ordnername** (bis zu 8 Zeichen)
* **Attribute**
* **Erstellungs-, Änderungs- und zuletzt Zugriffsdatum**
* **FAT-Tabellenadresse** (die den Start-Cluster der Datei angibt)
* **Dateigröße**

### EXT

**Ext2** ist das häufigste Dateisystem für **nicht journaling** Partitionen (**Partitionen, die sich nicht viel ändern**) wie die Bootpartition. **Ext3/4** sind **journaling** und werden normalerweise für die **restlichen Partitionen** verwendet.

## **Metadaten**

Einige Dateien enthalten Metadaten. Diese Informationen beziehen sich auf den Inhalt der Datei, die für einen Analysten manchmal interessant sein könnten, da sie je nach Dateityp Informationen wie Folgendes enthalten können:

* Titel
* Verwendete MS Office-Version
* Autor
* Erstellungs- und Änderungsdaten
* Kameramodell
* GPS-Koordinaten
* Bildinformationen

Sie können Tools wie [**exiftool**](https://exiftool.org) und [**Metadiver**](https://www.easymetadata.com/metadiver-2/) verwenden, um die Metadaten einer Datei abzurufen.

## **Wiederherstellung gelöschter Dateien**

### Protokollierte gelöschte Dateien

Wie bereits gesehen, gibt es mehrere Orte, an denen die Datei nach ihrer "Löschung" weiterhin gespeichert ist. Dies liegt daran, dass die Löschung einer Datei aus einem Dateisystem normalerweise nur als gelöscht markiert wird, die Daten jedoch nicht berührt werden. Daher ist es möglich, die Register der Dateien (wie die MFT) zu inspizieren und die gelöschten Dateien zu finden.

Außerdem speichert das Betriebssystem normalerweise viele Informationen über Änderungen am Dateisystem und Backups, sodass es möglich ist, zu versuchen, diese zu verwenden, um die Datei oder so viele Informationen wie möglich wiederherzustellen.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Dateicarving**

**Dateicarving** ist eine Technik, die versucht, **Dateien im Datenbulk zu finden**. Es gibt 3 Hauptmethoden, wie solche Tools funktionieren: **Basierend auf Dateitypen-Headern und -Fußzeilen**, basierend auf Dateitypen-**Strukturen** und basierend auf dem **Inhalt** selbst.

Beachten Sie, dass diese Technik **nicht funktioniert, um fragmentierte Dateien wiederherzustellen**. Wenn eine Datei **nicht in zusammenhängenden Sektoren gespeichert ist**, kann diese Technik sie nicht finden oder zumindest nicht einen Teil davon.

Es gibt mehrere Tools, die Sie für das Dateicarving verwenden können, indem Sie die Dateitypen angeben, nach denen Sie suchen möchten.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Datenstrom **C**arving

Datenstrom-Carving ähnelt dem Dateicarving, aber **anstatt nach vollständigen Dateien zu suchen, sucht es nach interessanten Fragmenten** von Informationen.\
Zum Beispiel, anstatt nach einer vollständigen Datei mit protokollierten URLs zu suchen, wird diese Technik nach URLs suchen.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Sichere Löschung

Offensichtlich gibt es Möglichkeiten, **Dateien und Teile von Protokollen über sie "sicher" zu löschen**. Zum Beispiel ist es möglich, den **Inhalt** einer Datei mehrmals mit Junk-Daten zu **überschreiben** und dann die **Protokolle** aus der **$MFT** und **$LOGFILE** über die Datei zu **entfernen** und die **Volume Shadow Copies** zu **entfernen**.\
Sie werden feststellen, dass selbst wenn Sie diese Aktion durchführen, es möglicherweise **andere Teile gibt, in denen die Existenz der Datei weiterhin protokolliert ist**, und das ist wahr, und ein Teil der Arbeit eines forensischen Fachmanns besteht darin, sie zu finden.

## Referenzen

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Zertifizierte Digitale Forensik Windows**

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
