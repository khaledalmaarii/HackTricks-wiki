# Firmware Analysis

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## **Einführung**

Firmware ist eine wesentliche Software, die es Geräten ermöglicht, ordnungsgemäß zu funktionieren, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und erleichtert. Sie wird in permanentem Speicher gespeichert und stellt sicher, dass das Gerät ab dem Zeitpunkt des Einschaltens auf wichtige Anweisungen zugreifen kann, was zum Start des Betriebssystems führt. Die Untersuchung und mögliche Modifizierung der Firmware ist ein wichtiger Schritt zur Identifizierung von Sicherheitslücken.

## **Informationen sammeln**

Das **Sammeln von Informationen** ist ein entscheidender erster Schritt, um die Zusammensetzung eines Geräts und die verwendeten Technologien zu verstehen. Dieser Prozess umfasst das Sammeln von Daten zu:

* Der CPU-Architektur und dem Betriebssystem, das es ausführt
* Bootloader-Spezifikationen
* Hardware-Layout und Datenblätter
* Codebase-Metriken und Quellorten
* Externe Bibliotheken und Lizenztypen
* Update-Verlauf und regulatorische Zertifizierungen
* Architektur- und Flussdiagramme
* Sicherheitsbewertungen und identifizierte Sicherheitslücken

Zu diesem Zweck sind **Open-Source-Intelligence (OSINT)**-Tools von unschätzbarem Wert, ebenso wie die Analyse verfügbarer Open-Source-Softwarekomponenten durch manuelle und automatisierte Überprüfungsprozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analyseverfahren, die zur Identifizierung potenzieller Probleme genutzt werden können.

## **Beschaffung der Firmware**

Die Beschaffung der Firmware kann auf verschiedene Weise erfolgen, wobei jede ihre eigene Komplexitätsebene aufweist:

* **Direkt** vom Hersteller (Entwickler, Hersteller)
* **Erstellen** anhand bereitgestellter Anweisungen
* **Herunterladen** von offiziellen Supportseiten
* Verwendung von **Google-Dork**-Abfragen zum Auffinden gehosteter Firmware-Dateien
* Direkter Zugriff auf **Cloud-Speicher** mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
* Abfangen von **Updates** mittels Man-in-the-Middle-Techniken
* **Extrahieren** aus dem Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
* **Mitschneiden** von Update-Anfragen in der Gerätekommunikation
* Identifizieren und Verwenden von **fest codierten Update-Endpunkten**
* **Dumping** aus dem Bootloader oder Netzwerk
* **Entfernen und Auslesen** des Speicherchips, wenn alle anderen Methoden fehlschlagen, unter Verwendung geeigneter Hardware-Tools

## Analyse der Firmware

Nun, da Sie die Firmware haben, müssen Sie Informationen darüber extrahieren, um zu wissen, wie Sie damit umgehen sollen. Verschiedene Tools, die Sie dafür verwenden können:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Wenn Sie mit diesen Tools nicht viel finden, überprüfen Sie die **Entropie** des Bildes mit `binwalk -E <bin>`. Wenn die Entropie niedrig ist, ist es unwahrscheinlich, dass es verschlüsselt ist. Wenn die Entropie hoch ist, ist es wahrscheinlich verschlüsselt (oder auf andere Weise komprimiert).

Darüber hinaus können Sie diese Tools verwenden, um **in der Firmware eingebettete Dateien** zu extrahieren:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) zur Inspektion der Datei.

### Erhalten des Dateisystems

Mit den zuvor genannten Tools wie `binwalk -ev <bin>` sollten Sie in der Lage gewesen sein, das **Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einem **Ordner mit dem Namen des Dateisystemtyps**, der normalerweise einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Extraktion des Dateisystems

Manchmal hat binwalk **nicht das magische Byte des Dateisystems in seinen Signaturen**. In diesen Fällen verwenden Sie binwalk, um den Offset des Dateisystems zu finden und das komprimierte Dateisystem aus der Binärdatei zu **schnitzen** und extrahieren Sie das Dateisystem manuell entsprechend seinem Typ mit den folgenden Schritten.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Führen Sie den folgenden **dd-Befehl** aus, um das Squashfs-Dateisystem auszulesen.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternativ kann auch der folgende Befehl ausgeführt werden.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Für squashfs (wie im obigen Beispiel verwendet)

`$ unsquashfs dir.squashfs`

Die Dateien befinden sich anschließend im Verzeichnis "`squashfs-root`".

* CPIO-Archivdateien

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Für jffs2-Dateisysteme

`$ jefferson rootfsfile.jffs2`

* Für ubifs-Dateisysteme mit NAND-Flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyse der Firmware

Sobald die Firmware erhalten wurde, ist es wichtig, sie zu analysieren, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dieser Prozess beinhaltet die Verwendung verschiedener Tools zur Analyse und Extraktion wertvoller Daten aus dem Firmware-Image.

### Tools für die erste Analyse

Eine Reihe von Befehlen wird zur ersten Inspektion der Binärdatei (als `<bin>` bezeichnet) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Zeichenketten zu extrahieren, binäre Daten zu analysieren und Informationen über Partitionen und Dateisysteme zu erhalten:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Um den Verschlüsselungsstatus des Bildes zu bewerten, wird die **Entropie** mit `binwalk -E <bin>` überprüft. Eine niedrige Entropie deutet auf eine fehlende Verschlüsselung hin, während eine hohe Entropie auf mögliche Verschlüsselung oder Kompression hinweist.

Für das Extrahieren von **eingebetteten Dateien** werden empfohlene Tools und Ressourcen wie die Dokumentation zu **file-data-carving-recovery-tools** und **binvis.io** zur Dateiinspektion verwendet.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` kann normalerweise das Dateisystem extrahiert werden, oft in ein Verzeichnis mit dem Namen des Dateisystemtyps (z. B. squashfs, ubifs). Wenn **binwalk** jedoch aufgrund fehlender Magic Bytes den Dateisystemtyp nicht erkennt, ist eine manuelle Extraktion erforderlich. Dies beinhaltet die Verwendung von `binwalk`, um den Offset des Dateisystems zu lokalisieren, gefolgt vom `dd`-Befehl, um das Dateisystem auszuschneiden:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Anschließend werden, abhängig vom Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs), verschiedene Befehle verwendet, um den Inhalt manuell zu extrahieren.

### Dateisystemanalyse

Nachdem das Dateisystem extrahiert wurde, beginnt die Suche nach Sicherheitslücken. Es wird auf unsichere Netzwerk-Daemons, fest codierte Anmeldeinformationen, API-Endpunkte, Update-Server-Funktionalitäten, nicht kompilierten Code, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

Zu überprüfende **Schlüsselpositionen** und **Elemente** sind:

* **etc/shadow** und **etc/passwd** für Benutzeranmeldeinformationen
* SSL-Zertifikate und Schlüssel in **etc/ssl**
* Konfigurations- und Skriptdateien auf mögliche Schwachstellen
* Eingebettete Binärdateien für weitere Analysen
* Häufig verwendete Webserver und Binärdateien für IoT-Geräte

Verschiedene Tools unterstützen bei der Suche nach sensiblen Informationen und Schwachstellen im Dateisystem:

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach sensiblen Informationen
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) für umfassende Firmware-Analyse
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analyse

### Sicherheitsüberprüfungen von kompilierten Binärdateien

Sowohl der Quellcode als auch die kompilierten Binärdateien im Dateisystem müssen auf Schwachstellen überprüft werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Emulation von Firmware für die dynamische Analyse

Die Emulation von Firmware ermöglicht die **dynamische Analyse** entweder des Betriebs eines Geräts oder eines einzelnen Programms. Bei diesem Ansatz können Herausforderungen mit Hardware- oder Architekturabhängigkeiten auftreten, aber das Übertragen des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Endianness, wie z. B. ein Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann weitere Tests erleichtern.

### Emulation einzelner Binärdateien

Für die Untersuchung einzelner Programme ist es entscheidend, die Endianness und CPU-Architektur des Programms zu identifizieren.

#### Beispiel mit MIPS-Architektur

Um eine MIPS-Architektur-Binärdatei zu emulieren, kann der Befehl verwendet werden:

```bash
file ./squashfs-root/bin/busybox
```

Und um die erforderlichen Emulationstools zu installieren:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Für MIPS (big-endian) wird `qemu-mips` verwendet, und für little-endian Binaries wäre `qemu-mipsel` die Wahl.

#### Emulation der ARM-Architektur

Für ARM-Binaries ist der Prozess ähnlich, wobei der Emulator `qemu-arm` zur Emulation verwendet wird.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere erleichtern die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen bei der dynamischen Analyse.

## Dynamische Analysetechniken in der Praxis

In diesem Stadium wird entweder eine reale oder eine emulierte Geräteumgebung für die Analyse verwendet. Es ist wichtig, den Zugriff auf die Shell des Betriebssystems und das Dateisystem aufrechtzuerhalten. Die Emulation kann die Hardwareinteraktionen möglicherweise nicht perfekt nachahmen, was gelegentliche Emulationsneustarts erforderlich macht. Bei der Analyse sollte das Dateisystem erneut überprüft, exponierte Webseiten und Netzwerkdienste ausgenutzt und Bootloader-Schwachstellen untersucht werden. Tests zur Integrität der Firmware sind entscheidend, um potenzielle Hintertür-Schwachstellen zu identifizieren.

## Techniken zur Laufzeitanalyse

Die Laufzeitanalyse beinhaltet die Interaktion mit einem Prozess oder Binary in seiner Betriebsumgebung unter Verwendung von Tools wie gdb-multiarch, Frida und Ghidra zum Setzen von Breakpoints und zur Identifizierung von Schwachstellen durch Fuzzing und andere Techniken.

## Binäre Ausnutzung und Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und des Programmierens in Low-Level-Sprachen. Binäre Laufzeitschutzmaßnahmen in eingebetteten Systemen sind selten, aber wenn sie vorhanden sind, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

## Vorbereitete Betriebssysteme für die Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für die Sicherheitstests von Firmware mit den erforderlichen Tools.

## Vorbereitete Betriebssysteme zur Analyse von Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die Ihnen dabei helfen soll, Sicherheitsbewertungen und Penetrationstests von Internet of Things (IoT)-Geräten durchzuführen. Es spart Ihnen viel Zeit, indem es eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded-Sicherheitstest-Betriebssystem basierend auf Ubuntu 18.04, vorab geladen mit Tools für die Sicherheitstests von Firmware.

## Verwundbare Firmware zum Üben

Um Schwachstellen in Firmware zu entdecken, können Sie die folgenden Projekte mit verwundbarer Firmware als Ausgangspunkt verwenden.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Referenzen

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Schulungen und Zertifizierungen

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
