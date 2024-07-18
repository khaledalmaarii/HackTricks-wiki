# Firmware-Analyse

{% hint style="success" %}
Lernen Sie und üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie und üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys einreichen.

</details>
{% endhint %}

## **Einführung**

Firmware ist eine wesentliche Software, die es Geräten ermöglicht, korrekt zu funktionieren, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und erleichtert. Sie wird im permanenten Speicher gespeichert, um sicherzustellen, dass das Gerät von dem Moment an, in dem es eingeschaltet wird, auf wichtige Anweisungen zugreifen kann, was zum Start des Betriebssystems führt. Die Untersuchung und mögliche Modifizierung der Firmware ist ein entscheidender Schritt zur Identifizierung von Sicherheitslücken.

## **Informationen sammeln**

**Informationen sammeln** ist ein entscheidender erster Schritt, um die Zusammensetzung eines Geräts und die verwendeten Technologien zu verstehen. Dieser Prozess umfasst das Sammeln von Daten zu:

* Der CPU-Architektur und dem Betriebssystem, das es ausführt
* Bootloader-Spezifikationen
* Hardware-Layout und Datenblätter
* Codebasis-Metriken und Quellorten
* Externe Bibliotheken und Lizenztypen
* Update-Verlauf und regulatorische Zertifizierungen
* Architektur- und Flussdiagramme
* Sicherheitsbewertungen und identifizierte Schwachstellen

Zu diesem Zweck sind **Open-Source-Intelligence (OSINT)**-Tools von unschätzbarem Wert, ebenso wie die Analyse verfügbarer Open-Source-Softwarekomponenten durch manuelle und automatisierte Überprüfungsprozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, die genutzt werden können, um potenzielle Probleme zu finden.

## **Beschaffung der Firmware**

Die Beschaffung der Firmware kann auf verschiedene Weisen angegangen werden, jede mit ihrem eigenen Komplexitätsgrad:

* **Direkt** vom Ursprung (Entwickler, Hersteller)
* **Erstellen** gemäß bereitgestellter Anweisungen
* **Herunterladen** von offiziellen Supportseiten
* Verwendung von **Google-Dork**-Abfragen zum Auffinden gehosteter Firmware-Dateien
* Direkter Zugriff auf **Cloud-Speicher** mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
* Abfangen von **Updates** über Man-in-the-Middle-Techniken
* **Extrahieren** vom Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
* **Sniffing** nach Update-Anfragen innerhalb der Gerätekommunikation
* Identifizieren und Verwenden von **fest codierten Update-Endpunkten**
* **Dumping** vom Bootloader oder Netzwerk
* **Entfernen und Lesen** des Speicherchips, wenn alle Stricke reißen, unter Verwendung geeigneter Hardware-Tools

## Analyse der Firmware

Nun, da Sie **die Firmware haben**, müssen Sie Informationen darüber extrahieren, um zu wissen, wie Sie damit umgehen sollen. Verschiedene Tools, die Sie dafür verwenden können:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Wenn Sie mit diesen Tools nicht viel finden, überprüfen Sie die **Entropie** des Bildes mit `binwalk -E <bin>`. Bei niedriger Entropie ist es wahrscheinlich nicht verschlüsselt. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Darüber hinaus können Sie diese Tools verwenden, um **in der Firmware eingebettete Dateien zu extrahieren**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) zur Inspektion der Datei.

### Dateisystem erhalten

Mit den zuvor kommentierten Tools wie `binwalk -ev <bin>` sollten Sie in der Lage gewesen sein, **das Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einem **Ordner mit dem Namen des Dateisystemtyps**, der normalerweise einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal wird binwalk **nicht das Magiebyte des Dateisystems in seinen Signaturen haben**. In diesen Fällen verwenden Sie binwalk, um **den Offset des Dateisystems zu finden und das komprimierte Dateisystem** aus dem Binärfile herauszuschneiden und **extrahieren Sie das Dateisystem manuell** gemäß seinem Typ unter Verwendung der folgenden Schritte.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Führen Sie den folgenden **dd Befehl** aus, um das Squashfs-Dateisystem zu extrahieren.
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

Dateien befinden sich anschließend im Verzeichnis "`squashfs-root`".

* CPIO-Archivdateien

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Für jffs2-Dateisysteme

`$ jefferson rootfsfile.jffs2`

* Für ubifs-Dateisysteme mit NAND-Flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyse der Firmware

Nachdem die Firmware erhalten wurde, ist es entscheidend, sie zu analysieren, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dieser Prozess beinhaltet die Verwendung verschiedener Tools zur Analyse und Extraktion wertvoller Daten aus dem Firmware-Image.

### Tools für die erste Analyse

Eine Reihe von Befehlen wird für die erste Inspektion der Binärdatei (bezeichnet als `<bin>`) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Zeichenfolgen zu extrahieren, binäre Daten zu analysieren und Details zu Partitionen und Dateisystemen zu verstehen:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Bildes zu bewerten, wird die **Entropie** mit `binwalk -E <bin>` überprüft. Eine niedrige Entropie deutet auf einen Mangel an Verschlüsselung hin, während eine hohe Entropie mögliche Verschlüsselung oder Kompression anzeigt.

Zur Extraktion von **eingebetteten Dateien** werden Tools und Ressourcen wie die Dokumentation zu **file-data-carving-recovery-tools** und **binvis.io** zur Dateiinspektion empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` kann normalerweise das Dateisystem extrahiert werden, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** jedoch aufgrund fehlender Magic Bytes den Dateisystemtyp nicht erkennt, ist eine manuelle Extraktion erforderlich. Dies beinhaltet die Verwendung von `binwalk`, um den Offset des Dateisystems zu lokalisieren, gefolgt vom `dd`-Befehl zum Ausschneiden des Dateisystems:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
### Dateisystemanalyse

Nach Extrahieren des Dateisystems beginnt die Suche nach Sicherheitslücken. Es wird auf unsichere Netzwerkdaemons, fest codierte Anmeldeinformationen, API-Endpunkte, Update-Server-Funktionalitäten, nicht kompilierten Code, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

Zu überprüfende **Schlüsselpositionen** und **Elemente** sind unter anderem:

- **etc/shadow** und **etc/passwd** für Benutzeranmeldeinformationen
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binärdateien für weitere Analyse
- Gängige IoT-Gerät-Webserver und Binärdateien

Mehrere Tools unterstützen dabei, sensible Informationen und Schwachstellen im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach sensiblen Informationen
- [**Das Firmware-Analyse- und Vergleichstool (FACT)**](https://github.com/fkie-cad/FACT\_core) für umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analyse

### Sicherheitsüberprüfungen von kompilierten Binärdateien

Sowohl der Quellcode als auch die kompilierten Binärdateien im Dateisystem müssen auf Schwachstellen überprüft werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Emulation von Firmware für dynamische Analyse

Die Emulation von Firmware ermöglicht eine **dynamische Analyse** entweder des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Herausforderungen mit Hardware- oder Architekturabhängigkeiten stoßen, aber das Übertragen des Root-Dateisystems oder spezifischer Binärdateien auf ein Gerät mit passender Architektur und Endianness, wie einem Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine, kann weitere Tests erleichtern.

### Emulation von einzelnen Binärdateien

Für die Untersuchung einzelner Programme ist es entscheidend, die Endianness und CPU-Architektur des Programms zu identifizieren.

#### Beispiel mit MIPS-Architektur

Um eine MIPS-Architektur-Binärdatei zu emulieren, kann man den Befehl verwenden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die erforderlichen Emulationstools zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
#### ARM-Architektur-Emulation

Für ARM-Binärdateien ist der Prozess ähnlich, wobei der Emulator `qemu-arm` zur Emulation verwendet wird.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere erleichtern die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamische Analyse in der Praxis

In diesem Stadium wird entweder eine reale oder eine emulierte Geräteumgebung für die Analyse verwendet. Es ist wichtig, den Shell-Zugriff auf das Betriebssystem und das Dateisystem aufrechtzuerhalten. Die Emulation kann Hardwareinteraktionen nicht perfekt nachahmen, was gelegentliche Emulationsneustarts erforderlich machen kann. Die Analyse sollte das Dateisystem erneut überprüfen, freigelegte Webseiten und Netzwerkdienste ausnutzen und Bootloader-Schwachstellen erkunden. Tests zur Überprüfung der Firmware-Integrität sind entscheidend, um potenzielle Hintertür-Schwachstellen zu identifizieren.

## Laufzeit-Analysetechniken

Die Laufzeitanalyse beinhaltet die Interaktion mit einem Prozess oder einer Binärdatei in seiner Betriebsumgebung unter Verwendung von Tools wie gdb-multiarch, Frida und Ghidra zum Setzen von Haltepunkten und Identifizieren von Schwachstellen durch Fuzzing und andere Techniken.

## Binäre Ausnutzung und Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und des Programmierens in Sprachen auf niedrigerer Ebene. Binäre Laufzeitschutzmaßnahmen in eingebetteten Systemen sind selten, aber wenn vorhanden, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

## Vorbereitete Betriebssysteme für die Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorab konfigurierte Umgebungen für die Sicherheitstests von Firmware, ausgestattet mit den erforderlichen Tools.

## Vorbereitete Betriebssysteme zur Analyse von Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die dazu gedacht ist, Ihnen bei der Durchführung von Sicherheitsbewertungen und Penetrationstests von Internet of Things (IoT)-Geräten zu helfen. Es spart Ihnen viel Zeit, indem es eine vorab konfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded-Sicherheitstest-Betriebssystem basierend auf Ubuntu 18.04, vorbeladen mit Tools für die Sicherheitstests von Firmware.

## Verwundbare Firmware zum Üben

Um das Entdecken von Schwachstellen in Firmware zu üben, verwenden Sie die folgenden verwundbaren Firmware-Projekte als Ausgangspunkt.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* Das Damn Vulnerable Router Firmware Project
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

## Schulung und Zertifizierung

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)
