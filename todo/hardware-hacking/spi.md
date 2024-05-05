# SPI

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Grundlegende Informationen

SPI (Serial Peripheral Interface) ist ein synchrones serielle Kommunikationsprotokoll, das in eingebetteten Systemen für die Kommunikation auf kurze Distanz zwischen ICs (Integrierte Schaltungen) verwendet wird. Das SPI-Kommunikationsprotokoll nutzt die Master-Slave-Architektur, die durch das Takt- und Chip-Select-Signal orchestriert wird. Eine Master-Slave-Architektur besteht aus einem Master (in der Regel ein Mikroprozessor), der externe Peripheriegeräte wie EEPROMs, Sensoren, Steuergeräte usw. verwaltet, die als Slaves betrachtet werden.

Mehrere Slaves können an einen Master angeschlossen werden, aber Slaves können nicht miteinander kommunizieren. Slaves werden von zwei Pins, Takt und Chip-Select, verwaltet. Da SPI ein synchrones Kommunikationsprotokoll ist, folgen die Eingangs- und Ausgangspins den Taktsignalen. Der Chip-Select wird vom Master verwendet, um einen Slave auszuwählen und mit ihm zu interagieren. Wenn der Chip-Select hoch ist, ist das Slave-Gerät nicht ausgewählt, während es niedrig ist, wurde der Chip ausgewählt und der Master würde mit dem Slave interagieren.

MOSI (Master Out, Slave In) und MISO (Master In, Slave Out) sind für das Senden und Empfangen von Daten verantwortlich. Daten werden über den MOSI-Pin an das Slave-Gerät gesendet, während der Chip-Select niedrig gehalten wird. Die Eingangsdaten enthalten Anweisungen, Speicheradressen oder Daten gemäß dem Datenblatt des Slave-Geräteherstellers. Bei gültiger Eingabe ist der MISO-Pin dafür verantwortlich, Daten an den Master zu übertragen. Die Ausgangsdaten werden genau im nächsten Taktzyklus nach dem Ende der Eingabe gesendet. Die MISO-Pins übertragen Daten, bis die Daten vollständig übertragen sind oder der Master den Chip-Select-Pin hoch setzt (in diesem Fall würde der Slave aufhören zu senden und der Master würde nach diesem Taktzyklus nicht mehr zuhören).

## Firmware von EEPROMs auslesen

Das Auslesen von Firmware kann nützlich sein, um die Firmware zu analysieren und Schwachstellen darin zu finden. Oftmals ist die Firmware nicht im Internet verfügbar oder aufgrund von Faktoren wie Modellnummer, Version usw. irrelevant. Daher kann es hilfreich sein, die Firmware direkt vom physischen Gerät zu extrahieren, um spezifisch bei der Suche nach Bedrohungen zu sein.

Das Abrufen der seriellen Konsole kann hilfreich sein, aber oft ist es so, dass die Dateien schreibgeschützt sind. Dies schränkt die Analyse aus verschiedenen Gründen ein. Zum Beispiel wären Tools, die zum Senden und Empfangen von Paketen erforderlich sind, nicht in der Firmware vorhanden. Daher ist es nicht machbar, die Binärdateien zu extrahieren, um sie umzukehren. Daher kann es sehr hilfreich sein, die gesamte Firmware auf dem System abzulegen und die Binärdateien zur Analyse zu extrahieren.

Auch beim Red Teaming und beim physischen Zugriff auf Geräte kann das Auslesen der Firmware dabei helfen, Dateien zu modifizieren oder bösartige Dateien einzuspeisen und sie dann in den Speicher zurückzuschreiben, was hilfreich sein könnte, um eine Hintertür in das Gerät einzubauen. Daher gibt es zahlreiche Möglichkeiten, die mit dem Auslesen von Firmware freigeschaltet werden können.

### CH341A EEPROM-Programmierer und -Leser

Dieses Gerät ist ein kostengünstiges Werkzeug zum Auslesen von Firmware von EEPROMs und auch zum Zurückflashen mit Firmware-Dateien. Dies war eine beliebte Wahl für die Arbeit mit Computer-BIOS-Chips (die nur EEPROMs sind). Dieses Gerät wird über USB angeschlossen und benötigt minimale Werkzeuge, um loszulegen. Außerdem erledigt es die Aufgabe normalerweise schnell, sodass es auch beim physischen Gerätezugriff hilfreich sein kann.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Verbinden Sie den EEPROM-Speicher mit dem CH341a-Programmierer und stecken Sie das Gerät in den Computer. Wenn das Gerät nicht erkannt wird, versuchen Sie, Treiber in den Computer zu installieren. Stellen Sie außerdem sicher, dass das EEPROM in der richtigen Ausrichtung angeschlossen ist (normalerweise den VCC-Pin in umgekehrter Ausrichtung zum USB-Anschluss platzieren), da die Software andernfalls den Chip nicht erkennen würde. Sehen Sie bei Bedarf das Diagramm:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Verwenden Sie schließlich Software wie flashrom, G-Flash (GUI) usw., um die Firmware auszulesen. G-Flash ist ein minimales GUI-Tool, das schnell ist und das EEPROM automatisch erkennt. Dies kann hilfreich sein, wenn die Firmware schnell extrahiert werden muss, ohne viel mit der Dokumentation herumzuspielen.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Nach dem Auslesen der Firmware kann die Analyse anhand der Binärdateien durchgeführt werden. Tools wie strings, hexdump, xxd, binwalk usw. können verwendet werden, um viele Informationen über die Firmware sowie das gesamte Dateisystem zu extrahieren.

Um die Inhalte aus der Firmware zu extrahieren, kann binwalk verwendet werden. Binwalk analysiert nach Hex-Signaturen und identifiziert die Dateien in der Binärdatei und ist in der Lage, sie zu extrahieren.
```
binwalk -e <filename>
```
Die Datei kann je nach den verwendeten Tools und Konfigurationen .bin oder .rom sein.

{% hint style="danger" %}
Bitte beachten Sie, dass die Extraktion der Firmware ein sensibler Prozess ist und viel Geduld erfordert. Eine unsachgemäße Handhabung kann die Firmware potenziell beschädigen oder sogar vollständig löschen und das Gerät unbrauchbar machen. Es wird empfohlen, das spezifische Gerät gründlich zu studieren, bevor Sie versuchen, die Firmware zu extrahieren.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Beachten Sie, dass auch wenn das PINOUT des Bus Pirate Pins für **MOSI** und **MISO** zum Anschließen an SPI angibt, einige SPIs Pins als DI und DO anzeigen können. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

In Windows oder Linux können Sie das Programm [**`flashrom`**](https://www.flashrom.org/Flashrom) verwenden, um den Inhalt des Flash-Speichers mit einem Befehl wie diesem zu dumpen:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
