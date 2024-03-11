<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


# Grundlegende Informationen

SPI (Serial Peripheral Interface) ist ein synchrones serielle Kommunikationsprotokoll, das in eingebetteten Systemen für die Kommunikation auf kurze Distanz zwischen ICs (Integrierte Schaltungen) verwendet wird. Das SPI-Kommunikationsprotokoll nutzt die Master-Slave-Architektur, die durch das Clock- und Chip-Select-Signal orchestriert wird. Eine Master-Slave-Architektur besteht aus einem Master (in der Regel ein Mikroprozessor), der externe Peripheriegeräte wie EEPROMs, Sensoren, Steuergeräte usw. verwaltet, die als Slaves betrachtet werden.

Mehrere Slaves können an einen Master angeschlossen werden, aber Slaves können nicht miteinander kommunizieren. Slaves werden von zwei Pins, Clock und Chip Select, verwaltet. Da SPI ein synchrone Kommunikationsprotokoll ist, folgen die Eingangs- und Ausgangspins den Clock-Signalen. Der Chip Select wird vom Master verwendet, um einen Slave auszuwählen und mit ihm zu interagieren. Wenn der Chip Select hoch ist, ist das Slave-Gerät nicht ausgewählt, während es niedrig ist, wurde der Chip ausgewählt und der Master würde mit dem Slave interagieren.

MOSI (Master Out, Slave In) und MISO (Master In, Slave Out) sind für das Senden und Empfangen von Daten verantwortlich. Daten werden über den MOSI-Pin an das Slave-Gerät gesendet, während der Chip Select niedrig gehalten wird. Die Eingangsdaten enthalten Anweisungen, Speicheradressen oder Daten gemäß dem Datenblatt des Slave-Geräteherstellers. Bei gültiger Eingabe ist der MISO-Pin für die Übertragung von Daten an den Master verantwortlich. Die Ausgangsdaten werden genau im nächsten Taktzyklus nach dem Ende der Eingabe gesendet. Die MISO-Pins übertragen Daten, bis die Daten vollständig übertragen sind oder der Master den Chip-Select-Pin hoch setzt (in diesem Fall würde der Slave aufhören zu senden und der Master würde nach diesem Taktzyklus nicht mehr zuhören).

# Flash dumpen

## Bus Pirate + flashrom

![](<../../.gitbook/assets/image (201).png>)

Beachten Sie, dass auch wenn das PINOUT des Bus Pirate Pins für **MOSI** und **MISO** zum Anschließen an SPI angibt, einige SPIs Pins als DI und DO anzeigen können. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (648) (1) (1).png>)

In Windows oder Linux können Sie das Programm [**`flashrom`**](https://www.flashrom.org/Flashrom) verwenden, um den Inhalt des Flash-Speichers auszulesen, indem Sie etwas Ähnliches ausführen:
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
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
