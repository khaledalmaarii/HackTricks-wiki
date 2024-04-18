# UART

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben** sehen möchten oder **HackTricks in PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihren Dienst **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

---

## Grundlegende Informationen

UART ist ein seriöses Protokoll, das bedeutet, dass es Daten zwischen Komponenten Bit für Bit überträgt. Im Gegensatz dazu übertragen parallele Kommunikationsprotokolle Daten gleichzeitig über mehrere Kanäle. Zu den gängigen seriellen Protokollen gehören RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express und USB.

Im Allgemeinen wird die Leitung hochgehalten (auf einem logischen Wert von 1), während UART sich im Leerlauf befindet. Dann sendet der Sender zur Signalisierung des Beginns einer Datenübertragung ein Startbit an den Empfänger, währenddessen das Signal niedrig gehalten wird (auf einem logischen Wert von 0). Als nächstes sendet der Sender fünf bis acht Datenbits mit der eigentlichen Nachricht, gefolgt von einem optionalen Paritätsbit und einem oder zwei Stoppbits (mit einem logischen Wert von 1), je nach Konfiguration. Das Paritätsbit, das zur Fehlerprüfung verwendet wird, wird in der Praxis selten gesehen. Das Stoppbit (oder die Stopbits) signalisieren das Ende der Übertragung.

Die häufigste Konfiguration nennen wir 8N1: acht Datenbits, keine Parität und ein Stoppbit. Wenn wir beispielsweise das Zeichen C oder 0x43 in ASCII in einer 8N1-UART-Konfiguration senden wollten, würden wir die folgenden Bits senden: 0 (das Startbit); 0, 1, 0, 0, 0, 0, 1, 1 (der Wert von 0x43 in binär) und 0 (das Stoppbit).

![](<../../.gitbook/assets/image (761).png>)

Hardware-Tools zur Kommunikation mit UART:

* USB-zu-Seriell-Adapter
* Adapter mit den Chips CP2102 oder PL2303
* Mehrzweckwerkzeug wie: Bus Pirate, den Adafruit FT232H, den Shikra oder das Attify Badge

### Identifizierung von UART-Ports

UART hat 4 Ports: **TX** (Senden), **RX** (Empfangen), **Vcc** (Spannung) und **GND** (Masse). Möglicherweise finden Sie 4 Ports mit den Buchstaben **`TX`** und **`RX`** auf der Leiterplatte **geschrieben**. Wenn keine Kennzeichnung vorhanden ist, müssen Sie möglicherweise versuchen, sie selbst mit einem **Multimeter** oder einem **Logikanalysator** zu finden.

Mit einem **Multimeter** und dem ausgeschalteten Gerät:

* Verwenden Sie den **Durchgangstest**-Modus, um den **GND**-Pin zu identifizieren. Platzieren Sie das hintere Messgeräteleit in die Masse und testen Sie mit dem roten, bis Sie einen Ton vom Multimeter hören. Auf der Leiterplatte können mehrere GND-Pins gefunden werden, sodass Sie möglicherweise denjenigen gefunden haben, der zu UART gehört oder auch nicht.
* Um den **VCC-Port** zu identifizieren, stellen Sie den **Gleichspannungsmodus** ein und stellen Sie ihn auf 20 V Spannung ein. Schwarze Sonde auf Masse und rote Sonde auf den Pin. Schalten Sie das Gerät ein. Wenn das Multimeter eine konstante Spannung von entweder 3,3 V oder 5 V misst, haben Sie den Vcc-Pin gefunden. Wenn Sie andere Spannungen erhalten, versuchen Sie es mit anderen Ports erneut.
* Um den **TX-Port** zu identifizieren, **Gleichspannungsmodus** bis zu 20 V Spannung, schwarze Sonde auf Masse und rote Sonde auf den Pin, und schalten Sie das Gerät ein. Wenn Sie feststellen, dass die Spannung einige Sekunden lang schwankt und dann auf den Vcc-Wert stabilisiert, haben Sie höchstwahrscheinlich den TX-Port gefunden. Dies liegt daran, dass beim Einschalten einige Debug-Daten gesendet werden.
* Der **RX-Port** wäre der nächstgelegene zu den anderen 3, er hat die geringste Spannungsschwankung und den niedrigsten Gesamtwert aller UART-Pins.

Sie können die TX- und RX-Ports verwechseln und es würde nichts passieren, aber wenn Sie den GND- und den VCC-Port verwechseln, könnten Sie die Schaltung zerstören.

In einigen Zielgeräten ist der UART-Port vom Hersteller deaktiviert, indem RX oder TX oder sogar beides deaktiviert werden. In diesem Fall kann es hilfreich sein, die Verbindungen auf der Leiterplatte nachzuverfolgen und einen Ausbruchpunkt zu finden. Ein starkes Indiz dafür, dass kein UART erkannt wird und die Schaltung unterbrochen ist, besteht darin, die Gerätegarantie zu überprüfen. Wenn das Gerät mit einer Garantie geliefert wurde, lässt der Hersteller einige Debug-Schnittstellen (in diesem Fall UART) und hat daher den UART getrennt und würde ihn wieder anschließen, während er debuggt. Diese Ausbruchspins können durch Löten oder Jumperdrähte verbunden werden.

### Identifizierung der UART-Baudrate

Der einfachste Weg, die richtige Baudrate zu identifizieren, besteht darin, sich die **Ausgabe des TX-Pins anzusehen und zu versuchen, die Daten zu lesen**. Wenn die empfangenen Daten nicht lesbar sind, wechseln Sie zur nächsten möglichen Baudrate, bis die Daten lesbar werden. Sie können hierfür einen USB-zu-Seriell-Adapter oder ein Mehrzweckgerät wie Bus Pirate verwenden, gepaart mit einem Hilfsskript wie [baudrate.py](https://github.com/devttys0/baudrate/). Die häufigsten Baudraten sind 9600, 38400, 19200, 57600 und 115200.

{% hint style="danger" %}
Es ist wichtig zu beachten, dass Sie in diesem Protokoll den TX eines Geräts mit dem RX des anderen verbinden müssen!
{% endhint %}

## CP210X UART zu TTY-Adapter

Der CP210X-Chip wird in vielen Prototyping-Boards wie NodeMCU (mit esp8266) für die serielle Kommunikation verwendet. Diese Adapter sind relativ kostengünstig und können verwendet werden, um sich mit der UART-Schnittstelle des Ziels zu verbinden. Das Gerät hat 5 Pins: 5V, GND, RXD, TXD, 3.3V. Stellen Sie sicher, dass die Spannung entsprechend dem Ziel unterstützt wird, um Schäden zu vermeiden. Verbinden Sie schließlich den RXD-Pin des Adapters mit dem TXD des Ziels und den TXD-Pin des Adapters mit dem RXD des Ziels.

Wenn der Adapter nicht erkannt wird, stellen Sie sicher, dass die CP210X-Treiber im Hostsystem installiert sind. Sobald der Adapter erkannt und verbunden ist, können Tools wie picocom, minicom oder screen verwendet werden.

Um die an Linux/MacOS-Systeme angeschlossenen Geräte aufzulisten:
```
ls /dev/
```
Für die grundlegende Interaktion mit der UART-Schnittstelle verwenden Sie den folgenden Befehl:
```
picocom /dev/<adapter> --baud <baudrate>
```
Für minicom verwenden Sie den folgenden Befehl, um es zu konfigurieren:
```
minicom -s
```
Konfigurieren Sie die Einstellungen wie Baudrate und Gerätename in der Option `Serienport einrichten`.

Nach der Konfiguration verwenden Sie den Befehl `minicom`, um die UART-Konsole zu starten.

## UART über Arduino UNO R3 (Abnehmbare Atmel 328p Chip Boards)

Falls UART Seriell-zu-USB-Adapter nicht verfügbar sind, kann Arduino UNO R3 mit einem schnellen Hack verwendet werden. Da Arduino UNO R3 normalerweise überall verfügbar ist, kann dies viel Zeit sparen.

Arduino UNO R3 verfügt über einen USB-zu-Seriell-Adapter, der bereits auf der Platine integriert ist. Um eine UART-Verbindung herzustellen, ziehen Sie einfach den Atmel 328p Mikrocontroller-Chip aus der Platine. Dieser Hack funktioniert bei Arduino UNO R3-Varianten, bei denen der Atmel 328p nicht auf der Platine gelötet ist (SMD-Version wird verwendet). Verbinden Sie den RX-Pin des Arduino (Digital Pin 0) mit dem TX-Pin des UART-Interfaces und den TX-Pin des Arduino (Digital Pin 1) mit dem RX-Pin des UART-Interfaces.

Abschließend wird empfohlen, die Arduino IDE zu verwenden, um die Serielle Konsole zu erhalten. Wählen Sie im Menü den Abschnitt `Werkzeuge`, wählen Sie die Option `Serielle Konsole` und setzen Sie die Baudrate entsprechend dem UART-Interface.

## Bus Pirate

In diesem Szenario werden wir die UART-Kommunikation des Arduino abhören, der alle Ausgaben des Programms an den Seriellen Monitor sendet.
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## Dumping Firmware mit UART-Konsole

Die UART-Konsole bietet eine großartige Möglichkeit, mit der zugrunde liegenden Firmware in der Laufzeitumgebung zu arbeiten. Wenn jedoch der Zugriff auf die UART-Konsole schreibgeschützt ist, kann dies viele Einschränkungen mit sich bringen. Bei vielen eingebetteten Geräten wird die Firmware in EEPROMs gespeichert und auf Prozessoren ausgeführt, die über einen flüchtigen Speicher verfügen. Daher bleibt die Firmware schreibgeschützt, da die ursprüngliche Firmware während der Herstellung im EEPROM selbst enthalten ist und neue Dateien aufgrund des flüchtigen Speichers verloren gehen würden. Daher ist das Dumpen der Firmware eine wertvolle Anstrengung bei der Arbeit mit eingebetteten Firmwares.

Es gibt viele Möglichkeiten, dies zu tun, und der SPI-Abschnitt behandelt Methoden zum direkten Extrahieren der Firmware aus dem EEPROM mit verschiedenen Geräten. Es wird jedoch empfohlen, zuerst zu versuchen, die Firmware mit UART zu dumpen, da das Dumpen der Firmware mit physischen Geräten und externen Interaktionen riskant sein kann.

Das Dumpen der Firmware von der UART-Konsole erfordert zunächst den Zugriff auf Bootloader. Viele beliebte Anbieter verwenden <b>uboot</b> (Universal Bootloader) als ihren Bootloader zum Laden von Linux. Daher ist es notwendig, Zugriff auf <b>uboot</b> zu erhalten.

Um Zugriff auf den <b>Boot</b>-Bootloader zu erhalten, schließen Sie den UART-Port an den Computer an und verwenden Sie eines der Serial Console-Tools, während die Stromversorgung des Geräts getrennt bleibt. Sobald das Setup bereit ist, drücken Sie die Eingabetaste und halten Sie sie gedrückt. Schließen Sie schließlich die Stromversorgung des Geräts an und lassen Sie es booten.

Dadurch wird <b>uboot</b> am Laden gehindert und es wird ein Menü angezeigt. Es wird empfohlen, die <b>uboot</b>-Befehle zu verstehen und das Hilfemenü zu verwenden, um sie aufzulisten. Dies könnte der Befehl `help` sein. Da verschiedene Anbieter unterschiedliche Konfigurationen verwenden, ist es notwendig, jede von ihnen separat zu verstehen.

Normalerweise lautet der Befehl zum Dumpen der Firmware:
```
md
```
welches für "Speicherabbild" steht. Dies wird den Speicher (EEPROM-Inhalt) auf dem Bildschirm ausgeben. Es wird empfohlen, die Ausgabe der seriellen Konsole zu protokollieren, bevor Sie mit dem Vorgang beginnen, um das Speicherabbild zu erfassen.

Schließlich entfernen Sie einfach alle unnötigen Daten aus der Protokolldatei und speichern Sie die Datei als `filename.rom` und verwenden Sie binwalk, um die Inhalte zu extrahieren:
```
binwalk -e <filename.rom>
```
Dies wird die möglichen Inhalte aus dem EEPROM gemäß den Signaturen in der Hex-Datei auflisten.

Es ist jedoch zu beachten, dass es nicht immer der Fall ist, dass das <b>uboot</b> entsperrt ist, auch wenn es verwendet wird. Wenn die Eingabetaste nichts bewirkt, überprüfen Sie auf verschiedene Tasten wie die Leertaste usw. Wenn das Bootloader gesperrt ist und nicht unterbrochen wird, funktioniert diese Methode nicht. Um zu überprüfen, ob <b>uboot</b> der Bootloader für das Gerät ist, überprüfen Sie die Ausgabe auf der UART-Konsole beim Booten des Geräts. Es könnte <b>uboot</b> während des Bootvorgangs erwähnen.


## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihren Dienst **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}


<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** möchten oder **HackTricks im PDF-Format herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
