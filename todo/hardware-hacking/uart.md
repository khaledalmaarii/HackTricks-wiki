<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


# Grundlegende Informationen

UART ist ein seriöses Protokoll, das bedeutet, dass es Daten zwischen Komponenten bitweise überträgt. Im Gegensatz dazu übertragen parallele Kommunikationsprotokolle Daten gleichzeitig über mehrere Kanäle. Zu den gängigen seriellen Protokollen gehören RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express und USB.

Im Allgemeinen wird die Leitung im Ruhezustand hochgehalten (mit einem logischen Wert von 1), während UART aktiv ist. Um den Beginn einer Datenübertragung anzuzeigen, sendet der Sender ein Startbit an den Empfänger, währenddessen das Signal niedrig gehalten wird (mit einem logischen Wert von 0). Anschließend sendet der Sender fünf bis acht Datenbits, die die eigentliche Nachricht enthalten, gefolgt von einem optionalen Paritätsbit und einem oder zwei Stoppbits (mit einem logischen Wert von 1), abhängig von der Konfiguration. Das Paritätsbit, das zur Fehlerprüfung verwendet wird, wird in der Praxis selten verwendet. Das Stoppbit (oder die Stoppbits) signalisieren das Ende der Übertragung.

Wir nennen die häufigste Konfiguration 8N1: acht Datenbits, keine Parität und ein Stoppbit. Wenn wir zum Beispiel den Buchstaben C oder 0x43 in ASCII in einer 8N1-UART-Konfiguration senden möchten, würden wir die folgenden Bits senden: 0 (das Startbit); 0, 1, 0, 0, 0, 0, 1, 1 (der Wert von 0x43 in binär) und 0 (das Stoppbit).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Hardware-Tools zur Kommunikation mit UART:

* USB-zu-Seriell-Adapter
* Adapter mit den Chips CP2102 oder PL2303
* Mehrzweckwerkzeug wie Bus Pirate, Adafruit FT232H, Shikra oder Attify Badge

## Identifizierung von UART-Ports

UART hat 4 Ports: **TX** (Transmit), **RX** (Receive), **Vcc** (Spannung) und **GND** (Ground). Sie können möglicherweise 4 Ports mit den Buchstaben **`TX`** und **`RX`** finden, die auf der Leiterplatte **geschrieben** sind. Wenn jedoch keine Kennzeichnung vorhanden ist, müssen Sie möglicherweise versuchen, sie mit einem **Multimeter** oder einem **Logikanalysator** zu finden.

Mit einem **Multimeter** und dem ausgeschalteten Gerät:

* Um den **GND-Pin** zu identifizieren, verwenden Sie den **Durchgangstest**-Modus, setzen Sie die Rückleitung auf Masse und testen Sie mit der roten Leitung, bis Sie einen Ton vom Multimeter hören. Auf der Leiterplatte können mehrere GND-Pins gefunden werden, daher haben Sie möglicherweise den zu UART gehörenden Pin gefunden oder nicht.
* Um den **VCC-Port** zu identifizieren, stellen Sie den **Gleichspannungsmodus** ein und stellen Sie ihn auf 20 V Spannung ein. Schwarze Sonde auf Masse und rote Sonde auf den Pin. Schalten Sie das Gerät ein. Wenn das Multimeter eine konstante Spannung von 3,3 V oder 5 V misst, haben Sie den Vcc-Pin gefunden. Wenn Sie andere Spannungen erhalten, versuchen Sie es mit anderen Ports erneut.
* Um den **TX-Port** zu identifizieren, stellen Sie den **Gleichspannungsmodus** auf 20 V Spannung ein, schwarze Sonde auf Masse und rote Sonde auf den Pin und schalten Sie das Gerät ein. Wenn Sie feststellen, dass die Spannung einige Sekunden lang schwankt und dann den Wert von Vcc stabilisiert, haben Sie höchstwahrscheinlich den TX-Port gefunden. Dies liegt daran, dass beim Einschalten einige Debug-Daten gesendet werden.
* Der **RX-Port** wäre der nächstgelegene zu den anderen 3, er hat die geringste Spannungsschwankung und den geringsten Gesamtwert aller UART-Pins.

Sie können die TX- und RX-Ports verwechseln und es würde nichts passieren, aber wenn Sie den GND- und den VCC-Port verwechseln, könnten Sie die Schaltung zerstören.

Mit einem Logikanalysator:

## Identifizierung der UART-Baudrate

Der einfachste Weg, die richtige Baudrate zu identifizieren, besteht darin, sich die Ausgabe des **TX-Pins anzusehen und die Daten zu lesen**. Wenn die empfangenen Daten nicht lesbar sind, wechseln Sie zur nächsten möglichen Baudrate, bis die Daten lesbar werden. Hierfür können Sie einen USB-zu-Seriell-Adapter oder ein Mehrzweckgerät wie den Bus Pirate verwenden, zusammen mit einem Hilfsskript wie [baudrate.py](https://github.com/devttys0/baudrate/). Die häufigsten Baudraten sind 9600, 38400, 19200, 57600 und 115200.

{% hint style="danger" %}
Es ist wichtig zu beachten, dass Sie in diesem Protokoll den TX eines Geräts mit dem RX des anderen verbinden müssen!
{% endhint %}

# Bus Pirate

In diesem Szenario werden wir die UART-Kommunikation des Arduino abhören, der alle Ausgaben des Programms an den Serial Monitor sendet.
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
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
