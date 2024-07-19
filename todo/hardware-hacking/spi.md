# SPI

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

## Grundinformationen

SPI (Serial Peripheral Interface) ist ein synchrones serielles Kommunikationsprotokoll, das in eingebetteten Systemen für die Kommunikation über kurze Strecken zwischen ICs (Integrierte Schaltungen) verwendet wird. Das SPI-Kommunikationsprotokoll nutzt die Master-Slave-Architektur, die durch das Takt- und Chip-Select-Signal orchestriert wird. Eine Master-Slave-Architektur besteht aus einem Master (in der Regel ein Mikroprozessor), der externe Peripheriegeräte wie EEPROM, Sensoren, Steuergeräte usw. verwaltet, die als Slaves betrachtet werden.

Mehrere Slaves können mit einem Master verbunden werden, aber Slaves können nicht miteinander kommunizieren. Slaves werden durch zwei Pins, Takt und Chip-Select, verwaltet. Da SPI ein synchrones Kommunikationsprotokoll ist, folgen die Eingangs- und Ausgangspins den Taktsignalen. Der Chip-Select wird vom Master verwendet, um einen Slave auszuwählen und mit ihm zu interagieren. Wenn der Chip-Select hoch ist, ist das Slave-Gerät nicht ausgewählt, während es bei niedrigem Pegel ausgewählt ist und der Master mit dem Slave interagiert.

Die MOSI (Master Out, Slave In) und MISO (Master In, Slave Out) sind verantwortlich für das Senden und Empfangen von Daten. Daten werden über den MOSI-Pin an das Slave-Gerät gesendet, während der Chip-Select niedrig gehalten wird. Die Eingabedaten enthalten Anweisungen, Speicheradressen oder Daten gemäß dem Datenblatt des Slave-Geräteanbieters. Bei einer gültigen Eingabe ist der MISO-Pin verantwortlich für die Übertragung von Daten an den Master. Die Ausgabedaten werden genau im nächsten Taktzyklus gesendet, nachdem die Eingabe endet. Die MISO-Pins übertragen Daten, bis die Daten vollständig übertragen sind oder der Master den Chip-Select-Pin hochsetzt (in diesem Fall würde das Slave aufhören zu übertragen und der Master würde nach diesem Taktzyklus nicht mehr hören).

## Firmware von EEPROMs dumpen

Das Dumpen von Firmware kann nützlich sein, um die Firmware zu analysieren und Schwachstellen darin zu finden. Oftmals ist die Firmware nicht im Internet verfügbar oder irrelevant aufgrund von Variationen wie Modellnummer, Version usw. Daher kann es hilfreich sein, die Firmware direkt vom physischen Gerät zu extrahieren, um spezifisch nach Bedrohungen zu suchen.

Der Zugriff auf die serielle Konsole kann hilfreich sein, aber oft sind die Dateien schreibgeschützt. Dies schränkt die Analyse aus verschiedenen Gründen ein. Zum Beispiel könnten Werkzeuge, die erforderlich sind, um Pakete zu senden und zu empfangen, nicht in der Firmware vorhanden sein. Daher ist es nicht machbar, die Binärdateien zu extrahieren, um sie zurückzuentwickeln. Daher kann es sehr hilfreich sein, die gesamte Firmware auf dem System zu dumpen und die Binärdateien zur Analyse zu extrahieren.

Außerdem kann das Dumpen der Firmware während des Red Teamings und des physischen Zugriffs auf Geräte helfen, die Dateien zu modifizieren oder bösartige Dateien einzuschleusen und sie dann in den Speicher zurückzuspielen, was hilfreich sein könnte, um ein Hintertür in das Gerät einzupflanzen. Daher gibt es zahlreiche Möglichkeiten, die durch das Dumpen von Firmware freigeschaltet werden können.

### CH341A EEPROM-Programmierer und -Lesegerät

Dieses Gerät ist ein kostengünstiges Werkzeug zum Dumpen von Firmwares von EEPROMs und auch zum Zurückspielen von Firmware-Dateien. Dies war eine beliebte Wahl für die Arbeit mit Computer-BIOS-Chips (die nur EEPROMs sind). Dieses Gerät wird über USB angeschlossen und benötigt minimale Werkzeuge, um zu starten. Außerdem erledigt es die Aufgabe normalerweise schnell, sodass es auch beim physischen Zugriff auf Geräte hilfreich sein kann.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Schließe den EEPROM-Speicher an den CH341A-Programmierer an und stecke das Gerät in den Computer. Falls das Gerät nicht erkannt wird, versuche, Treiber auf dem Computer zu installieren. Stelle auch sicher, dass der EEPROM in der richtigen Ausrichtung angeschlossen ist (normalerweise den VCC-Pin in umgekehrter Ausrichtung zum USB-Anschluss platzieren), da die Software sonst den Chip nicht erkennen kann. Siehe das Diagramm, falls erforderlich:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Verwende schließlich Software wie flashrom, G-Flash (GUI) usw. zum Dumpen der Firmware. G-Flash ist ein minimales GUI-Tool, das schnell ist und den EEPROM automatisch erkennt. Dies kann hilfreich sein, wenn die Firmware schnell extrahiert werden muss, ohne viel mit der Dokumentation herumzuprobieren.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Nach dem Dumpen der Firmware kann die Analyse an den Binärdateien durchgeführt werden. Werkzeuge wie strings, hexdump, xxd, binwalk usw. können verwendet werden, um viele Informationen über die Firmware sowie das gesamte Dateisystem zu extrahieren.

Um die Inhalte aus der Firmware zu extrahieren, kann binwalk verwendet werden. Binwalk analysiert nach Hex-Signaturen und identifiziert die Dateien in der Binärdatei und ist in der Lage, sie zu extrahieren.
```
binwalk -e <filename>
```
Die Dateien können .bin oder .rom sein, je nach den verwendeten Tools und Konfigurationen.

{% hint style="danger" %}
Beachten Sie, dass die Extraktion der Firmware ein heikler Prozess ist und viel Geduld erfordert. Jede unsachgemäße Handhabung kann die Firmware potenziell beschädigen oder sogar vollständig löschen und das Gerät unbrauchbar machen. Es wird empfohlen, das spezifische Gerät zu studieren, bevor Sie versuchen, die Firmware zu extrahieren.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Beachten Sie, dass selbst wenn das PINOUT des Pirate Bus Pins für **MOSI** und **MISO** angibt, um sich mit SPI zu verbinden, einige SPIs Pins als DI und DO angeben können. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

In Windows oder Linux können Sie das Programm [**`flashrom`**](https://www.flashrom.org/Flashrom) verwenden, um den Inhalt des Flashspeichers mit einem Befehl wie diesem zu dumpen:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
