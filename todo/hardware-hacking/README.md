# Hardware Hacking

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

## JTAG

JTAG ermöglicht es, einen Boundary-Scan durchzuführen. Der Boundary-Scan analysiert bestimmte Schaltungen, einschließlich eingebetteter Boundary-Scan-Zellen und Register für jeden Pin.

Der JTAG-Standard definiert **spezifische Befehle für die Durchführung von Boundary-Scans**, einschließlich der folgenden:

* **BYPASS** ermöglicht es, einen bestimmten Chip ohne den Overhead anderer Chips zu testen.
* **SAMPLE/PRELOAD** nimmt eine Probe der Daten auf, die das Gerät beim normalen Betriebsmodus ein- und ausgeben.
* **EXTEST** setzt und liest den Zustand der Pins.

Es kann auch andere Befehle unterstützen, wie:

* **IDCODE** zur Identifizierung eines Geräts
* **INTEST** für die interne Prüfung des Geräts

Du könntest auf diese Anweisungen stoßen, wenn du ein Tool wie den JTAGulator verwendest.

### Der Testzugangspunkt

Boundary-Scans umfassen Tests des vieradrigen **Test Access Port (TAP)**, einem universellen Port, der **Zugriff auf die JTAG-Testunterstützungs**funktionen bietet, die in ein Bauteil integriert sind. TAP verwendet die folgenden fünf Signale:

* Testtakt-Eingang (**TCK**) Der TCK ist der **Takt**, der definiert, wie oft der TAP-Controller eine einzelne Aktion ausführt (mit anderen Worten, zum nächsten Zustand in der Zustandsmaschine springt).
* Testmodus-Auswahl (**TMS**) Eingang TMS steuert die **endliche Zustandsmaschine**. Bei jedem Taktimpuls überprüft der JTAG TAP-Controller des Geräts die Spannung am TMS-Pin. Wenn die Spannung unter einem bestimmten Schwellenwert liegt, wird das Signal als niedrig betrachtet und als 0 interpretiert, während das Signal als hoch betrachtet und als 1 interpretiert wird, wenn die Spannung über einem bestimmten Schwellenwert liegt.
* Testdaten-Eingang (**TDI**) TDI ist der Pin, der **Daten in den Chip über die Scan-Zellen** sendet. Jeder Anbieter ist dafür verantwortlich, das Kommunikationsprotokoll über diesen Pin zu definieren, da JTAG dies nicht definiert.
* Testdaten-Ausgang (**TDO**) TDO ist der Pin, der **Daten aus dem Chip** sendet.
* Test-Reset (**TRST**) Eingang Der optionale TRST setzt die endliche Zustandsmaschine **auf einen bekannten guten Zustand** zurück. Alternativ, wenn der TMS fünf aufeinanderfolgende Taktzyklen lang auf 1 gehalten wird, wird ein Reset ausgelöst, ähnlich wie es der TRST-Pin tun würde, weshalb TRST optional ist.

Manchmal kannst du diese Pins auf der PCB markiert finden. In anderen Fällen musst du sie **finden**.

### Identifizierung von JTAG-Pins

Der schnellste, aber teuerste Weg, JTAG-Ports zu erkennen, ist die Verwendung des **JTAGulator**, eines Geräts, das speziell für diesen Zweck entwickelt wurde (obwohl es **auch UART-Pinouts erkennen kann**).

Es hat **24 Kanäle**, die du mit den Pins der Platine verbinden kannst. Dann führt es einen **BF-Angriff** auf alle möglichen Kombinationen durch, indem es **IDCODE** und **BYPASS** Boundary-Scan-Befehle sendet. Wenn es eine Antwort erhält, zeigt es den Kanal an, der jedem JTAG-Signal entspricht.

Eine günstigere, aber viel langsamere Methode zur Identifizierung von JTAG-Pinouts ist die Verwendung von [**JTAGenum**](https://github.com/cyphunk/JTAGenum/), das auf einem Arduino-kompatiblen Mikrocontroller geladen ist.

Mit **JTAGenum** würdest du zuerst **die Pins des Prüfgeräts definieren**, die du für die Enumeration verwenden wirst. Du müsstest das Pinout-Diagramm des Geräts konsultieren und dann diese Pins mit den Testpunkten deines Zielgeräts verbinden.

Eine **dritte Methode** zur Identifizierung von JTAG-Pins besteht darin, die **PCB zu inspizieren** und nach einem der Pinouts zu suchen. In einigen Fällen bieten PCBs möglicherweise bequem die **Tag-Connect-Schnittstelle**, was ein klares Indiz dafür ist, dass die Platine auch einen JTAG-Anschluss hat. Du kannst sehen, wie diese Schnittstelle aussieht unter [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Darüber hinaus könnte die Inspektion der **Datenblätter der Chipsätze auf der PCB** Pinout-Diagramme offenbaren, die auf JTAG-Schnittstellen hinweisen.

## SDW

SWD ist ein ARM-spezifisches Protokoll, das für das Debugging entwickelt wurde.

Die SWD-Schnittstelle benötigt **zwei Pins**: ein bidirektionales **SWDIO**-Signal, das dem JTAG-**TDI- und TDO-Pin** entspricht, und einen Takt, **SWCLK**, der dem **TCK** in JTAG entspricht. Viele Geräte unterstützen den **Serial Wire oder JTAG Debug Port (SWJ-DP)**, eine kombinierte JTAG- und SWD-Schnittstelle, die es dir ermöglicht, entweder eine SWD- oder JTAG-Sonde an das Ziel anzuschließen.

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
