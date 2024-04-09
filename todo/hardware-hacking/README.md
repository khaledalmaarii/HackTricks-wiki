# Hardware Hacking

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## JTAG

JTAG ermöglicht eine Boundary-Scan-Durchführung. Der Boundary-Scan analysiert bestimmte Schaltkreise, einschließlich eingebetteter Boundary-Scan-Zellen und Register für jeden Pin.

Der JTAG-Standard definiert **spezifische Befehle für die Durchführung von Boundary-Scans**, darunter:

* **BYPASS** ermöglicht es Ihnen, einen bestimmten Chip zu testen, ohne den Overhead durch andere Chips zu durchlaufen.
* **SAMPLE/PRELOAD** nimmt eine Stichprobe der Daten auf, die das Gerät beim normalen Betrieb eingeben und verlassen.
* **EXTEST** setzt und liest Pin-Zustände.

Es kann auch andere Befehle unterstützen, wie:

* **IDCODE** zur Identifizierung eines Geräts
* **INTEST** für den internen Test des Geräts

Sie könnten auf diese Anweisungen stoßen, wenn Sie ein Tool wie den JTAGulator verwenden.

### Der Testzugriffsport

Boundary-Scans umfassen Tests des vieradrigen **Testzugriffsports (TAP)**, einem universellen Port, der Zugriff auf die in ein Bauteil integrierten **JTAG-Testunterstützungsfunktionen** bietet. TAP verwendet die folgenden fünf Signale:

* Testtakt-Eingang (**TCK**) Der TCK ist die **Taktfrequenz**, die definiert, wie oft der TAP-Controller eine einzelne Aktion ausführt (sprich, zum nächsten Zustand in der Zustandsmaschine springt).
* Testmodusauswahl (**TMS**) Eingang TMS steuert die **endliche Zustandsmaschine**. Bei jedem Takt des Takts überprüft der JTAG-TAP-Controller des Geräts die Spannung am TMS-Pin. Wenn die Spannung unter einem bestimmten Schwellenwert liegt, wird das Signal als niedrig betrachtet und als 0 interpretiert, während es als hoch und als 1 interpretiert wird, wenn die Spannung über einem bestimmten Schwellenwert liegt.
* Testdateneingang (**TDI**) TDI ist der Pin, der **Daten über die Scan-Zellen in den Chip sendet**. Jeder Hersteller ist dafür verantwortlich, das Kommunikationsprotokoll über diesen Pin zu definieren, da JTAG dies nicht vorgibt.
* Testdatenausgang (**TDO**) TDO ist der Pin, der **Daten aus dem Chip sendet**.
* Testreset (**TRST**) Eingang Der optionale TRST setzt die endliche Zustandsmaschine **auf einen bekannten guten Zustand** zurück. Alternativ, wenn das TMS für fünf aufeinanderfolgende Taktzyklen auf 1 gehalten wird, ruft es einen Reset auf, genauso wie der TRST-Pin, weshalb TRST optional ist.

Manchmal werden Sie diese Pins auf der Leiterplatte markiert finden. In anderen Fällen müssen Sie sie **finden**.

### Identifizierung von JTAG-Pins

Der schnellste, aber teuerste Weg, JTAG-Ports zu erkennen, ist die Verwendung des **JTAGulators**, eines speziell für diesen Zweck erstellten Geräts (obwohl es **auch UART-Pinbelegungen erkennen** kann).

Es verfügt über **24 Kanäle**, die Sie mit den Pins der Boards verbinden können. Anschließend führt es einen **BF-Angriff** aller möglichen Kombinationen durch, indem es **IDCODE**- und **BYPASS**-Boundary-Scan-Befehle sendet. Wenn es eine Antwort erhält, zeigt es den Kanal für jedes JTAG-Signal an.

Ein kostengünstigerer, aber viel langsamerer Weg, JTAG-Pinbelegungen zu identifizieren, besteht darin, das [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) auf einem Arduino-kompatiblen Mikrocontroller zu laden.

Mit **JTAGenum** würden Sie zunächst die Pins des Prüfgeräts definieren, die Sie für die Auflistung verwenden werden. Sie müssten das Pinout-Diagramm des Geräts konsultieren und dann diese Pins mit den Testpunkten auf Ihrem Zielgerät verbinden.

Ein **dritter Weg**, um JTAG-Pins zu identifizieren, besteht darin, die Leiterplatte auf eine der Pinbelegungen zu überprüfen. In einigen Fällen könnten Leiterplatten bequemerweise die **Tag-Connect-Schnittstelle** bereitstellen, was ein deutlicher Hinweis darauf ist, dass die Platine auch einen JTAG-Anschluss hat. Sie können sehen, wie diese Schnittstelle aussieht unter [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Darüber hinaus könnten die **Datenblätter der Chipsätze auf der Leiterplatte** Pinbelegungsdiagramme enthalten, die auf JTAG-Schnittstellen hinweisen.

## SDW

SWD ist ein ARM-spezifisches Protokoll, das für das Debuggen entwickelt wurde.

Die SWD-Schnittstelle erfordert **zwei Pins**: ein bidirektionales **SWDIO**-Signal, das dem JTAG-Äquivalent von **TDI und TDO-Pins** entspricht, und einen Takt, **SWCLK**, der dem **TCK** in JTAG entspricht. Viele Geräte unterstützen den **Serial Wire oder JTAG Debug Port (SWJ-DP)**, eine kombinierte JTAG- und SWD-Schnittstelle, die es ermöglicht, entweder eine SWD- oder JTAG-Sonde mit dem Ziel zu verbinden.

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
