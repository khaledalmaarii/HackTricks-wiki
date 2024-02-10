<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


#

# JTAG

JTAG ermöglicht einen Boundary-Scan. Der Boundary-Scan analysiert bestimmte Schaltkreise, einschließlich eingebetteter Boundary-Scan-Zellen und Register für jeden Pin.

Der JTAG-Standard definiert **spezifische Befehle für die Durchführung von Boundary-Scans**, einschließlich der folgenden:

* **BYPASS** ermöglicht es Ihnen, einen bestimmten Chip zu testen, ohne die Überlastung durch andere Chips zu durchlaufen.
* **SAMPLE/PRELOAD** nimmt eine Probe der Daten auf, die das Gerät beim normalen Betrieb verlassen und eingehen.
* **EXTEST** setzt und liest Pin-Zustände.

Es kann auch andere Befehle unterstützen, wie zum Beispiel:

* **IDCODE** zur Identifizierung eines Geräts
* **INTEST** für den internen Test des Geräts

Sie könnten auf diese Anweisungen stoßen, wenn Sie ein Tool wie den JTAGulator verwenden.

## Der Test Access Port

Boundary-Scans umfassen Tests des vieradrigen **Test Access Port (TAP)**, einem allgemeinen Port, der den in eine Komponente eingebauten **JTAG-Test-Support** ermöglicht. TAP verwendet die folgenden fünf Signale:

* Test-Takt-Eingang (**TCK**) Der TCK ist der **Takt**, der definiert, wie oft der TAP-Controller eine einzelne Aktion ausführt (mit anderen Worten, zum nächsten Zustand in der Zustandsmaschine wechselt).
* Test-Modus-Auswahl (**TMS**) Eingang TMS steuert die **endliche Zustandsmaschine**. Bei jedem Taktimpuls überprüft der JTAG-TAP-Controller des Geräts die Spannung am TMS-Pin. Wenn die Spannung unter einem bestimmten Schwellenwert liegt, wird das Signal als niedrig betrachtet und als 0 interpretiert, während das Signal als hoch betrachtet und als 1 interpretiert wird, wenn die Spannung über einem bestimmten Schwellenwert liegt.
* Testdaten-Eingang (**TDI**) TDI ist der Pin, der **Daten über die Scan-Zellen in den Chip sendet**. Jeder Hersteller ist dafür verantwortlich, das Kommunikationsprotokoll über diesen Pin zu definieren, da JTAG dies nicht definiert.
* Testdaten-Ausgang (**TDO**) TDO ist der Pin, der **Daten aus dem Chip sendet**.
* Test-Reset (**TRST**) Eingang Das optionale TRST setzt die endliche Zustandsmaschine **auf einen bekannten guten Zustand** zurück. Alternativ, wenn das TMS für fünf aufeinanderfolgende Taktzyklen auf 1 gehalten wird, wird ein Reset ausgelöst, genauso wie es der TRST-Pin tun würde, weshalb TRST optional ist.

Manchmal finden Sie diese Pins möglicherweise auf der Leiterplatte markiert. In anderen Fällen müssen Sie sie möglicherweise **finden**.

## Identifizierung von JTAG-Pins

Der schnellste, aber teuerste Weg, JTAG-Ports zu erkennen, besteht darin, den **JTAGulator** zu verwenden, ein speziell für diesen Zweck entwickeltes Gerät (obwohl es **auch UART-Pinouts erkennen** kann).

Es verfügt über **24 Kanäle**, die Sie mit den Pins der Boards verbinden können. Anschließend führt es einen **BF-Angriff** auf alle möglichen Kombinationen aus, indem es **IDCODE**- und **BYPASS**-Boundary-Scan-Befehle sendet. Wenn es eine Antwort erhält, zeigt es den Kanal an, der jedem JTAG-Signal entspricht.

Ein günstigerer, aber viel langsamerer Weg, JTAG-Pinouts zu identifizieren, besteht darin, das [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) auf einem Arduino-kompatiblen Mikrocontroller zu laden.

Mit **JTAGenum** würden Sie zuerst die Pins des Prüfgeräts definieren, die Sie für die Aufzählung verwenden werden. Sie müssten das Pinout-Diagramm des Geräts konsultieren und dann diese Pins mit den Testpunkten auf Ihrem Zielgerät verbinden.

Ein **dritter Weg**, um JTAG-Pins zu identifizieren, besteht darin, die Leiterplatte auf eine der Pinbelegungen zu untersuchen. In einigen Fällen können Leiterplatten bequemerweise die **Tag-Connect-Schnittstelle** bereitstellen, was ein deutlicher Hinweis darauf ist, dass die Platine einen JTAG-Anschluss hat. Sie können sehen, wie diese Schnittstelle unter [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/) aussieht. Darüber hinaus können die **Datenblätter der Chipsätze auf der Leiterplatte** Pinbelegungsdiagramme enthalten, die auf JTAG-Schnittstellen hinweisen.

# SDW

SWD ist ein ARM-spezifisches Protokoll, das für das Debugging entwickelt wurde.

Die SWD-Schnittstelle erfordert **zwei Pins**: ein bidirektionales **SWDIO**-Signal, das dem **TDI- und TDO-Pin von JTAG** entspricht, und einen Takt, **SWCLK**, der dem **TCK von JTAG** entspricht. Viele Geräte unterstützen den **Serial Wire oder JTAG Debug Port (SWJ-DP)**, eine kombinierte JTAG- und SWD-Schnittstelle, mit der Sie entweder eine SWD- oder JTAG-Sonde mit dem Ziel verbinden können.


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
