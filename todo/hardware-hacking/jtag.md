# JTAG

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys senden.

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)ist ein Tool, das mit einem Raspberry PI oder einem Arduino verwendet werden kann, um JTAG-Pins von einem unbekannten Chip zu finden.\
Im **Arduino** verbinden Sie die **Pins von 2 bis 11 mit 10 Pins, die möglicherweise zu einem JTAG gehören**. Laden Sie das Programm auf den Arduino und es wird versuchen, alle Pins zu bruteforcen, um herauszufinden, ob ein Pin zu JTAG gehört und welcher es ist.\
Im **Raspberry PI** können Sie nur **Pins von 1 bis 6** verwenden (6 Pins, daher werden Sie langsamer jeden potenziellen JTAG-Pin testen).

### Arduino

Im Arduino, nachdem Sie die Kabel verbunden haben (Pin 2 bis 11 mit JTAG-Pins und Arduino GND mit dem Baseboard GND), **laden Sie das JTAGenum-Programm auf den Arduino** und im Seriellen Monitor senden Sie ein **`h`** (Befehl für Hilfe) und Sie sollten die Hilfe sehen:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

Konfigurieren Sie **"Kein Zeilenende" und 115200 Baud**.\
Senden Sie den Befehl s, um mit dem Scannen zu beginnen:

![](<../../.gitbook/assets/image (774).png>)

Wenn Sie einen JTAG kontaktieren, finden Sie eine oder mehrere **Zeilen, die mit FOUND! beginnen**, die die Pins des JTAG anzeigen.
