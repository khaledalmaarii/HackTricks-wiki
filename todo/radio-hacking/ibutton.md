# iButton

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Einführung

iButton ist ein generischer Name für einen elektronischen Identifikationsschlüssel, der in einem **münzförmigen Metallbehälter** verpackt ist. Es wird auch als **Dallas Touch** Memory oder Kontakt-Speicher bezeichnet. Obwohl es oft fälschlicherweise als "magnetischer" Schlüssel bezeichnet wird, ist darin **nichts Magnetisches** enthalten. Tatsächlich verbirgt sich darin ein vollwertiger **Mikrochip**, der nach einem digitalen Protokoll arbeitet.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### Was ist iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Normalerweise bezieht sich iButton auf die physische Form des Schlüssels und des Lesegeräts - eine runde Münze mit zwei Kontakten. Für den Rahmen, der es umgibt, gibt es viele Variationen, von einem häufigen Kunststoffhalter mit Loch bis hin zu Ringen, Anhängern usw.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Wenn der Schlüssel den Leser erreicht, kommen die **Kontakte in Berührung** und der Schlüssel wird mit Strom versorgt, um seine ID zu **übertragen**. Manchmal wird der Schlüssel **nicht sofort gelesen**, weil die **Kontakt-PSD eines Gegensprechsystems größer** ist als er sein sollte. In diesem Fall müssen Sie den Schlüssel gegen eine der Wände des Lesegeräts drücken.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-Protokoll** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas-Schlüssel tauschen Daten über das 1-Wire-Protokoll aus. Mit nur einem Kontakt für den Datentransfer (!!) in beide Richtungen, vom Master zum Slave und umgekehrt. Das 1-Wire-Protokoll funktioniert nach dem Master-Slave-Modell. In dieser Topologie initiiert der Master immer die Kommunikation und der Slave folgt seinen Anweisungen.

Wenn der Schlüssel (Slave) den Gegensprechanlage (Master) berührt, schaltet sich der Chip im Schlüssel ein, der vom Gegensprechanlage mit Strom versorgt wird, und der Schlüssel wird initialisiert. Anschließend fordert der Gegensprechanlage die Schlüssel-ID an. Als nächstes werden wir diesen Prozess genauer betrachten.

Flipper kann sowohl im Master- als auch im Slave-Modus arbeiten. Im Schlüssellesemodus fungiert Flipper als Lesegerät, das heißt, es funktioniert als Master. Und im Schlüsselemulationsmodus gibt sich der Flipper als Schlüssel aus, er befindet sich im Slave-Modus.

### Dallas-, Cyfral- & Metakom-Schlüssel

Für Informationen darüber, wie diese Schlüssel funktionieren, überprüfen Sie die Seite [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Angriffe

iButtons können mit Flipper Zero angegriffen werden:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referenzen

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)
