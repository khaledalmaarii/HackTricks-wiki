# iButton

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Einführung

iButton ist ein generischer Name für einen elektronischen Identifikationsschlüssel, der in einem **münzförmigen Metallbehälter** verpackt ist. Er wird auch als **Dallas Touch Memory** oder Kontaktspeicher bezeichnet. Obwohl er oft fälschlicherweise als "magnetischer" Schlüssel bezeichnet wird, ist darin **nichts Magnetisches** enthalten. Tatsächlich verbirgt sich darin ein vollwertiger **Mikrochip**, der nach einem digitalen Protokoll arbeitet.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### Was ist iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Normalerweise bezieht sich iButton auf die physische Form des Schlüssels und des Lesegeräts - eine runde Münze mit zwei Kontakten. Für den Rahmen, der sie umgibt, gibt es viele Variationen, von einem häufigen Kunststoffhalter mit einem Loch bis hin zu Ringen, Anhängern usw.

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

Wenn der Schlüssel den Leser erreicht, **berühren sich die Kontakte** und der Schlüssel wird mit Strom versorgt, um seine ID zu **übertragen**. Manchmal wird der Schlüssel **nicht sofort gelesen**, weil die **Kontakt-PSD eines Gegensprechanlagen größer** ist als sie sein sollte. In diesem Fall können die äußeren Konturen des Schlüssels und des Lesers sich nicht berühren. Wenn das der Fall ist, müssen Sie den Schlüssel gegen eine der Wände des Lesers drücken.

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-Protokoll** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Dallas-Schlüssel tauschen Daten mit dem 1-Wire-Protokoll aus. Es gibt nur einen Kontakt für den Datenverkehr (!!) in beide Richtungen, vom Master zum Slave und umgekehrt. Das 1-Wire-Protokoll funktioniert nach dem Master-Slave-Modell. In dieser Topologie initiiert der Master immer die Kommunikation und der Slave folgt seinen Anweisungen.

Wenn der Schlüssel (Slave) den Gegensprechanlage (Master) kontaktiert, schaltet sich der Chip im Schlüssel ein, der von der Gegensprechanlage mit Strom versorgt wird, und der Schlüssel wird initialisiert. Anschließend fordert die Gegensprechanlage die Schlüssel-ID an. Im nächsten Schritt werden wir uns diesen Prozess genauer ansehen.

Flipper kann sowohl im Master- als auch im Slave-Modus arbeiten. Im Schlüssellesemodus fungiert Flipper als Lesegerät, das heißt, es arbeitet als Master. Im Schlüsselemulationsmodus gibt sich der Flipper als Schlüssel aus und befindet sich im Slave-Modus.

### Dallas-, Cyfral- und Metakom-Schlüssel

Für Informationen darüber, wie diese Schlüssel funktionieren, besuchen Sie die Seite [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Angriffe

iButtons können mit Flipper Zero angegriffen werden:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referenzen

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
