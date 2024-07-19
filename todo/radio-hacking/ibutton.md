# iButton

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

## Intro

iButton ist ein allgemeiner Name für einen elektronischen Identifizierungsschlüssel, der in einem **münzförmigen Metallgehäuse** verpackt ist. Er wird auch als **Dallas Touch** Memory oder Kontakt-Speicher bezeichnet. Obwohl er oft fälschlicherweise als „magnetischer“ Schlüssel bezeichnet wird, ist **nichts magnetisch** daran. Tatsächlich verbirgt sich darin ein vollwertiger **Mikrochip**, der auf einem digitalen Protokoll basiert.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### Was ist iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Normalerweise bezieht sich iButton auf die physische Form des Schlüssels und Lesegeräts - eine runde Münze mit zwei Kontakten. Für den Rahmen, der ihn umgibt, gibt es viele Variationen, von der häufigsten Kunststoffhalterung mit einem Loch bis hin zu Ringen, Anhängern usw.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Wenn der Schlüssel das Lesegerät erreicht, **kommen die Kontakte in Berührung** und der Schlüssel wird mit Strom versorgt, um seine ID zu **übertragen**. Manchmal wird der Schlüssel **nicht sofort gelesen**, weil der **Kontakt-PSD eines Gegensprechers größer** ist, als er sein sollte. Daher konnten die äußeren Konturen des Schlüssels und des Lesegeräts nicht in Kontakt treten. In diesem Fall musst du den Schlüssel über eine der Wände des Lesegeräts drücken.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-Protokoll** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas-Schlüssel tauschen Daten über das 1-Wire-Protokoll aus. Mit nur einem Kontakt für die Datenübertragung (!!) in beide Richtungen, vom Master zum Slave und umgekehrt. Das 1-Wire-Protokoll funktioniert nach dem Master-Slave-Modell. In dieser Topologie initiiert der Master immer die Kommunikation und der Slave folgt seinen Anweisungen.

Wenn der Schlüssel (Slave) den Gegensprecher (Master) kontaktiert, wird der Chip im Schlüssel aktiviert, der vom Gegensprecher mit Strom versorgt wird, und der Schlüssel wird initialisiert. Danach fordert der Gegensprecher die Schlüssel-ID an. Im Folgenden werden wir diesen Prozess genauer betrachten.

Flipper kann sowohl im Master- als auch im Slave-Modus arbeiten. Im Schlüssel-Lesemodus fungiert Flipper als Leser, das heißt, er arbeitet als Master. Und im Schlüssel-Emulationsmodus gibt sich der Flipper als Schlüssel aus, er befindet sich im Slave-Modus.

### Dallas-, Cyfral- & Metakom-Schlüssel

Für Informationen darüber, wie diese Schlüssel funktionieren, siehe die Seite [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Angriffe

iButtons können mit Flipper Zero angegriffen werden:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referenzen

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

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
