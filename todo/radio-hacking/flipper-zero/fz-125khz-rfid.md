# FZ - 125kHz RFID

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Inleiding

Vir meer inligting oor hoe 125kHz-etikette werk, sien:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Aksies

Vir meer inligting oor hierdie tipes etikette [**lees hierdie inleiding**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lees

Probeer om die kaartinligting **te lees**. Dan kan dit **nageboots** word.

{% hint style="warning" %}
Let daarop dat sommige interkomme probeer om hulself teen sleutelverdubbeling te beskerm deur 'n skryfopdrag voor die leesopdrag te stuur. As die skryfopdrag slaag, word daardie etiket as vals beskou. Wanneer Flipper RFID naboots, is daar geen manier vir die leser om dit van die oorspronklike te onderskei nie, sodat sulke probleme nie voorkom nie.
{% endhint %}

### Voeg Handmatig By

Jy kan **vals kaarte in Flipper Zero skep wat die data** wat jy handmatig aandui, en dit dan naboots.

#### ID's op kaarte

Soms, wanneer jy 'n kaart kry, sal jy die ID (of 'n deel daarvan) daarvan sien geskryf op die kaart.

* **EM Marin**

Byvoorbeeld, op hierdie EM-Marin-kaart is dit moontlik om **die laaste 3 van 5 bytes duidelik te lees**.\
Die ander 2 kan gekraak word as jy hulle nie van die kaart kan lees nie.

<figure><img src="../../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

* **HID**

Dieselfde gebeur op hierdie HID-kaart waar slegs 2 uit 3 bytes op die kaart gedruk kan word

<figure><img src="../../../.gitbook/assets/image (1011).png" alt=""><figcaption></figcaption></figure>

### Naboots/Skryf

Nadat 'n kaart **gekopieer** of die ID **handmatig ingevoer** is, is dit moontlik om dit met Flipper Zero **na te boots** of dit in 'n werklike kaart **te skryf**.

## Verwysings

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
