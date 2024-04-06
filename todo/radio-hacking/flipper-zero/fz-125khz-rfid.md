# FZ - 125kHz RFID

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

## Inleiding

Vir meer inligting oor hoe 125kHz-etikette werk, kyk:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Aksies

Vir meer inligting oor hierdie tipes etikette, [**lees hierdie inleiding**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lees

Probeer om die kaartinligting **te lees**. Dan kan dit **nageboots** word.

{% hint style="warning" %}
Let daarop dat sommige interkomme probeer om hulself teen sleutelduplicering te beskerm deur 'n skryfopdrag voor die leesopdrag te stuur. As die skryf slaag, word daardie etiket as vals beskou. Wanneer Flipper RFID naboots, is daar geen manier vir die leser om dit van die oorspronklike een te onderskei nie, so sulke probleme kom nie voor nie.
{% endhint %}

### Handmatig byvoeg

Jy kan **vals kaarte in Flipper Zero skep deur die data** wat jy handmatig aandui, en dit dan naboots.

#### IDs op kaarte

Soms, wanneer jy 'n kaart kry, sal jy die ID (of 'n gedeelte daarvan) daarop geskryf vind.

* **EM Marin**

Byvoorbeeld, op hierdie EM-Marin-kaart kan jy die laaste 3 van 5 byte **duidelik lees** op die fisiese kaart.\
Die ander 2 kan gekraak word as jy dit nie van die kaart kan lees nie.

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

Dieselfde gebeur op hierdie HID-kaart waar slegs 2 van die 3 byte gedruk op die kaart gevind kan word.

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### Naboots/Skryf

Nadat 'n kaart **gekopieer** of die ID **handmatig ingevoer** is, is dit moontlik om dit met Flipper Zero **na te boots** of dit op 'n werklike kaart **te skryf**.

## Verwysings

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
