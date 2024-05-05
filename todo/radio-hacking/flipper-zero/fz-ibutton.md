# FZ - iButton

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Inleiding

Vir meer inligting oor wat 'n iButton is, kyk:

{% content-ref url="../ibutton.md" %}
[ibutton.md](../ibutton.md)
{% endcontent-ref %}

## Ontwerp

Die **blou** deel van die volgende beeld is hoe jy die werklike iButton moet **plaas sodat die Flipper dit kan lees.** Die **groen** deel is hoe jy die leser met die Flipper zero moet **aanraak om 'n iButton korrek na te boots.**

<figure><img src="../../../.gitbook/assets/image (565).png" alt=""><figcaption></figcaption></figure>

## Aksies

### Lees

In Leesmodus wag die Flipper vir die iButton sleutel om aan te raak en is in staat om enige van drie tipes sleutels te verwerk: **Dallas, Cyfral, en Metakom**. Flipper sal **self die tipe sleutel bepaal.** Die naam van die sleutelprotokol sal op die skerm bo die ID-nommer vertoon word.

### Handmatig byvoeg

Dit is moontlik om handmatig 'n iButton van die tipe: **Dallas, Cyfral, en Metakom** by te voeg.

### **Na-aap**

Dit is moontlik om gestoorde iButtons na te aap (gelees of handmatig bygevoeg).

{% hint style="info" %}
As jy nie die verwagte kontakte van die Flipper Zero die leser kan laat raak nie, kan jy **die eksterne GPIO gebruik:**
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

## Verwysings

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
