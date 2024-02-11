# iButton

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

## Inleiding

iButton is 'n generiese naam vir 'n elektroniese identifikasiesleutel wat verpak is in 'n **muntvormige metaalhouer**. Dit word ook genoem **Dallas Touch** Memory of kontakgeheue. Alhoewel dit dikwels verkeerdelik as 'n "magnetiese" sleutel verwys word, is daar **niks magneties** daarin nie. In werklikheid is daar 'n volwaardige **mikroskyfie** wat op 'n digitale protokol werk, daarin weggesteek.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### Wat is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Gewoonlik impliseer iButton die fisiese vorm van die sleutel en leser - 'n ronde munt met twee kontakte. Vir die raamwerk wat dit omring, is daar baie variasies, van die mees algemene plastiese houer met 'n gat tot ringe, hangertjies, ens.

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

Wanneer die sleutel die leser bereik, kom die **kontakte in aanraking** en word die sleutel van krag voorsien om sy ID **oor te dra**. Soms word die sleutel **nie dadelik gelees** nie omdat die **kontak-PSD van 'n interkom groter** is as wat dit behoort te wees. So kan die buitegrense van die sleutel en die leser nie raak nie. As dit die geval is, sal jy die sleutel teen een van die mure van die leser moet druk.

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-protokol** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Dallas-sleutels ruil data uit deur die 1-wire-protokol te gebruik. Met slegs een kontak vir data-oordrag (!!) in beide rigtings, van meester na slaaf en andersom. Die 1-wire-protokol werk volgens die Meester-Slaaf-model. In hierdie topologie inisieer die Meester altyd kommunikasie en volg die Slaaf sy instruksies.

Wanneer die sleutel (Slaaf) die interkom (Meester) kontak, skakel die skyfie binne die sleutel aan, aangedryf deur die interkom, en word die sleutel geïnisialiseer. Daarna vra die interkom die sleutel-ID. Hierna sal ons hierdie proses in meer detail bespreek.

Flipper kan in beide Meester- en Slaafmodusse werk. In die sleutelleesmodus tree Flipper op as 'n leser, dit wil sê dit werk as 'n Meester. En in die sleutel-emulasie-modus doen die flipper asof dit 'n sleutel is, dit is in die Slaafmodus.

### Dallas-, Cyfral- en Metakom-sleutels

Vir inligting oor hoe hierdie sleutels werk, kyk na die bladsy [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Aanvalle

iButtons kan aangeval word met Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Verwysings

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
