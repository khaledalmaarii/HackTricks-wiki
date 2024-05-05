# iButton

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Inleiding

iButton is 'n generiese naam vir 'n elektroniese identifikasiesleutel verpak in 'n **muntvormige metaalhouer**. Dit word ook genoem **Dallas Touch** Memory of kontakgeheue. Alhoewel dit dikwels verkeerdelik as 'n "magnetiese" sleutel verwys word, is daar **niks magneties** daarin nie. In werklikheid is 'n volwaardige **mikroskyfie** wat op 'n digitale protokol werk, binne-in weggesteek.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### Wat is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Gewoonlik impliseer iButton die fisiese vorm van die sleutel en leser - 'n ronde munt met twee kontakte. Vir die raam wat dit omring, is daar baie variasies van die mees algemene plastiekhouer met 'n gat tot ringe, hangers, ens.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Wanneer die sleutel die leser bereik, kom die **kontakte in aanraking** en word die sleutel van krag voorsien om sy ID te **oorstuur**. Soms word die sleutel **nie dadelik gelees** nie omdat die **kontak PSD van 'n interkom groter** is as wat dit behoort te wees. As dit die geval is, sal jy die sleutel teen een van die mure van die leser moet druk.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire-protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas-sleutels ruil data uit deur die 1-wire-protokol te gebruik. Met slegs een kontak vir data-oordrag (!!) in beide rigtings, van meester na slaaf en andersom. Die 1-wire-protokol werk volgens die Meester-Slaaf-model. In hierdie topologie inisieer die Meester altyd kommunikasie en volg die Slaaf sy instruksies.

Wanneer die sleutel (Slaaf) die interkom (Meester) kontak, skakel die skyfie binne-in die sleutel aan, van krag voorsien deur die interkom, en word die sleutel geïnisialiseer. Daarna versoek die interkom die sleutel-ID. Hierna sal ons na hierdie proses in meer detail kyk.

Flipper kan beide in Meester- en Slaaf-modus werk. In die sleutelleesmodus tree Flipper op as 'n leser, dit werk dus as 'n Meester. En in die sleutel-emulasie-modus, doen die flipper asof dit 'n sleutel is, dit is in die Slaaf-modus.

### Dallas, Cyfral & Metakom-sleutels

Vir inligting oor hoe hierdie sleutels werk, kyk na die bladsy [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Aanvalle

iButtons kan aangeval word met Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Verwysings

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)
