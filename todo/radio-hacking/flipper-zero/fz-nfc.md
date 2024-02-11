# FZ - NFC

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Inleiding <a href="#9wrzi" id="9wrzi"></a>

Vir inligting oor RFID en NFC, kyk na die volgende bladsy:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Ondersteunde NFC-kaarte <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Afgesien van NFC-kaarte ondersteun Flipper Zero **ander tipes hoëfrekwensie-kaarte** soos verskeie **Mifare** Classic en Ultralight en **NTAG**.
{% endhint %}

Nuwe tipes NFC-kaarte sal bygevoeg word tot die lys van ondersteunde kaarte. Flipper Zero ondersteun die volgende **NFC-kaarttipe A** (ISO 14443A):

* ﻿**Bankkaarte (EMV)** - lees slegs UID, SAK en ATQA sonder om dit te stoor.
* ﻿**Onbekende kaarte** - lees (UID, SAK, ATQA) en boots 'n UID na.

Vir **NFC-kaarttipe B, tipe F en tipe V**, kan Flipper Zero 'n UID lees sonder om dit te stoor.

### NFC-kaarte tipe A <a href="#uvusf" id="uvusf"></a>

#### Bankkaart (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero kan slegs 'n UID, SAK, ATQA en gestoorde data op bankkaarte lees **sonder om dit te stoor**.

BankkaartleesskermVir bankkaarte kan Flipper Zero slegs data lees **sonder om dit te stoor en na te boots**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Onbekende kaarte <a href="#37eo8" id="37eo8"></a>

Wanneer Flipper Zero **nie in staat is om die tipe NFC-kaart te bepaal nie**, kan slegs 'n **UID, SAK en ATQA** gelees en gestoor word.

Onbekende kaartleesskermVir onbekende NFC-kaarte kan Flipper Zero slegs 'n UID boots.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC-kaarte tipe B, F en V <a href="#wyg51" id="wyg51"></a>

Vir **NFC-kaarte tipe B, F en V**, kan Flipper Zero slegs 'n UID lees en vertoon sonder om dit te stoor.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Aksies

Vir 'n inleiding oor NFC [**lees hierdie bladsy**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lees

Flipper Zero kan **NFC-kaarte lees**, maar dit **verstaan nie al die protokolle** wat gebaseer is op ISO 14443 nie. Tog, aangesien **UID 'n lae-vlak eienskap is**, kan jy jouself in 'n situasie bevind waar **UID reeds gelees is, maar die hoë-vlak data-oordragprotokol steeds onbekend is**. Jy kan UID lees, boots en handmatig invoer met behulp van Flipper vir die primitiewe lesers wat UID gebruik vir outorisasie.

#### Die UID lees vs. Die data binne lees <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

In Flipper kan die lees van 13.56 MHz-etikette verdeel word in twee dele:

* **Laevlaklees** - lees slegs die UID, SAK en ATQA. Flipper probeer die hoëvlakprotokol raai op grond van hierdie data wat van die kaart gelees is. Jy kan nie 100% seker wees hiervan nie, aangesien dit net 'n aanname is gebaseer op sekere faktore.
* **Hoëvlaklees** - lees die data uit die kaart se geheue deur 'n spesifieke hoëvlakprotokol te gebruik. Dit sou wees om die data op 'n Mifare Ultralight te lees, die sektore van 'n Mifare Classic te lees, of die eienskappe van die kaart van PayPass/Apple Pay te lees.

### Spesifieke lees

In die geval dat Flipper Zero nie in staat is om die tipe kaart vanuit die laevlakdata te vind nie, kan jy in `Ekstra Aksies` kies vir `Spesifieke Kaarttipe Lees` en **handmatig** **aandui watter tipe kaart jy wil lees**.
#### EMV Bankkaarte (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Afgesien van bloot die UID te lees, kan jy baie meer data uit 'n bankkaart onttrek. Dit is moontlik om die **volledige kaartnommer** (die 16 syfers aan die voorkant van die kaart), **geldigheidsdatum**, en in sommige gevalle selfs die **eienaar se naam** saam met 'n lys van die **mees onlangse transaksies** te kry.\
Tog **kan jy nie die CVV op hierdie manier lees** (die 3 syfers aan die agterkant van die kaart nie). Bankkaarte is ook beskerm teen herhaalaanvalle, so dit sal nie werk om dit met Flipper te kopieer en dan te probeer emuleer om vir iets te betaal nie.

## Verwysings

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
