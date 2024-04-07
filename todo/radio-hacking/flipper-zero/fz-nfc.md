# FZ - NFC

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekerheidsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Inleiding <a href="#id-9wrzi" id="id-9wrzi"></a>

Vir inligting oor RFID en NFC, kyk na die volgende bladsy:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Ondersteunde NFC-kaarte <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Afgesien van NFC-kaarte ondersteun Flipper Zero **ander tipe Hoëfrekwensie-kaarte** soos verskeie **Mifare** Classic en Ultralight en **NTAG**.
{% endhint %}

Nuwe tipes NFC-kaarte sal by die lys van ondersteunde kaarte gevoeg word. Flipper Zero ondersteun die volgende **NFC-kaarte tipe A** (ISO 14443A):

* ﻿**Bankkaarte (EMV)** — lees slegs UID, SAK, en ATQA sonder om dit te stoor.
* ﻿**Onbekende kaarte** — lees (UID, SAK, ATQA) en boots 'n UID na.

Vir **NFC-kaarte tipe B, tipe F, en tipe V**, kan Flipper Zero 'n UID lees sonder om dit te stoor.

### NFC-kaarte tipe A <a href="#uvusf" id="uvusf"></a>

#### Bankkaart (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero kan slegs 'n UID, SAK, ATQA, en gestoorde data op bankkaarte lees **sonder om dit te stoor**.

Bankkaart lees-skermVir bankkaarte kan Flipper Zero slegs data lees **sonder om dit te stoor en na te boots**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Onbekende kaarte <a href="#id-37eo8" id="id-37eo8"></a>

Wanneer Flipper Zero **nie in staat is om die tipe NFC-kaart te bepaal nie**, kan slegs 'n **UID, SAK, en ATQA** gelees en gestoor word.

Onbekende kaart lees-skermVir onbekende NFC-kaarte kan Flipper Zero slegs 'n UID na boots.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC-kaarte tipes B, F, en V <a href="#wyg51" id="wyg51"></a>

Vir **NFC-kaarte tipes B, F, en V**, kan Flipper Zero slegs 'n UID **lees en vertoon** sonder om dit te stoor.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Aksies

Vir 'n inleiding oor NFC [**lees hierdie bladsy**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lees

Flipper Zero kan **NFC-kaarte lees**, maar dit **verstaan nie al die protokolle** wat gebaseer is op ISO 14443 nie. Aangesien **UID 'n lae-vlak eienskap is**, kan jy jouself in 'n situasie bevind waar die **UID reeds gelees is, maar die hoë-vlak data-oordragprotokol steeds onbekend is**. Jy kan UID lees, na boots en handmatig UID invoer met Flipper vir die primitiewe lesers wat UID vir magtiging gebruik.

#### Die UID lees VS Die Data Binne Lees <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (214).png" alt=""><figcaption></figcaption></figure>

In Flipper kan die lees van 13.56 MHz-etikette in twee dele verdeel word:

* **Laevlak lees** — lees slegs die UID, SAK, en ATQA. Flipper probeer die hoë-vlak protokol raai gebaseer op hierdie data wat van die kaart gelees is. Jy kan nie 100% seker wees hiermee nie, aangesien dit net 'n aanname is gebaseer op sekere faktore.
* **Hoë-vlak lees** — lees die data van die kaart se geheue deur 'n spesifieke hoë-vlak protokol te gebruik. Dit sou wees om die data op 'n Mifare Ultralight te lees, die sektore van 'n Mifare Classic te lees, of die kaart se eienskappe van PayPass/Apple Pay te lees.

### Spesifiek Lees

In die geval Flipper Zero nie in staat is om die tipe kaart vanuit die lae-vlak data te vind nie, kan jy in `Ekstra Aksies` kies vir `Spesifieke Kaarttipe Lees` en **handmatig** **aandui watter tipe kaart jy wil lees**.

#### EMV Bankkaarte (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Afgesien van bloot die UID te lees, kan jy baie meer data uit 'n bankkaart onttrek. Dit is moontlik om die **volledige kaartnommer** (die 16 syfers op die voorkant van die kaart), **geldigheidsdatum**, en in sommige gevalle selfs die **eienaar se naam** saam met 'n lys van die **mees onlangse transaksies** te kry.\
Tog **kan jy nie die CVV op hierdie manier lees nie** (die 3 syfers op die agterkant van die kaart). Ook **word bankkaarte beskerm teen herhaalaanvalle**, so om dit met Flipper te kopieer en dan te probeer na boots om vir iets te betaal, sal nie werk nie.
## Verwysings

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>
