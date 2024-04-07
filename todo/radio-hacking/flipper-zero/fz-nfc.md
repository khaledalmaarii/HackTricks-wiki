# FZ - NFC

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikionyeshwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Utangulizi <a href="#id-9wrzi" id="id-9wrzi"></a>

Kwa habari kuhusu RFID na NFC angalia ukurasa ufuatao:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Kadi za NFC Zilizoungwa Mkono <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Isipokuwa kadi za NFC, Flipper Zero inasaidia **aina nyingine za kadi za High-frequency** kama vile kadhaa za **Mifare** Classic na Ultralight na **NTAG**.
{% endhint %}

Aina mpya za kadi za NFC zitaongezwa kwenye orodha ya kadi zilizoungwa mkono. Flipper Zero inasaidia **aina zifuatazo za kadi za NFC A** (ISO 14443A):

* **Kadi za benki (EMV)** — kusoma tu UID, SAK, na ATQA bila kuokoa.
* **Kadi zisizojulikana** — kusoma (UID, SAK, ATQA) na kujifanya kuwa UID.

Kwa **aina za kadi za NFC B, F, na V**, Flipper Zero inaweza kusoma UID bila kuokoa.

### Aina za Kadi za NFC A <a href="#uvusf" id="uvusf"></a>

#### Kadi ya benki (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero inaweza kusoma tu UID, SAK, ATQA, na data iliyohifadhiwa kwenye kadi za benki **bila kuokoa**.

Skrini ya kusoma kadi ya benkiKwa kadi za benki, Flipper Zero inaweza tu kusoma data **bila kuokoa na kujifanya kuwa**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Kadi zisizojulikana <a href="#id-37eo8" id="id-37eo8"></a>

Wakati Flipper Zero inashindwa **kutambua aina ya kadi ya NFC**, basi tu **UID, SAK, na ATQA** zinaweza **kusomwa na kuokolewa**.

Skrini ya kusoma kadi isiyojulikanaKwa kadi za NFC zisizojulikana, Flipper Zero inaweza kujifanya kuwa UID tu.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Aina za Kadi za NFC B, F, na V <a href="#wyg51" id="wyg51"></a>

Kwa **aina za kadi za NFC B, F, na V**, Flipper Zero inaweza tu **kusoma na kuonyesha UID** bila kuokoa.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Vitendo

Kwa utangulizi kuhusu NFC [**soma ukurasa huu**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Kusoma

Flipper Zero inaweza **kusoma kadi za NFC**, hata hivyo, **haisitawi katika itifaki zote** zinazotegemea ISO 14443. Walakini, tangu **UID ni sifa ya kiwango cha chini**, unaweza kukuta mwenyewe katika hali ambapo **UID tayari umesomwa, lakini itifaki ya uhamisho wa data ya kiwango cha juu bado haijulikani**. Unaweza kusoma, kujifanya na kuingiza UID kwa kutumia Flipper kwa wasomaji wa kimsingi wanaotumia UID kwa idhini.

#### Kusoma UID DHIDI ya Kusoma Data Ndani <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (214).png" alt=""><figcaption></figcaption></figure>

Katika Flipper, kusoma vitambulisho vya 13.56 MHz kunaweza kugawanywa katika sehemu mbili:

* **Kusoma kiwango cha chini** — inasoma tu UID, SAK, na ATQA. Flipper inajaribu kudhani itifaki ya kiwango cha juu kulingana na data hii iliyosomwa kutoka kwenye kadi. Huwezi kuwa na uhakika wa asilimia 100 na hii, kwani ni dhana tu kulingana na sababu fulani.
* **Kusoma kiwango cha juu** — inasoma data kutoka kwenye kumbukumbu ya kadi kwa kutumia itifaki maalum ya kiwango cha juu. Hiyo itakuwa kusoma data kwenye Mifare Ultralight, kusoma sehemu kutoka kwa Mifare Classic, au kusoma sifa za kadi kutoka PayPass/Apple Pay.

### Kusoma Maalum

Kwa hali ambapo Flipper Zero hawezi kutambua aina ya kadi kutoka kwa data ya kiwango cha chini, katika `Vitendo Vingine` unaweza kuchagua `Soma Aina Maalum ya Kadi` na **kutaja kwa mkono** **aina ya kadi ungependa kusoma**.

#### Kadi za Benki za EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Isipokuwa tu kusoma UID, unaweza kutoa data nyingi zaidi kutoka kwa kadi ya benki. Inawezekana **kupata nambari kamili ya kadi** (nambari 16 mbele ya kadi), **tarehe ya halali**, na kwa baadhi ya visa hata **jina la mmiliki** pamoja na orodha ya **shughuli za hivi karibuni**.\
Walakini, **hauwezi kusoma CVV kwa njia hii** (nambari 3 nyuma ya kadi). Pia **kadi za benki zinalindwa dhidi ya mashambulizi ya kurudia**, hivyo kuiga na kujaribu kujifanya kuilipa kitu na Flipper haitafanikiwa.
## Marejeo

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikionyeshwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
