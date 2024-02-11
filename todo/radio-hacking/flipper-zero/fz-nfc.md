# FZ - NFC

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pata udhaifu unaowajali zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata masuala katika mfumo wako wa teknolojia mzima, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Utangulizi <a href="#9wrzi" id="9wrzi"></a>

Kwa habari kuhusu RFID na NFC angalia ukurasa ufuatao:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Kadi za NFC zilizoungwa mkono <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Mbali na kadi za NFC, Flipper Zero inasaidia **aina nyingine za kadi za kiwango cha juu** kama vile **Mifare** Classic na Ultralight na **NTAG** kadhaa.
{% endhint %}

Aina mpya za kadi za NFC zitaongezwa kwenye orodha ya kadi zilizoungwa mkono. Flipper Zero inasaidia aina zifuatazo za **kadi za NFC aina A** (ISO 14443A):

* ﻿**Kadi za benki (EMV)** - zinasoma tu UID, SAK, na ATQA bila kuhifadhi.
* ﻿**Kadi zisizojulikana** - zinasoma (UID, SAK, ATQA) na kudanganya UID.

Kwa **kadi za NFC aina B, aina F, na aina V**, Flipper Zero inaweza kusoma UID bila kuhifadhi.

### Kadi za NFC aina A <a href="#uvusf" id="uvusf"></a>

#### Kadi ya benki (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero inaweza kusoma tu UID, SAK, ATQA, na data iliyohifadhiwa kwenye kadi za benki **bila kuhifadhi**.

Skrini ya kusoma kadi ya benkiKwa kadi za benki, Flipper Zero inaweza tu kusoma data **bila kuhifadhi na kudanganya**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Kadi zisizojulikana <a href="#37eo8" id="37eo8"></a>

Wakati Flipper Zero **haiwezi kubainisha aina ya kadi ya NFC**, basi tu UID, SAK, na ATQA zinaweza **kusomwa na kuhifadhiwa**.

Skrini ya kusoma kadi isiyojulikanaKwa kadi za NFC zisizojulikana, Flipper Zero inaweza kudanganya tu UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Kadi za NFC aina B, F, na V <a href="#wyg51" id="wyg51"></a>

Kwa **kadi za NFC aina B, F, na V**, Flipper Zero inaweza tu **kusoma na kuonyesha UID** bila kuhifadhi.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Vitendo

Kwa utangulizi kuhusu NFC [**soma ukurasa huu**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Soma

Flipper Zero inaweza **kusoma kadi za NFC**, hata hivyo, **haisielewi itifaki zote** zinazotegemea ISO 14443. Walakini, tangu **UID ni sifa ya kiwango cha chini**, unaweza kukutana na hali ambapo **UID tayari imekusomwa, lakini itifaki ya uhamisho wa data ya kiwango cha juu bado haijulikani**. Unaweza kusoma, kudanganya, na kuingiza UID kwa kutumia Flipper kwa wasomaji wa kimsingi ambao hutumia UID kwa idhini.

#### Kusoma UID DHIDI ya Kusoma Data Ndani <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Katika Flipper, kusoma vitambulisho vya 13.56 MHz kunaweza kugawanywa katika sehemu mbili:

* **Kusoma kiwango cha chini** - inasoma tu UID, SAK, na ATQA. Flipper inajaribu kudhani itifaki ya kiwango cha juu kulingana na data hii iliyosomwa kutoka kadi. Huwezi kuwa na uhakika wa 100% na hii, kwani ni dhana tu kulingana na sababu fulani.
* **Kusoma kiwango cha juu** - inasoma data kutoka kwenye kumbukumbu ya kadi kwa kutumia itifaki maalum ya kiwango cha juu. Hiyo itakuwa kusoma data kwenye Mifare Ultralight, kusoma sekta kutoka Mifare Classic, au kusoma sifa za kadi kutoka PayPass/Apple Pay.

### Soma Maalum

Ikiwa Flipper Zero haiwezi kugundua aina ya kadi kutoka kwa data ya kiwango cha chini, katika `Vitendo Vingine` unaweza kuchagua `Soma Aina Maalum ya Kadi` na **kutaja kwa mkono** **aina ya kadi unayotaka kusoma**.
#### Kadi za Benki za EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Isipokuwa tu kusoma UID, unaweza kutoa data zaidi kutoka kwenye kadi ya benki. Ni **inawezekana kupata nambari kamili ya kadi** (nambari 16 zilizo mbele ya kadi), **tarehe ya uhalali**, na katika baadhi ya kesi hata **jina la mmiliki** pamoja na orodha ya **shughuli za hivi karibuni**.\
Hata hivyo, **hauwezi kusoma CVV kwa njia hii** (nambari 3 zilizo nyuma ya kadi). Pia **kadi za benki zinalindwa kutokana na mashambulizi ya kurudia**, hivyo kuikopisha na kisha kujaribu kuiga ili kulipia kitu hakitafanya kazi.

## Marejeo

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaowezekana ili uweze kuyatatua haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata matatizo katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? au ungependa kupata ufikiaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
