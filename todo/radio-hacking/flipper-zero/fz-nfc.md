# FZ - NFC

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki hila za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Kwa maelezo kuhusu RFID na NFC angalia ukurasa ufuatao:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Kadi za NFC zinazoungwa mkono <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Mbali na kadi za NFC Flipper Zero inasaidia **aina nyingine za kadi za masafa ya juu** kama vile kadhaa za **Mifare** Classic na Ultralight na **NTAG**.
{% endhint %}

Aina mpya za kadi za NFC zitaongezwa kwenye orodha ya kadi zinazoungwa mkono. Flipper Zero inasaidia aina zifuatazo za **kadi za NFC aina A** (ISO 14443A):

* ﻿**Kadi za benki (EMV)** — inasoma tu UID, SAK, na ATQA bila kuhifadhi.
* ﻿**Kadi zisizojulikana** — inasoma (UID, SAK, ATQA) na kuiga UID.

Kwa **kadi za NFC aina B, aina F, na aina V**, Flipper Zero inaweza kusoma UID bila kuuhifadhi.

### Kadi za NFC aina A <a href="#uvusf" id="uvusf"></a>

#### Kadi ya benki (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero inaweza kusoma tu UID, SAK, ATQA, na data iliyohifadhiwa kwenye kadi za benki **bila kuhifadhi**.

Kipengele cha kusoma kadi za benkiKwa kadi za benki, Flipper Zero inaweza kusoma data tu **bila kuhifadhi na kuiga**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Kadi zisizojulikana <a href="#id-37eo8" id="id-37eo8"></a>

Wakati Flipper Zero hawezi **kubaini aina ya kadi ya NFC**, basi tu **UID, SAK, na ATQA** zinaweza **kusomwa na kuhifadhiwa**.

Kipengele cha kusoma kadi zisizojulikanaKwa kadi za NFC zisizojulikana, Flipper Zero inaweza kuiga tu UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Kadi za NFC aina B, F, na V <a href="#wyg51" id="wyg51"></a>

Kwa **kadi za NFC aina B, F, na V**, Flipper Zero inaweza tu **kusoma na kuonyesha UID** bila kuuhifadhi.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Vitendo

Kwa utangulizi kuhusu NFC [**soma ukurasa huu**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Soma

Flipper Zero inaweza **kusoma kadi za NFC**, hata hivyo, **haiwezi kuelewa itifaki zote** zinazotegemea ISO 14443. Hata hivyo, kwa kuwa **UID ni sifa ya kiwango cha chini**, unaweza kujikuta katika hali ambapo **UID tayari umesomwa, lakini itifaki ya juu ya uhamishaji wa data bado haijulikani**. Unaweza kusoma, kuiga na kuingiza UID kwa mikono ukitumia Flipper kwa wasomaji wa msingi wanaotumia UID kwa idhini.

#### Kusoma UID VS Kusoma Data Ndani <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

Katika Flipper, kusoma lebo za 13.56 MHz kunaweza kugawanywa katika sehemu mbili:

* **Kusoma kiwango cha chini** — inasoma tu UID, SAK, na ATQA. Flipper inajaribu kudhani itifaki ya juu kulingana na data hii iliyosomwa kutoka kwa kadi. Huwezi kuwa na uhakika wa 100% na hii, kwani ni dhana tu kulingana na mambo fulani.
* **Kusoma kiwango cha juu** — inasoma data kutoka kwenye kumbukumbu ya kadi kwa kutumia itifaki maalum ya kiwango cha juu. Hii itakuwa kusoma data kwenye Mifare Ultralight, kusoma sekta kutoka Mifare Classic, au kusoma sifa za kadi kutoka PayPass/Apple Pay.

### Soma Maalum

Iwapo Flipper Zero haiwezi kubaini aina ya kadi kutoka kwa data ya kiwango cha chini, katika `Vitendo vya Ziada` unaweza kuchagua `Soma Aina Maalum ya Kadi` na **kuashiria kwa mikono** **aina ya kadi unayotaka kusoma**.

#### Kadi za Benki za EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Mbali na kusoma tu UID, unaweza kutoa data zaidi kutoka kwa kadi ya benki. Inawezekana **kupata nambari kamili ya kadi** (nambari 16 kwenye uso wa kadi), **tarehe ya uhalali**, na katika baadhi ya matukio hata **jina la mmiliki** pamoja na orodha ya **miamala ya hivi karibuni**.\
Hata hivyo, huwezi **kusoma CVV kwa njia hii** (nambari 3 kwenye nyuma ya kadi). Pia **kadi za benki zinalindwa dhidi ya mashambulizi ya kurudi**, hivyo kunakili kwa Flipper na kisha kujaribu kuiga ili kulipia kitu hakutafanya kazi.

## Marejeo

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki hila za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
