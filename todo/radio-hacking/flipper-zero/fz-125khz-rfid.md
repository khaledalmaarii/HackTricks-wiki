# FZ - 125kHz RFID

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Utangulizi

Kwa habari zaidi kuhusu jinsi vitambulisho vya 125kHz vinavyofanya kazi, angalia:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Hatua

Kwa habari zaidi kuhusu aina hizi za vitambulisho [**soma utangulizi huu**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Soma

Jaribu **kusoma** habari ya kadi. Kisha unaweza **kuiga** habari hizo.

{% hint style="warning" %}
Tafadhali kumbuka kuwa baadhi ya intercoms zinajaribu kujilinda dhidi ya nakala za funguo kwa kutuma amri ya kuandika kabla ya kusoma. Ikiwa kuandika kunafanikiwa, kadi hiyo inachukuliwa kuwa bandia. Wakati Flipper inaiga RFID, hakuna njia ya kusoma kuweza kutofautisha kati ya kadi ya asili na ile ya bandia, kwa hivyo hakuna matatizo kama hayo yanatokea.
{% endhint %}

### Ongeza Kwa Mkono

Unaweza kuunda **kadi bandia kwenye Flipper Zero ukionyesha data** kwa mkono kisha kuiga.

#### Vitambulisho kwenye kadi

Marafiki, wakati mwingine, unapopata kadi utapata kitambulisho (au sehemu) yake imeandikwa kwenye kadi inayoonekana.

* **EM Marin**

Kwa mfano, kwenye kadi ya EM-Marin hii kwenye kadi ya kimwili inawezekana **kusoma 3 ya 5 byte mwisho kwa wazi**.\
Wengine 2 wanaweza kuvunjwa kwa nguvu ikiwa huwezi kusoma kutoka kwenye kadi.

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

Hali kama hiyo inatokea kwenye kadi ya HID ambapo ni herufi 2 tu kati ya herufi 3 zinaweza kupatikana zimeandikwa kwenye kadi

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### Imita/Andika

Baada ya **kukopi** kadi au **kuingiza** kitambulisho **kwa mkono**, inawezekana kuiga kwa kutumia Flipper Zero au **kuandika** kwenye kadi halisi.

## Marejeo

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
