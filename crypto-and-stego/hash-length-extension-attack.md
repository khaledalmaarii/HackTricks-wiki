<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Muhtasari wa shambulio

Fikiria seva ambayo ina **kutilia sahihi** baadhi ya **data** kwa **kuongeza** **siri** kwa baadhi ya data wazi inayojulikana kisha kuhakiki data hiyo. Ikiwa unajua:

* **Urefu wa siri** (hii inaweza pia kufanywa kwa nguvu kutoka kwa safu ya urefu uliopewa)
* **Data wazi**
* **Algoritimu (na ni dhaifu kwa shambulio hili)**
* **Kujaza inajulikana**
* Kawaida moja ya msingi hutumiwa, hivyo ikiwa mahitaji mengine 3 yanakidhiwa, hii pia inatumika
* Kujaza hubadilika kulingana na urefu wa siri+data, ndio maana urefu wa siri unahitajika

Basi, inawezekana kwa **mshambuliaji** kuongeza **data** na **kuzalisha** sahihi **kwa data iliyopita + data iliyongezwa**.

## Vipi?

Kimsingi, algorithm dhaifu huzalisha hashes kwa kwanza **kutia sahihi kwa kundi la data**, na kisha, **kutoka** kwa **hash iliyoundwa awali** (hali), wan **ongeza kundi la data linalofuata** na **kulitia sahihi**.

Kisha, fikiria kwamba siri ni "siri" na data ni "data", MD5 ya "secretdata" ni 6036708eba0d11f6ef52ad44e8b74d5b.\
Ikiwa mshambuliaji anataka kuongeza herufi "ongeza" anaweza:

* Kuzalisha MD5 ya "A" 64
* Badilisha hali ya hash iliyoundwa awali kuwa 6036708eba0d11f6ef52ad44e8b74d5b
* Kuongeza herufi "ongeza"
* Kumaliza hash na hash inayotokana itakuwa **sahihi kwa "siri" + "data" + "kujaza" + "ongeza"**

## **Zana**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Marejeo

Unaweza kupata shambulio hili limeelezewa vizuri katika [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
