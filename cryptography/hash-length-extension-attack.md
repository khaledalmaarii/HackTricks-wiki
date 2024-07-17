<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Muhtasari wa shambulio

Fikiria server ambayo ina **kutilia sahihi** baadhi ya **data** kwa **kuongeza** **siri** kwa baadhi ya data dhahiri inayojulikana kisha kuhakiki data hiyo. Ikiwa unajua:

* **Urefu wa siri** (hii inaweza pia kufanywa kwa nguvu kutoka kwa safu ya urefu iliyopewa)
* **Data dhahiri**
* **Algoritimu (na inayoweza kushambuliwa na shambulio hili)**
* **Kujaza inajulikana**
* Kawaida moja ya msingi hutumiwa, hivyo ikiwa mahitaji mengine 3 yanakidhiwa, hii pia inatumika
* Kujaza hubadilika kulingana na urefu wa siri+data, ndio sababu urefu wa siri unahitajika

Basi, ni rahisi kwa **mshambuliaji** kuongeza **data** na **kuzalisha** sahihi **kwa data iliyopita + data iliyongezwa**.

## Vipi?

Kimsingi, algorithm zinazoweza kushambuliwa huzalisha hashes kwa kwanza **kutia hash kwa kibodi cha data**, na kisha, **kutoka** kwa **hash iliyoundwa hapo awali** (hali), wan **ongeza kibodi inayofuata ya data** na **kuitia hash**.

Kisha, fikiria kwamba siri ni "siri" na data ni "data", MD5 ya "secretdata" ni 6036708eba0d11f6ef52ad44e8b74d5b.\
Ikiwa mshambuliaji anataka kuongeza herufi "ongeza" anaweza:

* Kuzalisha MD5 ya 64 "A"s
* Badilisha hali ya hash iliyoundwa hapo awali kuwa 6036708eba0d11f6ef52ad44e8b74d5b
* Ongeza herufi "ongeza"
* Maliza hash na hash inayotokana itakuwa **sahihi kwa "siri" + "data" + "kujaza" + "ongeza"**

## **Zana**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Marejeo

Unaweza kupata shambulio hili likielezewa vizuri katika [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
