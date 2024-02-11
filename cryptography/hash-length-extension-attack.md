<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Muhtasari wa shambulio

Fikiria kuna seva ambayo ina **kutilia saini** baadhi ya **data** kwa **kuongeza** **siri** kwenye data fulani ya wazi inayojulikana na kisha kuhesabu hash ya data hiyo. Ikiwa unajua:

* **Urefu wa siri** (hii inaweza pia kuvunjwa kwa nguvu kutoka kwa safu ya urefu uliyopewa)
* **Data ya wazi**
* **Algorithm (na ina hatari ya shambulio hili)**
* **Kujaza inajulikana**
* Kawaida inatumika moja ya chaguo-msingi, kwa hivyo ikiwa mahitaji mengine 3 yanakidhiwa, hii pia inafaa
* Kujaza hubadilika kulingana na urefu wa siri+data, ndio sababu urefu wa siri unahitajika

Basi, inawezekana kwa **mshambuliaji** kuongeza **data** na **kuunda** saini **sahihi** kwa **data iliyotangulia + data iliyoongezwa**.

## Vipi?

Kimsingi, algorithm zinazoweza kudhurika huzalisha hash kwa kwanza **kwa kuhesabu hash kwa kipande cha data**, na kisha, **kutoka** kwa **hash iliyoundwa hapo awali** (hali), wanapata **kuongeza kipande cha data kijacho** na **kuihesabu hash**.

Basi, fikiria siri ni "siri" na data ni "data", MD5 ya "siridata" ni 6036708eba0d11f6ef52ad44e8b74d5b.\
Ikiwa mshambuliaji anataka kuongeza herufi "ongeza" anaweza:

* Kuzalisha MD5 ya "A" 64
* Badilisha hali ya hash iliyoundwa hapo awali kuwa 6036708eba0d11f6ef52ad44e8b74d5b
* Ongeza herufi "ongeza"
* Maliza hash na hash inayotokana itakuwa **sahihi kwa "siri" + "data" + "kujaza" + "ongeza"**

## **Zana**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Marejeo

Unaweza kupata shambulio hili limeelezewa vizuri katika [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
