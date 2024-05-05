# Shambulizi la Upanuzi wa Urefu wa Hash

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

***

## Muhtasari wa shambulizi

Fikiria server ambayo ina **kutilia sahihi** baadhi ya **data** kwa **kuongeza** **siri** kwa baadhi ya data dhahiri inayojulikana kisha kuhakiki data hiyo. Ikiwa unajua:

* **Urefu wa siri** (hii inaweza pia kudukuliwa kutoka kwa safu ya urefu uliopewa)
* **Data dhahiri**
* **Algoritimu (na inayoweza kushambuliwa na shambulizi hili)**
* **Kujaza inajulikana**
* Kawaida moja ya msingi hutumiwa, hivyo ikiwa mahitaji mengine 3 yanakidhiwa, hii pia inakidhiwa
* Kujaza hubadilika kulingana na urefu wa siri+data, ndio sababu urefu wa siri unahitajika

Basi, ni rahisi kwa **mshambuliaji** kuongeza **data** na **kuzalisha** sahihi **ya data iliyotangulia + data iliyongezwa**.

### Vipi?

Kimsingi, algorithm zinazoweza kushambuliwa huzalisha hash kwa kwanza **kutia hash kwa kundi la data**, na kisha, **kutoka** kwa **hash iliyoundwa awali** (hali), wan **ongeza kundi la data linalofuata** na **kulihakiki**.

Kisha, fikiria kwamba siri ni "siri" na data ni "data", MD5 ya "secretdata" ni 6036708eba0d11f6ef52ad44e8b74d5b.\
Ikiwa mshambuliaji anataka kuongeza herufi "ongeza" anaweza:

* Kuzalisha MD5 ya "A" 64
* Kubadilisha hali ya hash iliyowekwa awali kuwa 6036708eba0d11f6ef52ad44e8b74d5b
* Kuongeza herufi "ongeza"
* Kumaliza hash na hash inayotokana itakuwa **sahihi kwa "siri" + "data" + "kujaza" + "ongeza"**

### **Zana**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Marejeo

Unaweza kupata shambulizi hili limeelezewa vizuri katika [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
