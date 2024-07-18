{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}


# Muhtasari wa shambulio

Fikiria server ambayo ina **kutilia sahihi** baadhi ya **data** kwa **kuongeza** **siri** kwa baadhi ya data dhahiri inayojulikana kisha kuhakiki data hiyo. Ikiwa unajua:

* **Urefu wa siri** (hii inaweza pia kufanywa kwa nguvu kutoka kwa safu ya urefu uliopewa)
* **Data dhahiri**
* **Algoritimu (na ni dhaifu kwa shambulio hili)**
* **Kujaza inajulikana**
* Kawaida moja ya msingi hutumiwa, hivyo ikiwa mahitaji mengine 3 yanakidhiwa, hii pia inafaa
* Kujaza hubadilika kulingana na urefu wa siri+data, ndio maana urefu wa siri unahitajika

Basi, ni rahisi kwa **mshambuliaji** kuongeza **data** na **kuzalisha** sahihi **ya awali + data iliyongezwa**.

## Vipi?

Kimsingi, algorithm dhaifu huzalisha hashes kwa kwanza **kutia hash kibodi cha data**, na kisha, **kutoka** kwa **hash iliyoundwa awali** (hali), wan **ongeza kibodi inayofuata ya data** na **kuitia hash**.

Kisha, fikiria kwamba siri ni "siri" na data ni "data", MD5 ya "secretdata" ni 6036708eba0d11f6ef52ad44e8b74d5b.\
Ikiwa mshambuliaji anataka kuongeza herufi "ongeza" anaweza:

* Kuzalisha MD5 ya 64 "A"s
* Badilisha hali ya hash iliyoundwa awali kuwa 6036708eba0d11f6ef52ad44e8b74d5b
* Ongeza herufi "ongeza"
* Maliza hash na hash inayotokana itakuwa **sahihi kwa "siri" + "data" + "kujaza" + "ongeza"**

## **Zana**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Marejeo

Unaweza kupata shambulio hili limeelezewa vizuri katika [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
