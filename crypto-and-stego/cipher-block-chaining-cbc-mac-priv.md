{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks kwa Wataalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks kwa Wataalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>unga mkono HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}


# CBC

Ikiwa **cookie** ni **tu** **jina la mtumiaji** (au sehemu ya kwanza ya cookie ni jina la mtumiaji) na unataka kujifanya kuwa jina la mtumiaji "**admin**". Kisha, unaweza kuunda jina la mtumiaji **"bdmin"** na **kufanya jaribio la nguvu** ya **byte ya kwanza** ya cookie.

# CBC-MAC

**Msimbo wa uthibitishaji wa ujumbe wa kufungwa kwa mnyororo** (**CBC-MAC**) ni njia inayotumiwa katika kriptografia. Inafanya kazi kwa kuchukua ujumbe na kuuweka kwa kufungwa kwa kila kibodi, ambapo kufungwa kwa kila kibodi kunahusishwa na ile iliyotangulia. Mchakato huu unajenga **mnyororo wa kibodi**, ukisafisha kwamba kubadilisha hata kidogo tu biti ya ujumbe halisi kutapelekea mabadiliko yasiyotabirika katika kibodi ya mwisho ya data iliyofungwa. Ili kufanya au kubadilisha mabadiliko kama hayo, ufunguo wa kufungwa unahitajika, ikisimamia usalama.

Ili kuhesabu CBC-MAC ya ujumbe m, mtu anafunga m katika hali ya CBC na vector ya kuanzisha sifuri na kuhifadhi kibodi ya mwisho. Mchoro unaofuata unapanga hesabu ya CBC-MAC ya ujumbe unaoundwa na kibodi![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) ukitumia ufunguo wa siri k na kibodi ya kibodi E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Udhaifu

Kwa CBC-MAC kawaida **IV iliyotumiwa ni 0**.\
Hii ni tatizo kwa sababu ujumbe 2 uliojulikana (`m1` na `m2`) kila mmoja utazalisha saini 2 (`s1` na `s2`). Kwa hivyo:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Kisha ujumbe uliojumuisha m1 na m2 (m3) utazalisha saini 2 (s31 na s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Ambayo inawezekana kuhesabu bila kujua ufunguo wa kufungwa.**

Fikiria unafunga jina **Msimamizi** katika kibodi za **8bytes**:

* `Administ`
* `rator\00\00\00`

Unaweza kuunda jina la mtumiaji linaloitwa **Administ** (m1) na kupata saini (s1).\
Kisha, unaweza kuunda jina la mtumiaji lililopatikana kutoka `rator\00\00\00 XOR s1`. Hii itazalisha `E(m2 XOR s1 XOR 0)` ambayo ni s32.\
sasa, unaweza kutumia s32 kama saini ya jina kamili **Msimamizi**.

### Muhtasari

1. Pata saini ya jina la mtumiaji **Administ** (m1) ambayo ni s1
2. Pata saini ya jina la mtumiaji **rator\x00\x00\x00 XOR s1 XOR 0** ni s32**.**
3. Weka cookie kwa s32 na itakuwa cookie halali kwa mtumiaji **Msimamizi**.

# Kudhibiti Mashambulizi ya IV

Ikiwa unaweza kudhibiti IV iliyotumiwa mashambulizi yanaweza kuwa rahisi sana.\
Ikiwa vidakuzi ni tu jina la mtumiaji lililofungwa, kujifanya kuwa mtumiaji "**msimamizi**" unaweza kuunda mtumiaji "**Msimamizi**" na utapata cookie yake.\
Sasa, ikiwa unaweza kudhibiti IV, unaweza kubadilisha Byte ya kwanza ya IV ili **IV\[0] XOR "A" == IV'\[0] XOR "a"** na kuzalisha upya cookie kwa mtumiaji **Msimamizi.** Cookie hii itakuwa halali kwa **kujifanya** kuwa mtumiaji **msimamizi** na IV ya awali.

## Marejeo

Maelezo zaidi kwenye [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks kwa Wataalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks kwa Wataalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>unga mkono HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
