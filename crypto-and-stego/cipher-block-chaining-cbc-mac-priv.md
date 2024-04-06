<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# CBC

Ikiwa **kidakuzi** ni **jina la mtumiaji** tu (au sehemu ya kwanza ya kidakuzi ni jina la mtumiaji) na unataka kujifanya kuwa jina la mtumiaji "**admin**". Kisha, unaweza kuunda jina la mtumiaji **"bdmin"** na **kuvunja nguvu** herufi ya kwanza ya kidakuzi.

# CBC-MAC

**Cipher block chaining message authentication code** (**CBC-MAC**) ni njia inayotumiwa katika kriptografia. Inafanya kazi kwa kuchukua ujumbe na kuifanyia uchawi kwa kila kizuizi, ambapo uchawi wa kila kizuizi unahusishwa na ule uliotangulia. Mchakato huu unajenga **mlolongo wa vizuizi**, kuhakikisha kuwa kubadilisha hata kidogo tu biti ya ujumbe asili kutapelekea mabadiliko yasiyotabirika katika kizuizi cha mwisho cha data iliyofichwa. Ili kufanya au kubadilisha mabadiliko kama hayo, ufunguo wa uchawi unahitajika, kuhakikisha usalama.

Kwa kuhesabu CBC-MAC ya ujumbe m, mtu anafanya uchawi wa m katika hali ya CBC na vector ya kuanzisha sifuri na kuhifadhi kizuizi cha mwisho. Picha ifuatayo inaelezea hesabu ya CBC-MAC ya ujumbe unaoundwa na vizuizi![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) kwa kutumia ufunguo wa siri k na uchawi wa kizuizi E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Udhaifu

Kwa kawaida, IV inayotumiwa na CBC-MAC ni 0.\
Hii ni tatizo kwa sababu ujumbe uliojulikana (`m1` na `m2`) kwa kujitegemea utazalisha saini 2 (`s1` na `s2`). Kwa hivyo:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Kisha ujumbe uliojumuishwa na m1 na m2 (m3) utazalisha saini 2 (s31 na s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Ambayo inawezekana kuhesabu bila kujua ufunguo wa uchawi.**

Fikiria unaficha jina **Msimamizi** katika vizuizi vya **8bytes**:

* `Administ`
* `rator\00\00\00`

Unaweza kuunda jina la mtumiaji linaloitwa **Administ** (m1) na kupata saini (s1).\
Kisha, unaweza kuunda jina la mtumiaji linaloitwa matokeo ya `rator\00\00\00 XOR s1`. Hii itazalisha `E(m2 XOR s1 XOR 0)` ambayo ni s32.\
sasa, unaweza kutumia s32 kama saini ya jina kamili **Msimamizi**.

### Muhtasari

1. Pata saini ya jina la mtumiaji **Administ** (m1) ambayo ni s1
2. Pata saini ya jina la mtumiaji **rator\x00\x00\x00 XOR s1 XOR 0** ni s32**.**
3. Weka kidakuzi kuwa s32 na itakuwa kidakuzi halali kwa mtumiaji **Msimamizi**.

# Kudhibiti IV ya Shambulio

Ikiwa unaweza kudhibiti IV iliyotumiwa, shambulio linaweza kuwa rahisi sana.\
Ikiwa kidakuzi ni jina la mtumiaji tu lililofichwa, ili kujifanya kuwa mtumiaji "**msimamizi**" unaweza kuunda mtumiaji "**Msimamizi**" na utapata kidakuzi chake.\
Sasa, ikiwa unaweza kudhibiti IV, unaweza kubadilisha herufi ya kwanza ya IV ili **IV\[0] XOR "A" == IV'\[0] XOR "a"** na kuzalisha upya kidakuzi kwa mtumiaji **Msimamizi**. Kidakuzi hiki kitakuwa halali kwa **kujifanya** kuwa mtumiaji **msimamizi** na IV ya awali.

## Marejeo

Taarifa zaidi katika [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
