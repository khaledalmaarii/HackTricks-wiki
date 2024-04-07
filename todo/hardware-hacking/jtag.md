# JTAG

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)ni chombo kinachoweza kutumika na Raspberry PI au Arduino kutafuta pini za JTAG kutoka kwa chip isiyojulikana.\
Kwenye **Arduino**, unaweza kuunganisha **pini kutoka 2 hadi 11 kwenye pini 10 zinazoweza kuwa za JTAG**. Pakia programu kwenye Arduino na itajaribu kufanya nguvu ya brute kwenye pini zote ili kugundua ikiwa kuna pini yoyote inayomiliki JTAG na ni ipi kila moja.\
Kwenye **Raspberry PI** unaweza kutumia tu **pini kutoka 1 hadi 6** (pini 6, hivyo utapima polepole kila pini inayowezekana ya JTAG).

### Arduino

Kwenye Arduino, baada ya kuunganisha nyaya (pini 2 hadi 11 kwenye pini za JTAG na Arduino GND kwa GND ya ubao wa mzunguko), **pakia programu ya JTAGenum kwenye Arduino** na kwenye Mfuatiliaji wa Serial tuma **`h`** (amri ya msaada) na unapaswa kuona msaada:

![](<../../.gitbook/assets/image (936).png>)

![](<../../.gitbook/assets/image (575).png>)

Sanidi **"Hakuna mwisho wa mstari" na 115200baud**.\
Tuma amri s kuanza skanning:

![](<../../.gitbook/assets/image (771).png>)

Ikiwa unawasiliana na JTAG, utapata moja au zaidi ya **mistari inayoanza na KUPATIKANA!** ikionyesha pini za JTAG.
