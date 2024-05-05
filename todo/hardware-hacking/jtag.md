# JTAG

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)ni chombo kinachoweza kutumika na Raspberry PI au Arduino kutafuta pins za JTAG kutoka kwa chip isiyojulikana.\
Kwenye **Arduino**, unaweza kuunganisha **pins kutoka 2 hadi 11 kwa pins 10 zinazoweza kuwa za JTAG**. Pakia programu kwenye Arduino na itajaribu kufanya nguvu ya brute kwenye pins zote ili kupata ikiwa kuna pins zinazohusiana na JTAG na kila moja ni ipi.\
Kwenye **Raspberry PI** unaweza kutumia tu **pins kutoka 1 hadi 6** (pins 6, hivyo utapima polepole kila pin inayowezekana ya JTAG).

### Arduino

Kwenye Arduino, baada ya kuunganisha nyaya (pin 2 hadi 11 kwa pins za JTAG na Arduino GND kwa GND ya ubao wa mzunguko), **pakia programu ya JTAGenum kwenye Arduino** na kwenye Serial Monitor tuma **`h`** (amri ya msaada) na unapaswa kuona msaada:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

Sanidi **"Hakuna mwisho wa mstari" na 115200baud**.\
Tuma amri s kuanza skanning:

![](<../../.gitbook/assets/image (774).png>)

Ikiwa unawasiliana na JTAG, utapata moja au zaidi **mistari ikiwaanza na KUPATIKANA!** ikionyesha pins za JTAG.
