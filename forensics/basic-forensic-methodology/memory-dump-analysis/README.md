# Uchambuzi wa Kumbukumbu ya Kufuja

<details>

<summary><strong>Jifunze kuhusu kufuja AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kufuja kwa kuwasilisha PR kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni sehemu ya kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila uwanja.

{% embed url="https://www.rootedcon.com/" %}

## Kuanza

Anza **kutafuta** **programu hasidi** ndani ya pcap. Tumia **zana** zilizotajwa katika [**Uchambuzi wa Programu Hasidi**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility ni mfumo wa chanzo wazi kuu kwa uchambuzi wa kumbukumbu ya kufuja**. Zana hii ya Python inachambua kumbukumbu za vyanzo vya nje au VMware VMs, ikigundua data kama michakato na nywila kulingana na maelezo ya OS ya kumbukumbu. Inaweza kupanuliwa na programu-jalizi, ikifanya iweze kutumika kwa uchunguzi wa kufuja.

**[Pata hapa karatasi ya kumbukumbu](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**


## Ripoti ya Kufuja ya Kufa kwa Mini

Wakati kumbukumbu ni ndogo (tu KB chache, labda MB chache) basi inawezekana kuwa ni ripoti ya kufa kwa mini na sio kumbukumbu ya kufuja.

![](<../../../.gitbook/assets/image (216).png>)

Ikiwa una Visual Studio imewekwa, unaweza kufungua faili hii na kuunganisha habari za msingi kama jina la mchakato, muundo, habari ya kipekee na moduli zinazotekelezwa:

![](<../../../.gitbook/assets/image (217).png>)

Pia unaweza kupakia kipekee na kuona maagizo yaliyofafanuliwa

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

Hata hivyo, Visual Studio sio zana bora ya kufanya uchambuzi wa kina wa kufuja.

Unapaswa **kuifungua** kwa kutumia **IDA** au **Radare** kuiangalia kwa **kina**.



​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni sehemu ya kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila uwanja.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Jifunze kuhusu kufuja AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kufuja kwa kuwasilisha PR kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
