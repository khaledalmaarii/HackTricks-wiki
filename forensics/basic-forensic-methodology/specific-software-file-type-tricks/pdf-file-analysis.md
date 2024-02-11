# Uchambuzi wa Faili ya PDF

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuendesha mchakato wa kiotomatiki** uliojengwa na zana za jamii za **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

**Kwa maelezo zaidi angalia: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)**

Muundo wa PDF unajulikana kwa utata wake na uwezo wake wa kuficha data, hivyo kuwa kitovu cha changamoto za uchunguzi wa CTF. Inachanganya vipengele vya maandishi wazi na vitu vya binary, ambavyo vinaweza kuwa vimepakwa au kusimbwa, na inaweza kujumuisha hati za lugha kama JavaScript au Flash. Ili kuelewa muundo wa PDF, mtu anaweza kurejelea vifaa vya utangulizi vya Didier Stevens's [hapa](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/), au kutumia zana kama mhariri wa maandishi au mhariri maalum wa PDF kama Origami.

Kwa uchunguzi au uhariri wa kina wa PDF, zana kama [qpdf](https://github.com/qpdf/qpdf) na [Origami](https://github.com/mobmewireless/origami-pdf) zinapatikana. Data iliyofichwa ndani ya PDF inaweza kufichwa katika:

* Tabaka zisizoonekana
* Muundo wa metadata wa XMP na Adobe
* Kuongezeka kwa vizazi
* Maandishi yenye rangi sawa na mandhari ya nyuma
* Maandishi nyuma ya picha au picha zinazopishana
* Maoni yasiyoonyeshwa

Kwa uchambuzi wa PDF ulioboreshwa, maktaba za Python kama [PeepDF](https://github.com/jesparza/peepdf) zinaweza kutumika kuunda hati za uchanganuzi maalum. Zaidi ya hayo, uwezo wa PDF wa kuhifadhi data iliyofichwa ni mkubwa sana hivi kwamba rasilimali kama mwongozo wa NSA juu ya hatari na mikakati ya PDF, ingawa haipo tena kwenye eneo lake la asili, bado hutoa ufahamu muhimu. [Nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) na mkusanyiko wa [mbinu za muundo wa PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) na Ange Albertini zinaweza kutoa maelezo zaidi kuhusu somo hili.

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
