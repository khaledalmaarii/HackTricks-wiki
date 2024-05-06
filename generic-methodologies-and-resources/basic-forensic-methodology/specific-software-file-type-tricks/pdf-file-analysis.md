# Uchambuzi wa Faili ya PDF

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=pdf-file-analysis) kujenga na **kutumia mifumo ya kazi** zilizowezeshwa na zana za jamii za **juu zaidi** ulimwenguni.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=pdf-file-analysis" %}

**Kwa maelezo zaidi angalia:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Muundo wa PDF unajulikana kwa utata wake na uwezo wa kuficha data, hivyo kuwa kitovu cha changamoto za uchunguzi wa CTF. Inachanganya vipengele vya maandishi wazi na vitu vya binary, ambavyo vinaweza kuwa vimepakwa au kusimbwa, na vinaweza kujumuisha scripts katika lugha kama JavaScript au Flash. Ili kuelewa muundo wa PDF, mtu anaweza kurejelea vifaa vya kuanzisha vya Didier Stevens's [introductory material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/), au kutumia zana kama mhariri wa maandishi au mhariri maalum wa PDF kama Origami.

Kwa uchunguzi au upangaji wa kina wa PDFs, zana kama [qpdf](https://github.com/qpdf/qpdf) na [Origami](https://github.com/mobmewireless/origami-pdf) zinapatikana. Data iliyofichwa ndani ya PDF inaweza kufichwa katika:

* Tabaka zisizoonekana
* Muundo wa metadata wa XMP na Adobe
* Kuongezeka kwa vizazi
* Maandishi yenye rangi sawa na background
* Maandishi nyuma ya picha au picha zinazopishana
* Maoni yasiyoonyeshwa

Kwa uchambuzi wa kawaida wa PDF, maktaba za Python kama [PeepDF](https://github.com/jesparza/peepdf) zinaweza kutumika kutengeneza scripts za uchambuzi maalum. Zaidi, uwezo wa PDF wa kuhifadhi data iliyofichwa ni mkubwa sana hivi kwamba rasilimali kama mwongozo wa NSA kuhusu hatari na mikakati ya PDF, ingawa sasa haupo tena kwenye eneo lake la awali, bado hutoa ufahamu muhimu. [Nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) na mkusanyiko wa [mbinu za muundo wa PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) na Ange Albertini zinaweza kutoa maelezo zaidi kuhusu mada hiyo. 

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
