# Mbinu Nyingine za Wavuti

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### Kichwa cha Mwenyeji

Maranyingi seva ya nyuma inaamini **kichwa cha mwenyeji (Host header)** kutekeleza baadhi ya vitendo. Kwa mfano, inaweza kutumia thamani yake kama **kikoa cha kutuma upya nywila**. Kwa hivyo unapopokea barua pepe na kiungo cha kusahihisha nywila yako, kikoa kinachotumiwa ni kile ulichoweka kwenye kichwa cha mwenyeji. Kisha, unaweza kuomba kusahihisha nywila ya watumiaji wengine na kubadilisha kikoa kuwa moja unayodhibiti ili kuiba nambari zao za kusahihisha nywila. [Andika](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Tambua kwamba inawezekana hata usihitaji kusubiri mtumiaji bonyeze kiungo cha kusahihisha nywila kupata ishara, labda hata **filti za barua taka au vifaa/bots vya kati vitabonyeza** kuchambua.
{% endhint %}

### Vigezo vya Kikao

Wakati mwingine unapokamilisha uthibitisho fulani kwa usahihi, seva ya nyuma itaongeza tu boolean yenye thamani "Kweli" kwa sifa ya usalama ya kikao chako. Kisha, mwisho tofauti utajua ikiwa umepita mtihani huo kwa mafanikio.\
Hata hivyo, ikiwa **unapita mtihani** na kikao chako kinapewa thamani ya "Kweli" kwenye sifa ya usalama, unaweza kujaribu **kupata rasilimali nyingine** ambazo **zinategemea sifa ile ile** lakini **hupaswi kuwa na ruhusa** ya kufikia. [Andika](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Kazi ya Usajili

Jaribu kusajili kama mtumiaji anayepo tayari. Jaribu pia kutumia herufi sawa (madoa, nafasi nyingi na Unicode).

### Kuchukua Barua pepe

Sajili barua pepe, kabla ya kuidhibitisha ibadilishe barua pepe, kisha, ikiwa barua pepe mpya ya uthibitisho inatumwa kwa barua pepe ya kwanza iliyosajiliwa, unaweza kuchukua barua pepe yoyote. Au ikiwa unaweza kuwezesha barua pepe ya pili kuidhinisha ile ya kwanza, unaweza pia kuchukua akaunti yoyote.

### Kufikia Dawati la Huduma za Ndani za Kampuni zinazotumia Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Mbinu ya TRACE

Wabunifu wanaweza kusahau kulemaza chaguo mbalimbali za kurekebisha katika mazingira ya uzalishaji. Kwa mfano, njia ya HTTP ya `TRACE` imeundwa kwa madhumuni ya uchunguzi. Ikiwa imeanzishwa, seva ya wavuti itajibu maombi yanayotumia njia ya `TRACE` kwa kutoa katika jibu ombi kamili lililopokelewa. Tabia hii mara nyingi ni salama, lakini mara chache husababisha kufichua habari, kama jina la vichwa vya kuthibitisha vya ndani ambavyo vinaweza kuongezwa kwa maombi na wakala wa kurudisha.![Picha kwa chapisho](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Picha kwa chapisho](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)
