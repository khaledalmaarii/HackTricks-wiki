# Mbinu Nyingine za Wavuti

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### Kichwa cha Mwenyeji

Maranyingi, seva ya nyuma inategemea **kichwa cha mwenyeji (Host header)** kufanya vitendo fulani. Kwa mfano, inaweza kutumia thamani yake kama **kikoa cha kutuma upya nenosiri**. Kwa hivyo, unapopokea barua pepe na kiunga cha kurejesha nenosiri lako, kikoa kinachotumiwa ni kile ulichoweka kwenye kichwa cha mwenyeji. Kwa hiyo, unaweza kuomba kurejesha nenosiri la watumiaji wengine na kubadilisha kikoa kuwa kimoja kinachodhibitiwa na wewe ili kuiba nambari zao za kurejesha nenosiri. [Andika](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Tambua kwamba inawezekana hata usihitaji kusubiri mtumiaji bonyeze kiunga cha kurejesha nenosiri ili kupata ishara, kwani labda hata **filters za barua taka au vifaa/boti vya kati vingine vitabonyeza kiunga hicho kwa ajili ya uchambuzi**.
{% endhint %}

### Seseni za Boolean

Maranyingi, unapokamilisha uthibitisho fulani kwa usahihi, seva ya nyuma itaongeza tu boolean na thamani "True" kwa sifa ya usalama ya seseni yako. Kisha, mwisho tofauti utajua ikiwa umepita kwa mafanikio ukaguzi huo.\
Hata hivyo, ikiwa **unapita ukaguzi** na seseni yako inapewa thamani "True" kwenye sifa ya usalama, unaweza kujaribu **kupata rasilimali nyingine** ambazo **zinategemea sifa hiyo hiyo** lakini ambazo **haukupaswa kuwa na ruhusa** ya kufikia. [Andika](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Utendaji wa Usajili

Jaribu kujisajili kama mtumiaji ambaye tayari yupo. Jaribu pia kutumia herufi sawa (nukta, nafasi nyingi na Unicode).

### Kuchukua Udhibiti wa Barua pepe

Sajili anwani ya barua pepe, kabla ya kuidhibitisha, badilisha barua pepe, kisha, ikiwa barua pepe mpya ya uthibitisho inatumwa kwa barua pepe ya kwanza iliyosajiliwa, unaweza kuchukua udhibiti wa barua pepe yoyote. Au ikiwa unaweza kuwezesha barua pepe ya pili kwa kuidhibitisha ya kwanza, unaweza pia kuchukua udhibiti wa akaunti yoyote.

### Pata Huduma ya Ndani ya kampuni kwa kutumia atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Njia ya TRACE

Watengenezaji wanaweza kusahau kuzima chaguo mbalimbali za kurekebisha katika mazingira ya uzalishaji. Kwa mfano, njia ya HTTP `TRACE` imeundwa kwa madhumuni ya uchunguzi. Ikiwa imezimishwa, seva ya wavuti itajibu maombi yanayotumia njia ya `TRACE` kwa kutoa jibu la maombi halisi yaliyopokelewa. Tabia hii mara nyingi haileti madhara, lakini mara chache inasababisha ufichuzi wa habari, kama jina la vichwa vya uwakilishi wa ndani ambavyo vinaweza kuongezwa kwa maombi na wakala wa kurudisha nyuma.![Picha kwa chapisho](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Picha kwa chapisho](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
