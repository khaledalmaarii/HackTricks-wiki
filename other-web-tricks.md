# Mbinu Nyingine za Wavuti

{% hint style="success" %}
Jifunze na zoea AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoea GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### Kichwa cha Mwenyeji

Maranyingi seva ya nyuma huiamini **Kichwa cha Mwenyeji (Host header)** kufanya baadhi ya vitendo. Kwa mfano, inaweza kutumia thamani yake kama **kikoa cha kutuma upya nywila**. Kwa hivyo unapopokea barua pepe na kiungo cha kusahihisha nywila yako, kikoa kinachotumiwa ni kile ulichoweka kwenye Kichwa cha Mwenyeji. Kisha, unaweza kuomba kusahihisha nywila ya watumiaji wengine na kubadilisha kikoa kuwa kimoja kinachodhibitiwa na wewe ili kuiba nambari zao za kusahihisha nywila. [Andika](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Tambua kwamba inawezekana hata usihitaji kusubiri mtumiaji bonyeze kiungo cha kusahihisha nywila ili kupata ishara, labda hata **filti za barua taka au vifaa/bots vya kati vitabonyeza** kuchambua.
{% endhint %}

### Vigezo vya Kikao

Wakati mwingine unapokamilisha uthibitisho fulani kwa usahihi, seva ya nyuma ita**ongeza tu boolean yenye thamani "Kweli" kwa sifa ya usalama ya kikao chako**. Kisha, mwisho tofauti utajua ikiwa umepita mtihani huo kwa mafanikio.\
Hata hivyo, ikiwa **unapita mtihani** na kikao chako kinapewa thamani ya "Kweli" kwenye sifa ya usalama, unaweza kujaribu **kupata rasilimali nyingine** ambazo **zinategemea sifa ile ile** lakini **hupaswi kuwa na ruhusa** ya kufikia. [Andika](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Utendaji wa Usajili

Jaribu kusajili kama mtumiaji anayepo tayari. Jaribu pia kutumia herufi sawa (pembejeo, nafasi nyingi na Unicode).

### Kuchukua Barua pepe

Sajili barua pepe, kabla ya kuisahihi, badilisha barua pepe, kisha, ikiwa barua pepe mpya ya uthibitisho inatumwa kwa barua pepe ya kwanza iliyosajiliwa, unaweza kuchukua barua pepe yoyote. Au ikiwa unaweza kuwezesha barua pepe ya pili kuthibitisha ile ya kwanza, unaweza pia kuchukua akaunti yoyote.

### Kufikia Dawati la Huduma za Ndani za Kampuni zinazotumia atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Mbinu ya TRACE

Wabunifu wanaweza kusahau kulemaza chaguo mbalimbali za kurekebisha katika mazingira ya uzalishaji. Kwa mfano, njia ya HTTP ya `TRACE` imeundwa kwa madhumuni ya uchunguzi. Ikiwezeshwa, seva ya wavuti itajibu maombi yanayotumia njia ya `TRACE` kwa kutoa katika jibu ombi kamili lililopokelewa. Tabia hii mara nyingi ni salama, lakini mara chache husababisha kufichua habari, kama jina la vichwa vya kuthibitisha vya ndani ambavyo vinaweza kuongezwa kwa maombi na wakala wa kurudisha.![Picha kwa chapisho](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Picha kwa chapisho](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
Jifunze na zoea AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoea GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
