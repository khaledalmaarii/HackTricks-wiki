# FZ - Sub-GHz

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pata udhaifu unaowezekana zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata masuala katika mfumo wako wa teknolojia nzima, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Utangulizi <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero inaweza **kupokea na kutuma masafa ya redio katika kiwango cha 300-928 MHz** na moduli yake iliyojengwa, ambayo inaweza kusoma, kuhifadhi, na kuiga udhibiti wa kijijini. Udhibiti huu hutumiwa kwa mwingiliano na milango, vizuizi, kufungia redio, swichi za udhibiti wa kijijini, kengele za mlango zisizo na waya, taa za akili, na zaidi. Flipper Zero inaweza kukusaidia kujua ikiwa usalama wako umehatarishwa.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Vifaa vya Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ina moduli ya sub-1 GHz iliyojengwa kwenye [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[kipini cha CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) na antena ya redio (mbalimbali ya juu ni mita 50). Kipini cha CC1101 na antena vimeundwa kufanya kazi kwa masafa katika bendi za 300-348 MHz, 387-464 MHz, na 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Vitendo

### Mchambuzi wa Masafa

{% hint style="info" %}
Jinsi ya kupata masafa ambayo udhibiti wa kijijini unatumia
{% endhint %}

Wakati wa kuchambua, Flipper Zero inachunguza nguvu ya ishara (RSSI) kwa masafa yote yanayopatikana katika usanidi wa masafa. Flipper Zero inaonyesha masafa na thamani ya RSSI kubwa zaidi, na nguvu ya ishara zaidi ya -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Ili kujua masafa ya udhibiti wa kijijini, fanya yafuatayo:

1. Weka udhibiti wa kijijini karibu sana na upande wa kushoto wa Flipper Zero.
2. Nenda kwenye **Menyu Kuu** **→ Sub-GHz**.
3. Chagua **Mchambuzi wa Masafa**, kisha bonyeza na ushike kifungo kwenye udhibiti wa kijijini unayotaka kuchambua.
4. Angalia thamani ya masafa kwenye skrini.

### Soma

{% hint style="info" %}
Pata habari kuhusu masafa yanayotumiwa (njia nyingine ya kupata masafa yanayotumiwa)
{% endhint %}

Chaguo la **Soma** **inasikiliza kwenye masafa yaliyosanidiwa** kwenye modulisheni iliyotajwa: 433.92 AM kwa chaguo-msingi. Ikiwa **kitu kinapatikana** wakati wa kusoma, **habari inatolewa** kwenye skrini. Habari hii inaweza kutumiwa kuiga ishara hapo baadaye.

Wakati Soma inatumika, inawezekana bonyeza **kitufe cha kushoto** na **kuisanidi**.\
Kwa sasa ina **modulisheni 4** (AM270, AM650, FM328, na FM476), na **masafa muhimu kadhaa** yaliyohifadhiwa:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Unaweza kuweka **yoyote inayokuvutia**, hata hivyo, ikiwa **haujui masafa gani** yanaweza kutumiwa na udhibiti wa kijijini ulionao, **weka Hopping kuwa ON** (Off kwa chaguo-msingi), na bonyeza kitufe mara kadhaa hadi Flipper ichukue na kukupa habari unayohitaji kuweka masafa.

{% hint style="danger" %}
Kubadilisha kati ya masafa huchukua muda fulani, kwa hivyo ishara zinazotumwa wakati wa kubadilisha zinaweza kukosa. Ili kupokea ishara vizuri, weka masafa yaliyofikiriwa na Mchambuzi wa Masafa.
{% endhint %}

### **Soma Raw**

{% hint style="info" %}
Dukua (na rudia) ishara kwenye masafa yaliyosanidiwa
{% endhint %}

Chaguo la **Soma Raw** **inarekodi ishara** zinazotumwa kwenye masafa ya kusikiliza. Hii inaweza kutumika kudukua ishara na kuirudia.

Kwa chaguo-msingi **Soma Raw pia iko kwenye 433.92 katika AM650**, lakini ikiwa kwa chaguo la Soma uligundua kuwa ishara inayokuvutia iko kwenye **masafa/modulisheni tofauti, unaweza pia kubadilisha hiyo** kwa kubonyeza kushoto (wakati uko ndani ya chaguo la Soma Raw).

### Brute-Force

Ikiwa unajua itifaki inayotumiwa kwa mfano na mlango wa garaji, ni **inawezekana kuzalisha nambari zote na kuzituma na Flipper Zero.** Hii ni mfano ambao unasaidia aina za kawaida za milango ya garaji: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### Ongeza Kwa Mkono

{% hint style="info" %}
Ongeza ishara kutoka kwenye orodha iliyosanidiwa ya itifaki
{% endhint %}

#### Orodha ya [itifaki zinazoungwa mkono](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (inafanya kazi na mfumo wa nambari za msimamo wa weng
### Wauzaji wanaoungwa mkono wa Sub-GHz

Angalia orodha katika [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Mafurushi yanayoungwa mkono kwa kanda

Angalia orodha katika [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Jaribio

{% hint style="info" %}
Pata dBms za mafurushi yaliyohifadhiwa
{% endhint %}

## Marejeo

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuyatatua haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata matatizo katika mfumo wako wa teknolojia mzima, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
