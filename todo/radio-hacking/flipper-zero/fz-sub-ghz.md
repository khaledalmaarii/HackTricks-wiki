# FZ - Sub-GHz

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Kikundi cha Usalama cha Kujitahidi**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Utangulizi <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero inaweza **kupokea na kutuma masafa ya redio kwenye safu ya 300-928 MHz** na moduli yake iliyojengwa, ambayo inaweza kusoma, kuhifadhi, na kumwiga udhibiti wa mbali. Udhibiti huu hutumiwa kwa mwingiliano na milango, vizuizi, kufungia redio, swichi za udhibiti wa mbali, visinga vya mlango visivyo na waya, taa za akili, na zaidi. Flipper Zero inaweza kukusaidia kujua ikiwa usalama wako umevamiwa.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Vifaa vya Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ina moduli ya sub-1 GHz iliyojengwa kulingana na [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) na antena ya redio (umbali wa juu ni mita 50). Chipi ya CC1101 na antena zimedesign kufanya kazi kwenye masafa ya 300-348 MHz, 387-464 MHz, na 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Vitendo

### Mchambuzi wa Masafa

{% hint style="info" %}
Jinsi ya kugundua ni masafa gani yanayotumiwa na udhibiti
{% endhint %}

Wakati wa uchambuzi, Flipper Zero inachunguza nguvu za ishara (RSSI) kwenye masafa yote yanayopatikana katika usanidi wa masafa. Flipper Zero inaonyesha masafa yenye thamani kubwa ya RSSI, na nguvu ya ishara zaidi ya -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Ili kujua masafa ya udhibiti, fanya yafuatayo:

1. Weka udhibiti wa mbali karibu sana na upande wa kushoto wa Flipper Zero.
2. Nenda kwa **Menyu Kuu** **→ Sub-GHz**.
3. Chagua **Mchambuzi wa Masafa**, kisha bonyeza na ushikilie kitufe kwenye udhibiti wa mbali unayotaka kuchambua.
4. Angalia thamani ya masafa kwenye skrini.

### Soma

{% hint style="info" %}
Pata habari kuhusu masafa yanayotumiwa (njia nyingine ya kugundua ni masafa gani yanayotumiwa)
{% endhint %}

Chaguo la **Soma** **inasikiliza kwenye masafa yaliyosanidiwa** kwenye modulisheni iliyotajwa: 433.92 AM kwa chaguo-msingi. Ikiwa **kitu kinapatikana** wakati wa kusoma, **habari inatolewa** kwenye skrini. Habari hii inaweza kutumika kurudia ishara hapo baadaye.

Wakati Soma inatumika, unaweza bonyeza **kitufe cha kushoto** na **kuisanidi**.\
Wakati huu ina **modulisheni 4** (AM270, AM650, FM328 na FM476), na **masafa kadhaa muhimu** yameshikiliwa:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Unaweza kuweka **yoyote inayokuvutia**, hata hivyo, ikiwa **haujui ni masafa gani** yanaweza kutumiwa na udhibiti unaouweka, **weka Hopping kuwa ON** (Off kwa chaguo-msingi), na bonyeza kitufe mara kadhaa hadi Flipper inapochukua na kukupa habari unayohitaji kuweka masafa.

{% hint style="danger" %}
Kubadilisha kati ya masafa kunachukua muda fulani, kwa hivyo ishara zinazotumwa wakati wa kubadilisha zinaweza kukosa. Kwa kupokea ishara bora, weka masafa yaliyowekwa kulingana na Mchambuzi wa Masafa.
{% endhint %}

### **Soma Raw**

{% hint style="info" %}
Dukua (na rudufu) ishara kwenye masafa yaliyosanidiwa
{% endhint %}

Chaguo la **Soma Raw** **inarekodi ishara** zilizotumwa kwenye masafa ya kusikiliza. Hii inaweza kutumika kudukua ishara na **kurudufu**.

Kwa chaguo-msingi **Soma Raw pia iko kwenye 433.92 katika AM650**, lakini ikiwa kwa chaguo la Soma uligundua kuwa ishara inayokuvutia iko kwenye **masafa/modulisheni tofauti, unaweza pia kuibadilisha** kwa kubonyeza kushoto (wakati ndani ya chaguo la Soma Raw).

### Kuvunja-Nguvu

Ikiwa unajua itifaki inayotumiwa kwa mfano na mlango wa garaji, ni rahisi k**uzalisha nambari zote na kuzituma na Flipper Zero.** Hii ni mfano unaounga mkono aina za kawaida za kawaida za garaji: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Ongeza Kwa Mikono

{% hint style="info" %}
Ongeza ishara kutoka kwa orodha iliyosanidiwa ya itifaki
{% endhint %}

#### Orodha ya [itifaki zinazoungwa mkono](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (inayofanya kazi na mfumo wa nambari za msimbo wa kawaida) | 433.92 | Stati  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | Stati  |
| Nice Flo 24bit\_433                                             | 433.92 | Stati  |
| CAME 12bit\_433                                                 | 433.92 | Stati  |
| CAME 24bit\_433                                                 | 433.92 | Stati  |
| Linear\_300                                                     | 300.00 | Stati  |
| CAME TWEE                                                       | 433.92 | Stati  |
| Gate TX\_433                                                    | 433.92 | Stati  |
| DoorHan\_315                                                    | 315.00 | Kinamik  |
| DoorHan\_433                                                    | 433.92 | Kinamik  |
| LiftMaster\_315                                                 | 315.00 | Kinamik  |
| LiftMaster\_390                                                 | 390.00 | Kinamik  |
| Security+2.0\_310                                               | 310.00 | Kinamik  |
| Security+2.0\_315                                               | 315.00 | Kinamik  |
| Security+2.0\_390                                               | 390.00 | Kinamik  |
### Wauzaji wanaoungwa mkono wa Sub-GHz

Angalia orodha kwenye [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Vipimo vinavyoungwa mkono kwa kanda

Angalia orodha kwenye [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Jaribio

{% hint style="info" %}
Pata dBms za vipimo vilivyohifadhiwa
{% endhint %}

## Marejeleo

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

**Kikundi cha Usalama cha Kujitahidi**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
