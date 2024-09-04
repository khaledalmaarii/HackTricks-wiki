# FZ - Sub-GHz

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}


## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero inaweza **kupokea na kutuma masafa ya redio katika anuwai ya 300-928 MHz** kwa moduli yake iliyojengwa, ambayo inaweza kusoma, kuhifadhi, na kuiga remote controls. Remote hizi zinatumika kwa mwingiliano na milango, vizuizi, funguo za redio, swichi za remote control, kengele za mlango zisizo na waya, mwanga wa smart, na zaidi. Flipper Zero inaweza kukusaidia kujifunza ikiwa usalama wako umeathirika.

<figure><img src="../../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ina moduli ya sub-1 GHz iliyojengwa inayotegemea [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) na antenna ya redio (anuwai ya juu ni mita 50). Chip ya CC1101 na antenna zimeundwa kufanya kazi katika masafa ya 300-348 MHz, 387-464 MHz, na 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

{% hint style="info" %}
Jinsi ya kupata ni masafa gani remote inatumia
{% endhint %}

Wakati wa kuchambua, Flipper Zero inachanganua nguvu za ishara (RSSI) katika masafa yote yanayopatikana katika usanidi wa masafa. Flipper Zero inaonyesha masafa yenye thamani ya juu ya RSSI, ikiwa na nguvu ya ishara zaidi ya -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Ili kubaini masafa ya remote, fanya yafuatayo:

1. Weka remote control karibu sana na kushoto ya Flipper Zero.
2. Nenda kwenye **Main Menu** **→ Sub-GHz**.
3. Chagua **Frequency Analyzer**, kisha bonyeza na ushikilie kitufe kwenye remote control unayotaka kuchambua.
4. Kagua thamani ya masafa kwenye skrini.

### Read

{% hint style="info" %}
Pata habari kuhusu masafa yanayotumika (pia njia nyingine ya kupata ni masafa gani yanayotumika)
{% endhint %}

Chaguo la **Read** **linasikiliza kwenye masafa yaliyosanidiwa** kwenye moduli iliyotajwa: 433.92 AM kwa chaguo-msingi. Ikiwa **kitu kinapatikana** wakati wa kusoma, **habari inatolewa** kwenye skrini. Habari hii inaweza kutumika kuiga ishara siku zijazo.

Wakati Read inatumika, inawezekana kubonyeza **kitufe cha kushoto** na **kuisakinisha**.\
Katika wakati huu ina **modulations 4** (AM270, AM650, FM328 na FM476), na **masafa kadhaa muhimu** yaliyohifadhiwa:

<figure><img src="../../../.gitbook/assets/image (947).png" alt=""><figcaption></figcaption></figure>

Unaweza kuweka **yoyote inayokuvutia**, hata hivyo, ikiwa **hujui ni masafa gani** yanaweza kuwa yanayotumiwa na remote ulionayo, **weka Hopping kuwa ON** (Off kwa chaguo-msingi), na bonyeza kitufe mara kadhaa hadi Flipper ikiteka na kukupa habari unayohitaji kuweka masafa.

{% hint style="danger" %}
Kubadilisha kati ya masafa kunachukua muda, kwa hivyo ishara zinazotumwa wakati wa kubadilisha zinaweza kupuuziliwa mbali. Kwa kupokea ishara bora, weka masafa thabiti yaliyopangwa na Frequency Analyzer.
{% endhint %}

### **Read Raw**

{% hint style="info" %}
Pora (na rudia) ishara katika masafa yaliyosanidiwa
{% endhint %}

Chaguo la **Read Raw** **linarekodi ishara** zinazotumwa katika masafa yanayosikilizwa. Hii inaweza kutumika **kuiba** ishara na **kurudia** hiyo.

Kwa chaguo-msingi **Read Raw pia iko katika 433.92 katika AM650**, lakini ikiwa kwa chaguo la Read umepata kuwa ishara inayokuvutia iko katika **masafa/modulation tofauti, unaweza pia kubadilisha hiyo** kwa kubonyeza kushoto (wakati uko ndani ya chaguo la Read Raw).

### Brute-Force

Ikiwa unajua itifaki inayotumiwa kwa mfano na mlango wa garaji inawezekana **kuunda nambari zote na kuzituma kwa Flipper Zero.** Hii ni mfano unaounga mkono aina za kawaida za garages: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

{% hint style="info" %}
Ongeza ishara kutoka orodha iliyosanidiwa ya itifaki
{% endhint %}

#### Orodha ya [itifaki zinazoungwa mkono](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (inafanya kazi na mfumo wa nambari za statiki nyingi) | 433.92 | Statiki  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | Statiki  |
| Nice Flo 24bit\_433                                             | 433.92 | Statiki  |
| CAME 12bit\_433                                                 | 433.92 | Statiki  |
| CAME 24bit\_433                                                 | 433.92 | Statiki  |
| Linear\_300                                                     | 300.00 | Statiki  |
| CAME TWEE                                                       | 433.92 | Statiki  |
| Gate TX\_433                                                    | 433.92 | Statiki  |
| DoorHan\_315                                                    | 315.00 | Dinamiki |
| DoorHan\_433                                                    | 433.92 | Dinamiki |
| LiftMaster\_315                                                 | 315.00 | Dinamiki |
| LiftMaster\_390                                                 | 390.00 | Dinamiki |
| Security+2.0\_310                                               | 310.00 | Dinamiki |
| Security+2.0\_315                                               | 315.00 | Dinamiki |
| Security+2.0\_390                                               | 390.00 | Dinamiki |

### Wauzaji wa Sub-GHz wanaoungwa mkono

Angalia orodha katika [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Masafa yanayoungwa mkono kwa eneo

Angalia orodha katika [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Pata dBms za masafa yaliyohifadhiwa
{% endhint %}

## Reference

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
