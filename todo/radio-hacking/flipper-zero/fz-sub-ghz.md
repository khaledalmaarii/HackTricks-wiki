# FZ - Sub-GHz

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Inleiding <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero kan **radiofrekwensies in die reeks van 300-928 MHz ontvang en uitsaai** met sy ingeboude module, wat afstandsbeheerders kan lees, stoor en naboots. Hierdie beheerders word gebruik vir interaksie met hekke, versperrings, radioslote, afstandsbeheerskakelaars, draadlose deurklokkies, slim ligte en meer. Flipper Zero kan jou help om uit te vind of jou sekuriteit in gedrang is.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardeware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero het 'n ingeboude sub-1 GHz-module gebaseer op 'n [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101-skyf](https://www.ti.com/lit/ds/symlink/cc1101.pdf) en 'n radio-antenne (die maksimum reikafstand is 50 meter). Beide die CC1101-skyf en die antenne is ontwerp om te werk by frekwensies in die 300-348 MHz, 387-464 MHz en 779-928 MHz-bande.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Aksies

### Frekwensie-analiseerder

{% hint style="info" %}
Hoe om uit te vind watter frekwensie die afstandsbeheerder gebruik
{% endhint %}

Wanneer Flipper Zero geanaliseer word, skandeer dit seine se sterkte (RSSI) by al die beskikbare frekwensies in die frekwensiekonfigurasie. Flipper Zero wys die frekwensie met die hoogste RSSI-waarde, met 'n seinsterkte hoër as -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Om die frekwensie van die afstandsbeheerder te bepaal, doen asseblief die volgende:

1. Plaas die afstandsbeheerder baie naby aan die linkerkant van Flipper Zero.
2. Gaan na **Hoofmenu** **→ Sub-GHz**.
3. Kies **Frekwensie-analiseerder**, druk dan die knoppie op die afstandsbeheerder wat jy wil analiseer.
4. Kyk na die frekwensiewaarde op die skerm.

### Lees

{% hint style="info" %}
Vind inligting oor die gebruikte frekwensie (ook 'n ander manier om uit te vind watter frekwensie gebruik word)
{% endhint %}

Die **Lees**-opsie **luister na die gekonfigureerde frekwensie** met die aangeduide modulasie: 433.92 AM as verstek. As daar **iets gevind word** tydens die lees, word **inligting gegee** op die skerm. Hierdie inligting kan gebruik word om die sein in die toekoms te dupliseer.

Terwyl Lees in gebruik is, is dit moontlik om die **linkerknoppie** te druk en dit te **konfigureer**.\
Op hierdie oomblik het dit **4 modulasies** (AM270, AM650, FM328 en FM476), en **verskeie relevante frekwensies** wat gestoor is:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Jy kan **enigeen wat jou interesseer** instel, maar as jy **nie seker is watter frekwensie** die een is wat deur die afstandsbeheerder gebruik word nie, **stel Hopping aan** (Standaard af) en druk die knoppie verskeie kere totdat Flipper dit vasvang en die inligting gee wat jy nodig het om die frekwensie in te stel.

{% hint style="danger" %}
Oorskakeling tussen frekwensies neem 'n rukkie, daarom kan seine wat tydens die oorskakeling uitgesaai word, gemis word. Stel 'n vasgestelde frekwensie wat deur die Frekwensie-analiseerder bepaal is, in vir beter seinontvangs.
{% endhint %}

### **Lees Raw**

{% hint style="info" %}
Steel (en herhaal) 'n sein in die gekonfigureerde frekwensie
{% endhint %}

Die **Lees Raw**-opsie **neem seine op** wat in die luisterfrekwensie gestuur word. Dit kan gebruik word om 'n sein te **steel** en dit te **herhaal**.

Standaard is **Lees Raw ook in 433.92 in AM650**, maar as jy met die Lees-opsie gevind het dat die sein wat jou interesseer in 'n **ander frekwensie/modulasie is, kan jy dit ook wysig** deur links te druk (terwyl jy binne die Lees Raw-opsie is).

### Brute-Force

As jy die protokol ken wat byvoorbeeld deur die motorhuisdeur gebruik word, is dit moontlik om **alle kodes te genereer en hulle met die Flipper Zero te stuur.** Hierdie is 'n voorbeeld wat algemene tipes motorhuise ondersteun: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### Voeg handmatig by

{% hint style="info" %}
Voeg seine by van 'n gekonfigureerde lys protokolle
{% endhint %}

#### Lys van [ondersteunde protokolle](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (werk met die meeste statiese kodesisteme) | 433.92 | Statisch |
| ------------------------------------------------------- | ------ | -------- |
| Nice Flo 12bit\_433                                     | 433.92 | Statisch |
| Nice Flo 24bit\_433                                     | 433.92 | Statisch |
| CAME 12bit\_433                                         | 433.92 | Statisch |
| CAME 24bit\_433                                         | 433.92 | Statisch |
| Linear\_300                                             | 300.00 | Statisch |
| CAME TWEE                                               | 433.92 | Statisch |
| Gate TX\_433                                            | 433.92 | Statisch |
| DoorHan\_315                                            | 315.00 | Dinamies |
| DoorHan\_433                                            | 433.92 | Dinamies |
| LiftMaster\_315                                         | 315.00 | Dinamies |
| LiftMaster\_390                                         | 390.00 | Dinamies |
| Security
### Ondersteunde Sub-GHz-leweransiers

Kyk na die lys in [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Ondersteunde Frekwensies per streek

Kyk na die lys in [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Toets

{% hint style="info" %}
Kry dBms van die gestoorde frekwensies
{% endhint %}

## Verwysing

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
