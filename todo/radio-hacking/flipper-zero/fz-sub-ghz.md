# FZ - Sub-GHz

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Inleiding <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero kan **radiofrekwensies in die reeks van 300-928 MHz ontvang en uitsaai** met sy ingeboude module, wat afstandsbeheerders kan lees, stoor en naboots. Hierdie beheerders word gebruik vir interaksie met hekke, versperrings, radio-slotte, afstandsbeheer-sakelaars, draadlose deurklokkies, slim ligte, en meer. Flipper Zero kan jou help om te leer of jou sekuriteit gekompromitteer is.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardeware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero het 'n ingeboude sub-1 GHz module gebaseer op 'n [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101-skyf](https://www.ti.com/lit/ds/symlink/cc1101.pdf) en 'n radio-antenne (die maksimum reikafstand is 50 meter). Beide die CC1101-skyf en die antenne is ontwerp om te werk by frekwensies in die 300-348 MHz, 387-464 MHz, en 779-928 MHz bande.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Aksies

### Frekwensie Analiseerder

{% hint style="info" %}
Hoe om te vind watter frekwensie die afstandsbeheerder gebruik
{% endhint %}

Tydens analiseer skandeer Flipper Zero seine sterkte (RSSI) by al die beskikbare frekwensies in frekwensie-konfigurasie. Flipper Zero wys die frekwensie met die hoogste RSSI-waarde, met seinsterkte hoër as -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Om die frekwensie van die afstandsbeheerder te bepaal, doen die volgende:

1. Plaas die afstandsbeheerder baie naby aan die linkerkant van Flipper Zero.
2. Gaan na **Hoofmenu** **→ Sub-GHz**.
3. Kies **Frekwensie Analiseerder**, druk dan die knoppie op die afstandsbeheerder wat jy wil analiseer.
4. Kyk na die frekwensiewaarde op die skerm.

### Lees

{% hint style="info" %}
Vind inligting oor die gebruikte frekwensie (ook 'n ander manier om te vind watter frekwensie gebruik word)
{% endhint %}

Die **Lees**-opsie **luister na die gekonfigureerde frekwensie** op die aangeduide modulasie: 433.92 AM standaard. As **iets gevind word** tydens die lees, word **inligting gegee** op die skerm. Hierdie inligting kan gebruik word om die sein in die toekoms te dupliseer.

Terwyl Lees in gebruik is, is dit moontlik om die **linker knoppie** te druk en dit te **konfigureer**.\
Op hierdie oomblik het dit **4 modulasies** (AM270, AM650, FM328 en FM476), en **verskeie relevante frekwensies** gestoor:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Jy kan **enige een wat jou interesseer** instel, maar as jy **nie seker is watter frekwensie** die een is wat deur die afstandsbeheerder gebruik word nie, **stel Hopping aan** (Standaard af) en druk die knoppie verskeie kere totdat Flipper dit vasvang en jou die inligting gee wat jy nodig het om die frekwensie in te stel.

{% hint style="danger" %}
Oorskakeling tussen frekwensies neem 'n rukkie, daarom kan seine wat tydens die oorskakeling uitgesaai word, gemis word. Stel vir beter seinontvangs 'n vaste frekwensie vas wat deur die Frekwensie Analiseerder bepaal is.
{% endhint %}

### **Lees Rou**

{% hint style="info" %}
Steel (en speel weer) 'n sein in die gekonfigureerde frekwensie
{% endhint %}

Die **Lees Rou**-opsie **neem seine op** wat in die luisterfrekwensie gestuur word. Dit kan gebruik word om 'n sein te **steel** en dit **te herhaal**.

Standaard is **Lees Rou ook in 433.92 in AM650**, maar as jy met die Lees-opsie gevind het dat die sein wat jou interesseer in 'n **ander frekwensie/modulasie is, kan jy dit ook wysig** deur links te druk (terwyl jy binne die Lees Rou-opsie is).

### Brute-Krag

As jy die protokol ken wat byvoorbeeld deur die motorhuisdeur gebruik word, is dit moontlik om **alle kodes te genereer en hulle met die Flipper Zero te stuur.** Hierdie is 'n voorbeeld wat algemene tipes motorhuise ondersteun: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Voeg Handmatig By

{% hint style="info" %}
Voeg seine by vanaf 'n gekonfigureerde lys van protokolle
{% endhint %}

#### Lys van [ondersteunde protokolle](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (werk met die meeste statiese kode-stelsels) | 433.92 | Statisch  |
| ---------------------------------------------------------- | ------ | --------- |
| Nice Flo 12bit\_433                                        | 433.92 | Statisch  |
| Nice Flo 24bit\_433                                        | 433.92 | Statisch  |
| CAME 12bit\_433                                            | 433.92 | Statisch  |
| CAME 24bit\_433                                            | 433.92 | Statisch  |
| Linear\_300                                                | 300.00 | Statisch  |
| CAME TWEE                                                  | 433.92 | Statisch  |
| Gate TX\_433                                               | 433.92 | Statisch  |
| DoorHan\_315                                               | 315.00 | Dinamies  |
| DoorHan\_433                                               | 433.92 | Dinamies  |
| LiftMaster\_315                                            | 315.00 | Dinamies  |
| LiftMaster\_390                                            | 390.00 | Dinamies  |
| Security+2.0\_310                                          | 310.00 | Dinamies  |
| Security+2.0\_315                                          | 315.00 | Dinamies  |
| Security+2.0\_390                                          | 390.00 | Dinamies  |
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

**Probeer Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
