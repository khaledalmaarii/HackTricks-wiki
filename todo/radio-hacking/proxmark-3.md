# Proxmark 3

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Aanvalle op RFID-stelsels met Proxmark3

Die eerste ding wat jy moet doen, is om 'n [**Proxmark3**](https://proxmark.com) te hê en [**die sagteware te installeer en sy afhanklikhede**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Aanvalle op MIFARE Classic 1KB

Dit het **16 sektore**, elk met **4 blokke** en elke blok bevat **16B**. Die UID is in sektor 0 blok 0 (en kan nie verander word nie).\
Om toegang te verkry tot elke sektor, het jy **2 sleutels** (**A** en **B**) nodig wat in **blok 3 van elke sektor** (sektor-trailer) gestoor word. Die sektor-trailer stoor ook die **toegangsbits** wat die **lees- en skryfregte** op **elke blok** gee deur die 2 sleutels te gebruik.\
2 sleutels is nuttig om leesregte te gee as jy die eerste een ken en skryfregte as jy die tweede een ken (byvoorbeeld).

Verskeie aanvalle kan uitgevoer word
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Die Proxmark3 maak dit moontlik om ander aksies uit te voer, soos die **afluistering** van 'n **Tag to Reader kommunikasie** om te probeer om sensitiewe data te vind. Op hierdie kaart kan jy net die kommunikasie afluister en die gebruikte sleutel bereken omdat die **kriptografiese operasies wat gebruik word, swak is** en deur die plain en cipher teks te ken, kan jy dit bereken (`mfkey64` instrument).

### Rou Bevele

IoT-stelsels gebruik soms **nie-handelsmerk of nie-kommersiële etikette**. In hierdie geval kan jy die Proxmark3 gebruik om aangepaste **rou bevele na die etikette** te stuur.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Met hierdie inligting kan jy probeer om inligting oor die kaart en die manier waarop dit kommunikeer, te soek. Proxmark3 maak dit moontlik om rou bevele te stuur soos: `hf 14a raw -p -b 7 26`

### Skripte

Die Proxmark3 sagteware kom met 'n voorgelaaide lys van **outomatiseringsskripte** wat jy kan gebruik om eenvoudige take uit te voer. Om die volledige lys te herwin, gebruik die `script list` bevel. Gebruik daarna die `script run` bevel, gevolg deur die naam van die skrip:
```
proxmark3> script run mfkeys
```
Jy kan 'n skripsie skep om **etiketlesers te fuzz**, deur die data van 'n **geldige kaart** te kopieer en 'n **Lua-skripsie** te skryf wat een of meer **willekeurige byte** randomiseer en nagaan of die **leser crasht** met enige iterasie.

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is, sodat jy hulle vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit en vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm\_campaign=hacktricks&utm\_source=referral" %}


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
