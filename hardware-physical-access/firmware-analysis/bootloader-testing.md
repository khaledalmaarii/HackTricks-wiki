<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

Hatua zifuatazo zinapendekezwa kwa kubadilisha mipangilio ya kuanza kifaa na bootloaders kama U-boot:

1. **Fikia Shell ya Mfasiri wa Bootloader**:
- Wakati wa kuanza, bonyeza "0", nafasi, au nambari nyingine za "mambo ya ajabu" zilizotambuliwa kufikia shell ya mfasiri wa bootloader.

2. **Badilisha Vigezo vya Kuanza**:
- Tekeleza amri zifuatazo kuongeza '`init=/bin/sh`' kwenye vigezo vya kuanza, kuruhusu utekelezaji wa amri ya shell:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Sanidi Seva ya TFTP**:
- Sanidi seva ya TFTP kupakia picha kupitia mtandao wa ndani:
%%%
#setenv ipaddr 192.168.2.2 #IP ya ndani ya kifaa
#setenv serverip 192.168.2.1 #IP ya seva ya TFTP
#saveenv
#reset
#ping 192.168.2.1 #angalia ufikivu wa mtandao
#tftp ${loadaddr} uImage-3.6.35 #loadaddr inachukua anwani ya kupakia faili na jina la faili la picha kwenye seva ya TFTP
%%%

4. **Tumia `ubootwrite.py`**:
- Tumia `ubootwrite.py` kuandika picha ya U-boot na kusukuma firmware iliyobadilishwa kupata ufikiaji wa mizizi.

5. **Angalia Vipengele vya Kurekebisha**:
- Thibitisha ikiwa vipengele vya kurekebisha kama kuingiza kumbukumbu za maelezo, kupakia miundombinu isiyojulikana, au kuanza kutoka vyanzo visivyoaminika vimezimwa.

6. **Uingiliaji wa Vifaa kwa Tahadhari**:
- Kuwa mwangalifu unapounganisha pini moja na ardhi na kuingiliana na vifaa vya SPI au NAND flash wakati wa mfululizo wa kuanza wa kifaa, hasa kabla ya kernel kufyonzua. Shauriana na karatasi ya data ya NAND flash kabla ya kufupisha pini.

7. **Sanidi Seva ya DHCP ya Kijanja**:
- Sanidi seva ya DHCP ya kijanja na vigezo vya madhara kwa kifaa kuingiza wakati wa kuanza kwa PXE. Tumia zana kama seva ya msaidizi ya DHCP ya Metasploit (MSF). Badilisha parameter 'FILENAME' na amri za kuingiza amri kama `'a";/bin/sh;#'` kufanya majaribio ya uthibitishaji wa kuingiza kwa taratibu za kuanza kifaa.

**Maelezo**: Hatua zinazohusisha uingiliano wa kimwili na pini za kifaa (*zilizochorwa na asterisks) zinapaswa kufikiriwa kwa tahadhari kali ili kuepuka kuharibu kifaa.


## Marejeo
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
