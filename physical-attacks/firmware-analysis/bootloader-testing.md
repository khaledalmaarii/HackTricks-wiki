<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

Hatua zifuatazo zinapendekezwa kwa kubadilisha mipangilio ya kuanza kifaa na bootloaders kama U-boot:

1. **Pata Shell ya Tafsiri ya Bootloader**:
- Wakati wa kuanza, bonyeza "0", nafasi, au "codes" nyingine zilizotambuliwa kuipata shell ya tafsiri ya bootloader.

2. **Badilisha Hoja za Kuanza**:
- Tekeleza amri zifuatazo kuongeza '`init=/bin/sh`' kwenye hoja za kuanza, kuruhusu utekelezaji wa amri ya shell:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Sanidi Seva ya TFTP**:
- Sanidi seva ya TFTP ili kupakia picha kupitia mtandao wa ndani:
%%%
#setenv ipaddr 192.168.2.2 #IP ya ndani ya kifaa
#setenv serverip 192.168.2.1 #IP ya seva ya TFTP
#saveenv
#reset
#ping 192.168.2.1 #angalia ufikiaji wa mtandao
#tftp ${loadaddr} uImage-3.6.35 #loadaddr inachukua anwani ya kupakia faili na jina la faili ya picha kwenye seva ya TFTP
%%%

4. **Tumia `ubootwrite.py`**:
- Tumia `ubootwrite.py` kuandika picha ya U-boot na kusukuma firmware iliyobadilishwa kupata ufikiaji wa msingi.

5. **Angalia Vipengele vya Kurekebisha**:
- Thibitisha ikiwa vipengele vya kurekebisha kama kuingiza kumbukumbu za kina, kupakia mifumo ya uendeshaji isiyojulikana, au kuanza kutoka vyanzo visivyotegemewa vimeamilishwa.

6. **Tahadhari ya Kuingilia Vifaa**:
- Kuwa mwangalifu unapounganisha pini moja na ardhi na kuingiliana na vifaa vya SPI au NAND flash wakati wa mfululizo wa kuanza kifaa, haswa kabla ya kernel kujazwa. Angalia karatasi ya data ya chip ya NAND flash kabla ya kufupisha pini.

7. **Sanidi Seva ya DHCP ya Udanganyifu**:
- Sanidi seva ya DHCP ya udanganyifu na vigezo vya uovu kwa kifaa kuingiza wakati wa kuanza kwa PXE. Tumia zana kama seva ya ziada ya DHCP ya Metasploit (MSF). Badilisha parameter 'FILENAME' na amri za kuingiza amri kama `'a";/bin/sh;#'` ili jaribu ukaguzi wa kuingiza kwa taratibu za kuanza kifaa.

**Note**: Hatua zinazohusisha kuingiliana kimwili na pini za kifaa (*zilizowekwa alama na asterisk) zinapaswa kufanywa kwa tahadhari kubwa ili kuepuka kuharibu kifaa.


## Marejeo
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
