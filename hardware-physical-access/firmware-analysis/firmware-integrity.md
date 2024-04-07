<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Uadilifu wa Firmware

**Firmware ya kawaida na/au programu za kutekelezwa zinaweza kupakiwa ili kutumia kasoro za uadilifu au uthibitisho wa saini**. Hatua zifuatazo zinaweza kufuatwa kwa ajili ya ujenzi wa mlango wa nyuma wa bind shell:

1. Firmware inaweza kuchimbuliwa kutumia kit ya firmware-mod-kit (FMK).
2. Mimariri ya firmware ya lengo na endianness inapaswa kutambuliwa.
3. Compiler ya msalaba inaweza kujengwa kutumia Buildroot au njia zingine zinazofaa kwa mazingira.
4. Mlango wa nyuma unaweza kujengwa kutumia compiler ya msalaba.
5. Mlango wa nyuma unaweza kunakiliwa kwenye saraka ya /usr/bin ya firmware iliyochimbuliwa.
6. Binary sahihi ya QEMU inaweza kunakiliwa kwenye rootfs ya firmware iliyochimbuliwa.
7. Mlango wa nyuma unaweza kufuatwa kwa kutumia chroot na QEMU.
8. Mlango wa nyuma unaweza kupatikana kupitia netcat.
9. Binary ya QEMU inapaswa kuondolewa kutoka kwenye rootfs ya firmware iliyochimbuliwa.
10. Firmware iliyobadilishwa inaweza kufungwa upya kutumia FMK.
11. Firmware iliyowekewa mlango wa nyuma inaweza kujaribiwa kwa kuiiga na zana ya uchambuzi wa firmware (FAT) na kuunganisha kwenye IP na bandari ya mlango wa nyuma wa lengo kwa kutumia netcat.

Ikiwa kabla tayari mlango wa mizizi umepatikana kupitia uchambuzi wa kudukua, upangaji wa bootloader, au vipimo vya usalama wa vifaa, programu hasidi zilizopangwa mapema kama vile implants au reverse shells zinaweza kutekelezwa. Zana za mzigo/implant zilizoautomatishwa kama fremu ya Metasploit na 'msfvenom' zinaweza kutumika kwa kutumia hatua zifuatazo:

1. Mimariri ya firmware ya lengo na endianness inapaswa kutambuliwa.
2. Msfvenom inaweza kutumika kutaja mzigo wa lengo, IP ya mwenye shambulio, nambari ya bandari ya kusikiliza, aina ya faili, mimariri, jukwaa, na faili ya pato.
3. Mzigo unaweza kuhamishwa kwenye kifaa kilichoharibiwa na kuhakikisha kuwa ina ruhusa za utekelezaji.
4. Metasploit inaweza kuandaliwa kushughulikia maombi yanayoingia kwa kuanza msfconsole na kusanidi mipangilio kulingana na mzigo.
5. Mfumo wa nyuma wa meterpreter unaweza kutekelezwa kwenye kifaa kilichoharibiwa.
6. Vikao vya meterpreter vinaweza kufuatiliwa wanapofunguliwa.
7. Shughuli za baada ya kudukua zinaweza kutekelezwa.

Ikiwezekana, kasoro ndani ya skripti za kuanza zinaweza kutumika kudukua kupata ufikivu endelevu kwenye kifaa kila baada ya kuanza upya. Kasoro hizi hutokea wakati skripti za kuanza zinarejelea, [kiungo cha ishara](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), au kutegemea nambari iliyoko kwenye maeneo yaliyofungwa kama vile kadi za SD na voli za flash zinazotumiwa kuhifadhi data nje ya mifumo ya mizizi.

## Marejeo
* Kwa habari zaidi angalia [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
