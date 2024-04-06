# Android Forensics

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kifaa Kilichofungwa

Ili kuanza kuchambua data kutoka kifaa cha Android, lazima kiwe kimefunguliwa. Ikiwa kimefungwa, unaweza:

* Angalia ikiwa kifaa kina uwezo wa kudhibiti kupitia USB umewezeshwa.
* Angalia uwezekano wa [shambulio la kucha](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)
* Jaribu na [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Uchukuaji wa Data

Tengeneza [hifadhi ya Android kwa kutumia adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) na ichimbue kwa kutumia [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Ikiwa kuna ufikiaji wa mizizi au uhusiano wa kimwili na kiolesura cha JTAG

* `cat /proc/partitions` (tafuta njia ya kumbukumbu ya flash, kwa ujumla kuingia ya kwanza ni _mmcblk0_ na inalingana na kumbukumbu nzima ya flash).
* `df /data` (Gundua ukubwa wa kizuizi cha mfumo).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (itekeleze na habari uliyokusanya kutoka kwa ukubwa wa kizuizi).

### Kumbukumbu

Tumia Linux Memory Extractor (LiME) kuondoa habari ya RAM. Ni nyongeza ya kernel ambayo inapaswa kupakia kupitia adb.

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
