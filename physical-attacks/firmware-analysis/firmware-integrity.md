<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Uadilifu wa Firmware

**Firmware ya kawaida na/au faili za kutekelezwa zinaweza kupakiwa ili kudukua uadilifu au kasoro za uthibitisho wa saini**. Hatua zifuatazo zinaweza kufuatwa kwa ajili ya kujenga backdoor bind shell:

1. Firmware inaweza kuchimbwa kutumia firmware-mod-kit (FMK).
2. Kiwango cha usanifu wa firmware na endianness inapaswa kutambuliwa.
3. Compiler ya msalaba inaweza kujengwa kwa kutumia Buildroot au njia nyingine inayofaa kwa mazingira.
4. Backdoor inaweza kujengwa kwa kutumia compiler ya msalaba.
5. Backdoor inaweza kunakiliwa kwenye saraka ya /usr/bin ya firmware iliyochimbwa.
6. Binary sahihi ya QEMU inaweza kunakiliwa kwenye rootfs ya firmware iliyochimbwa.
7. Backdoor inaweza kufanywa kwa kutumia chroot na QEMU.
8. Backdoor inaweza kufikiwa kupitia netcat.
9. Binary ya QEMU inapaswa kuondolewa kutoka kwenye rootfs ya firmware iliyochimbwa.
10. Firmware iliyobadilishwa inaweza kufungwa tena kwa kutumia FMK.
11. Firmware iliyo na backdoor inaweza kujaribiwa kwa kuiiga na kutumia zana ya uchambuzi wa firmware (FAT) na kuunganisha kwenye IP na bandari ya backdoor ya lengo kwa kutumia netcat.

Ikiwa tayari kuna shell ya mizizi kupitia uchambuzi wa kina, upangaji wa bootloader, au upimaji wa usalama wa vifaa, faili za kutekelezwa zenye nia mbaya kama implants au reverse shells zinaweza kutekelezwa. Zana za malipo/implant za moja kwa moja kama mfumo wa Metasploit na 'msfvenom' zinaweza kutumika kwa kutumia hatua zifuatazo:

1. Kiwango cha usanifu wa firmware na endianness inapaswa kutambuliwa.
2. Msfvenom inaweza kutumika kuweka malipo ya lengo, IP ya mwenye shambulio, nambari ya bandari ya kusikiliza, aina ya faili, usanifu, jukwaa, na faili ya matokeo.
3. Malipo yanaweza kuhamishwa kwenye kifaa kilichodhulumiwa na kuhakikisha kuwa ina ruhusa ya utekelezaji.
4. Metasploit inaweza kujiandaa kushughulikia maombi yanayokuja kwa kuanza msfconsole na kusanidi mipangilio kulingana na malipo.
5. Shell ya nyuma ya meterpreter inaweza kutekelezwa kwenye kifaa kilichodhulumiwa.
6. Vikao vya meterpreter vinaweza kufuatiliwa wanapofunguliwa.
7. Shughuli za baada ya kudukua zinaweza kutekelezwa.

Ikiwa inawezekana, kasoro ndani ya skripti za kuanza zinaweza kutumika kudukua kupata ufikiaji endelevu kwenye kifaa hata baada ya kuanza upya. Kasoro hizi hutokea wakati skripti za kuanza zinarejelea, [kiungo kwa njia ya ishara](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), au kutegemea nambari iliyoko kwenye maeneo yaliyosakinishwa ambayo hayawezi kuaminika kama kadi za SD na sehemu za flash zinazotumiwa kuhifadhi data nje ya mfumo wa mizizi.

## Marejeo
* Kwa habari zaidi angalia [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
