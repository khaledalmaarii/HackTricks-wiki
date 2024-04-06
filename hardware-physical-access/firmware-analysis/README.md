# Firmware Analysis

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## **Utangulizi**

Firmware ni programu muhimu ambayo inawezesha vifaa kufanya kazi kwa usahihi kwa kusimamia na kurahisisha mawasiliano kati ya sehemu za vifaa na programu ambayo watumiaji wanashirikiana nayo. Inahifadhiwa kwenye kumbukumbu ya kudumu, ikiruhusu kifaa kupata maagizo muhimu tangu wakati wa kuwasha, na kusababisha uzinduzi wa mfumo wa uendeshaji. Kuchunguza na kubadilisha firmware ni hatua muhimu katika kutambua udhaifu wa usalama.

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali katika kuelewa muundo wa kifaa na teknolojia inayotumia. Mchakato huu unahusisha kukusanya data kuhusu:

* Muundo wa CPU na mfumo wa uendeshaji unaotumia
* Maelezo ya bootloader
* Mpangilio wa vifaa na datasheets
* Takwimu za msingi za nambari na maeneo ya chanzo
* Maktaba za nje na aina za leseni
* Historia za sasisho na vyeti vya udhibiti
* Mchoro wa muundo na mchoro wa mzunguko
* Tathmini za usalama na udhaifu ulioainishwa

Kwa kusudi hili, zana za **open-source intelligence (OSINT)** ni muhimu, pamoja na uchambuzi wa vipengele vya programu zinazopatikana kupitia mchakato wa ukaguzi wa mwongozo na wa kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) zinatoa uchambuzi wa kiwango cha juu ambao unaweza kutumika kutambua masuala yanayowezekana.

## **Kupata Firmware**

Kupata firmware kunaweza kufanywa kupitia njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

* **Moja kwa moja** kutoka chanzo (watengenezaji, watengenezaji)
* **Kuijenga** kutoka kwa maelekezo yaliyotolewa
* **Kupakua** kutoka kwenye tovuti rasmi za msaada
* Kutumia **Google dork** kuangalia faili za firmware zilizohifadhiwa
* Kupata ufikiaji wa **hifadhi ya wingu** moja kwa moja, kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
* Kuingilia **sasisho** kupitia mbinu za man-in-the-middle
* **Kuondoa** kutoka kifaa kupitia uhusiano kama **UART**, **JTAG**, au **PICit**
* **Kuchunguza** ombi la sasisho ndani ya mawasiliano ya kifaa
* Kutambua na kutumia **vifaa vya sasisho vilivyowekwa kwa nguvu**
* **Kuchukua** kutoka kwa bootloader au mtandao
* **Kuondoa na kusoma** kichipu cha kuhifadhi, wakati njia zingine zote zimeshindwa, kwa kutumia zana sahihi za vifaa.

## Kuchambua firmware

Sasa **una firmware**, unahitaji kuchambua habari kuhusu hiyo ili ujue jinsi ya kuishughulikia. Zana tofauti unazoweza kutumia kwa hilo:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ikiwa hutapata mengi na zana hizo, angalia **entropy** ya picha na `binwalk -E <bin>`, ikiwa entropy ni ndogo, basi haiwezekani kuwa imefichwa. Ikiwa entropy ni kubwa, inawezekana kuwa imefichwa (au imepakwa kwa njia fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kuondoa **faili zilizojumuishwa ndani ya firmware**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kuangalia faili.

### Kupata Mfumo wa Faili

Kwa zana zilizotajwa hapo awali kama `binwalk -ev <bin>`, unapaswa kuweza **kuchimba mfumo wa faili**.\
Kawaida, binwalk huichimba ndani ya **folda iliyoitwa kama aina ya mfumo wa faili**, ambayo kawaida ni moja ya zifuatazo: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Uchimbaji wa Mfumo wa Faili kwa Mikono

Marafiki, binwalk **hawana herufi ya uchawi ya mfumo wa faili katika saini zao**. Katika kesi hizi, tumia binwalk ku **kupata nafasi ya mfumo wa faili na kuchimba mfumo wa faili uliopakwa kutoka kwenye faili ya binary na kuchimba mfumo wa faili kwa mikono** kulingana na aina yake kwa kutumia hatua zifuatazo.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Chalaza amri ifuatayo ya **dd** ikichonga mfumo wa faili wa Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Kwa upande mwingine, amri ifuatayo inaweza pia kutekelezwa.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Kwa squashfs (ilitumiwa katika mfano hapo juu)

`$ unsquashfs dir.squashfs`

Faili zitakuwa katika saraka ya "`squashfs-root`" baadaye.

* Faili za kumbukumbu za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Kwa mfumo wa jffs2

`$ jefferson rootfsfile.jffs2`

* Kwa mfumo wa ubifs na NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Uchambuzi wa Firmware

Baada ya kupata firmware, ni muhimu kuchambua kwa kina muundo wake na udhaifu wake. Mchakato huu unahusisha kutumia zana mbalimbali kuchambua na kutoa data muhimu kutoka kwenye picha ya firmware.

### Zana za Uchambuzi wa Awali

Seti ya amri zinapatikana kwa ukaguzi wa awali wa faili ya binary (inayojulikana kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa herufi, kuchambua data ya binary, na kuelewa maelezo ya kugawanya na mfumo wa faili:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Kuamua hali ya kusimbwa kwa picha, **entropy** inachunguzwa kwa kutumia `binwalk -E <bin>`. Entropy ndogo inaonyesha ukosefu wa kusimbwa, wakati entropy kubwa inaashiria uwezekano wa kusimbwa au kusagwa.

Kwa ajili ya kuchimbua **faili zilizojumuishwa**, zana na rasilimali kama **file-data-carving-recovery-tools** na hati ya **binvis.io** kwa ukaguzi wa faili zinapendekezwa.

### Kuchimbua Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida unaweza kuchimbua mfumo wa faili, mara nyingi kwenye saraka iliyoitwa kwa jina la aina ya mfumo wa faili (k.m., squashfs, ubifs). Hata hivyo, wakati **binwalk** inashindwa kutambua aina ya mfumo wa faili kutokana na kuwepo kwa herufi za uchawi zilizokosekana, uchimbuzi wa mwongozo unahitajika. Hii inahusisha kutumia `binwalk` ili kupata mahali pa mfumo wa faili, kisha kutumia amri ya `dd` ili kuchimba mfumo wa faili:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Baadaye, kulingana na aina ya mfumo wa faili (k.m., squashfs, cpio, jffs2, ubifs), amri tofauti hutumiwa kuchambua maudhui kwa mkono.

### Uchambuzi wa Mfumo wa Faili

Baada ya mfumo wa faili kuchambuliwa, utafutaji wa kasoro za usalama unaanza. Tahadhari inalipwa kwa daemons dhaifu za mtandao, vitambulisho vya uthibitishaji vilivyowekwa ngumu, vituo vya API, utendaji wa seva ya sasisho, nambari isiyokamilika, hati za kuanza, na programu zilizokamilishwa kwa uchambuzi nje ya mtandao.

**Maeneo muhimu** na **vitengo** vya ukaguzi ni pamoja na:

* **etc/shadow** na **etc/passwd** kwa vitambulisho vya mtumiaji
* Vyeti vya SSL na funguo katika **etc/ssl**
* Faili za usanidi na hati za hatari za uwezekano
* Programu zilizojumuishwa kwa uchambuzi zaidi
* Seva za wavuti za kifaa cha IoT na programu zilizokamilishwa

Zana kadhaa zinasaidia kugundua habari nyeti na kasoro za usalama ndani ya mfumo wa faili:

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa utafutaji wa habari nyeti
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) kwa uchambuzi kamili wa firmware
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa uchambuzi wa tuli na wa kudumu

### Ukaguzi wa Usalama kwenye Programu Zilizokamilishwa

Nambari chanzo na programu zilizokamilishwa zilizopatikana kwenye mfumo wa faili lazima ziangaliwe kwa kasoro za usalama. Zana kama **checksec.sh** kwa programu za Unix na **PESecurity** kwa programu za Windows husaidia kutambua programu zisizolindwa ambazo zinaweza kudukuliwa.

## Kuiga Firmware kwa Uchambuzi wa Kudumu

Mchakato wa kuiga firmware unawezesha **uchambuzi wa kudumu** wa uendeshaji wa kifaa au programu binafsi. Njia hii inaweza kukabili changamoto za vifaa au utegemezi wa usanifu, lakini kuhamisha mfumo wa faili wa msingi au programu maalum kwa kifaa chenye usanifu na mwisho unaolingana, kama Raspberry Pi, au kwa mashine ya kawaida iliyoundwa mapema, inaweza kurahisisha majaribio zaidi.

### Kuiga Programu Binafsi

Kwa kuchunguza programu moja, ni muhimu kutambua mwisho wa programu na usanifu wa CPU.

#### Mfano na Usanifu wa MIPS

Kuiga programu ya usanifu wa MIPS, mtu anaweza kutumia amri:

```bash
file ./squashfs-root/bin/busybox
```

Na kufunga zana za uigaji muundo zinazohitajika:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Kwa MIPS (big-endian), `qemu-mips` hutumiwa, na kwa mipangilio midogo ya mwisho, `qemu-mipsel` ndiyo chaguo sahihi.

#### Uwakilishi wa Mimarobota wa ARM

Kwa mipangilio ya ARM, mchakato ni sawa, na emulator ya `qemu-arm` hutumiwa kwa uwakilishi.

### Uwakilishi Kamili wa Mfumo

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na zingine, hufanikisha uwakilishi kamili wa firmware, kwa kiotomatiki mchakato na kusaidia katika uchambuzi wa kina.

## Uchambuzi wa Muda wa Uendeshaji katika Vitendo

Katika hatua hii, mazingira halisi au yaliyowakilishwa ya kifaa hutumiwa kwa uchambuzi. Ni muhimu kuwa na ufikiaji wa kabati kwenye mfumo wa uendeshaji na mfumo wa faili. Uwakilishi huenda usiwe kamili katika kuiga mwingiliano wa vifaa, na hivyo kuhitaji kuanza upya kwa uwakilishi mara kwa mara. Uchambuzi unapaswa kuzingatia mfumo wa faili, kutumia kurasa za wavuti na huduma za mtandao zilizofichuliwa, na kuchunguza udhaifu wa bootloader. Vipimo vya ukamilifu wa firmware ni muhimu ili kutambua udhaifu wa mlango wa nyuma.

## Mbinu za Uchambuzi wa Muda wa Uendeshaji

Uchambuzi wa muda wa uendeshaji unahusisha kuingiliana na mchakato au faili katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida, na Ghidra kwa kuweka alama za kusimamisha na kutambua udhaifu kupitia mbinu za fuzzing na zingine.

## Ushambuliaji wa Faili na Uthibitisho wa Wazo

Kuendeleza Wazo la Uthibitisho (PoC) kwa udhaifu uliogunduliwa kunahitaji uelewa wa kina wa muundo wa lengo na programu katika lugha za kiwango cha chini. Ulinzi wa faili wa muda wa uendeshaji katika mifumo iliyowekwa ni nadra, lakini wakati unapokuwepo, mbinu kama Return Oriented Programming (ROP) inaweza kuwa muhimu.

## Mifumo ya Uendeshaji Tayari kwa Uchambuzi wa Firmware

Mifumo ya uendeshaji kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyowekwa tayari kwa ajili ya upimaji wa usalama wa firmware, ikiwa na zana muhimu.

## Mifumo ya Uendeshaji Tayari kwa Uchambuzi wa Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni mfumo wa usambazaji uliokusudiwa kukusaidia kufanya tathmini ya usalama na upenyezaji wa vifaa vya Intaneti ya Vitu (IoT). Inakusaidia kuokoa muda kwa kutoa mazingira yaliyowekwa tayari na zana zote muhimu.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Mfumo wa uendeshaji wa upimaji wa usalama wa vifaa vilivyowekwa kwenye Ubuntu 18.04 uliojaa zana za upimaji wa usalama wa firmware.

## Firmware Zenye Udhaifu kwa Mazoezi

Ili kufanya mazoezi ya kugundua udhaifu katika firmware, tumia miradi ifuatayo ya firmware yenye udhaifu kama mwanzo.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Marejeo

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Mafunzo na Cheti

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**]\(https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
