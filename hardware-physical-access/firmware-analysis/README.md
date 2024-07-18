# Uchambuzi wa Firmware

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **Utangulizi**

Firmware ni programu muhimu inayowezesha vifaa kufanya kazi kwa usahihi kwa kusimamia na kurahisisha mawasiliano kati ya vipengele vya vifaa na programu ambayo watumiaji wanashirikiana nayo. Imehifadhiwa kwenye kumbukumbu ya kudumu, ikahakikisha kifaa kinaweza kupata maagizo muhimu tangu kifunguliwe, ikisababisha uzinduzi wa mfumo wa uendeshaji. Kuchunguza na labda kurekebisha firmware ni hatua muhimu katika kutambua mapungufu ya usalama.

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali katika kuelewa muundo wa kifaa na teknolojia inayotumia. Mchakato huu unahusisha kukusanya data kuhusu:

* Miundo ya CPU na mfumo wa uendeshaji inayotumika
* Maelezo ya bootloader
* Mpangilio wa vifaa na datasheets
* Vigezo vya msingi vya kanuni na maeneo ya chanzo
* Maktaba za nje na aina za leseni
* Historia za sasisho na vyeti vya udhibiti
* Michoro ya usanifu na mifumo
* Tathmini za usalama na mapungufu yaliyotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu, kama vile uchambuzi wa vipengele vya programu zilizopo kupitia mchakato wa ukaguzi wa mwongozo na wa kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa uchambuzi wa tuli wa bure ambao unaweza kutumika kutambua masuala yanayowezekana.

## **Kupata Firmware**

Kupata firmware kunaweza kufikiwa kupitia njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

* **Moja kwa moja** kutoka kwa chanzo (waendelezaji, watengenezaji)
* **Kuijenga** kutoka kwa maagizo yaliyotolewa
* **Kuidownload** kutoka kwenye tovuti rasmi za msaada
* Kutumia **Google dork** kutafuta faili za firmware zilizohifadhiwa
* Kupata ufikiaji wa **kuhifadhi wingu** moja kwa moja, kwa zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
* Kuingilia **sasisho** kupitia mbinu za mtu katikati
* **Kuichimbua** kutoka kwenye kifaa kupitia uhusiano kama **UART**, **JTAG**, au **PICit**
* **Kuchunguza** maombi ya sasisho ndani ya mawasiliano ya kifaa
* Kutambua na kutumia **vituo vya sasisho vilivyoingizwa kiotomatiki**
* **Kuidondoa** kutoka kwa bootloader au mtandao
* **Kuondoa na kuisoma** chipu ya kuhifadhi, wakati njia zingine zote zinashindwa, kwa kutumia zana sahihi za vifaa. 

## Kuchambua firmware

Sasa **unayo firmware**, unahitaji kutoa taarifa kuhusu hiyo ili ujue jinsi ya kuishughulikia. Zana tofauti unazoweza kutumia kwa hilo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ikiwa hauoni mengi na zana hizo, angalia **entropy** ya picha na `binwalk -E <bin>`, ikiwa entropy ni ndogo, basi ni nadra kuwa imefichwa. Ikiwa entropy ni kubwa, ni nadra imefichwa (au imepakatishwa kwa njia fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **faili zilizowekwa ndani ya firmware**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kuchunguza faili.

### Kupata Mfumo wa Faili

Kwa zana zilizotajwa hapo awali kama `binwalk -ev <bin>`, unapaswa kuweza **kutoa mfumo wa faili**.\
Kawaida, Binwalk hutoa ndani ya **folda iliyoitwa kama aina ya mfumo wa faili**, ambayo kawaida ni moja ya yafuatayo: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Uchimbaji wa Mfumo wa Faili kwa Mkono

Marafiki, binwalk **hawana herufi ya uchawi ya mfumo wa faili katika saini zake**. Katika kesi hizi, tumia binwalk kutafuta **offset ya mfumo wa faili na uchimbe mfumo wa faili uliopakatishwa** kutoka kwa binary na **utoe mfumo wa faili kwa mkono** kulingana na aina yake kwa kutumia hatua zifuatazo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Chukua amri ya **dd** ifanyie kazi mfumo wa faili wa Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Kwa upande mwingine, amri ifuatayo inaweza pia kutekelezwa.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Kwa squashfs (ilitumika katika mfano hapo juu)

`$ unsquashfs dir.squashfs`

Faili zitakuwa katika saraka ya "`squashfs-root`" baadaye.

* Faili za kumbukumbu za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Kwa mfumo wa faili za jffs2

`$ jefferson rootfsfile.jffs2`

* Kwa mifumo ya faili za ubifs na NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Uchambuzi wa Firmware

Marafiki firmware inapopatikana, ni muhimu kuitenganua ili kuelewa muundo wake na uwezekano wa mapungufu. Mchakato huu unahusisha kutumia zana mbalimbali kuchambua na kutoa data muhimu kutoka kwa picha ya firmware.

### Zana za Uchambuzi wa Awali

Seti ya amri zinatolewa kwa ukaguzi wa awali wa faili ya binary (inayojulikana kama `<bin>`). Amri hizi husaidia katika kutambua aina za faili, kutoa herufi, kuchambua data ya binary, na kuelewa undani wa sehemu na maelezo ya mfumo wa faili:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Kuchunguza hali ya kifaa cha kielelezo, **entropy** hupimwa kwa kutumia `binwalk -E <bin>`. Entropy ya chini inaashiria ukosefu wa kifaa cha kielelezo, wakati entropy ya juu inaweza kuashiria kuwepo kwa encryption au compression.

Kwa ajili ya kutoa **faili zilizofichwa**, zana na rasilimali kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili zinapendekezwa.

### Kutoa Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida unaweza kutoa mfumo wa faili, mara nyingi kwenye saraka iliyoitwa kwa jina la aina ya mfumo wa faili (k.m., squashfs, ubifs). Hata hivyo, wakati **binwalk** inashindwa kutambua aina ya mfumo wa faili kutokana na kuwepo kwa magic bytes zilizokosekana, uchimbaji wa kawaida unahitajika. Hii inahusisha kutumia `binwalk` kutambua offset ya mfumo wa faili, ikifuatiwa na amri ya `dd` kuchonga mfumo wa faili:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Baadaye, kutegemea aina ya mfumo wa faili (k.m., squashfs, cpio, jffs2, ubifs), amri tofauti hutumiwa kuchambua maudhui kwa mkono.

### Uchambuzi wa Mfumo wa Faili

Baada ya mfumo wa faili kuchambuliwa, utafutaji wa dosari za usalama huanza. Tahadhari hulipwa kwa daemons dhaifu za mtandao, siri za nguvu, vituo vya API, utendaji wa seva ya sasisho, nambari isiyokamilika, hati za kuanzisha, na binaries zilizokamilishwa kwa uchambuzi nje ya mtandao.

**Maeneo muhimu** na **vitu** vya kuangalia ni pamoja na:

* **etc/shadow** na **etc/passwd** kwa siri za mtumiaji
* Vyeti vya SSL na funguo katika **etc/ssl**
* Mipangilio na faili za hati kwa dosari za uwezekano
* Binaries zilizojumuishwa kwa uchambuzi zaidi
* Seva za wavuti za vifaa vya IoT na binaries

Zana kadhaa husaidia kufunua habari nyeti na dosari ndani ya mfumo wa faili:

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa utafutaji wa habari nyeti
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) kwa uchambuzi kamili wa firmware
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa uchambuzi wa tuli na wa kudumu

### Ukaguzi wa Usalama kwenye Binaries Zilizokamilishwa

Zote nambari ya chanzo na binaries zilizokamilishwa zilizopatikana kwenye mfumo wa faili lazima zichunguzwe kwa dosari. Zana kama **checksec.sh** kwa binaries za Unix na **PESecurity** kwa binaries za Windows husaidia kutambua binaries zisizolindwa ambazo zinaweza kutumiwa vibaya.

## Kuenakili Firmware kwa Uchambuzi wa Kudumu

Mchakato wa kuenakili firmware huwezesha **uchambuzi wa kudumu** wa operesheni ya kifaa au programu binafsi. Mbinu hii inaweza kukutana na changamoto za vifaa au mitego ya usanifu, lakini kuhamisha mfumo wa faili wa msingi au binaries maalum kwa kifaa chenye usanifu na endianness inayolingana, kama Raspberry Pi, au kwa mashine ya kawaida iliyoundwa mapema, inaweza kurahisisha majaribio zaidi.

### Kuenakili Binaries Binafsi

Kwa kuchunguza programu moja, kutambua endianness na usanifu wa CPU wa programu ni muhimu.

#### Mfano na Usanifu wa MIPS

Kwa kuenakili binary ya usanifu wa MIPS, mtu anaweza kutumia amri:
```bash
file ./squashfs-root/bin/busybox
```
Na kufunga zana za uigaji muhimu:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
### Uigaji wa Mimarobaini (big-endian)

Kwa MIPS (big-endian), `qemu-mips` hutumiwa, na kwa mipangilio ya little-endian, `qemu-mipsel` ingekuwa chaguo sahihi.

### Uigaji wa Mimarobaini wa Mimarobaini

Kwa mipangilio ya ARM, mchakato ni sawa, na emulator `qemu-arm` hutumiwa kwa uigaji.

### Uigaji wa Mfumo Kamili

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na zingine, hufanikisha uigaji kamili wa firmware, kiotomatiki mchakato na kusaidia katika uchambuzi wa kudumu.

### Uchambuzi wa Kudumu kwa Vitendo

Katika hatua hii, mazingira halisi au yaliyoigizwa ya kifaa hutumiwa kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa kabati kwa OS na mfumo wa faili. Uigaji huenda usiigeze kikamilifu mwingiliano wa vifaa, hivyo kuhitaji kuzindua upya uigaji mara kwa mara. Uchambuzi unapaswa kurejelea mfumo wa faili, kutumia kurasa za wavuti zilizofichuliwa na huduma za mtandao, na kuchunguza mapungufu ya bootloader. Vipimo vya usalama wa firmware ni muhimu kutambua mapungufu ya mlango wa nyuma.

### Mbinu za Uchambuzi wa Wakati wa Uendeshaji

Uchambuzi wa wakati wa uendeshaji unahusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, kutumia zana kama gdb-multiarch, Frida, na Ghidra kwa kuweka vituo vya kuvunja na kutambua mapungufu kupitia fuzzing na mbinu zingine.

### Uchimbaji wa Binary na Uthibitisho wa Dhana

Kuendeleza PoC kwa mapungufu yaliyotambuliwa kunahitaji uelewa wa kina wa muundo wa lengo na programu katika lugha za kiwango cha chini. Kinga ya wakati wa uendeshaji wa binary katika mifumo iliyowekwa ni nadra, lakini ikipo, mbinu kama Return Oriented Programming (ROP) inaweza kuwa muhimu.

### Mifumo ya Uendeshaji Tayari kwa Uchambuzi wa Firmware

Mifumo ya uendeshaji kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyopangwa mapema kwa ajili ya upimaji wa usalama wa firmware, yenye zana muhimu.

### Mifumo ya Uendeshaji Tayari kuchambua Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya tathmini ya usalama na upimaji wa kuingilia kati wa vifaa vya Intaneti ya Vitu (IoT). Inakusaidia kuokoa muda kwa kutoa mazingira yaliyopangwa mapema na zana zote muhimu zilizopakiwa.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Mfumo wa uendeshaji wa upimaji wa usalama uliojikita kwenye vifaa vilivyowekwa Ubuntu 18.04 uliopakiwa na zana za upimaji wa usalama wa firmware.

### Firmware Zenye Mapungufu kwa Mazoezi

Kwa mazoezi ya kutambua mapungufu katika firmware, tumia miradi ifuatayo ya firmware yenye mapungufu kama mwanzo.

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

### Marejeo

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

### Mafunzo na Cheti

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)
