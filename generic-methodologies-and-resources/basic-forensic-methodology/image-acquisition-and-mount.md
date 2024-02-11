# Kupata Picha na Kuimount

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Kupata

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

dcfldd ni chombo cha kufanya nakala ya picha ya disk. Inafanya kazi sawa na dd, lakini inaongeza baadhi ya vipengele vya ziada kama vile uwezo wa kufuatilia maendeleo ya nakala na kuhakikisha usahihi wa data iliyohamishwa. Chombo hiki kinaweza kutumiwa kwa uchunguzi wa kisayansi wa kisheria na kwa kazi zingine za kufufua data.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

Unaweza [**kupakua FTK imager hapa**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

Unaweza kuzalisha picha ya diski kwa kutumia [**zana za ewf**](https://github.com/libyal/libewf).
```bash
ewfacquire /dev/sdb
#Name: evidence
#Case number: 1
#Description: A description for the case
#Evidence number: 1
#Examiner Name: Your name
#Media type: fixed
#Media characteristics: physical
#File format: encase6
#Compression method: deflate
#Compression level: fast

#Then use default values
#It will generate the disk image in the current directory
```
## Weka

### Aina kadhaa

Katika **Windows** unaweza kujaribu kutumia toleo la bure la Arsenal Image Mounter ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)) kuweka **picha ya uchunguzi**. 

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

EWF (Expert Witness Format) ni muundo wa faili unaotumiwa kuhifadhi nakala za picha za kumbukumbu za tarakilishi. Nakala hizi za picha zinaweza kutumiwa kwa uchunguzi wa kisheria na kufanya uchambuzi wa data. EWF inaruhusu kuhifadhi picha za kumbukumbu za tarakilishi kwa njia ambayo inahakikisha usalama na ukamilifu wa data.

Kuna njia mbili za kufanya picha ya kumbukumbu ya tarakilishi kwa kutumia EWF:

1. **Picha ya kumbukumbu ya kimwili**: Hii inahusisha kufanya nakala ya kumbukumbu ya tarakilishi nzima, pamoja na mfumo wa faili na data yote iliyohifadhiwa. Hii inaweza kufanywa kwa kutumia zana kama `dcfldd` au `dd`.

2. **Picha ya kumbukumbu ya mantiki**: Hii inahusisha kufanya nakala ya sehemu maalum ya kumbukumbu ya tarakilishi, kama vile mfumo wa faili au folda maalum. Hii inaweza kufanywa kwa kutumia zana kama `ewfacquire` au `FTK Imager`.

Baada ya kufanya picha ya kumbukumbu, unaweza kuiweka kwenye kifaa cha uhifadhi, kama vile diski ngumu au kifaa cha USB, ili kuifanya iweze kufikiwa kwa uchambuzi zaidi. Pia, unaweza kuiweka kwenye seva ya uhifadhi au kwenye wingu kwa usalama zaidi.

Kumbuka kuwa wakati wa kufanya picha ya kumbukumbu, ni muhimu kuhakikisha kuwa unafuata miongozo ya kisheria na kufuata taratibu sahihi za kuchukua na kuhifadhi ushahidi wa kielektroniki.
```bash
#Get file type
file evidence.E01
evidence.E01: EWF/Expert Witness/EnCase image file format

#Transform to raw
mkdir output
ewfmount evidence.E01 output/
file output/ewf1
output/ewf1: Linux rev 1.0 ext4 filesystem data, UUID=05acca66-d042-4ab2-9e9c-be813be09b24 (needs journal recovery) (extents) (64bit) (large files) (huge files)

#Mount
mount output/ewf1 -o ro,norecovery /mnt
```
### ArsenalImageMounter

Ni Programu ya Windows ya kufunga sehemu. Unaweza kuipakua hapa [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Makosa

* **`hawezi kufunga /dev/loop0 kwa kusoma tu`** katika kesi hii unahitaji kutumia bendera **`-o ro,norecovery`**
* **`aina mbaya ya fs, chaguo mbaya, superblock mbaya kwenye /dev/loop0, ukurasa wa msimbo uliopotea au programu msaidizi, au kosa lingine.`** katika kesi hii kufunga kumeshindwa kwa sababu offset ya mfumo wa faili ni tofauti na ile ya picha ya diski. Unahitaji kupata ukubwa wa Sekta na Sekta ya Kuanza:
```bash
fdisk -l disk.img
Disk disk.img: 102 MiB, 106954648 bytes, 208896 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00495395

Device        Boot Start    End Sectors  Size Id Type
disk.img1       2048 208895  206848  101M  1 FAT12
```
Tafadhali kumbuka kuwa ukubwa wa sehemu ni **512** na kuanza ni **2048**. Kisha funga picha kama ifuatavyo:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
