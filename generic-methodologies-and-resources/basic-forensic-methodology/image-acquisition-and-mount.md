# Beeldverwerwing & Monteer

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks-opslag](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud-opslag](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Verwerwing

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

Jy kan die [**FTK imager hier aflaai**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

Jy kan 'n skyfafbeelding genereer deur die [**ewf tools**](https://github.com/libyal/libewf) te gebruik.
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
## Monteer

### Verskeie tipes

In **Windows** kan jy probeer om die gratis weergawe van Arsenal Image Mounter ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)) te gebruik om **die forensiese beeld te monteer**.
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

#### Beeldverkryging en -montage

EWF is 'n formaat wat gebruik word vir die verwerking van beelde. Dit is 'n betroubare metode vir die verkryging van beelde en word dikwels gebruik vir forensiese doeleindes. Die proses behels die skep van 'n beeldlêer van 'n bronstasie sonder om die bronstasie self te verander. Die beeld kan dan op 'n ander stelsel gemonteer word vir ondersoek, sonder om die oorspronklike data te verander.
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

Dit is 'n Windows-toepassing om volumes te koppel. Jy kan dit hier aflaai [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Foute

* **`kan nie /dev/loop0 as slegs leesbaar koppel nie`** in hierdie geval moet jy die vlae **`-o ro,norecovery`** gebruik
* **`verkeerde fs-tipe, slegte opsie, slegte superblock op /dev/loop0, ontbrekende kodebladsy of hulpprogram, of ander fout.`** in hierdie geval het die koppeling misluk omdat die afsnit van die lêersisteem verskil van dié van die skyfafbeelding. Jy moet die Sektor-grootte en die Beginsektor vind:
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
Let wel dat die sektor grootte **512** is en die begin is **2048**. Monteer dan die beeld soos hierdie:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks-opslagplaas](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud-opslagplaas](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
