# Beeldverwerwing & Monteer

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Verwerwing

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

dcfldd is a command-line tool that is used for creating and hashing disk images. It is an enhanced version of the dd command and provides additional features such as on-the-fly hashing, progress reporting, and error handling.

To use dcfldd, you need to specify the input and output files or devices. You can also specify options such as block size, hash algorithm, and progress reporting interval.

Here is an example command to create a disk image using dcfldd:

```
dcfldd if=/dev/sda of=image.dd bs=4M hash=md5 hashwindow=10M hashlog=image.md5.log statusinterval=1MB
```

In this example, we are creating a disk image from the /dev/sda device and saving it as image.dd. We are using a block size of 4MB and hashing the image using the MD5 algorithm. The hash window is set to 10MB, which means that the hash is calculated for every 10MB of data. The hash log is saved in the image.md5.log file. The status interval is set to 1MB, which means that progress is reported every 1MB.

dcfldd is a powerful tool that can be used for forensic imaging and data acquisition. It is widely used in the field of digital forensics and can help in preserving and analyzing evidence.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

Jy kan die FTK imager [**hier aflaai**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

Jy kan 'n skyfbeeld genereer deur die [**ewf tools**](https://github.com/libyal/libewf) te gebruik.
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

### Rou
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

EWF (EnCase Evidence File) is a file format used for forensic disk imaging. It is commonly used in digital forensics to create a forensic image of a disk or a partition. The EWF format ensures the integrity and authenticity of the acquired image by storing a cryptographic hash of the data.

To acquire an image using EWF, you can use tools like EnCase, FTK Imager, or ewfacquire. These tools allow you to create a bit-by-bit copy of the disk or partition, including both allocated and unallocated space.

The EWF format has several advantages over other imaging formats. It supports compression, which can reduce the size of the acquired image. It also supports encryption, which can protect the image from unauthorized access. Additionally, EWF files can be easily mounted and accessed using tools like ewfmount.

To mount an EWF file, you can use the ewfmount command followed by the path to the EWF file and the mount point. This will create a virtual disk that contains the contents of the EWF file, allowing you to access and analyze the data within.

Overall, EWF is a reliable and widely used format for acquiring and analyzing disk images in digital forensics. Its support for compression, encryption, and easy mounting makes it a valuable tool for forensic investigators.
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

Dit is 'n Windows-toepassing om volumes te monteer. Jy kan dit hier aflaai [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Foute

* **`kan nie /dev/loop0 as slegs-lees monteer nie`** in hierdie geval moet jy die vlae **`-o ro,norecovery`** gebruik
* **`verkeerde fs-tipe, slegte opsie, slegte superblock op /dev/loop0, ontbrekende kodebladsy of hulpprogram, of ander fout.`** in hierdie geval het die monteer misluk as gevolg van die verskil in die verskuiwing van die lêersisteem en die skyfbeeld. Jy moet die Sektor-grootte en die Beginsektor vind:
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
Let daarop dat die sektor grootte **512** is en die beginpunt is **2048**. Monteer dan die prent soos volg:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks-repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud-repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
