# 'Iw HIq vItlhutlh 'ej vItlhutlh

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>DaH jImej</strong></a><strong>!</strong></summary>

* **'Iv 'oH 'ej 'Iv** **cybersecurity company**? **HackTricks** **company advertised** **want**? **PEASS latest version** **download HackTricks PDF** **want**? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **check**!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **Discover**, **exclusive NFTs** **collection** **our**
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Get**
* **Join** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) **telegram group** **or follow** **me** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share** **hacking tricks** **submitting PRs** **hacktricks repo** **hacktricks-cloud repo** **by**

</details>

## Acquisition

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

**Description**: dcfldd is an enhanced version of the dd command, commonly used for data acquisition and imaging in forensic investigations. It provides additional features such as on-the-fly hashing, progress reporting, and error handling.

**Usage**: The basic syntax for using dcfldd is as follows:

```bash
dcfldd if=<input_file> of=<output_file> [options]
```

**Options**: Some commonly used options with dcfldd are:

- `hash=md5`: Calculates the MD5 hash of the input file during the acquisition process.
- `hash=sha256`: Calculates the SHA256 hash of the input file during the acquisition process.
- `hashlog=<output_file>`: Saves the calculated hash values to a log file.
- `bs=<block_size>`: Specifies the block size for data transfer. Default is 512 bytes.
- `count=<number_of_blocks>`: Limits the number of blocks to be transferred.
- `statusinterval=<interval>`: Sets the interval for progress reporting.

**Example**: To acquire an image of a disk and calculate the MD5 hash using dcfldd, the following command can be used:

```bash
dcfldd if=/dev/sda of=image.dd hash=md5 hashlog=hashes.log
```

This command will create an image file named `image.dd` from the `/dev/sda` device and calculate the MD5 hash of the acquired data, saving the hash value to `hashes.log`.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

[**QaQ Imager**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1) vItlhutlh.
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

**ewf tools** (https://github.com/libyal/libewf) **'ej** disk image **lu'** generate **lIj**.
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
## Qa'vam

### chel

**Windows** DaH jImej Arsenal Image Mounter ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)) **Qa'vam the forensics image** laH.
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

#### tlhIngan Hol

#### EWF

EWF (Encase Image File Format) jatlhlaHbe'chugh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e' vItlhutlh, 'oH 'e' vItlhutlh, 'ej 'oH 'e' vItlhutlh. 'Iv 'e'
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

**ArsenalImageMounter** jIH Windows Application vItlhutlh. 'oH [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/) Daq download 'e' vItlhutlh.

### Errors

* **`cannot mount /dev/loop0 read-only`** vaj **`-o ro,norecovery`** flags vIlo'laHbe'chugh **`-o ro,norecovery`**.
* **`wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.`** vaj mount vItlhutlh **`filesystem`** offset vItlhutlh **`disk image`** offset vItlhutlh vItlhutlh. Sector size je Start sector vIqel:
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
ghItlh sector size **512** 'ej start **2048**. jImej 'e' vItlhutlh.
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
