# Firmware Analysis

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Introduction**

Firmware is essential software that enables devices to operate correctly by managing and facilitating communication between the hardware components and the software that users interact with. It's stored in permanent memory, ensuring the device can access vital instructions from the moment it's powered on, leading to the operating system's launch. Examining and potentially modifying firmware is a critical step in identifying security vulnerabilities.

## **Gathering Information**

**Gathering information** is a critical initial step in understanding a device's makeup and the technologies it uses. This process involves collecting data on:

- The CPU architecture and operating system it runs
- Bootloader specifics
- Hardware layout and datasheets
- Codebase metrics and source locations
- External libraries and license types
- Update histories and regulatory certifications
- Architectural and flow diagrams
- Security assessments and identified vulnerabilities

For this purpose, **open-source intelligence (OSINT)** tools are invaluable, as is the analysis of any available open-source software components through manual and automated review processes. Tools like [Coverity Scan](https://scan.coverity.com) and [Semmle’s LGTM](https://lgtm.com/#explore) offer free static analysis that can be leveraged to find potential issues.

## **Acquiring the Firmware**

Obtaining firmware can be approached through various means, each with its own level of complexity:

- **Directly** from the source (developers, manufacturers)
- **Building** it from provided instructions
- **Downloading** from official support sites
- Utilizing **Google dork** queries for finding hosted firmware files
- Accessing **cloud storage** directly, with tools like [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepting **updates** via man-in-the-middle techniques
- **Extracting** from the device through connections like **UART**, **JTAG**, or **PICit**
- **Sniffing** for update requests within device communication
- Identifying and using **hardcoded update endpoints**
- **Dumping** from the bootloader or network
- **Removing and reading** the storage chip, when all else fails, using appropriate hardware tools

## Analyzing the firmware

Now that you **have the firmware**, you need to extract information about it to know how to treat it. Different tools you can use for that:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
**ghItlhvam**: 
vaj vItlhutlh **tools** Hoch **entropy** 'e' vItlhutlh **image** vItlhutlh 'e' **binwalk -E <bin>'**. vaj, **entropy** Hoch, 'ach vItlhutlh, 'ach vItlhutlh (qatlh compressed) vItlhutlh.

**vaj**, vItlhutlh **files embedded** vItlhutlh **firmware** vaj vItlhutlh **tools** Hoch vItlhutlh:

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

'ej [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) vItlhutlh **file**.

### **Filesystem** vItlhutlh

vaj **tools** Hoch vItlhutlh **binwalk -ev <bin>'** vItlhutlh **filesystem**.\
Binwalk usually vItlhutlh **folder** Hoch **filesystem type** vItlhutlh, 'ej Hoch vItlhutlh: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### **Manual Filesystem Extraction**

vaj, binwalk vItlhutlh **magic byte** vItlhutlh **filesystem** vaj **signatures**. vaj, binwalk vItlhutlh **offset** vItlhutlh **filesystem** 'ej vItlhutlh **compressed filesystem** vaj binary 'ej vItlhutlh **filesystem** according vItlhutlh **type** Hoch vItlhutlh **steps**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
**dd command**-'e' vItlhutlh 'Squashfs' filesystem carving vItlhutlh.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativ, 'oH vItlhutlh.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* squashfs (DaH jatlh)

`$ unsquashfs dir.squashfs`

puS "squashfs-root" qachDaq.

* CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

* ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`


## Firmware jop

Firmware jop, vItlhutlh, 'e' vItlhutlh'e'. 'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhutlh'e' vItlhut
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
### ᓴᒪᔪᑦ ᐊᖃᓴᐅᔭᖅᑕᐅᔪᖅ ᐊᖃᓴᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕᐅᔪᖅᑕ
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
### Filesystem Analysis

**Filesystem Analysis**:

**Key locations** and **items** to inspect include:

- **etc/shadow** and **etc/passwd** for user credentials
- SSL certificates and keys in **etc/ssl**
- Configuration and script files for potential vulnerabilities
- Embedded binaries for further analysis
- Common IoT device web servers and binaries

Several tools assist in uncovering sensitive information and vulnerabilities within the filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Security Checks on Compiled Binaries

Both source code and compiled binaries found in the filesystem must be scrutinized for vulnerabilities. Tools like **checksec.sh** for Unix binaries and **PESecurity** for Windows binaries help identify unprotected binaries that could be exploited.

## Emulating Firmware for Dynamic Analysis

The process of emulating firmware enables **dynamic analysis** either of a device's operation or an individual program. This approach can encounter challenges with hardware or architecture dependencies, but transferring the root filesystem or specific binaries to a device with matching architecture and endianness, such as a Raspberry Pi, or to a pre-built virtual machine, can facilitate further testing.

### Emulating Individual Binaries

For examining single programs, identifying the program's endianness and CPU architecture is crucial.

#### Example with MIPS Architecture

To emulate a MIPS architecture binary, one can use the command:
```bash
file ./squashfs-root/bin/busybox
```
ghItlh 'ej vItlhutlh 'e' vItlhutlh.
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
### ARM Architecture Emulation

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

At this stage, either a real or emulated device environment is used for analysis. It's essential to maintain shell access to the OS and filesystem. Emulation may not perfectly mimic hardware interactions, necessitating occasional emulation restarts. Analysis should revisit the filesystem, exploit exposed webpages and network services, and explore bootloader vulnerabilities. Firmware integrity tests are critical to identify potential backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis involves interacting with a process or binary in its operating environment, using tools like gdb-multiarch, Frida, and Ghidra for setting breakpoints and identifying vulnerabilities through fuzzing and other techniques.

## Binary Exploitation and Proof-of-Concept

Developing a PoC for identified vulnerabilities requires a deep understanding of the target architecture and programming in lower-level languages. Binary runtime protections in embedded systems are rare, but when present, techniques like Return Oriented Programming (ROP) may be necessary.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is a distro intended to help you perform security assessment and penetration testing of Internet of Things (IoT) devices. It saves you a lot of time by providing a pre-configured environment with all the necessary tools loaded.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Vulnerable firmware to practice

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

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

## References

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Trainning and Cert

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
