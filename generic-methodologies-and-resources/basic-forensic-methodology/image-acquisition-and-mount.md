# 이미지 획득 및 마운트

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>을 통해 **제로부터 영웅이 되는 AWS 해킹을 배우세요**!</summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으세요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으세요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 받으세요
* **[💬](https://emojipedia.org/speech-balloon/) Discord 그룹**에 **가입**하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**을 팔로우**하세요.
* **해킹 트릭을 공유하고 싶으시다면 [hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**로 PR을 제출하세요.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 획득

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
### FTK 이미저

[여기에서 FTK 이미저를 다운로드할 수 있습니다](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

[**ewf tools**](https://github.com/libyal/libewf)를 사용하여 디스크 이미지를 생성할 수 있습니다.
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
## Mount

### 여러 유형

**Windows**에서는 **포렌식 이미지를 마운트**하기 위해 무료 버전의 Arsenal Image Mounter([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/))를 사용해 볼 수 있습니다.

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

### EWF
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

Windows Application으로 볼륨을 마운트하는 데 사용됩니다. [여기](https://arsenalrecon.com/downloads/)에서 다운로드할 수 있습니다.

### 오류

* **`cannot mount /dev/loop0 read-only`** 이 경우에는 **`-o ro,norecovery`** 플래그를 사용해야 합니다.
* **`wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.`** 이 경우에는 파일 시스템의 오프셋이 디스크 이미지의 것과 다르기 때문에 마운트에 실패했습니다. 섹터 크기와 시작 섹터를 찾아야 합니다:
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
섹터 크기가 **512**이고 시작 위치가 **2048**임을 유의하십시오. 그런 다음 이미지를 다음과 같이 마운트하십시오:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>와 함께 **제로부터 영웅이 되는 AWS 해킹을 배우세요**!</summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 광고하고 싶으신가요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 받아보세요
* **💬** [**Discord 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**을 팔로우**하세요.
* **해킹 트릭을 공유하고 싶으시다면 [hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**로 PR을 제출하세요.

</details>
