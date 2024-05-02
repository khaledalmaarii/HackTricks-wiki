# 이미지 획득 및 마운트

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>을 통해 **제로부터 영웅이 되는 AWS 해킹을 배우세요**!</summary>

* **사이버 보안 회사**에서 일하시나요? **회사가 HackTricks에 광고되길 원하시나요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 받아보세요
* **[💬](https://emojipedia.org/speech-balloon/) Discord 그룹**에 **가입**하거나 [텔레그램 그룹](https://t.me/peass)에 **참여**하거나 **트위터**에서 저를 팔로우하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 요령을 공유하고 싶으시다면 [hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**로 PR을 제출하세요.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

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
## 마운트

### 여러 유형

**Windows**에서는 **포렌식 이미지를 마운트**하기 위해 Arsenal Image Mounter의 무료 버전을 사용해 볼 수 있습니다 ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)).

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
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

볼륨을 마운트하는 Windows 응용 프로그램입니다. [여기](https://arsenalrecon.com/downloads/)에서 다운로드할 수 있습니다.

### 오류

* **`/dev/loop0을 읽기 전용으로 마운트할 수 없음`** 이 경우 **`-o ro,norecovery`** 플래그를 사용해야 합니다.
* **`/dev/loop0에 잘못된 fs 유형, 잘못된 옵션, 잘못된 수퍼블록, 코드 페이지 누락 또는 도우미 프로그램이 없음`** 이 경우 파일 시스템의 오프셋이 디스크 이미지의 것과 다른 경우 마운트에 실패합니다. 섹터 크기와 시작 섹터를 찾아야 합니다:
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
<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>영웨이 에이더블유에스 해킹을 제로부터 히어로로 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **사이버 보안 회사에서 일하시나요**? **HackTricks에 귀사의 회사를 광고하고 싶으신가요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드하고 싶으신가요**? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요
* **💬** [**디스코드 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하시거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우하세요**.
* **[hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**로 PR을 제출하여 귀하의 해킹 트릭을 공유하세요.

</details>
