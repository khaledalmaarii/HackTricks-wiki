# 이미지 획득 및 마운트

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>

## 획득

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

dcfldd는 Linux 환경에서 사용되는 이미지 획득 도구입니다. 기본적으로 dd 명령어와 유사하지만, 추가적인 기능을 제공합니다. dcfldd는 진행 상황을 보고하고, 중단된 경우 재개할 수 있으며, 입력 및 출력 파일의 해시 값을 계산할 수 있습니다. 또한, dcfldd는 이미지 획득 시 데이터 무결성을 검사하기 위해 사용되는 해시 알고리즘을 지원합니다.

#### 사용법

dcfldd를 사용하여 이미지를 획득하려면 다음과 같은 명령어를 사용합니다:

```
dcfldd if=/dev/sda of=image.dd
```

위의 예시에서 `/dev/sda`는 이미지를 획득할 디스크 또는 파티션의 경로를 나타냅니다. `image.dd`는 생성될 이미지 파일의 이름입니다.

#### 중단 및 재개

dcfldd를 사용하여 이미지 획득 중에 중단된 경우, 다음과 같은 명령어를 사용하여 재개할 수 있습니다:

```
dcfldd if=/dev/sda of=image.dd status=on
```

위의 예시에서 `status=on`은 진행 상황을 보고하는 옵션입니다. 이를 통해 중단된 지점부터 이미지 획득을 재개할 수 있습니다.

#### 해시 값 계산

dcfldd를 사용하여 이미지 획득 시 입력 및 출력 파일의 해시 값을 계산하려면 다음과 같은 명령어를 사용합니다:

```
dcfldd if=/dev/sda of=image.dd hash=md5,sha1
```

위의 예시에서 `hash=md5,sha1`은 입력 및 출력 파일의 해시 값을 MD5와 SHA-1 알고리즘을 사용하여 계산하도록 지정한 것입니다.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

[**여기에서 FTK 이미저를 다운로드할 수 있습니다**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

[**ewf 도구**](https://github.com/libyal/libewf)를 사용하여 디스크 이미지를 생성할 수 있습니다.
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

### 여러 가지 유형

**Windows**에서는 **포렌식 이미지를 마운트**하기 위해 Arsenal Image Mounter의 무료 버전([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/))를 사용해 볼 수 있습니다.

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

EWF(Evidence File Format)는 디스크 이미지를 효율적으로 획득하고 분석하기 위한 형식입니다. EWF 형식은 디스크 이미지를 섹터 단위로 압축하여 저장하며, 압축된 이미지는 E01 확장자를 가집니다.

EWF 형식을 사용하여 이미지를 획득하려면 다음 단계를 따르십시오.

1. EWF 형식으로 이미지를 생성하기 위해 `ewfacquire` 도구를 사용합니다.
2. 이미지를 저장할 위치와 파일 이름을 지정합니다.
3. 획득할 디스크 또는 파티션을 선택합니다.
4. 이미지 획득을 시작합니다.

이미지 획득이 완료되면, EWF 형식의 이미지를 마운트하여 분석할 수 있습니다. 마운트는 다음과 같은 단계로 수행됩니다.

1. `ewfmount` 도구를 사용하여 이미지를 마운트합니다.
2. 마운트할 이미지 파일과 마운트할 디렉토리를 지정합니다.
3. 마운트된 이미지를 탐색하고 분석합니다.

EWF 형식은 디스크 이미지 획득과 분석에 유용한 기능을 제공합니다. 이를 통해 디지털 포렌식 작업을 보다 효율적으로 수행할 수 있습니다.
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

ArsenalImageMounter는 볼륨을 마운트하는 Windows 애플리케이션입니다. [여기](https://arsenalrecon.com/downloads/)에서 다운로드할 수 있습니다.

### 오류

* **`cannot mount /dev/loop0 read-only`** 이 경우에는 플래그 **`-o ro,norecovery`**를 사용해야 합니다.
* **`wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.`** 이 경우에는 마운트가 실패했으며 파일 시스템의 오프셋이 디스크 이미지와 다릅니다. 섹터 크기와 시작 섹터를 찾아야 합니다.
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
sector size가 **512**이고 시작 위치가 **2048**임을 유의하세요. 그런 다음 다음과 같이 이미지를 마운트하세요:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기교를 공유해주세요.

</details>
