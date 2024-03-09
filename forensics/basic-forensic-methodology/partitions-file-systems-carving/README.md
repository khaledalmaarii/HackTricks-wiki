# 파티션/파일 시스템/카빙

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>

## 파티션

**하드 드라이브** 또는 **SSD 디스크에는 데이터를 물리적으로 분리하기 위한 다른 파티션**이 포함될 수 있습니다.\
디스크의 **최소** 단위는 **섹터**입니다(일반적으로 512B로 구성됨). 따라서 각 파티션 크기는 해당 크기의 배수여야 합니다.

### MBR (마스터 부트 레코드)

**부팅 코드의 446B 이후 디스크의 첫 번째 섹터에 할당**됩니다. 이 섹터는 PC에게 파티션을 어디에서 어떻게 마운트해야 하는지 알려주는 데 중요합니다.\
**최대 4개의 파티션**(최대 **1개만 활성/부팅 가능**)을 허용합니다. 그러나 더 많은 파티션이 필요한 경우 **확장 파티션**을 사용할 수 있습니다. 이 첫 번째 섹터의 마지막 바이트는 부트 레코드 서명 **0x55AA**입니다. 하나의 파티션만 활성화될 수 있습니다.\
MBR은 **최대 2.2TB**를 허용합니다.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

MBR의 **바이트 440에서 443**까지는 **Windows 디스크 서명**(Windows를 사용하는 경우)을 찾을 수 있습니다. 하드 디스크의 논리 드라이브 문자는 Windows 디스크 서명에 따라 달라집니다. 이 서명을 변경하면 Windows 부팅이 방해될 수 있습니다(도구: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**형식**

| 오프셋      | 길이       | 아이템            |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | 부팅 코드          |
| 446 (0x1BE) | 16 (0x10)  | 첫 번째 파티션     |
| 462 (0x1CE) | 16 (0x10)  | 두 번째 파티션    |
| 478 (0x1DE) | 16 (0x10)  | 세 번째 파티션     |
| 494 (0x1EE) | 16 (0x10)  | 네 번째 파티션    |
| 510 (0x1FE) | 2 (0x2)    | 서명 0x55 0xAA     |

**파티션 레코드 형식**

| 오프셋    | 길이     | 아이템                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | 활성 플래그 (0x80 = 부팅 가능)                          |
| 1 (0x01)  | 1 (0x01) | 시작 헤드                                               |
| 2 (0x02)  | 1 (0x01) | 시작 섹터 (비트 0-5); 실린더의 상위 비트 (6-7)          |
| 3 (0x03)  | 1 (0x01) | 시작 실린더 최하위 8비트                               |
| 4 (0x04)  | 1 (0x01) | 파티션 유형 코드 (0x83 = Linux)                        |
| 5 (0x05)  | 1 (0x01) | 끝 헤드                                                |
| 6 (0x06)  | 1 (0x01) | 끝 섹터 (비트 0-5); 실린더의 상위 비트 (6-7)            |
| 7 (0x07)  | 1 (0x01) | 끝 실린더 최하위 8비트                                |
| 8 (0x08)  | 4 (0x04) | 파티션 이전 섹터 수 (리틀 엔디안)                      |
| 12 (0x0C) | 4 (0x04) | 파티션 내 섹터 수                                      |

Linux에서 MBR을 마운트하려면 먼저 시작 오프셋을 얻어야 합니다(`fdisk`와 `p` 명령을 사용할 수 있음).

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

그런 다음 다음 코드를 사용하세요.
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (논리 블록 주소 지정)**

**논리 블록 주소 지정** (**LBA**)은 컴퓨터 저장 장치에 저장된 데이터 블록의 위치를 지정하는 데 사용되는 일반적인 체계로, 일반적으로 하드 디스크 드라이브와 같은 보조 저장 시스템에 사용됩니다. LBA는 특히 간단한 선형 주소 지정 체계이며, **블록은 정수 인덱스에 의해 찾아집니다**. 첫 번째 블록은 LBA 0이고, 두 번째는 LBA 1이며, 이와 같이 계속됩니다.

### GPT (GUID 파티션 테이블)

GUID 파티션 테이블인 GPT는 MBR (마스터 부트 레코드)와 비교하여 향상된 기능으로 인해 선호됩니다. 파티션을 위한 **전역적으로 고유한 식별자**로 특징 지어지는 GPT는 여러 측면에서 두드러집니다:

* **위치 및 크기**: GPT와 MBR은 모두 **섹터 0**에서 시작합니다. 그러나 GPT는 **64비트**에서 작동하며, MBR의 32비트와 대조됩니다.
* **파티션 제한**: GPT는 Windows 시스템에서 최대 **128개의 파티션**을 지원하며, 최대 **9.4ZB**의 데이터를 수용합니다.
* **파티션 이름**: 최대 36개의 유니코드 문자로 파티션에 이름을 지정할 수 있습니다.

**데이터 내구성 및 복구**:

* **중복성**: MBR과 달리 GPT는 파티션 및 부팅 데이터를 단일 위치에 제한하지 않습니다. 이 데이터를 디스크 전체에 복제하여 데이터 무결성과 내구성을 향상시킵니다.
* **순환 중복 검사 (CRC)**: GPT는 데이터 무결성을 보장하기 위해 CRC를 사용합니다. 데이터 손상을 적극적으로 모니터링하며, 감지되면 GPT는 손상된 데이터를 다른 디스크 위치에서 복구하려고 시도합니다.

**보호 MBR (LBA0)**:

* GPT는 보호 MBR을 통해 역호환성을 유지합니다. 이 기능은 레거시 MBR 공간에 위치하며, 오래된 MBR 기반 유틸리티가 GPT 디스크를 실수로 덮어쓰지 않도록 설계되어 GPT 형식의 디스크의 데이터 무결성을 보호합니다.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**하이브리드 MBR (LBA 0 + GPT)**

[Wikipedia에서](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

BIOS 서비스를 통해 **GPT 기반 부팅을 지원하는 운영 체제**에서는 첫 번째 섹터를 사용하여 **부트로더** 코드의 첫 번째 단계를 저장할 수 있지만, **수정**하여 **GPT 파티션**을 인식하도록 합니다. MBR의 부트로더는 섹터 크기를 512바이트로 가정해서는 안 됩니다.

**파티션 테이블 헤더 (LBA 1)**

[Wikipedia에서](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

파티션 테이블 헤더는 디스크의 사용 가능한 블록을 정의합니다. 또한 파티션 테이블을 구성하는 파티션 항목의 수와 크기를 정의합니다 (표의 오프셋 80 및 84).

| 오프셋    | 길이     | 내용                                                                                                                                                                           |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 바이트 | 시그니처 ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h 또는 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8) 리틀 엔디안 기계에서) |
| 8 (0x08)  | 4 바이트 | UEFI 2.8을 위한 리비전 1.0 (00h 00h 01h 00h)                                                                                                                                     |
| 12 (0x0C) | 4 바이트 | 리틀 엔디안에서 헤더 크기 (바이트 단위, 일반적으로 5Ch 00h 00h 00h 또는 92 바이트)                                                                                                 |
| 16 (0x10) | 4 바이트 | 헤더의 [CRC32](https://en.wikipedia.org/wiki/CRC32) (오프셋 +0부터 헤더 크기까지)의 리틀 엔디안 값, 이 필드는 계산 중에 0으로 설정됨                                      |
| 20 (0x14) | 4 바이트 | 예약됨; 0이어야 함                                                                                                                                                             |
| 24 (0x18) | 8 바이트 | 현재 LBA (이 헤더 사본의 위치)                                                                                                                                               |
| 32 (0x20) | 8 바이트 | 백업 LBA (다른 헤더 사본의 위치)                                                                                                                                             |
| 40 (0x28) | 8 바이트 | 파티션의 첫 번째 사용 가능한 LBA (기본 파티션 테이블의 마지막 LBA + 1)                                                                                                        |
| 48 (0x30) | 8 바이트 | 마지막 사용 가능한 LBA (보조 파티션 테이블의 첫 번째 LBA - 1)                                                                                                                  |
| 56 (0x38) | 16 바이트 | 혼합 엔디안의 디스크 GUID                                                                                                                                                      |
| 72 (0x48) | 8 바이트 | 파티션 항목 배열의 시작 LBA (기본 사본에서 항상 2)                                                                                                                               |
| 80 (0x50) | 4 바이트 | 배열의 파티션 항목 수                                                                                                                                                          |
| 84 (0x54) | 4 바이트 | 단일 파티션 항목의 크기 (일반적으로 80h 또는 128)                                                                                                                               |
| 88 (0x58) | 4 바이트 | 리틀 엔디안의 파티션 항목 배열의 CRC32                                                                                                                                         |
| 92 (0x5C) | \*       | 나머지 블록에 대해 0이어야 하는 예약된 값 (512바이트 섹터 크기의 경우 420바이트이지만 더 큰 섹터 크기의 경우 더 많을 수 있음)                                         |

**파티션 항목 (LBA 2–33)**

| GUID 파티션 항목 형식 |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| 오프셋                      | 길이   | 내용                                                                                                          |
| 0 (0x00)                    | 16 바이트 | [파티션 유형 GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (혼합 엔디안) |
| 16 (0x10)                   | 16 바이트 | 고유한 파티션 GUID (혼합 엔디안)                                                                              |
| 32 (0x20)                   | 8 바이트  | 첫 번째 LBA ([리틀 엔디안](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                   | 8 바이트  | 마지막 LBA (포함, 일반적으로 홀수)                                                                                 |
| 48 (0x30)                   | 8 바이트  | 속성 플래그 (예: 비트 60은 읽기 전용을 나타냄)                                                                   |
| 56 (0x38)                   | 72 바이트 | 파티션 이름 (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE 코드 단위)                                   |

**파티션 유형**

![](<../../../.gitbook/assets/image (492).png>)

더 많은 파티션 유형은 [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)에서 확인할 수 있습니다.

### 검사

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/)를 사용하여 포렌식 이미지를 마운트한 후 Windows 도구 [**Active Disk Editor**](https://www.disk-editor.org/index.html)를 사용하여 첫 번째 섹터를 검사할 수 있습니다. 다음 이미지에서 **MBR**이 **섹터 0**에서 감지되고 해석되었습니다:

![](<../../../.gitbook/assets/image (494).png>)

**MBR 대신 GPT 테이블**이었다면 **섹터 1**에서 _EFI PART_ 서명이 나타날 것입니다 (이전 이미지에서는 비어 있음).
## 파일 시스템

### Windows 파일 시스템 목록

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** 파일 시스템은 핵심 구성 요소인 파일 할당 테이블을 기준으로 설계되었습니다. 이 시스템은 데이터 무결성을 보호하기 위해 테이블의 **두 개의 사본**을 유지하여 한쪽이 손상되더라도 데이터 무결성을 보장합니다. 테이블과 루트 폴더는 **고정 위치**에 있어야 하며 시스템의 시작 프로세스에 중요합니다.

파일 시스템의 기본 저장 단위는 **클러스터**이며, 일반적으로 512B로 구성되어 여러 섹터를 포함합니다. FAT는 다음과 같은 버전을 통해 발전해 왔습니다:

* **FAT12**: 12비트 클러스터 주소를 지원하며 최대 4078개의 클러스터(UNIX 포함 4084개)를 처리합니다.
* **FAT16**: 16비트 주소로 향상되어 최대 65,517개의 클러스터를 수용합니다.
* **FAT32**: 32비트 주소로 더 발전하여 볼륨 당 268,435,456개의 클러스터를 허용합니다.

FAT 버전 간의 중요한 제한 사항은 파일 크기 저장을 위해 사용되는 32비트 필드로 인한 **최대 4GB 파일 크기**입니다.

특히 FAT12 및 FAT16의 루트 디렉토리의 주요 구성 요소는 다음과 같습니다:

* **파일/폴더 이름** (최대 8자)
* **속성**
* **생성, 수정 및 최근 액세스 날짜**
* **FAT 테이블 주소** (파일의 시작 클러스터를 나타냄)
* **파일 크기**

### EXT

**Ext2**는 부팅 파티션과 같이 **잘 변하지 않는 파티션**을 위한 가장 일반적인 파일 시스템입니다. **Ext3/4**는 **저널링**이며 일반적으로 **나머지 파티션**에 사용됩니다.

## **메타데이터**

일부 파일에는 메타데이터가 포함되어 있습니다. 이 정보는 파일의 내용에 대한 것으로, 파일 유형에 따라 제목, 사용된 MS Office 버전, 작성자, 생성 및 최종 수정 날짜, 카메라 모델, GPS 좌표, 이미지 정보와 같은 정보가 있을 수 있습니다.

파일의 메타데이터를 얻기 위해 [**exiftool**](https://exiftool.org) 및 [**Metadiver**](https://www.easymetadata.com/metadiver-2/)와 같은 도구를 사용할 수 있습니다.

## **삭제된 파일 복구**

### 기록된 삭제된 파일

이전에 볼 수 있듯이 파일이 "삭제"된 후에도 여전히 저장된 여러 위치가 있습니다. 이는 일반적으로 파일 시스템에서 파일을 삭제하면 삭제로 표시되지만 데이터는 손상되지 않기 때문입니다. 그런 다음 파일의 레지스트리(예: MFT)를 검사하고 삭제된 파일을 찾을 수 있습니다.

또한 OS는 파일 시스템 변경 및 백업에 대한 많은 정보를 저장하므로 파일이나 가능한 많은 정보를 복구하기 위해 이를 사용할 수 있습니다.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **파일 카빙**

**파일 카빙**은 데이터 덩어리에서 파일을 찾으려는 기술입니다. 이러한 도구가 작동하는 주요 방법은 **파일 유형 헤더 및 푸터**를 기반으로, 파일 유형 **구조**를 기반으로, 그리고 **콘텐츠** 자체를 기반으로 합니다.

이 기술은 **단편화된 파일을 검색하는 데 사용할 수 없습니다**. 파일이 **연속적인 섹터에 저장되지 않으면**, 이 기술로 파일이나 적어도 일부를 찾을 수 없습니다.

파일 카빙에 사용할 수 있는 여러 도구가 있으며, 검색할 파일 유형을 지정할 수 있습니다.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 데이터 스트림 **카빙**

데이터 스트림 카빙은 파일 카빙과 유사하지만 **완전한 파일 대신 흥미로운 조각 정보를 찾습니다**.\
예를 들어, 로그된 URL을 포함한 완전한 파일을 찾는 대신, 이 기술은 URL을 검색합니다.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 안전한 삭제

물론 파일을 **"안전하게" 삭제하고 그에 대한 로그 일부를 제거하는 방법**이 있습니다. 예를 들어, 파일의 내용을 여러 번 쓰레기 데이터로 덮어쓰고, 그런 다음 **$MFT** 및 **$LOGFILE**에 대한 파일에 대한 로그를 제거하고 **볼륨 그림자 사본**을 제거할 수 있습니다.\
이 작업을 수행해도 파일의 존재가 여전히 로깅된 부분이 있을 수 있음을 알 수 있으며, 이는 포렌식 전문가의 업무 중 일부입니다.

## 참고 자료

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**
