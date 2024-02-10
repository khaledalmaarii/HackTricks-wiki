# 파티션/파일 시스템/카빙

## 파티션/파일 시스템/카빙

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요. 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 파티션

하드 드라이브 또는 **SSD 디스크에는 데이터를 물리적으로 분리하기 위한 다른 파티션**이 포함될 수 있습니다.\
디스크의 **최소** 단위는 **섹터**입니다(일반적으로 512B로 구성됨). 따라서 각 파티션 크기는 해당 크기의 배수여야 합니다.

### MBR (마스터 부트 레코드)

이것은 **부트 코드의 446B 이후 디스크의 첫 번째 섹터에 할당**됩니다. 이 섹터는 PC에게 파티션을 어디에서 어떻게 마운트해야 하는지 알려주는 데 필수적입니다.\
최대 **4개의 파티션**을 허용합니다(최대 **1개**만 활성화/부팅 가능). 그러나 더 많은 파티션을 필요로 하는 경우 **확장 파티션**을 사용할 수 있습니다. 이 첫 번째 섹터의 마지막 바이트는 부트 레코드 서명인 **0x55AA**입니다. 하나의 파티션만 활성화될 수 있습니다.\
MBR은 **최대 2.2TB**를 지원합니다.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

MBR의 **440에서 443 바이트**에는 **Windows 디스크 서명**을 찾을 수 있습니다(Windows를 사용하는 경우). 하드 디스크의 논리 드라이브 문자는 Windows 디스크 서명에 따라 달라집니다. 이 서명을 변경하면 Windows의 부팅이 방지될 수 있습니다(도구: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**형식**

| 오프셋      | 길이       | 항목                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | 부트 코드           |
| 446 (0x1BE) | 16 (0x10)  | 첫 번째 파티션     |
| 462 (0x1CE) | 16 (0x10)  | 두 번째 파티션    |
| 478 (0x1DE) | 16 (0x10)  | 세 번째 파티션     |
| 494 (0x1EE) | 16 (0x10)  | 네 번째 파티션    |
| 510 (0x1FE) | 2 (0x2)    | 서명 0x55 0xAA |

**파티션 레코드 형식**

| 오프셋    | 길이     | 항목                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | 활성 플래그 (0x80 = 부팅 가능)                          |
| 1 (0x01)  | 1 (0x01) | 시작 헤드                                             |
| 2 (0x02)  | 1 (0x01) | 시작 섹터 (비트 0-5); 실린더의 상위 비트 (6-7) |
| 3 (0x03)  | 1 (0x01) | 시작 실린더 하위 8비트                           |
| 4 (0x04)  | 1 (0x01) | 파티션 유형 코드 (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | 종료 헤드                                               |
| 6 (0x06)  | 1 (0x01) | 종료 섹터 (비트 0-5); 실린더의 상위 비트 (6-7)   |
| 7 (0x07)  | 1 (0x01) | 종료 실린더 하위 8비트                             |
| 8 (0x08)  | 4 (0x04) | 파티션 이전 섹터 (리틀 엔디언)            |
| 12 (0x0C) | 4 (0x04) | 파티션 내 섹터                                   |

Linux에서 MBR을 마운트하려면 먼저 시작 오프셋을 얻어야 합니다(`fdisk`와 `p` 명령을 사용할 수 있음).

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

그런 다음 다음 코드를 사용하세요.
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (논리 블록 주소 지정)**

**논리 블록 주소 지정** (**LBA**)는 일반적으로 하드 디스크 드라이브와 같은 보조 저장 장치에 저장된 데이터 블록의 위치를 지정하는 데 사용되는 일반적인 체계입니다. LBA는 특히 간단한 선형 주소 지정 체계입니다. **블록은 정수 인덱스로 찾아지며**, 첫 번째 블록은 LBA 0이고 두 번째 블록은 LBA 1이며 이런 식으로 계속됩니다.

### GPT (GUID 파티션 테이블)

GUID 파티션 테이블인 GPT는 MBR (마스터 부트 레코드)와 비교하여 향상된 기능으로 인해 선호됩니다. 파티션에 대한 **전역 고유 식별자**를 가지고 있는 GPT는 다음과 같은 특징을 가지고 있습니다:

- **위치와 크기**: GPT와 MBR은 모두 **0번 섹터**에서 시작합니다. 그러나 GPT는 MBR의 32비트와 대조적으로 **64비트**에서 작동합니다.
- **파티션 제한**: GPT는 Windows 시스템에서 최대 **128개의 파티션**을 지원하며 최대 **9.4ZB**의 데이터를 수용할 수 있습니다.
- **파티션 이름**: 최대 36개의 유니코드 문자로 파티션에 이름을 지정할 수 있습니다.

**데이터 내구성과 복구**:

- **중복성**: MBR과 달리 GPT는 파티션 및 부트 데이터를 단일 위치에 제한하지 않습니다. 이 데이터를 디스크 전체에 복제하여 데이터 무결성과 내구성을 향상시킵니다.
- **순환 중복 검사 (CRC)**: GPT는 데이터 무결성을 보장하기 위해 CRC를 사용합니다. 데이터 손상을 적극적으로 모니터링하고 감지되면 GPT는 손상된 데이터를 다른 디스크 위치에서 복구하려고 시도합니다.

**보호용 MBR (LBA0)**:

- GPT는 보호용 MBR을 통해 역호환성을 유지합니다. 이 기능은 기존 MBR 공간에 있지만 오래된 MBR 기반 유틸리티가 GPT 디스크를 잘못 덮어쓰지 않도록 설계되어 GPT 형식의 디스크의 데이터 무결성을 보호합니다.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**하이브리드 MBR (LBA 0 + GPT)**

[Wikipedia에서](https://en.wikipedia.org/wiki/GUID_Partition_Table)

BIOS를 통해 **GPT 기반 부팅을 지원하는 운영 체제**에서는 첫 번째 섹터를 **부트로더** 코드의 첫 단계를 저장하는 데 사용할 수 있지만, 이 코드는 **GPT 파티션**을 인식하도록 **수정**되어야 합니다. MBR의 부트로더는 섹터 크기가 512바이트라고 가정해서는 안 됩니다.

**파티션 테이블 헤더 (LBA 1)**

[Wikipedia에서](https://en.wikipedia.org/wiki/GUID_Partition_Table)

파티션 테이블 헤더는 디스크의 사용 가능한 블록을 정의합니다. 또한 파티션 테이블을 구성하는 파티션 항목의 수와 크기를 정의합니다 (테이블의 오프셋 80과 84).

| 오프셋    | 길이     | 내용                                                                                                                                                                           |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0 (0x00)  | 8바이트  | 시그니처 ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h 또는 리틀 엔디언 기계에서 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)) |
| 8 (0x08)  | 4바이트  | UEFI 2.8의 경우 1.0 (00h 00h 01h 00h)                                                                                                                                         |
| 12 (0x0C) | 4바이트  | 리틀 엔디언에서 헤더 크기 (바이트 단위, 일반적으로 5Ch 00h 00h 00h 또는 92바이트)                                                                                                 |
| 16 (0x10) | 4바이트  | 헤더의 CRC32 (오프셋 +0부터 헤더 크기까지)의 리틀 엔디언, 이 필드는 계산 중에 0으로 초기화됩니다.                                                                                   |
| 20 (0x14) | 4바이트  | 예약됨; 0이어야 함                                                                                                                                                             |
| 24 (0x18) | 8바이트  | 현재 LBA (이 헤더 사본의 위치)                                                                                                                                                  |
| 32 (0x20) | 8바이트  | 백업 LBA (다른 헤더 사본의 위치)                                                                                                                                                |
| 40 (0x28) | 8바이트  | 파티션의 첫 번째 사용 가능한 LBA (기본 파티션 테이블의 마지막 LBA + 1)                                                                                                           |
| 48 (0x30) | 8바이트  | 마지막 사용 가능한 LBA (보조 파티션 테이블의 첫 번째 LBA - 1)                                                                                                                     |
| 56 (0x38) | 16바이트 | 혼합 엔디언의 디스크 GUID                                                                                                                                                       |
| 72 (0x48) | 8바이트  | 파티션 항목 배열의 시작 LBA (기본 사본에서 항상 2)                                                                                                                               |
| 80 (0x50) | 4바이트  | 배열의 파티션 항목 수                                                                                                                                                           |
| 84 (0x54) | 4바이트  | 단일 파티션 항목의 크기 (일반적으로 80h 또는 128)                                                                                                                                 |
| 88 (0x58) | 4바이트  | 리틀 엔디언의 파티션 항목 배열의 CRC32                                                                                                                                         |
| 92 (0x5C) | \*       | 나머지 블록에 대해 0이어야 함 (512바이트 섹터 크기의 경우 420바이트이지만 더 큰 섹터 크기의 경우 더 많을 수 있음)                                                               |

**파티션 항목 (LBA 2–33)**

| GUID 파티션 항목 형식 |          |                                                                                                                   |
| --------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| 오프셋                | 길이     | 내용                                                                                                              |
| 0 (0x00)              | 16바이트 | [파티션 유형 GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (혼합 엔디언)       |
| 16 (0x10)             | 16바이트 | 고유한 파티션 GUID (혼합 엔디언)                                                                                   |
| 32 (0x20)             | 8바이트  | 첫 번째 LBA ([리틀 엔디언](https://en.wikipedia.org/wiki/Little\_endian))                                          |
| 40 (0x28)             | 8바이트  | 마지막 LBA (포함, 일반적으로 홀수)                                                                                 |
| 48 (0x30)             | 8바이트  | 속성 플래그 (예: 비트 60은 읽기 전용을 나타냄)                                                                    |
| 56 (0x38)             | 72바이트 | 파티션 이름 (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE 코드 단위)                                        |

**파티션 유형**

![](<../../../.gitbook/assets/image (492).png>)

더 많은 파티션 유형은 [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org
## 파일 시스템

### Windows 파일 시스템 목록

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** 파일 시스템은 핵심 구성 요소인 파일 할당 테이블을 기반으로 설계되었습니다. 이 시스템은 테이블의 두 개의 사본을 유지하여 데이터 무결성을 보장하며, 한 개의 사본이 손상되더라도 데이터를 보호합니다. 테이블은 루트 폴더와 함께 **고정 위치**에 있어야 하며, 시스템의 시작 프로세스에 중요합니다.

이 파일 시스템의 기본 저장 단위는 **클러스터**이며, 일반적으로 512B로 구성되어 있습니다. FAT는 다음과 같은 버전을 거쳐 발전해 왔습니다:

- **FAT12**: 12비트 클러스터 주소를 지원하며 최대 4078개의 클러스터(UNIX 시스템에서는 4084개)를 처리합니다.
- **FAT16**: 16비트 주소를 지원하여 최대 65,517개의 클러스터를 수용합니다.
- **FAT32**: 32비트 주소를 사용하여 볼륨 당 최대 268,435,456개의 클러스터를 처리할 수 있습니다.

FAT 버전에 걸친 중요한 제한 사항은 32비트 필드를 사용하여 파일 크기를 저장하므로 **4GB 이하의 최대 파일 크기**입니다.

특히 FAT12와 FAT16의 경우 루트 디렉토리의 주요 구성 요소는 다음과 같습니다:

- **파일/폴더 이름** (최대 8자)
- **속성**
- **생성, 수정 및 최근 액세스 날짜**
- **FAT 테이블 주소** (파일의 시작 클러스터를 나타냄)
- **파일 크기**

### EXT

**Ext2**는 부트 파티션과 같이 **변경되지 않는 파티션**에 대한 가장 일반적인 파일 시스템입니다. **Ext3/4**는 **저널링**을 지원하며 일반적으로 **나머지 파티션**에 사용됩니다.

## **메타데이터**

일부 파일에는 메타데이터가 포함되어 있습니다. 이 정보는 파일의 내용에 대한 것으로, 파일 유형에 따라 다음과 같은 정보가 포함될 수 있습니다:

* 제목
* 사용된 MS Office 버전
* 작성자
* 생성 및 최종 수정 날짜
* 카메라 모델
* GPS 좌표
* 이미지 정보

[**exiftool**](https://exiftool.org)과 [**Metadiver**](https://www.easymetadata.com/metadiver-2/)와 같은 도구를 사용하여 파일의 메타데이터를 가져올 수 있습니다.

## **삭제된 파일 복구**

### 로그된 삭제된 파일

이전에 언급한 대로 파일이 "삭제"된 후에도 여러 곳에 파일이 여전히 저장되어 있습니다. 일반적으로 파일 시스템에서 파일을 삭제하면 파일이 삭제되었음을 표시하지만 데이터는 손상되지 않습니다. 따라서 파일의 레지스트리(예: MFT)를 검사하고 삭제된 파일을 찾을 수 있습니다.

또한, 운영 체제는 파일 시스템 변경 및 백업에 대한 많은 정보를 저장하므로 파일을 복구하거나 가능한한 많은 정보를 복구하기 위해 이러한 정보를 사용할 수 있습니다.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **파일 카빙**

**파일 카빙**은 데이터의 덩어리에서 파일을 찾으려는 기술입니다. 이와 같은 도구는 주로 다음 3가지 방식으로 작동합니다: **파일 유형 헤더와 푸터를 기반으로**, 파일 유형 **구조를 기반으로**하며, **콘텐츠 자체**를 기반으로 합니다.

이 기술은 **단편화된 파일을 검색하는 데는 사용할 수 없습니다**. 파일이 **연속적인 섹터에 저장되지 않은 경우**, 이 기술로 파일이나 적어도 일부를 찾을 수 없습니다.

파일 카빙을 위해 원하는 파일 유형을 지정하여 여러 도구를 사용할 수 있습니다.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 데이터 스트림 **카빙**

데이터 스트림 카빙은 파일 카빙과 유사하지만 **완전한 파일을 찾는 대신 흥미로운 단편 정보**를 찾습니다.\
예를 들어, 로그된 URL을 포함한 완전한 파일을 찾는 대신 이 기술은 URL을 검색합니다.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 안전한 삭제

물론, 파일을 **"안전하게" 삭제하고 관련 로그 일부를 제거하는 방법**이 있습니다. 예를 들어, 파일의 내용을 여러 번의 쓰기 작업으로 더미 데이터로 덮어쓰고, 그런 다음 파일에 대한 **$MFT** 및 **$LOGFILE**의 **로그**를 **제거**하고 **볼륨 그림자 복사본**을 제거할 수 있습니다.\
이 작업을 수행하더라도 파일의 존재가 여전히 로그되는 다른 부분이 있을 수 있음에 유의하십시오. 따라서 디지털 포렌식 전문가의 역할은 이러한 부분을 찾는 것입니다.

## 참고 자료

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로에서 영웅까지 AWS 해킹을 배워보세요**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **Twitter**에서 **@hacktricks_live**를 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
