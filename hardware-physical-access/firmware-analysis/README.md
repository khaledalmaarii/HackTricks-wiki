# 펌웨어 분석

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}

## **소개**

펌웨어는 하드웨어 구성 요소와 사용자가 상호 작용하는 소프트웨어 간의 통신을 관리하고 운영 장치가 올바르게 작동할 수 있도록 하는 필수 소프트웨어입니다. 펌웨어는 영구 메모리에 저장되어 있어 장치가 전원을 켤 때부터 중요한 명령에 액세스할 수 있도록 하여 운영 체제를 시작합니다. 펌웨어를 조사하고 수정하는 것은 보안 취약점을 식별하는 중요한 단계입니다.

## **정보 수집**

**정보 수집**은 장치의 구성 및 사용하는 기술을 이해하는 초기 중요한 단계입니다. 이 프로세스에는 다음 데이터 수집이 포함됩니다:

* CPU 아키텍처 및 실행 중인 운영 체제
* 부트로더 세부 정보
* 하드웨어 레이아웃 및 데이터 시트
* 코드베이스 메트릭 및 소스 위치
* 외부 라이브러리 및 라이선스 유형
* 업데이트 기록 및 규제 인증
* 구조 및 흐름 다이어그램
* 보안 평가 및 식별된 취약점

이를 위해 **오픈 소스 인텔리전스 (OSINT)** 도구와 사용 가능한 오픈 소스 소프트웨어 구성 요소를 수동 및 자동 검토 프로세스를 통해 분석하는 것이 중요합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore)과 같은 도구는 잠재적인 문제를 찾기 위해 활용할 수 있는 무료 정적 분석을 제공합니다.

## **펌웨어 획득**

펌웨어를 얻는 방법은 각각의 복잡성 수준을 가지고 다양한 방법으로 접근할 수 있습니다:

* **소스**에서 직접 (개발자, 제조업체)
* 제공된 지침을 통해 **빌드**
* 공식 지원 사이트에서 **다운로드**
* 호스팅된 펌웨어 파일을 찾기 위해 **Google 도크** 쿼리 사용
* [S3Scanner](https://github.com/sa7mon/S3Scanner)와 같은 도구를 사용하여 **클라우드 저장소**에 직접 액세스
* 중간자 공격 기술을 사용하여 업데이트 **가로채기**
* **UART**, **JTAG**, 또는 **PICit**과 같은 연결을 통해 장치에서 **추출**
* 장치 통신 내에서 업데이트 요청을 **스니핑**
* 식별 및 **하드코딩된 업데이트 엔드포인트** 사용
* 부트로더 또는 네트워크에서 **덤프**
* 모든 것이 실패할 때 적절한 하드웨어 도구를 사용하여 **저장 칩 제거 및 읽기**

## 펌웨어 분석

이제 **펌웨어를** 가지고 있으므로, 어떻게 처리할지 알기 위해 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 다양한 도구들:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
만약 그 도구들로 많은 것을 찾지 못했다면, 이미지의 **엔트로피**를 `binwalk -E <bin>`로 확인하세요. 낮은 엔트로피라면, 암호화되지 않았을 가능성이 높습니다. 높은 엔트로피라면, 암호화되었을 가능성이 높습니다 (또는 어떤 방식으로 압축되었을 수 있음).

또한, 이러한 도구들을 사용하여 **펌웨어 내에 포함된 파일을 추출**할 수 있습니다:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

또는 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))를 사용하여 파일을 검사할 수 있습니다.

### 파일 시스템 가져오기

이전에 언급된 `binwalk -ev <bin>`과 같은 도구를 사용하여 **파일 시스템을 추출**해야 합니다.\
보통 Binwalk은 **파일 시스템 유형과 동일한 이름의 폴더** 내에 추출합니다. 이는 보통 다음 중 하나일 수 있습니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 수동 파일 시스템 추출

가끔씩, binwalk에는 **시그니처에 파일 시스템의 매직 바이트가 없을 수 있습니다**. 이런 경우에는 binwalk를 사용하여 **파일 시스템의 오프셋을 찾고 바이너리에서 압축된 파일 시스템을 추출**하고, 아래 단계를 따라 파일 시스템을 **수동으로 추출**해야 합니다.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
다음 **dd 명령어**를 실행하여 Squashfs 파일 시스템을 추출하십시오.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
또는 다음 명령어를 실행할 수도 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* squashfs에 대한 (위의 예시에서 사용됨)

`$ unsquashfs dir.squashfs`

파일은 이후 "`squashfs-root`" 디렉토리에 있게 됩니다.

* CPIO 아카이브 파일

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* jffs2 파일 시스템의 경우

`$ jefferson rootfsfile.jffs2`

* NAND 플래시를 사용하는 ubifs 파일 시스템의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

펌웨어를 획득한 후, 해당 구조와 잠재적 취약점을 이해하기 위해 분해하는 것이 중요합니다. 이 과정은 펌웨어 이미지에서 가치 있는 데이터를 분석하고 추출하기 위해 다양한 도구를 활용하는 것을 포함합니다.

### 초기 분석 도구

바이너리 파일( `<bin>`으로 지칭됨)의 초기 검사를 위해 일련의 명령어가 제공됩니다. 이러한 명령어는 파일 유형 식별, 문자열 추출, 이진 데이터 분석, 파티션 및 파일 시스템 세부 정보 이해에 도움이 됩니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
이미지의 암호화 상태를 평가하기 위해 **엔트로피**를 `binwalk -E <bin>`로 확인합니다. 낮은 엔트로피는 암호화 부재를 시사하며, 높은 엔트로피는 가능한 암호화 또는 압축을 나타냅니다.

**임베디드 파일**을 추출하기 위해 **file-data-carving-recovery-tools** 문서와 **binvis.io**와 같은 도구 및 자료를 사용하여 파일을 검사하는 것이 좋습니다.

### 파일 시스템 추출

`binwalk -ev <bin>`을 사용하여 파일 시스템을 일반적으로 추출할 수 있으며, 종종 파일 시스템 유형(예: squashfs, ubifs)으로 명명된 디렉토리로 추출됩니다. 그러나 **binwalk**가 마법 바이트가 누락되어 파일 시스템 유형을 인식하지 못할 때 수동 추출이 필요합니다. 이는 `binwalk`를 사용하여 파일 시스템의 오프셋을 찾은 다음 `dd` 명령을 사용하여 파일 시스템을 분리하는 과정을 포함합니다:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
### 파일시스템 분석

파일시스템이 추출된 후 보안 취약점을 찾기 시작합니다. 보안되지 않은 네트워크 데몬, 하드코딩된 자격 증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트 및 오프라인 분석을 위한 컴파일된 이진 파일에 주의가 기울어집니다.

검사해야 할 **주요 위치** 및 **항목**은 다음과 같습니다:

- 사용자 자격 증명을 위한 **etc/shadow** 및 **etc/passwd**
- **etc/ssl**에 있는 SSL 인증서 및 키
- 잠재적인 취약점을 위한 구성 및 스크립트 파일
- 추가 분석을 위한 포함된 이진 파일
- 일반적인 IoT 장치 웹 서버 및 이진 파일

파일시스템 내에서 민감한 정보 및 취약점을 발견하는 데 도움이 되는 여러 도구가 있습니다:

- 민감한 정보 검색을 위한 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 포괄적인 펌웨어 분석을 위한 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core)
- 정적 및 동적 분석을 위한 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 및 [**EMBA**](https://github.com/e-m-b-a/emba)

### 컴파일된 이진 파일의 보안 확인

파일시스템에서 발견된 소스 코드와 컴파일된 이진 파일은 취약점을 조사해야 합니다. Unix 이진 파일에 대한 **checksec.sh** 및 Windows 이진 파일에 대한 **PESecurity**와 같은 도구를 사용하여 악의적으로 이용될 수 있는 보호되지 않은 이진 파일을 식별하는 데 도움이 됩니다.

## 동적 분석을 위한 펌웨어 에뮬레이션

펌웨어를 에뮬레이션하는 과정은 장치의 작동 또는 개별 프로그램의 **동적 분석**을 가능하게 합니다. 이 접근 방식은 하드웨어 또는 아키텍처 종속성으로 인해 도전을 겪을 수 있지만, 루트 파일시스템이나 특정 이진 파일을 Raspberry Pi와 같은 일치하는 아키텍처 및 엔디안을 가진 장치로 또는 미리 빌드된 가상 머신으로 전송함으로써 추가 테스트를 용이하게 할 수 있습니다.

### 개별 이진 파일 에뮬레이션

단일 프로그램을 검사하기 위해서는 프로그램의 엔디안과 CPU 아키텍처를 식별하는 것이 중요합니다.

#### MIPS 아키텍처 예시

MIPS 아키텍처 이진 파일을 에뮬레이션하기 위해 다음 명령을 사용할 수 있습니다:
```bash
file ./squashfs-root/bin/busybox
```
그리고 필요한 에뮬레이션 도구를 설치하십시오:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
### MIPS (big-endian)를 위해, `qemu-mips`를 사용하고, little-endian 바이너리의 경우, `qemu-mipsel`을 선택해야 합니다.

#### ARM 아키텍처 에뮬레이션

ARM 바이너리의 경우, `qemu-arm` 에뮬레이터를 사용하여 유사한 프로세스가 진행됩니다.

### 전체 시스템 에뮬레이션

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 등의 도구들은 전체 펌웨어 에뮬레이션을 용이하게 하며, 프로세스를 자동화하고 동적 분석을 돕습니다.

## 실전 동적 분석

이 단계에서는 분석을 위해 실제 또는 에뮬레이션된 장치 환경을 사용합니다. OS 및 파일 시스템에 대한 쉘 액세스를 유지하는 것이 중요합니다. 에뮬레이션은 하드웨어 상호작용을 완벽하게 모방하지 못할 수 있으므로 때때로 에뮬레이션을 다시 시작해야 할 수 있습니다. 분석은 파일 시스템을 다시 검토하고 노출된 웹페이지 및 네트워크 서비스를 악용하며 부트로더 취약점을 탐색해야 합니다. 펌웨어 무결성 테스트는 잠재적인 배후 취약점을 식별하는 데 중요합니다.

## 런타임 분석 기술

런타임 분석은 gdb-multiarch, Frida, Ghidra와 같은 도구를 사용하여 프로세스나 바이너리와 상호작용하며 퍼징 및 기타 기술을 통해 취약점을 식별하는 것을 의미합니다.

## 바이너리 악용 및 증명 개념

식별된 취약점에 대한 PoC를 개발하려면 대상 아키텍처에 대한 심층적인 이해와 저수준 언어 프로그래밍 능력이 필요합니다. 내장 시스템의 바이너리 런타임 보호 기능은 드물지만 존재할 경우 Return Oriented Programming (ROP)과 같은 기술이 필요할 수 있습니다.

## 펌웨어 분석을 위한 준비된 운영 체제

[AttifyOS](https://github.com/adi0x90/attifyos) 및 [EmbedOS](https://github.com/scriptingxss/EmbedOS)와 같은 운영 체제는 펌웨어 보안 테스트를 위한 사전 구성된 환경을 제공하며 필요한 도구를 갖추고 있습니다.

## 펌웨어 분석을 위한 준비된 운영 체제

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 사전 구성된 환경을 제공하여 사물 인터넷(IoT) 장치의 보안 평가 및 침투 테스트를 수행하는 데 도움을 주는 배포판입니다. 필요한 모든 도구가 로드된 사전 구성된 환경으로 많은 시간을 절약할 수 있습니다.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 기반의 내장 보안 테스트 운영 체제로, 펌웨어 보안 테스트 도구가 미리 로드되어 있습니다.

## 연습용 취약한 펌웨어

펌웨어에서 취약점을 발견하기 위한 연습으로 다음 취약한 펌웨어 프로젝트를 시작점으로 활용하세요.

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

## 참고 자료

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## 교육 및 인증

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)
