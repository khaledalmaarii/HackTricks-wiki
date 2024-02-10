<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정하세요. Intruder는 공격 표면을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Carving & 복구 도구

[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)에서 더 많은 도구를 찾을 수 있습니다.

## Autopsy

이미지에서 파일을 추출하는 데 가장 일반적으로 사용되는 도구는 [**Autopsy**](https://www.autopsy.com/download/)입니다. 다운로드하고 설치한 후 파일을 검색하여 "숨겨진" 파일을 찾도록 설정하세요. Autopsy는 디스크 이미지 및 다른 종류의 이미지를 지원하도록 설계되었지만 간단한 파일은 지원하지 않습니다.

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**는 이진 파일을 분석하여 포함된 콘텐츠를 찾는 도구입니다. `apt`를 통해 설치할 수 있으며 소스는 [GitHub](https://github.com/ReFirmLabs/binwalk)에 있습니다.

**유용한 명령어**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

또 다른 숨겨진 파일을 찾기 위한 일반적인 도구는 **foremost**입니다. Foremost의 구성 파일은 `/etc/foremost.conf`에 있습니다. 특정 파일을 검색하려면 주석 처리하십시오. 아무것도 주석 처리하지 않으면 foremost는 기본으로 구성된 파일 유형을 검색합니다.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel**은 파일에 포함된 파일을 찾아 추출하는 데 사용할 수 있는 또 다른 도구입니다. 이 경우, 추출하려는 파일 유형을 구성 파일(_/etc/scalpel/scalpel.conf_)에서 주석 처리를 해제해야 합니다.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

이 도구는 칼리 안에 포함되어 있지만 여기에서 찾을 수 있습니다: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

이 도구는 이미지를 스캔하고 그 안에서 **pcap 파일**, **네트워크 정보 (URL, 도메인, IP, MAC, 메일)** 및 **더 많은 파일**을 추출할 수 있습니다. 다음을 수행하기만 하면 됩니다:
```
bulk_extractor memory.img -o out_folder
```
**모든 정보**를 툴이 수집한 것을 통해 탐색하고 (비밀번호?), **패킷**을 분석하고 ([**Pcaps 분석**](../pcap-inspection/)을 읽으세요), **이상한 도메인** (악성코드나 존재하지 않는 도메인과 관련된 도메인)을 검색하세요.

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)에서 찾을 수 있습니다.

GUI 및 CLI 버전이 함께 제공됩니다. PhotoRec에서 검색할 **파일 유형**을 선택할 수 있습니다.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

[코드](https://code.google.com/archive/p/binvis/)와 [웹 페이지 도구](https://binvis.io/#/)를 확인하세요.

### BinVis의 기능

* 시각적이고 활성화된 **구조 뷰어**
* 다양한 초점 지점에 대한 여러 플롯
* 샘플의 일부에 초점을 맞추기
* PE 또는 ELF 실행 파일에서 **문자열과 리소스** 보기
* 파일의 암호 해독을 위한 **패턴** 얻기
* 패커 또는 인코더 알고리즘 **감지**
* 패턴에 따른 스테가노그래피 **식별**
* **시각적인** 이진 차이 비교

BinVis는 블랙박싱 시나리오에서 알려지지 않은 대상에 익숙해지기 위한 좋은 **시작점**입니다.

# 특정 데이터 복구 도구

## FindAES

TrueCrypt 및 BitLocker에서 사용되는 128, 192 및 256 비트 키와 같은 AES 키를 찾기 위해 키 스케줄을 검색합니다.

[여기](https://sourceforge.net/projects/findaes/)에서 다운로드하세요.

# 보완 도구

터미널에서 이미지를 보기 위해 [**viu**](https://github.com/atanunq/viu)를 사용할 수 있습니다.\
리눅스 명령 줄 도구 **pdftotext**를 사용하여 PDF를 텍스트로 변환하고 읽을 수 있습니다.


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정하세요. Intruder는 공격 표면을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>로부터 <strong>AWS 해킹을 처음부터 전문가까지 배워보세요</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
