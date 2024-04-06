# File/Data Carving & Recovery Tools

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅이 되는 AWS 해킹을 배우세요**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* \*\*💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

**Try Hard Security Group**

<figure><img src="https://github.com/carlospolop/hacktricks/blob/kr/forensics/basic-forensic-methodology/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Carving & 복구 도구

더 많은 도구: [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

이미지에서 파일을 추출하는 데 가장 일반적으로 사용되는 도구는 [**Autopsy**](https://www.autopsy.com/download/)입니다. 다운로드하고 설치한 후 파일을 처리하여 "숨겨진" 파일을 찾으세요. Autopsy는 디스크 이미지 및 다른 종류의 이미지를 지원하도록 구축되었지만 간단한 파일은 지원하지 않습니다.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**은 이진 파일을 분석하여 포함된 콘텐츠를 찾는 도구입니다. `apt`를 통해 설치할 수 있으며 소스는 [GitHub](https://github.com/ReFirmLabs/binwalk)에 있습니다.

**유용한 명령어**:

```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```

### Foremost

또 다른 숨겨진 파일을 찾는 데 사용되는 일반적인 도구는 **foremost**입니다. Foremost의 구성 파일은 `/etc/foremost.conf`에 있습니다. 특정 파일을 검색하려면 해당 파일을 주석 처리하십시오. 아무것도 주석 처리하지 않으면 foremost는 기본 구성된 파일 유형을 검색합니다.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel**은 파일 내에 포함된 파일을 찾아 추출하는 데 사용할 수 있는 또 다른 도구입니다. 이 경우, 추출하려는 파일 유형을 구성 파일(_/etc/scalpel/scalpel.conf_)에서 주석 처리 해제해야 합니다.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Bulk Extractor

이 도구는 칼리 안에 포함되어 있지만 여기에서 찾을 수 있습니다: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

이 도구는 이미지를 스캔하고 그 안에 있는 **pcaps를 추출**하며, **네트워크 정보(URL, 도메인, IP, MAC, 이메일)** 및 **더 많은 파일**을 추출할 수 있습니다. 수행해야 할 작업은 다음과 같습니다:

```
bulk_extractor memory.img -o out_folder
```

### PhotoRec

[PhotoRec](https://www.cgsecurity.org/wiki/TestDisk\_Download)를 찾을 수 있습니다.

GUI 및 CLI 버전이 함께 제공됩니다. PhotoRec가 검색할 **파일 유형**을 선택할 수 있습니다.

![](<../../../.gitbook/assets/image (524).png>)

### binvis

[코드](https://code.google.com/archive/p/binvis/) 및 [웹 페이지 도구](https://binvis.io/#/)를 확인하세요.

#### BinVis의 기능

* 시각적이고 활성 **구조 뷰어**
* 서로 다른 초점 지점에 대한 여러 플롯
* 샘플 일부에 초점을 맞춤
* PE 또는 ELF 실행 파일에서 **문자열 및 리소스** 확인
* 파일의 암호 해독을 위한 **패턴** 획득
* 패커 또는 인코더 알고리즘 **발견**
* 패턴에 의한 스테가노그래피 **식별**
* **시각적** 이진 차이

BinVis는 블랙박싱 시나리오에서 **알 수 없는 대상에 익숙해지는 데 좋은 시작점**입니다.

## 특정 데이터 카빙 도구

### FindAES

AES 키를 찾기 위해 키 스케줄을 검색하여 AES 키를 찾습니다. TrueCrypt 및 BitLocker에서 사용되는 것과 같이 128, 192 및 256 비트 키를 찾을 수 있습니다.

[여기에서 다운로드](https://sourceforge.net/projects/findaes/).

## 보조 도구

터미널에서 이미지를 보려면 [**viu**](https://github.com/atanunq/viu)를 사용할 수 있습니다.\
pdf를 텍스트로 변환하고 읽기 위해 리눅스 명령 줄 도구 **pdftotext**를 사용할 수 있습니다.

**Try Hard Security Group**

<figure><img src="https://github.com/carlospolop/hacktricks/blob/kr/forensics/basic-forensic-methodology/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**를 통해 제로부터 AWS 해킹을 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* 귀하의 **회사를 HackTricks에서 광고**하거나 **PDF 형식으로 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 귀하의 해킹 트릭을 공유하세요.

</details>
