<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


# 파일 추출 도구

## Autopsy

이미지에서 파일을 추출하는 데 가장 일반적으로 사용되는 도구는 [**Autopsy**](https://www.autopsy.com/download/)입니다. 다운로드하고 설치한 후 파일을 분석하여 "숨겨진" 파일을 찾을 수 있습니다. Autopsy는 디스크 이미지 및 다른 종류의 이미지를 지원하지만 단순한 파일은 지원하지 않습니다.

## Binwalk <a id="binwalk"></a>

**Binwalk**는 이미지 및 오디오 파일과 같은 이진 파일에서 포함된 파일과 데이터를 검색하는 도구입니다.
`apt`를 사용하여 설치할 수 있지만 [소스](https://github.com/ReFirmLabs/binwalk)는 github에서 찾을 수 있습니다.
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

**Scalpel**은 파일에 포함된 파일을 찾아 추출하는 데 사용할 수 있는 또 다른 도구입니다. 이 경우에는 추출하려는 파일 유형을 설정 파일 \(_/etc/scalpel/scalpel.conf_\)에서 주석 처리 해제해야 합니다.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

이 도구는 칼리 안에 포함되어 있지만 여기에서 찾을 수 있습니다: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

이 도구는 이미지를 스캔하고 그 안에서 **pcap 파일**, **네트워크 정보\(URL, 도메인, IP, MAC, 메일\)** 및 **기타 파일**을 추출할 수 있습니다. 다음을 수행하기만 하면 됩니다:
```text
bulk_extractor memory.img -o out_folder
```
**모든 정보**\(비밀번호?\)를 도구가 수집한 것을 통해 탐색하고, **패킷**을 분석하고\(Pcaps 분석 참조\), **이상한 도메인**\(악성코드나 존재하지 않는 도메인과 관련된 도메인\)을 검색합니다.

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)에서 찾을 수 있습니다.

GUI 및 CLI 버전이 함께 제공됩니다. PhotoRec에서 검색할 **파일 유형**을 선택할 수 있습니다.

![](../../../.gitbook/assets/image%20%28524%29.png)

# 특정 데이터 추출 도구

## FindAES

키 스케줄을 검색하여 AES 키를 찾습니다. TrueCrypt 및 BitLocker에서 사용되는 128, 192 및 256비트 키와 같은 키를 찾을 수 있습니다.

[여기](https://sourceforge.net/projects/findaes/)에서 다운로드할 수 있습니다.

# 보조 도구

터미널에서 이미지를 보려면 [**viu** ](https://github.com/atanunq/viu)를 사용할 수 있습니다.
리눅스 명령 줄 도구 **pdftotext**를 사용하여 PDF를 텍스트로 변환하고 읽을 수 있습니다.



<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로에서 영웅까지 AWS 해킹을 배워보세요**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왑**](https://peass.creator-spring.com)을 구매하세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>
