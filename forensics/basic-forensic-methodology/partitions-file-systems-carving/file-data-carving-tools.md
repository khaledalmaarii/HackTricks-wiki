{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}


# Carving tools

## Autopsy

이미지에서 파일을 추출하는 데 가장 일반적으로 사용되는 도구는 [**Autopsy**](https://www.autopsy.com/download/)입니다. 다운로드하고 설치한 후 파일을 처리하여 "숨겨진" 파일을 찾으십시오. Autopsy는 디스크 이미지 및 다른 종류의 이미지를 지원하도록 구축되었지만 간단한 파일은 지원하지 않습니다.

## Binwalk <a id="binwalk"></a>

**Binwalk**은 이미지 및 오디오 파일과 같은 이진 파일에서 포함된 파일 및 데이터를 검색하는 도구입니다.
`apt`를 사용하여 설치할 수 있지만 [소스](https://github.com/ReFirmLabs/binwalk)는 github에서 찾을 수 있습니다.
**유용한 명령어**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

또 다른 숨겨진 파일을 찾는 데 일반적으로 사용되는 도구는 **foremost**입니다. Foremost의 구성 파일은 `/etc/foremost.conf`에 있습니다. 특정 파일을 검색하려면 해당 파일의 주석을 해제하면 됩니다. 아무것도 주석 처리하지 않으면 Foremost는 기본 구성된 파일 유형을 검색합니다.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel**은 파일 내에 포함된 파일을 찾아 추출하는 데 사용할 수 있는 또 다른 도구입니다. 이 경우 추출하려는 파일 유형을 설정 파일 \(_/etc/scalpel/scalpel.conf_\)에서 주석 처리 해제해야 합니다.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

이 도구는 칼리 안에 포함되어 있지만 여기에서 찾을 수 있습니다: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

이 도구는 이미지를 스캔하고 그 안에 있는 **pcaps를 추출**하며, **네트워크 정보\(URL, 도메인, IP, MAC, 이메일\)** 및 더 많은 **파일**을 추출할 수 있습니다. 수행해야 할 작업은 다음과 같습니다:
```text
bulk_extractor memory.img -o out_folder
```
**모든 정보**를 도구가 수집한 것\(비밀번호?\)을 통해 탐색하고, **패킷**을 **분석**하고\(읽기[ **Pcaps 분석**](../pcap-inspection/)\), **이상한 도메인**\(악성 코드와 관련된 도메인 또는 **존재하지 않는** 도메인\)을 검색합니다.

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)에서 찾을 수 있습니다.

GUI 및 CLI 버전이 제공됩니다. PhotoRec가 검색할 **파일 유형**을 선택할 수 있습니다.

![](../../../.gitbook/assets/image%20%28524%29.png)

# 특정 데이터 카빙 도구

## FindAES

키 스케줄을 검색하여 AES 키를 찾습니다. TrueCrypt 및 BitLocker에서 사용되는 128, 192 및 256비트 키와 같은 키를 찾을 수 있습니다.

[여기](https://sourceforge.net/projects/findaes/)에서 다운로드하세요.

# 보조 도구

터미널에서 이미지를 볼 수 있는 [**viu** ](https://github.com/atanunq/viu)를 사용할 수 있습니다.
pdf를 텍스트로 변환하여 읽을 수 있는 리눅스 명령줄 도구 **pdftotext**를 사용할 수 있습니다.



{% hint style="success" %}
AWS 해킹을 배우고 실습하세요:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹을 배우고 실습하세요: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}
