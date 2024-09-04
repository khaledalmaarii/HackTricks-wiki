# File/Data Carving & Recovery Tools

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Carving & Recovery tools

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

포렌식에서 이미지를 통해 파일을 추출하는 데 가장 일반적으로 사용되는 도구는 [**Autopsy**](https://www.autopsy.com/download/)입니다. 다운로드하여 설치한 후 파일을 가져와 "숨겨진" 파일을 찾으세요. Autopsy는 디스크 이미지 및 기타 종류의 이미지를 지원하도록 설계되었지만 단순 파일은 지원하지 않습니다.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**는 임베디드 콘텐츠를 찾기 위해 이진 파일을 분석하는 도구입니다. `apt`를 통해 설치할 수 있으며 소스는 [GitHub](https://github.com/ReFirmLabs/binwalk)에 있습니다.

**유용한 명령어**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

또 다른 일반적인 도구는 **foremost**입니다. foremost의 구성 파일은 `/etc/foremost.conf`에 있습니다. 특정 파일을 검색하려면 주석을 제거하면 됩니다. 아무것도 주석을 제거하지 않으면 foremost는 기본적으로 구성된 파일 유형을 검색합니다.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**은 **파일에 포함된 파일**을 찾고 추출하는 데 사용할 수 있는 또 다른 도구입니다. 이 경우, 추출하려는 파일 유형을 구성 파일(_/etc/scalpel/scalpel.conf_)에서 주석을 제거해야 합니다.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

이 도구는 칼리 안에 포함되어 있지만 여기에서 찾을 수 있습니다: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

이 도구는 이미지를 스캔하고 그 안에서 **pcap**을 **추출**하며, **네트워크 정보 (URL, 도메인, IP, MAC, 메일)** 및 기타 **파일**을 추출할 수 있습니다. 당신이 해야 할 일은:
```
bulk_extractor memory.img -o out_folder
```
모든 정보를 탐색하세요 **도구가 수집한** (비밀번호?), **패킷을 분석**하세요 (읽기 [**Pcaps 분석**](../pcap-inspection/)), **이상한 도메인**을 검색하세요 ( **악성코드** 또는 **존재하지 않는** 도메인과 관련된).

### PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)에서 찾을 수 있습니다.

GUI 및 CLI 버전이 함께 제공됩니다. PhotoRec이 검색할 **파일 유형**을 선택할 수 있습니다.

![](<../../../.gitbook/assets/image (524).png>)

### binvis

[코드](https://code.google.com/archive/p/binvis/)와 [웹 페이지 도구](https://binvis.io/#/)를 확인하세요.

#### BinVis의 기능

* 시각적이고 능동적인 **구조 뷰어**
* 다양한 초점에 대한 여러 플롯
* 샘플의 일부에 집중
* PE 또는 ELF 실행 파일에서 **문자열 및 리소스 보기**
* 파일에 대한 암호 분석을 위한 **패턴** 얻기
* **패커** 또는 인코더 알고리즘 **찾기**
* 패턴으로 스테가노그래피 **식별**
* **시각적** 바이너리 차이 비교

BinVis는 블랙박스 시나리오에서 **알 수 없는 대상에 익숙해지기 위한 훌륭한 시작점**입니다.

## 특정 데이터 카빙 도구

### FindAES

키 스케줄을 검색하여 AES 키를 검색합니다. TrueCrypt 및 BitLocker에서 사용하는 128, 192 및 256 비트 키를 찾을 수 있습니다.

[여기에서 다운로드](https://sourceforge.net/projects/findaes/).

## 보조 도구

[**viu**](https://github.com/atanunq/viu)를 사용하여 터미널에서 이미지를 볼 수 있습니다.\
리눅스 명령줄 도구 **pdftotext**를 사용하여 PDF를 텍스트로 변환하고 읽을 수 있습니다.

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter**에서 **팔로우**하세요 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.

</details>
{% endhint %}
