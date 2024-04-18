# Wireshark 트릭

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로**부터 **히어로**까지 **AWS 해킹**을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

- **회사를 HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)는 **다크 웹**을 활용한 검색 엔진으로, **회사** 또는 **고객**이 **스틸러 악성 소프트웨어**에 의해 **침해**되었는지 **무료**로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보 도난 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 확인하고 **무료**로 엔진을 시도해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

---

## Wireshark 스킬 향상

### 튜토리얼

다음 튜토리얼은 멋진 기본 트릭을 배우는 데 훌륭합니다:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 분석된 정보

**전문가 정보**

_**Analyze** --> **Expert Information**_을 클릭하면 **분석된** 패킷에서 일어나는 일에 대한 **개요**를 얻을 수 있습니다:

![](<../../../.gitbook/assets/image (253).png>)

**해결된 주소**

_**Statistics --> Resolved Addresses**_ 아래에서 wireshark에 의해 **해결된** 여러 **정보**를 찾을 수 있습니다. 포트/전송에서 프로토콜, MAC에서 제조업체 등과 같은 것들이 포함되어 있습니다. 통신에 관련된 것을 알아두는 것이 흥미로울 수 있습니다.

![](<../../../.gitbook/assets/image (890).png>)

**프로토콜 계층 구조**

_**Statistics --> Protocol Hierarchy**_ 아래에서 통신에 관련된 **프로토콜**을 찾을 수 있으며 그에 대한 데이터도 포함되어 있습니다.

![](<../../../.gitbook/assets/image (583).png>)

**대화**

_**Statistics --> Conversations**_ 아래에서 통신에서의 **대화 요약**과 그에 대한 데이터를 찾을 수 있습니다.

![](<../../../.gitbook/assets/image (450).png>)

**엔드포인트**

_**Statistics --> Endpoints**_ 아래에서 통신에서의 **엔드포인트 요약**과 각각에 대한 데이터를 찾을 수 있습니다.

![](<../../../.gitbook/assets/image (893).png>)

**DNS 정보**

_**Statistics --> DNS**_ 아래에서 캡처된 DNS 요청에 대한 통계를 찾을 수 있습니다.

![](<../../../.gitbook/assets/image (1060).png>)

**I/O 그래프**

_**Statistics --> I/O Graph**_ 아래에서 통신의 **그래프**를 찾을 수 있습니다.

![](<../../../.gitbook/assets/image (989).png>)

### 필터

여기서 프로토콜에 따라 wireshark 필터를 찾을 수 있습니다: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
다른 흥미로운 필터:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS 트래픽
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS 트래픽 + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS 트래픽 + TCP SYN + DNS 요청

### 검색

세션의 **패킷** 내용을 **검색**하려면 _CTRL+f_를 누르세요. 오른쪽 버튼을 누르고 열 편집을 눌러 주요 정보 표시줄에 새 레이어를 추가할 수 있습니다(번호, 시간, 출처 등).

### 무료 pcap 랩

**무료 도전 과제로 연습하세요:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## 도메인 식별

Host HTTP 헤더를 표시하는 열을 추가할 수 있습니다:

![](<../../../.gitbook/assets/image (635).png>)

발신 HTTPS 연결에서 서버 이름을 추가하는 열을 추가할 수 있습니다 (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## 로컬 호스트 이름 식별

### DHCP에서

현재 Wireshark에서는 `bootp` 대신 `DHCP`를 검색해야 합니다.

![](<../../../.gitbook/assets/image (1010).png>)

### NBNS에서

![](<../../../.gitbook/assets/image (1000).png>)

## TLS 해독

### 서버 개인 키로 https 트래픽 해독

_편집>환경설정>프로토콜>ssl>_

![](<../../../.gitbook/assets/image (1100).png>)

_편집_을 누르고 서버 및 개인 키의 모든 데이터를 추가하세요(_IP, 포트, 프로토콜, 키 파일 및 암호_)

### 대칭 세션 키로 https 트래픽 해독

Firefox와 Chrome은 TLS 세션 키를 기록할 수 있는 능력이 있으며, 이는 Wireshark와 함께 사용하여 TLS 트래픽을 해독하는 데 사용될 수 있습니다. 이를 통해 안전한 통신의 심층 분석이 가능해집니다. 이 해독을 수행하는 방법에 대한 자세한 내용은 [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)의 가이드에서 찾을 수 있습니다.

이를 감지하려면 환경 내에서 `SSLKEYLOGFILE` 변수를 검색하세요

공유 키 파일은 다음과 같이 보일 것입니다:

![](<../../../.gitbook/assets/image (817).png>)

Wireshark에 이를 가져오려면 \_편집 > 환경설정 > 프로토콜 > ssl >로 이동하여 (Pre)-Master-Secret 로그 파일 이름에 가져옵니다:

![](<../../../.gitbook/assets/image (986).png>)
## ADB 통신

APK가 전송된 ADB 통신에서 APK를 추출하세요:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**당했는지 확인할 수 있는 **무료** 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난하는 악성 소프트웨어로 인한 계정 탈취와 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 **무료**로 엔진을 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)**이나 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
