# Wireshark 트릭

## Wireshark 트릭

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 트릭을 공유**하세요.

</details>

## Wireshark 기술 향상

### 튜토리얼

다음 튜토리얼은 멋진 기본 트릭을 배우는 데 도움이 됩니다:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 분석된 정보

**전문가 정보**

_**Analyze** --> **Expert Information**_을 클릭하면 분석된 패킷에 대한 **개요**를 얻을 수 있습니다:

![](<../../../.gitbook/assets/image (570).png>)

**해결된 주소**

_**Statistics --> Resolved Addresses**_에서 포트/전송 프로토콜에서 프로토콜, MAC에서 제조업체 등과 같이 wireshark에 의해 "**해결된**" 여러 **정보**를 찾을 수 있습니다. 통신에 관련된 내용을 알아두는 것이 흥미로울 수 있습니다.

![](<../../../.gitbook/assets/image (571).png>)

**프로토콜 계층 구조**

_**Statistics --> Protocol Hierarchy**_에서 통신에 관련된 **프로토콜**과 관련된 데이터를 찾을 수 있습니다.

![](<../../../.gitbook/assets/image (572).png>)

**대화**

_**Statistics --> Conversations**_에서 통신에 대한 **대화 요약**과 관련된 데이터를 찾을 수 있습니다.

![](<../../../.gitbook/assets/image (573).png>)

**엔드포인트**

_**Statistics --> Endpoints**_에서 통신에 대한 **엔드포인트 요약**과 관련된 데이터를 찾을 수 있습니다.

![](<../../../.gitbook/assets/image (575).png>)

**DNS 정보**

_**Statistics --> DNS**_에서 캡처된 DNS 요청에 대한 통계를 찾을 수 있습니다.

![](<../../../.gitbook/assets/image (577).png>)

**I/O 그래프**

_**Statistics --> I/O Graph**_에서 통신의 **그래프**를 찾을 수 있습니다.

![](<../../../.gitbook/assets/image (574).png>)

### 필터

다음은 프로토콜에 따른 wireshark 필터를 찾을 수 있는 곳입니다: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
다른 흥미로운 필터:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP 및 초기 HTTPS 트래픽
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP 및 초기 HTTPS 트래픽 + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP 및 초기 HTTPS 트래픽 + TCP SYN + DNS 요청

### 검색

세션의 패킷 내용을 **검색**하려면 _CTRL+f_를 누르세요. 오른쪽 버튼을 누르고 편집 열을 눌러 주요 정보 막대에 새로운 레이어를 추가할 수 있습니다 (No., Time, Source 등).

### 무료 pcap 랩

**[https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)**의 무료 도전 과제로 연습하세요.

## 도메인 식별

Host HTTP 헤더를 표시하는 열을 추가할 수 있습니다:

![](<../../../.gitbook/assets/image (403).png>)

그리고 시작하는 HTTPS 연결에서 서버 이름을 추가하는 열을 추가할 수 있습니다 (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## 로컬 호스트 이름 식별

### DHCP에서

현재 Wireshark에서는 `bootp` 대신 `DHCP`를 검색해야 합니다.

![](<../../../.gitbook/assets/image (404).png>)

### NBNS에서

![](<../../../.gitbook/assets/image (405).png>)

## TLS 해독

### 서버 개인 키로 https 트래픽 해독

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

_Edit_를 누르고 서버와 개인 키의 모든 데이터 (_IP, Port, Protocol, Key file and password_)를 추가하세요.

### 대칭 세션 키로 https 트래픽 해독

Firefox와 Chrome은 TLS 세션 키를 기록하는 기능을 갖추고 있으며, 이를 Wireshark와 함께 사용하여 TLS 트래픽을 해독할 수 있습니다. 이를 통해 안전한 통신의 깊은 분석이 가능합니다. 이 해독을 수행하는 방법에 대한 자세한 내용은 [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)의 가이드에서 찾을 수 있습니다.

이를 감지하려면 환경에서 `SSLKEYLOGFILE` 변수를 검색하세요.

공유 키 파일은 다음과 같이 보일 것입니다:

![](<../../../.gitbook/assets/image (99).png>)

Wireshark에서 이를 가져오려면 \_edit > preference > protocol > ssl >로 이동하여 (Pre)-Master-Secret log filename에 가져옵니다:

![](<../../../.gitbook/assets/image (100).png>)

## ADB 통신

APK가 전송된 ADB 통신에서 APK를 추출하세요.
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
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
