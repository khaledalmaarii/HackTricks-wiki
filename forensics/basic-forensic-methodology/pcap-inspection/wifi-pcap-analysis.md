<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>


# BSSID 확인

WireShark를 사용하여 주요 트래픽이 Wifi인 캡처를 받으면 _Wireless --> WLAN Traffic_를 사용하여 캡처의 모든 SSID를 조사할 수 있습니다:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## 브루트 포스

해당 화면의 열 중 하나는 pcap 내에서 **인증이 발견되었는지 여부**를 나타냅니다. 그렇다면 `aircrack-ng`를 사용하여 브루트 포스를 시도할 수 있습니다:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
예를 들어, 나중에 트래픽을 해독하기 위해 필요한 PSK (사전 공유 키)를 보호하는 WPA 암호를 검색할 수 있습니다.

# 비콘 / 사이드 채널의 데이터

만약 **Wifi 네트워크의 비콘 내에서 데이터가 유출되고 있다고 의심**한다면, 다음과 같은 필터를 사용하여 네트워크의 비콘을 확인할 수 있습니다: `wlan contains <네트워크이름>`, 또는 `wlan.ssid == "네트워크이름"` 필터링된 패킷 내에서 의심스러운 문자열을 찾습니다.

# Wifi 네트워크에서 알 수 없는 MAC 주소 찾기

다음 링크는 **Wifi 네트워크 내에서 데이터를 보내는 기기들을 찾는 데 유용**할 것입니다:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

이미 알고 있는 **MAC 주소를 알고 있다면 출력에서 제외**하기 위해 다음과 같은 체크를 추가할 수 있습니다: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

네트워크 내에서 통신하는 **알 수 없는 MAC 주소를 감지한 후**, 다음과 같은 필터를 사용하여 해당 트래픽을 필터링할 수 있습니다: `wlan.addr==<MAC 주소> && (ftp || http || ssh || telnet)`. 트래픽을 해독한 경우 ftp/http/ssh/telnet 필터는 유용합니다.

# 트래픽 해독

편집 --> 환경 설정 --> 프로토콜 --> IEEE 802.11 --> 편집

![](<../../../.gitbook/assets/image (426).png>)





<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
