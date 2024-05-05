# Wifi Pcap 분석

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고**하거나 **HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## BSSID 확인

WireShark를 사용하여 Wifi 주요 트래픽을 포함하는 캡처를 받았을 때, _Wireless --> WLAN Traffic_를 사용하여 캡처의 모든 SSID를 조사할 수 있습니다:

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### 브루트 포스

해당 화면의 열 중 하나는 **pcap 내에서 인증이 발견되었는지 여부**를 나타냅니다. 그렇다면 `aircrack-ng`를 사용하여 브루트 포스를 시도할 수 있습니다:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
## 비콘 / 사이드 채널의 데이터

예를 들어 **Wifi 네트워크의 비콘 내에서 데이터가 유출되고 있다고 의심**하는 경우 다음과 같은 필터를 사용하여 네트워크의 비콘을 확인할 수 있습니다: `wlan contains <NAMEofNETWORK>`, 또는 `wlan.ssid == "NAMEofNETWORK"` 필터링된 패킷 내에서 의심스러운 문자열을 찾습니다.

## Wifi 네트워크에서 알 수 없는 MAC 주소 찾기

다음 링크는 **Wifi 네트워크 내에서 데이터를 보내는 기기를 찾는 데 유용**합니다:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

이미 알고 있는 **MAC 주소가 있다면 출력에서 제거**하려면 다음과 같은 확인 사항을 추가하십시오: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

네트워크 내에서 통신하는 **알 수 없는 MAC 주소를 감지**한 후 다음과 같은 **필터**를 사용할 수 있습니다: `wlan.addr==<MAC 주소> && (ftp || http || ssh || telnet)` ftp/http/ssh/telnet 필터는 트래픽을 해독했다면 유용합니다.

## 트래픽 해독

편집 --> 환경 설정 --> 프로토콜 --> IEEE 802.11--> 편집

![](<../../../.gitbook/assets/image (499).png>)

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>
