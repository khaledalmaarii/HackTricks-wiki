# JTAG

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team 전문가)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 요령을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)은 알 수 없는 칩에서 JTAG 핀을 시도하기 위해 라즈베리 파이 또는 아두이노와 함께 사용할 수 있는 도구입니다.\
**아두이노**에서는 **핀 2에서 11까지를 JTAG에 속할 수 있는 10개의 핀에 연결**합니다. 아두이노에 프로그램을 로드하면 모든 핀을 무차별 대입하여 JTAG에 속하는지 여부와 각각이 무엇인지 찾으려고 합니다.\
**라즈베리 파이**에서는 **핀 1에서 6까지만 사용**할 수 있습니다 (6개의 핀이므로 각 잠재적인 JTAG 핀을 테스트하는 데 더 느릴 것입니다).

### 아두이노

아두이노에서 케이블을 연결한 후 (핀 2에서 11을 JTAG 핀에 연결하고 아두이노 GND를 베이스보드 GND에 연결), **아두이노에 JTAGenum 프로그램을 로드**하고 시리얼 모니터에서 **`h`** (도움말 명령)을 보내면 도움말이 표시됩니다:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

**"개행 없음"과 115200baud**로 구성하세요.\
스캔을 시작하려면 명령 s를 보냅니다:

![](<../../.gitbook/assets/image (774).png>)

JTAG에 연결되어 있다면 JTAG의 핀을 나타내는 **FOUND!**로 시작하는 하나 이상의 줄을 찾을 수 있습니다.
