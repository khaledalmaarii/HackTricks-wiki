<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>


# JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum)은 Raspberry PI 또는 Arduino와 함께 사용하여 알 수 없는 칩에서 JTAG 핀을 찾을 수 있는 도구입니다.\
**Arduino**에서는 **2에서 11까지의 핀을 JTAG에 속할 수 있는 10개의 핀에 연결**합니다. Arduino에 프로그램을 로드하면 모든 핀을 무차별 대입하여 JTAG에 속하는 핀과 각각의 핀을 찾으려고 시도합니다.\
**Raspberry PI**에서는 **1에서 6까지의 핀**만 사용할 수 있습니다(6개의 핀이므로 각 잠재적인 JTAG 핀을 테스트하는 데 더 느릴 수 있음).

## Arduino

Arduino에서 케이블을 연결한 후(핀 2에서 11을 JTAG 핀에 연결하고 Arduino GND를 기판 GND에 연결), **Arduino에 JTAGenum 프로그램을 로드**하고 Serial Monitor에서 **`h`** (도움말 명령)을 보내면 도움말이 표시됩니다:

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

**"No line ending"과 115200baud**로 구성하세요.\
스캔을 시작하려면 명령 s를 보냅니다:

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

JTAG에 연결되어 있는 경우 JTAG의 핀을 나타내는 하나 이상의 **FOUND!로 시작하는 라인**을 찾을 수 있습니다.


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
