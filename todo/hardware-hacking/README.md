<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 해킹 트릭을 공유하세요.

</details>


#

# JTAG

JTAG는 경계 스캔을 수행할 수 있게 해줍니다. 경계 스캔은 각 핀에 대한 임베디드 경계 스캔 셀과 레지스터를 포함한 특정 회로를 분석합니다.

JTAG 표준은 다음과 같은 경계 스캔을 수행하기 위한 **특정 명령어**를 정의합니다:

* **BYPASS**는 다른 칩을 통과하지 않고 특정 칩을 테스트할 수 있게 합니다.
* **SAMPLE/PRELOAD**는 장치가 정상 작동 모드일 때 장치로 들어오고 나가는 데이터의 샘플을 가져옵니다.
* **EXTEST**는 핀 상태를 설정하고 읽습니다.

또한 다음과 같은 다른 명령어를 지원할 수도 있습니다:

* 장치 식별을 위한 **IDCODE**
* 장치의 내부 테스트를 위한 **INTEST**

JTAGulator와 같은 도구를 사용할 때 이러한 명령어를 사용할 수 있습니다.

## 테스트 액세스 포트

경계 스캔에는 일반적인 목적의 포트인 **테스트 액세스 포트 (TAP)**를 테스트하는 것이 포함됩니다. TAP는 구성 요소에 내장된 JTAG 테스트 지원 기능에 **액세스를 제공**하는 포트입니다. TAP은 다음 다섯 개의 신호를 사용합니다:

* 테스트 클럭 입력 (**TCK**) TCK는 TAP 컨트롤러가 단일 동작을 수행할 때마다 (다른 말로 상태 머신에서 다음 상태로 이동) 얼마나 자주 동작할지를 정의하는 **클럭**입니다.
* 테스트 모드 선택 (**TMS**) 입력 TMS는 **유한 상태 머신**을 제어합니다. 클럭의 각 비트마다 장치의 JTAG TAP 컨트롤러는 TMS 핀의 전압을 확인합니다. 전압이 특정 임계값 아래에 있는 경우 신호는 낮은 상태로 간주되고 0으로 해석되며, 전압이 특정 임계값 위에 있는 경우 신호는 높은 상태로 간주되고 1로 해석됩니다.
* 테스트 데이터 입력 (**TDI**) TDI는 스캔 셀을 통해 칩으로 **데이터를 보내는 핀**입니다. 각 공급업체는 이 핀을 통한 통신 프로토콜을 정의하는 것이므로 JTAG는 이를 정의하지 않습니다.
* 테스트 데이터 출력 (**TDO**) TDO는 칩에서 **데이터를 보내는 핀**입니다.
* 테스트 리셋 (**TRST**) 입력 선택적인 TRST는 유한 상태 머신을 **알려진 좋은 상태로 재설정**합니다. 또는 TMS를 1로 5개의 연속 클럭 주기 동안 유지하면 TRST 핀과 동일한 방식으로 리셋을 호출합니다. 이것이 TRST가 선택적인 이유입니다.

때로는 PCB에서 이러한 핀을 표시된 상태로 찾을 수 있습니다. 다른 경우에는 **찾아야 할 수도** 있습니다.

## JTAG 핀 식별

JTAG 포트를 감지하는 가장 빠르지만 가장 비싼 방법은 목적에 특화된 장치인 **JTAGulator**를 사용하는 것입니다 (UART 핀 배치도를 **감지**할 수도 있습니다).

JTAGulator에 연결할 수 있는 **24개의 채널**이 있습니다. 그런 다음 모든 가능한 조합에 대해 **IDCODE** 및 **BYPASS** 경계 스캔 명령을 보내는 **BF 공격**을 수행합니다. 응답을 받으면 각 JTAG 신호에 해당하는 채널을 표시합니다.

JTAG 핀 배치를 식별하는 더 저렴하지만 훨씬 느린 방법은 Arduino 호환 마이크로컨트롤러에 로드된 [**JTAGenum**](https://github.com/cyphunk/JTAGenum/)을 사용하는 것입니다.

**JTAGenum**을 사용하면 먼저 열거를 위해 사용할 프로빙 장치의 핀을 **정의**해야 합니다. 장치의 핀 배치도를 참조하고 이러한 핀을 대상 장치의 테스트 포인트에 연결해야 합니다.

JTAG 핀을 식별하는 **세 번째 방법**은 PCB를 **검사**하여 핀 배치도 중 하나를 찾는 것입니다. 일부 경우에는 PCB가 **Tag-Connect 인터페이스**를 편리하게 제공할 수 있으며, 이는 보드에 JTAG 커넥터가 있다는 명확한 표시입니다. 이 인터페이스의 모습은 [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/)에서 확인할 수 있습니다. 또한 PCB의 칩셋 데이터시트를 검사하면 JTAG 인터페이스를 가리키는 핀 배치도를 확인할 수 있습니다.

# SDW

SWD는 디버깅을 위해 설계된 ARM 전용 프로토콜입니다.

SWD 인터페이스는 **두 개의 핀**을 필요로 합니다: 양방향 **SWDIO** 신호, 이는 JTAG의 **TDI 및 TDO 핀과 동일한 역할을 하는 신호**이며, 클럭인 **SWCLK**, 이는 JTAG의 **TCK와 동일한 역할을 하는 신호**입니다. 많은 장치가 **Serial Wire 또는 JTAG 디버그 포트 (SWJ-DP)**를 지원하며, 이는 SWD 또는 JTAG 프로브를 대상에 연결할 수 있도록 하는 결합된 JTAG 및 SWD 인터페이스입니다.


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 해
