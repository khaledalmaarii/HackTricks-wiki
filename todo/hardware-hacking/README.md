# 하드웨어 해킹

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWS 해킹을 제로부터 전문가까지 배우세요</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 요령을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

## JTAG

JTAG는 경계 스캔을 수행하는 것을 허용합니다. 경계 스캔은 특정 회로를 분석하며, 각 핀에 대한 임베디드 경계 스캔 셀과 레지스터를 포함합니다.

JTAG 표준은 **경계 스캔을 수행하기 위한 특정 명령어**를 정의하며, 다음을 포함합니다:

* **BYPASS**는 다른 칩을 통과하지 않고 특정 칩을 테스트할 수 있습니다.
* **SAMPLE/PRELOAD**는 장치가 정상 작동 모드일 때 들어오고 나가는 데이터의 샘플을 취합니다.
* **EXTEST**는 핀 상태를 설정하고 읽습니다.

또한 다음과 같은 다른 명령어를 지원할 수 있습니다:

* 장치를 식별하기 위한 **IDCODE**
* 장치의 내부 테스트를 위한 **INTEST**

JTAGulator와 같은 도구를 사용할 때 이러한 명령어를 만날 수 있습니다.

### 테스트 액세스 포트

경계 스캔에는 **테스트 액세스 포트 (TAP)**라는 네선이 포함되며, 이는 구성 요소에 내장된 JTAG 테스트 지원 기능에 **액세스**를 제공하는 일반용 포트입니다. TAP는 다음 다섯 신호를 사용합니다:

* 테스트 클럭 입력 (**TCK**) TCK는 TAP 컨트롤러가 단일 작업을 얼마나 자주 수행할지 정의하는 **클록**입니다 (다시 말해, 상태 머신에서 다음 상태로 이동하는 빈도).
* 테스트 모드 선택 (**TMS**) 입력 TMS는 **유한 상태 머신**을 제어합니다. 클록의 각 비트마다 장치의 JTAG TAP 컨트롤러는 TMS 핀의 전압을 확인합니다. 전압이 일정 임계값 아래인 경우 신호는 낮은 것으로 간주되고 0으로 해석되며, 전압이 일정 임계값을 초과하면 신호는 높은 것으로 간주되고 1로 해석됩니다.
* 테스트 데이터 입력 (**TDI**) TDI는 **스캔 셀을 통해 칩으로 데이터를 보내는 핀**입니다. 각 벤더는 이 핀을 통해 통신 프로토콜을 정의해야 합니다. 왜냐하면 JTAG는 이를 정의하지 않기 때문입니다.
* 테스트 데이터 출력 (**TDO**) TDO는 칩에서 **데이터를 보내는 핀**입니다.
* 테스트 리셋 (**TRST**) 입력 선택적인 TRST는 유한 상태 머신을 **알려진 좋은 상태로 재설정**합니다. 또는 TMS가 1로 5개의 연속 클록 주기 동안 유지되면 TRST 핀이 수행하는 것과 동일한 리셋을 호출합니다. 이것이 TRST가 선택 사항인 이유입니다.

때로는 PCB에서 이러한 핀들이 표시되어 있을 수 있습니다. 다른 경우에는 **찾아야 할 수도** 있습니다.

### JTAG 핀 식별

JTAG 포트를 감지하는 가장 빠르지만 가장 비싼 방법은 **JTAGulator**를 사용하는 것입니다. 이 장치는 이 목적을 위해 특별히 만들어졌으며 (또한 **UART 핀 배치도를 감지**할 수 있음), 보드 핀에 연결할 수 있는 **24개 채널**을 가지고 있습니다. 그런 다음 모든 가능한 조합에 대한 **IDCODE** 및 **BYPASS** 경계 스캔 명령을 보내는 **BF 공격**을 수행합니다. 응답을 받으면 각 JTAG 신호에 해당하는 채널을 표시합니다.

JTAG 핀 배치를 식별하는 더 저렴하지만 훨씬 느린 방법은 Arduino 호환 마이크로컨트롤러에 로드된 [**JTAGenum**](https://github.com/cyphunk/JTAGenum/)을 사용하는 것입니다.

**JTAGenum**을 사용하면 먼저 열거에 사용할 프로빙 장치의 핀을 **정의**해야 합니다. 장치의 핀 배치도를 참조한 다음 이러한 핀을 대상 장치의 테스트 포인트에 연결해야 합니다.

JTAG 핀을 식별하는 **세 번째 방법**은 PCB를 **검사**하여 핀 배치 중 하나를 찾는 것입니다. 경우에 따라 PCB가 JTAG 커넥터를 가지고 있음을 명확히 나타내는 **Tag-Connect 인터페이스**를 제공할 수 있습니다. 또한 PCB에 있는 칩셋의 **데이터시트를 검사**하면 JTAG 인터페이스를 가리키는 핀 배치도를 확인할 수 있습니다.

## SDW

SWD는 디버깅을 위해 설계된 ARM 특정 프로토콜입니다.

SWD 인터페이스는 **두 개의 핀**을 필요로 합니다: 양방향 **SWDIO** 신호, 이는 JTAG의 **TDI 및 TDO 핀에 해당하는 것**과 클록인 **SWCLK**가 필요합니다. 많은 장치가 **Serial Wire 또는 JTAG 디버그 포트 (SWJ-DP)**를 지원하며, 이는 SWD 또는 JTAG 프로브를 대상에 연결할 수 있도록 하는 결합된 JTAG 및 SWD 인터페이스입니다.
