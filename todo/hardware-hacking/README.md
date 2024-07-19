# 하드웨어 해킹

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

## JTAG

JTAG는 경계 스캔을 수행할 수 있게 해줍니다. 경계 스캔은 각 핀에 대한 내장 경계 스캔 셀 및 레지스터를 포함한 특정 회로를 분석합니다.

JTAG 표준은 다음을 포함하여 **경계 스캔을 수행하기 위한 특정 명령**을 정의합니다:

* **BYPASS**는 다른 칩을 통과하는 오버헤드 없이 특정 칩을 테스트할 수 있게 해줍니다.
* **SAMPLE/PRELOAD**는 장치가 정상 작동 모드에 있을 때 들어오고 나가는 데이터의 샘플을 가져옵니다.
* **EXTEST**는 핀 상태를 설정하고 읽습니다.

또한 다음과 같은 다른 명령도 지원할 수 있습니다:

* **IDCODE**는 장치를 식별합니다.
* **INTEST**는 장치의 내부 테스트를 수행합니다.

JTAGulator와 같은 도구를 사용할 때 이러한 명령을 접할 수 있습니다.

### 테스트 액세스 포트

경계 스캔에는 네 개의 와이어로 구성된 **테스트 액세스 포트 (TAP)** 테스트가 포함되며, 이는 구성 요소에 내장된 **JTAG 테스트 지원** 기능에 대한 **액세스**를 제공합니다. TAP는 다음 다섯 개의 신호를 사용합니다:

* 테스트 클럭 입력 (**TCK**) TCK는 TAP 컨트롤러가 단일 작업을 수행하는 빈도를 정의하는 **클럭**입니다(즉, 상태 기계에서 다음 상태로 점프).
* 테스트 모드 선택 (**TMS**) 입력 TMS는 **유한 상태 기계**를 제어합니다. 클럭의 각 비트에서 장치의 JTAG TAP 컨트롤러는 TMS 핀의 전압을 확인합니다. 전압이 특정 임계값 이하이면 신호는 낮은 것으로 간주되어 0으로 해석되고, 전압이 특정 임계값 이상이면 신호는 높은 것으로 간주되어 1로 해석됩니다.
* 테스트 데이터 입력 (**TDI**) TDI는 **스캔 셀을 통해 칩으로 데이터를 전송하는 핀**입니다. 각 공급업체는 이 핀을 통한 통신 프로토콜을 정의할 책임이 있습니다. JTAG는 이를 정의하지 않습니다.
* 테스트 데이터 출력 (**TDO**) TDO는 **칩에서 데이터를 전송하는 핀**입니다.
* 테스트 리셋 (**TRST**) 입력 선택적 TRST는 유한 상태 기계를 **알려진 좋은 상태**로 리셋합니다. 또는 TMS가 연속적으로 5개의 클럭 사이클 동안 1로 유지되면 TRST 핀과 동일한 방식으로 리셋을 호출합니다. 그래서 TRST는 선택적입니다.

때때로 PCB에서 이러한 핀에 마킹된 것을 찾을 수 있습니다. 다른 경우에는 **찾아야 할 수도 있습니다**.

### JTAG 핀 식별하기

JTAG 포트를 감지하는 가장 빠르고 비싼 방법은 **JTAGulator**를 사용하는 것입니다. 이는 이 목적을 위해 특별히 제작된 장치입니다(또한 **UART 핀 배치**도 감지할 수 있습니다).

이 장치는 보드 핀에 연결할 수 있는 **24개 채널**을 가지고 있습니다. 그런 다음 **BF 공격**을 수행하여 가능한 모든 조합에 대해 **IDCODE** 및 **BYPASS** 경계 스캔 명령을 전송합니다. 응답을 받으면 각 JTAG 신호에 해당하는 채널을 표시합니다.

더 저렴하지만 훨씬 느린 JTAG 핀 배치를 식별하는 방법은 Arduino 호환 마이크로컨트롤러에 로드된 [**JTAGenum**](https://github.com/cyphunk/JTAGenum/)을 사용하는 것입니다.

**JTAGenum**을 사용하면 먼저 열거에 사용할 프로빙 장치의 핀을 **정의해야** 합니다. 장치의 핀 배치 다이어그램을 참조한 다음 이러한 핀을 대상 장치의 테스트 포인트에 연결해야 합니다.

JTAG 핀을 식별하는 **세 번째 방법**은 **PCB를 검사하여 핀 배치를 찾는 것입니다**. 경우에 따라 PCB는 **Tag-Connect 인터페이스**를 제공할 수 있으며, 이는 보드에 JTAG 커넥터가 있다는 명확한 표시입니다. 해당 인터페이스가 어떻게 생겼는지는 [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/)에서 확인할 수 있습니다. 또한 PCB의 칩셋 데이터시트를 검사하면 JTAG 인터페이스를 가리키는 핀 배치 다이어그램을 발견할 수 있습니다.

## SDW

SWD는 디버깅을 위해 설계된 ARM 전용 프로토콜입니다.

SWD 인터페이스는 **두 개의 핀**이 필요합니다: 양방향 **SWDIO** 신호, 이는 JTAG의 **TDI 및 TDO 핀**과 클럭에 해당하며, **SWCLK**는 JTAG의 **TCK**에 해당합니다. 많은 장치는 **직렬 와이어 또는 JTAG 디버그 포트 (SWJ-DP)**를 지원하며, 이는 SWD 또는 JTAG 프로브를 대상에 연결할 수 있게 해줍니다.

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
