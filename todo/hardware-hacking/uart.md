<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>


# 기본 정보

UART는 시리얼 프로토콜로, 구성 요소 간에 데이터를 한 번에 한 비트씩 전송합니다. 반면에 병렬 통신 프로토콜은 여러 채널을 통해 동시에 데이터를 전송합니다. 일반적인 시리얼 프로토콜에는 RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express 및 USB가 있습니다.

일반적으로 UART가 대기 상태에 있을 때는 라인이 높은 상태(논리 1 값)로 유지됩니다. 그런 다음, 데이터 전송의 시작을 신호하기 위해 송신기는 수신기로 시작 비트를 보내며, 이 동안 신호는 낮은 상태(논리 0 값)로 유지됩니다. 그 다음, 송신기는 실제 메시지를 포함하는 다섯 개에서 여덟 개의 데이터 비트를 보내고, 선택적으로 패리티 비트와 하나 또는 두 개의 스톱 비트(논리 1 값)를 보냅니다. 오류 확인에 사용되는 패리티 비트는 실제로는 거의 사용되지 않습니다. 스톱 비트(또는 비트)는 전송의 끝을 나타냅니다.

가장 일반적인 구성은 8N1입니다. 여덟 개의 데이터 비트, 패리티 없음 및 하나의 스톱 비트를 의미합니다. 예를 들어, 8N1 UART 구성에서 문자 C 또는 ASCII에서의 0x43을 보내려면 다음 비트를 보냅니다: 0(시작 비트); 0, 1, 0, 0, 0, 0, 1, 1(2진수로 표현한 0x43의 값); 0(스톱 비트).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

UART와 통신하기 위한 하드웨어 도구:

* USB-시리얼 어댑터
* CP2102 또는 PL2303 칩을 사용한 어댑터
* Bus Pirate, Adafruit FT232H, Shikra 또는 Attify Badge와 같은 다기능 도구

## UART 포트 식별

UART에는 **TX**(송신), **RX**(수신), **Vcc**(전압), **GND**(접지) 4개의 포트가 있습니다. PCB에 **`TX`**와 **`RX`** 글자가 **표시**된 포트를 찾을 수도 있습니다. 그러나 표시가 없는 경우 멀티미터나 로직 분석기를 사용하여 직접 찾아야 할 수도 있습니다.

멀티미터와 장치가 꺼진 상태에서:

* **접지(GND) 핀을 식별**하려면 **연속성 테스트** 모드를 사용하고, 백색 리드를 접지에 놓고 빨간색 리드로 테스트를 수행하면 멀티미터에서 소리가 들릴 때까지 찾습니다. 여러 GND 핀을 PCB에서 찾을 수 있으므로 UART에 속하는 핀을 찾았을 수도 있고 아닐 수도 있습니다.
* **VCC 포트를 식별**하려면 **DC 전압 모드**를 설정하고 전압을 20 V로 설정합니다. 검은색 프로브를 접지에, 빨간색 프로브를 핀에 대고 장치를 켭니다. 멀티미터가 3.3 V 또는 5 V의 일정한 전압을 측정하면 Vcc 핀을 찾은 것입니다. 다른 전압이 나오면 다른 포트로 다시 시도하세요.
* **TX 포트를 식별**하려면 **DC 전압 모드**를 사용하고 전압을 20 V로 설정하고, 검은색 프로브를 접지에, 빨간색 프로브를 핀에 대고 장치를 켭니다. 전압이 몇 초 동안 변동한 다음 Vcc 값으로 안정화되면 대부분 TX 포트를 찾은 것입니다. 이는 전원을 켤 때 디버그 데이터를 보내기 때문입니다.
* **RX 포트**는 다른 3개의 포트 중에서 가장 가까운 포트이며, 전압 변동이 가장 적고 UART 핀 중에서 가장 낮은 전압 값을 가지고 있습니다.

TX와 RX 포트를 혼동하면 아무 일도 일어나지 않지만, GND와 VCC 포트를 혼동하면 회로를 손상시킬 수 있습니다.

로직 분석기를 사용하여:

## UART 보드레이트 식별

올바른 보드레이트를 식별하는 가장 쉬운 방법은 **TX 핀의 출력을 확인하고 데이터를 읽어보는 것**입니다. 받은 데이터가 읽을 수 없는 경우, 데이터가 읽을 수 있을 때까지 다음 가능한 보드레이트로 전환합니다. 이 작업을 수행하기 위해 USB-시리얼 어댑터나 Bus Pirate와 같은 다기능 장치를 사용하고, [baudrate.py](https://github.com/devttys0/baudrate/)와 같은 도우미 스크립트를 사용할 수 있습니다. 가장 일반적인 보드레이트는 9600, 38400, 19200, 57600 및 115200입니다.

{% hint style="danger" %}
이 프로토콜에서는 한 장치의 TX를 다른 장치의 RX에 연결해야 함을 유의해야 합니다!
{% endhint %}

# Bus Pirate

이 시나리오에서는 프로그램의 모든 출력을 Serial Monitor로 보내는 Arduino의 UART 통신을 스니핑할 것입니다.
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
