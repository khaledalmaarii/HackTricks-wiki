<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식으로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>


# 기본 정보

UART는 컴포넌트 간에 데이터를 한 번에 한 비트씩 전송하는 직렬 프로토콜입니다. 반면에 병렬 통신 프로토콜은 여러 채널을 통해 동시에 데이터를 전송합니다. 일반적인 직렬 프로토콜에는 RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express 및 USB가 포함됩니다.

일반적으로 UART가 대기 상태에 있을 때 라인은 고수준(논리 1 값)을 유지합니다. 그런 다음 송신기는 수신기에 시작 비트를 보내어 데이터 전송의 시작을 신호합니다. 이 동안 신호는 낮은 수준(논리 0 값)을 유지합니다. 그런 다음 송신기는 실제 메시지를 포함하는 다섯 개에서 여덟 개의 데이터 비트를 보내고, 선택적으로 패리티 비트와 논리 1 값을 가진 하나 또는 두 개의 스톱 비트를 보냅니다. 오류 확인에 사용되는 패리티 비트는 실제로는 거의 보이지 않습니다. 스톱 비트(또는 비트)는 전송의 끝을 나타냅니다.

가장 일반적인 구성인 8N1을 사용합니다: 여덟 개의 데이터 비트, 패리티 없음 및 하나의 스톱 비트. 예를 들어, 8N1 UART 구성에서 문자 C 또는 ASCII에서 0x43을 보내려면 다음 비트를 보냅니다: 0(시작 비트); 0, 1, 0, 0, 0, 0, 1, 1(2진수 0x43의 값) 및 0(스톱 비트).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

UART와 통신하기 위한 하드웨어 도구:

* USB-시리얼 어댑터
* CP2102 또는 PL2303 칩이 장착된 어댑터
* Bus Pirate, Adafruit FT232H, Shikra 또는 Attify Badge와 같은 다목적 도구

## UART 포트 식별

UART에는 **TX**(송신), **RX**(수신), **Vcc**(전압) 및 **GND**(그라운드) 4개의 포트가 있습니다. PCB에 **`TX`** 및 **`RX`** 글자가 **쓰여 있는** 4개의 포트를 찾을 수 있습니다. 그러나 표시가 없는 경우 **멀티미터**나 **로직 분석기**를 사용하여 직접 찾아야 할 수 있습니다.

**멀티미터**와 장치 전원을 끈 상태에서:

* **Continuity Test** 모드를 사용하여 **GND** 핀을 식별하려면 백색 리드를 그라운드에 놓고 빨간 리드로 테스트하여 멀티미터에서 소리가 들리면 됩니다. PCB에는 여러 GND 핀이 있으므로 UART에 속한 핀을 찾았을 수도 있고 아닐 수도 있습니다.
* **VCC 포트**를 식별하려면 **DC 전압 모드**를 설정하고 20V의 전압으로 설정하세요. 검은 프로브를 그라운드에 놓고 빨간 프로브를 핀에 놓습니다. 장치의 전원을 켭니다. 멀티미터가 3.3V 또는 5V의 일정한 전압을 측정하면 Vcc 핀을 찾은 것입니다. 다른 전압을 측정하면 다른 포트로 다시 시도하세요.
* **TX** **포트**를 식별하려면 **DC 전압 모드**를 20V의 전압으로 설정하고 검은 프로브를 그라운드에 놓고 빨간 프로브를 핀에 놓고 장치의 전원을 켭니다. 전압이 몇 초 동안 변동한 다음 Vcc 값으로 안정화되면 대부분 TX 포트를 찾은 것입니다. 이는 전원을 켤 때 일부 디버그 데이터를 보내기 때문입니다.
* **RX 포트**는 다른 3개의 포트 중에서 가장 가까운 위치에 있으며 UART 핀 중에서 가장 낮은 전압 변동과 전체 값이 가장 낮습니다.

TX와 RX 포트를 혼동해도 아무 일도 일어나지 않지만 GND와 VCC 포트를 혼동하면 회로를 손상시킬 수 있습니다.

일부 대상 장치에서 제조업체가 RX 또는 TX를 비활성화하거나 둘 다 비활성화하여 UART 포트를 비활성화하는 경우가 있습니다. 이 경우 회로 기판에서 연결을 추적하고 일부 브레이크아웃 포인트를 찾는 것이 도움이 될 수 있습니다. UART를 감지하지 못하고 회로가 끊어진 것을 확인하는 강력한 힌트는 장치 보증을 확인하는 것입니다. 장치에 보증이 함께 제공된 경우 제조업체는 일부 디버그 인터페이스(이 경우 UART)를 남겨두고 있으며 디버깅 중에 UART를 연결하고 다시 연결할 것입니다. 이러한 브레이크아웃 핀은 솔더링이나 점퍼 와이어로 연결할 수 있습니다.

## UART 보드 속도 식별

올바른 보드 속도를 식별하는 가장 쉬운 방법은 **TX 핀의 출력을 확인하고 데이터를 읽어보는 것**입니다. 받은 데이터가 읽을 수 없는 경우 데이터가 읽을 수 있을 때까지 다음 가능한 보드 속도로 전환하세요. 이 작업을 수행하려면 USB-시리얼 어댑터나 Bus Pirate와 함께 [baudrate.py](https://github.com/devttys0/baudrate/)와 같은 도우미 스크립트를 사용할 수 있습니다. 가장 일반적인 보드 속도는 9600, 38400, 19200, 57600 및 115200입니다.

{% hint style="danger" %}
이 프로토콜에서는 한 장치의 TX를 다른 장치의 RX에 연결해야 합니다!
{% endhint %}

# CP210X UART to TTY 어댑터

CP210X 칩은 NodeMCU(esp8266이 장착된)와 같은 프로토타이핑 보드에서 시리얼 통신에 사용됩니다. 이러한 어댑터는 비교적 저렴하며 대상의 UART 인터페이스에 연결하는 데 사용할 수 있습니다. 이 장치에는 5개의 핀이 있습니다: 5V, GND, RXD, TXD, 3.3V. 대상이 지원하는 전압으로 연결하여 손상을 방지하세요. 마지막으로 어댑터의 RXD 핀을 대상의 TXD에 연결하고 어댑터의 TXD 핀을 대상의 RXD에 연결하세요.

어댑터가 감지되지 않는 경우 호스트 시스템에 CP210X 드라이버가 설치되어 있는지 확인하세요. 어댑터가 감지되고 연결된 후에는 picocom, minicom 또는 screen과 같은 도구를 사용할 수 있습니다.

Linux/MacOS 시스템에 연결된 장치 목록을 나열하려면:
```
ls /dev/
```
UART 인터페이스와의 기본 상호 작용을 위해 다음 명령을 사용하십시오:
```
picocom /dev/<adapter> --baud <baudrate>
```
minicom을 구성하려면 다음 명령을 사용하십시오:
```
minicom -s
```
설정을 구성하십시오. `Serial port setup` 옵션에서 보드 속도 및 장치 이름과 같은 설정을 구성하십시오.

구성 후 `minicom` 명령을 사용하여 UART 콘솔을 시작하십시오.

# Bus Pirate

이 시나리오에서는 프로그램의 모든 출력을 시리얼 모니터로 보내는 아두이노의 UART 통신을 스니핑할 것입니다.
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

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요!</summary>

다른 방법으로 HackTricks를 지원하는 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원한다면** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)에서 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
