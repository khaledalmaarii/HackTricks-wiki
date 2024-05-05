# UART

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

- **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
- **해킹 요령을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**되었는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보 도난 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 확인하고 무료로 엔진을 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

***

## 기본 정보

UART는 시리얼 프로토콜로, 구성 요소 간에 데이터를 한 번에 한 비트씩 전송합니다. 반면에 병렬 통신 프로토콜은 여러 채널을 통해 동시에 데이터를 전송합니다. 일반적인 시리얼 프로토콜로는 RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express, USB 등이 있습니다.

일반적으로 UART가 대기 상태일 때 라인은 높은 상태(논리 1 값)를 유지합니다. 그런 다음 송신기는 데이터 전송의 시작을 신호하기 위해 시작 비트를 수신기에 보내는데, 이때 신호는 낮은 상태(논리 0 값)를 유지합니다. 그런 다음 송신기는 실제 메시지를 포함하는 다섯 개에서 여덟 개의 데이터 비트를 보내고, 선택적으로 패리티 비트와 한 개 또는 두 개의 스톱 비트(논리 1 값)를 보냅니다. 오류 확인에 사용되는 패리티 비트는 실제로는 거의 보이지 않습니다. 스톱 비트(또는 비트)는 전송의 끝을 나타냅니다.

가장 일반적인 구성인 8N1을 사용합니다: 여덟 개의 데이터 비트, 패리티 없음 및 하나의 스톱 비트. 예를 들어, 8N1 UART 구성에서 문자 C 또는 ASCII에서 0x43을 보내려면 다음 비트를 보냅니다: 0(시작 비트); 0, 1, 0, 0, 0, 0, 1, 1(2진수 0x43의 값) 및 0(스톱 비트).

![](<../../.gitbook/assets/image (764).png>)

UART와 통신하기 위한 하드웨어 도구:

- USB-시리얼 어댑터
- CP2102 또는 PL2303 칩이 장착된 어댑터
- Bus Pirate, Adafruit FT232H, Shikra 또는 Attify Badge와 같은 다목적 도구

### UART 포트 식별

UART에는 **TX**(송신), **RX**(수신), **Vcc**(전압), **GND**(그라운드)가 있습니다. PCB에 **`TX`** 및 **`RX`** 글자가 **쓰여진** 4개의 포트를 찾을 수 있습니다. 그러나 표시가 없는 경우, **멀티미터**나 **로직 분석기**를 사용하여 직접 찾아야 할 수 있습니다.

**멀티미터**와 장치 전원을 끈 상태에서:

- **Continuity Test** 모드를 사용하여 **GND** 핀을 식별하려면, 백색 리드를 그라운드에 놓고 빨간색 리드로 테스트하여 멀티미터에서 소리가 들릴 때까지 테스트합니다. PCB에는 여러 GND 핀이 있을 수 있으므로 UART에 속하는 핀을 찾았을 수도, 못 찾았을 수도 있습니다.
- **VCC 포트**를 식별하려면 **DC 전압 모드**를 설정하고 20V 전압으로 설정합니다. 검은 프로브를 그라운드에 놓고 빨간 프로브를 핀에 놓습니다. 장치의 전원을 켭니다. 멀티미터가 3.3V 또는 5V의 일정한 전압을 측정하면 Vcc 핀을 찾은 것입니다. 다른 전압을 측정하면 다른 포트로 다시 시도하세요.
- **TX** **포트**를 식별하려면 **DC 전압 모드**를 최대 20V의 전압으로 설정하고, 검은 프로브를 그라운드에 놓고 빨간 프로브를 핀에 놓고 장치의 전원을 켭니다. 전압이 몇 초 동안 변동한 후 Vcc 값으로 안정화되면 대부분 TX 포트를 찾은 것입니다. 이는 전원을 켤 때 디버그 데이터를 보내기 때문입니다.
- **RX 포트**는 다른 3개에 가장 가까운 포트이며, UART 핀 중에서 전압 변동이 가장 낮고 전체 값이 가장 낮습니다.

TX와 RX 포트를 혼동해도 아무 일도 일어나지 않지만, GND와 VCC 포트를 혼동하면 회로를 손상시킬 수 있습니다.

일부 대상 장치에서 제조업체가 RX 또는 TX를 비활성화하여 UART 포트를 비활성화하는 경우가 있습니다. 이 경우 회로 기판에서 연결을 추적하고 일부 분기점을 찾는 것이 도움이 될 수 있습니다. UART를 감지하지 못하고 회로가 끊어진 것을 확인하는 강력한 힌트는 장치 보증을 확인하는 것입니다. 장치에 보증이 함께 제공된 경우 제조업체는 일부 디버그 인터페이스(이 경우 UART)를 남겨두고 있으며, 디버깅 중에 UART를 연결하고 다시 연결할 것입니다. 이러한 분기 핀은 솔더링이나 점퍼 와이어로 연결할 수 있습니다.

### UART 보드 속도 식별

올바른 보드 속도를 식별하는 가장 쉬운 방법은 **TX 핀의 출력을 확인하고 데이터를 읽어보는 것**입니다. 받은 데이터가 읽을 수 없는 경우, 데이터가 읽을 수 있을 때까지 다음 가능한 보드 속도로 전환하세요. 이 작업을 수행하기 위해 USB-시리얼 어댑터나 Bus Pirate와 함께 [baudrate.py](https://github.com/devttys0/baudrate/)와 같은 도우미 스크립트를 사용할 수 있습니다. 가장 일반적인 보드 속도는 9600, 38400, 19200, 57600, 115200입니다.

{% hint style="danger" %}
이 프로토콜에서는 한 장치의 TX를 다른 장치의 RX에 연결해야 합니다!
{% endhint %}

## CP210X UART to TTY 어댑터

CP210X 칩은 NodeMCU(esp8266와 함께)와 같은 프로토타이핑 보드에서 시리얼 통신에 사용됩니다. 이러한 어댑터는 비교적 저렴하며 대상의 UART 인터페이스에 연결하는 데 사용할 수 있습니다. 이 장치에는 5개의 핀이 있습니다: 5V, GND, RXD, TXD, 3.3V. 대상이 지원하는 전압으로 연결하여 손상을 방지하세요. 마지막으로 어댑터의 RXD 핀을 대상의 TXD에 연결하고 어댑터의 TXD 핀을 대상의 RXD에 연결하세요.

어댑터가 감지되지 않는 경우, 호스트 시스템에 CP210X 드라이버가 설치되어 있는지 확인하세요. 어댑터가 감지되고 연결된 후에는 picocom, minicom 또는 screen과 같은 도구를 사용할 수 있습니다.

Linux/MacOS 시스템에 연결된 장치를 나열하려면:
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
`시리얼 포트 설정` 옵션에서 보레이트 및 장치 이름과 같은 설정을 구성합니다.

구성 후 `minicom` 명령을 사용하여 UART 콘솔을 시작합니다.

## Arduino UNO R3를 통한 UART (탈착 가능한 Atmel 328p 칩 보드)

UART 시리얼 대 USB 어댑터를 사용할 수 없는 경우, Arduino UNO R3를 빠른 해킹으로 사용할 수 있습니다. Arduino UNO R3는 일반적으로 어디서나 사용할 수 있으므로 많은 시간을 절약할 수 있습니다.

Arduino UNO R3에는 보드 자체에 내장된 USB에서 시리얼 어댑터가 있습니다. UART 연결을 얻으려면 보드에서 Atmel 328p 마이크로컨트롤러 칩을 뽑기만 하면 됩니다. 이 해킹은 보드에 납땜되지 않은 Atmel 328p가 있는 Arduino UNO R3 변형에서 작동합니다 (SMD 버전이 사용됨). Arduino의 RX 핀 (디지털 핀 0)을 UART 인터페이스의 TX 핀에 연결하고 Arduino의 TX 핀 (디지털 핀 1)을 UART 인터페이스의 RX 핀에 연결합니다.

마지막으로 UART 인터페이스에 따라 보레이트 속도를 설정하고 Arduino IDE를 사용하는 것이 좋습니다. 메뉴의 `도구` 섹션에서 `시리얼 콘솔` 옵션을 선택하고 UART 인터페이스에 맞게 보레이트 속도를 설정합니다.

## Bus Pirate

이 시나리오에서는 프로그램의 모든 출력을 시리얼 모니터로 보내는 Arduino의 UART 통신을 스니핑할 것입니다.
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
## UART 콘솔을 사용하여 펌웨어 덤프

UART 콘솔은 런타임 환경에서 기본 펌웨어를 다루는 훌륭한 방법을 제공합니다. 그러나 UART 콘솔 액세스가 읽기 전용인 경우 많은 제약 사항이 발생할 수 있습니다. 많은 임베디드 장치에서 펌웨어는 EEPROM에 저장되고 휘발성 메모리를 갖는 프로세서에서 실행됩니다. 따라서 제조 중에 원래 펌웨어가 EEPROM 자체에 있으며 새 파일은 휘발성 메모리로 인해 손실될 수 있기 때문에 펌웨어는 읽기 전용으로 유지됩니다. 따라서 임베디드 펌웨어를 다룰 때 펌웨어 덤프는 귀중한 노력입니다.

이를 수행하는 다양한 방법이 있으며 SPI 섹션에서는 다양한 장치를 사용하여 EEPROM에서 펌웨어를 직접 추출하는 방법을 다룹니다. 그러나 물리적 장치 및 외부 상호 작용을 사용하여 펌웨어를 덤프하는 것은 위험할 수 있으므로 먼저 UART를 사용하여 펌웨어를 덤프하는 것이 권장됩니다.

UART 콘솔에서 펌웨어를 덤프하려면 먼저 부트로더에 액세스해야 합니다. 많은 인기 있는 공급업체는 리눅스를 로드하기 위해 uboot (Universal Bootloader)을 부트로더로 사용합니다. 따라서 uboot에 액세스하는 것이 필요합니다.

부트로더에 액세스하려면 UART 포트를 컴퓨터에 연결하고 시리얼 콘솔 도구 중 하나를 사용하고 장치에 전원 공급을 끊은 상태로 유지합니다. 설정이 준비되면 Enter 키를 누르고 누른 채로 유지합니다. 마지막으로 장치에 전원을 공급하고 부팅을 시작합니다.

이렇게 하면 uboot의 로드가 중단되고 메뉴가 제공됩니다. uboot 명령을 이해하고 도움 메뉴를 사용하여 목록을 표시하는 것이 좋습니다. 이것은 `help` 명령일 수 있습니다. 다른 공급업체가 서로 다른 구성을 사용하므로 각각을 별도로 이해하는 것이 필요합니다.

일반적으로 펌웨어를 덤프하는 명령은 다음과 같습니다:
```
md
```
"memory dump"의 약자입니다. 이는 화면에 메모리 (EEPROM 콘텐츠)를 덤프합니다. 메모리 덤프를 캡처하기 위해 proceedure를 시작하기 전에 Serial Console 출력을 기록하는 것이 좋습니다.

마지막으로, 로그 파일에서 모든 불필요한 데이터를 제거하고 파일을 `filename.rom`으로 저장하고 binwalk를 사용하여 콘텐츠를 추출합니다:
```
binwalk -e <filename.rom>
```
이 파일에서 발견된 헥스 파일의 서명에 따라 EEPROM에서 가능한 내용을 나열합니다.

그러나 사용 중인 경우에도 항상 uboot가 잠겨 있지 않을 수 있음을 유의해야 합니다. Enter 키가 작동하지 않는 경우 Space 키 등 다른 키를 확인하십시오. 부트로더가 잠겨 있고 중단되지 않으면이 방법은 작동하지 않습니다. 장치의 부팅 중 UART 콘솔 출력을 확인하여 uboot가 장치의 부트로더인지 확인하십시오. 부팅 중에 uboot를 언급할 수 있습니다.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 하는 회사 또는 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**되었는지 확인하는 **무료** 기능을 제공하는 검색 엔진입니다.

WhiteIntel의 주요 목표는 정보를 도난 당한 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 **무료**로 엔진을 시도해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로**부터 **히어로**까지 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하고 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션을 만나보세요
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
