<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **당신의 해킹 기술을 공유**하세요.

</details>


# 기본 정보

SPI (Serial Peripheral Interface)는 임베디드 시스템에서 사용되는 동기식 직렬 통신 프로토콜로, ICs (통합 회로) 간의 짧은 거리 통신에 사용됩니다. SPI 통신 프로토콜은 클럭 및 칩 선택 신호에 의해 조정되는 마스터-슬레이브 아키텍처를 사용합니다. 마스터-슬레이브 아키텍처는 주로 마이크로프로세서와 같은 마스터가 EEPROM, 센서, 제어 장치 등 외부 페리페럴을 관리하는 슬레이브로 구성됩니다.

여러 슬레이브를 마스터에 연결할 수 있지만 슬레이브끼리 통신할 수는 없습니다. 슬레이브는 클럭 및 칩 선택 두 핀에 의해 관리됩니다. SPI는 동기식 통신 프로토콜이므로 입력 및 출력 핀은 클럭 신호를 따릅니다. 칩 선택은 마스터가 슬레이브를 선택하고 상호 작용하는 데 사용됩니다. 칩 선택이 높을 때는 슬레이브 장치가 선택되지 않으며, 낮을 때는 칩이 선택되고 마스터가 슬레이브와 상호 작용합니다.

MOSI (Master Out, Slave In) 및 MISO (Master In, Slave Out)는 데이터 송수신을 담당합니다. 데이터는 MOSI 핀을 통해 슬레이브 장치로 전송되며 칩 선택이 유지됩니다. 입력 데이터에는 슬레이브 장치 공급 업체의 데이터 시트에 따라 명령, 메모리 주소 또는 데이터가 포함됩니다. 유효한 입력 후 MISO 핀은 데이터를 마스터로 전송합니다. 출력 데이터는 입력이 끝난 다음 클럭 싸이클에서 정확히 전송됩니다. MISO 핀은 데이터가 완전히 전송될 때까지 데이터를 전송하거나 마스터가 칩 선택 핀을 높이 설정할 때까지 데이터를 전송합니다 (이 경우 슬레이브는 전송을 중지하고 마스터는 해당 클럭 싸이클 이후에 수신하지 않습니다).

# 플래시 덤프

## Bus Pirate + flashrom

![](<../../.gitbook/assets/image (201).png>)

Pirate Bus의 PINOUT에 **MOSI** 및 **MISO** 핀이 SPI에 연결되어야 한다고 나와 있지만 일부 SPI는 핀을 DI와 DO로 나타낼 수 있습니다. **MOSI -> DI, MISO -> DO**로 연결합니다.

![](<../../.gitbook/assets/image (648) (1) (1).png>)

Windows 또는 Linux에서 [**`flashrom`**](https://www.flashrom.org/Flashrom) 프로그램을 사용하여 플래시 메모리의 내용을 덤프할 수 있습니다. 다음과 같이 실행합니다:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 제로부터 영웅까지 AWS 해킹 배우기!</summary>

다른 방법으로 HackTricks를 지원하는 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하고 싶다면** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)에서 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
