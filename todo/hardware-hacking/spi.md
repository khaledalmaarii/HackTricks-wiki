# SPI

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)에 가입하거나 [텔레그램 그룹](https://t.me/peass)에 가입하거나** **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 요령을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출하세요.**

</details>

## 기본 정보

SPI (Serial Peripheral Interface)는 임베디드 시스템에서 사용되는 동기식 직렬 통신 프로토콜로, IC(통합 회로) 간의 짧은 거리 통신에 사용됩니다. SPI 통신 프로토콜은 마스터-슬레이브 아키텍처를 사용하며, 클럭 및 칩 선택 신호에 의해 조정됩니다. 마스터-슬레이브 아키텍처는 마스터(일반적으로 마이크로프로세서)와 EEPROM, 센서, 제어 장치 등 외부 페리페럴을 관리하는 슬레이브로 구성됩니다.

여러 슬레이브를 마스터에 연결할 수 있지만 슬레이브끼리 통신할 수는 없습니다. 슬레이브는 클럭 및 칩 선택 두 핀에 의해 관리됩니다. SPI는 동기식 통신 프로토콜이므로 입력 및 출력 핀은 클럭 신호를 따릅니다. 칩 선택은 마스터가 슬레이브를 선택하고 상호 작용하는 데 사용됩니다. 칩 선택이 높으면 슬레이브 장치가 선택되지 않으며, 낮으면 칩이 선택되고 마스터가 슬레이브와 상호 작용합니다.

MOSI(Master Out, Slave In) 및 MISO(Master In, Slave Out)는 데이터 송수신을 담당합니다. 데이터는 MOSI 핀을 통해 슬레이브 장치로 전송되며 칩 선택이 낮은 상태로 유지됩니다. 입력 데이터에는 슬레이브 장치 공급 업체의 데이터 시트에 따라 명령, 메모리 주소 또는 데이터가 포함됩니다. 유효한 입력 후 MISO 핀은 데이터를 마스터로 전송합니다. 출력 데이터는 입력이 끝난 후 다음 클럭 주기에 정확히 전송됩니다. MISO 핀은 데이터가 완전히 전송될 때까지 데이터를 전송하거나 마스터가 칩 선택 핀을 높게 설정할 때까지 데이터를 전송합니다(이 경우 슬레이브는 전송을 중지하고 마스터는 해당 클럭 주기 이후에 수신하지 않습니다).

## EEPROM에서 펌웨어 덤프

펌웨어 덤프는 펌웨어를 분석하고 그 중 취약점을 찾는 데 유용할 수 있습니다. 종종 펌웨어가 인터넷에서 사용할 수 없거나 모델 번호, 버전 등의 요소의 변화로 인해 관련이 없는 경우가 있습니다. 따라서 물리적 장치에서 펌웨어를 직접 추출하면 위협을 찾는 동안 구체적일 수 있어 도움이 될 수 있습니다.

시리얼 콘솔을 얻는 것이 도움이 될 수 있지만, 파일이 읽기 전용인 경우가 종종 있습니다. 이는 다양한 이유로 분석을 제한합니다. 예를 들어, 패키지를 보내고 수신하는 데 필요한 도구가 펌웨어에 없을 수 있습니다. 따라서 전체 펌웨어를 시스템에 덤프하고 분석을 위해 바이너리를 추출하는 것이 현실적이지 않을 수 있습니다. 따라서 펌웨어를 덤프하고 바이너리를 추출하여 분석하는 것이 매우 도움이 될 수 있습니다.

또한, 레드팀 활동 및 장치에 물리적 액세스를 얻는 경우, 펌웨어를 덤프하면 파일을 수정하거나 악성 파일을 삽입한 다음 메모리에 다시 플래싱하여 장치에 백도어를 심을 수 있습니다. 따라서 펌웨어 덤프로 잠금 해제할 수 있는 다양한 가능성이 있습니다.

### CH341A EEPROM 프로그래머 및 리더

이 장치는 EEPROM에서 펌웨어를 덤프하고 펌웨어 파일로 다시 플래싱하는 저렴한 도구입니다. 컴퓨터 BIOS 칩(단순히 EEPROM)과 작업하는 데 인기 있는 선택 사항이었습니다. 이 장치는 USB로 연결되며 시작하기 위한 최소한의 도구가 필요합니다. 또한 일반적으로 작업을 빠르게 완료하므로 물리적 장치 액세스에도 도움이 될 수 있습니다.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

EEPROM 메모리를 CH341a 프로그래머에 연결하고 장치를 컴퓨터에 연결합니다. 장치가 감지되지 않는 경우 컴퓨터에 드라이버를 설치해 보세요. 또한 EEPROM이 올바른 방향으로 연결되어 있는지 확인하세요(일반적으로 VCC 핀을 USB 커넥터의 반대 방향에 배치) 그렇지 않으면 소프트웨어가 칩을 감지하지 못할 수 있습니다. 필요한 경우 다음 다이어그램을 참조하세요:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

마지막으로, flashrom, G-Flash(GUI) 등과 같은 소프트웨어를 사용하여 펌웨어를 덤프하세요. G-Flash는 최소한의 GUI 도구로 빠르게 작업을 감지하고 EEPROM을 자동으로 감지합니다. 이는 문서를 많이 참고하지 않고 빠르게 펌웨어를 추출해야 하는 경우에 유용할 수 있습니다.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

펌웨어를 덤프한 후 바이너리 파일에서 분석을 수행할 수 있습니다. 문자열, hexdump, xxd, binwalk 등과 같은 도구를 사용하여 펌웨어 및 전체 파일 시스템에 대한 많은 정보를 추출할 수 있습니다.

펌웨어에서 내용을 추출하려면 binwalk를 사용할 수 있습니다. Binwalk는 16진수 시그니처를 분석하고 바이너리 파일에서 파일을 식별하며 추출할 수 있습니다.
```
binwalk -e <filename>
```
파일은 도구 및 구성에 따라 .bin 또는 .rom이 될 수 있습니다.

{% hint style="danger" %}
펌웨어 추출은 섬세한 과정이며 많은 인내심이 필요합니다. 잘못 다루면 펌웨어가 손상될 수 있거나 완전히 지워져 장치를 사용할 수 없게 만들 수 있습니다. 펌웨어를 추출하기 전에 특정 장치를 연구하는 것이 권장됩니다.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Pirate Bus의 핀 배치가 **MOSI** 및 **MISO** 핀을 SPI에 연결하도록 지시하지만 일부 SPI는 핀을 DI 및 DO로 지시할 수 있습니다. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

Windows 또는 Linux에서 [**`flashrom`**](https://www.flashrom.org/Flashrom) 프로그램을 사용하여 다음과 같이 플래시 메모리의 내용을 덤프할 수 있습니다:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 구매하세요
* [**PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 트릭을 공유하고 싶다면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
