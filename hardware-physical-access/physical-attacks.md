# Physical Attacks

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 여러분의 해킹 기교를 공유하세요.

</details>

## BIOS 비밀번호 복구 및 시스템 보안

**BIOS 재설정**은 여러 가지 방법으로 수행할 수 있습니다. 대부분의 마더보드에는 약 **30분 동안 제거**되면 BIOS 설정과 비밀번호를 포함하여 재설정하는 **배터리**가 포함되어 있습니다. 또는 **마더보드의 점퍼**를 조정하여 특정 핀을 연결하여 이러한 설정을 재설정할 수 있습니다.

하드웨어 조정이 불가능하거나 실용적이지 않은 경우, **소프트웨어 도구**를 사용하여 해결책을 제공합니다. **Kali Linux**와 같은 배포판을 사용하여 **Live CD/USB**에서 시스템을 실행하면 _**killCmos**_ 및 _**CmosPWD**_와 같은 도구를 사용하여 BIOS 비밀번호를 복구할 수 있습니다.

BIOS 비밀번호를 모르는 경우, 잘못된 비밀번호를 **세 번** 입력하면 일반적으로 오류 코드가 발생합니다. 이 코드는 [https://bios-pw.org](https://bios-pw.org)와 같은 웹 사이트에서 사용 가능한 비밀번호를 검색하는 데 사용할 수 있습니다.

### UEFI 보안

전통적인 BIOS 대신 **UEFI**를 사용하는 현대 시스템의 경우, **chipsec** 도구를 사용하여 UEFI 설정을 분석하고 수정할 수 있습니다. 다음 명령을 사용하여 **Secure Boot**를 비활성화할 수 있습니다:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM 분석 및 Cold Boot 공격

RAM은 전원이 차단된 후에도 데이터를 일시적으로 보유하며, 일반적으로 **1\~2분 동안** 지속됩니다. 이 지속 시간은 액체 질소와 같은 차가운 물질을 적용하여 **10분**까지 연장될 수 있습니다. 이 확장된 기간 동안 **dd.exe** 및 **volatility**와 같은 도구를 사용하여 **메모리 덤프**를 생성하여 분석할 수 있습니다.

### 직접 메모리 접근 (DMA) 공격

**INCEPTION**은 **FireWire** 및 **Thunderbolt**와 같은 인터페이스와 호환되는 DMA를 통한 **물리적 메모리 조작**을 위한 도구입니다. 이를 사용하여 메모리를 패치하여 모든 비밀번호를 허용하도록 메모리를 우회할 수 있습니다. 그러나 이는 **Windows 10** 시스템에는 효과가 없습니다.

### 시스템 액세스를 위한 Live CD/USB

_**sethc.exe**_ 또는 _**Utilman.exe**_과 같은 시스템 이진 파일을 _**cmd.exe**_의 사본으로 변경하면 시스템 권한이 있는 명령 프롬프트를 제공할 수 있습니다. **chntpw**와 같은 도구를 사용하여 Windows 설치의 **SAM** 파일을 편집하여 비밀번호를 변경할 수 있습니다.

**Kon-Boot**은 Windows 시스템에 암호를 모르고 로그인하는 데 도움이 되는 도구로, Windows 커널이나 UEFI를 일시적으로 수정합니다. 자세한 정보는 [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)에서 찾을 수 있습니다.

### Windows 보안 기능 다루기

#### 부팅 및 복구 바로 가기

* **Supr**: BIOS 설정에 액세스합니다.
* **F8**: 복구 모드로 진입합니다.
* Windows 배너 이후 **Shift**를 누르면 자동 로그인을 우회할 수 있습니다.

#### BAD USB 장치

**Rubber Ducky** 및 **Teensyduino**와 같은 장치는 대상 컴퓨터에 연결되었을 때 미리 정의된 페이로드를 실행할 수 있는 **bad USB** 장치를 생성하는 플랫폼으로 사용됩니다.

#### 볼륨 그림자 복사

관리자 권한을 사용하면 PowerShell을 통해 **SAM** 파일을 포함한 민감한 파일의 사본을 생성할 수 있습니다.

### BitLocker 암호 우회

BitLocker 암호는 메모리 덤프 파일 (**MEMORY.DMP**)에서 **복구 비밀번호**를 찾으면 우회될 수 있습니다. **Elcomsoft Forensic Disk Decryptor** 또는 **Passware Kit Forensic**와 같은 도구를 사용할 수 있습니다.

### 복구 키 추가를 위한 사회 공학

사회 공학 전술을 사용하여 새로운 BitLocker 복구 키를 추가할 수 있으며, 사용자를 설득하여 새로운 복구 키를 0으로 구성하여 복호화 프로세스를 간소화할 수 있습니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 여러분의 해킹 기교를 공유하세요.

</details>
