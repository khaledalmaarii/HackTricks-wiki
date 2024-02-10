<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 여러분의 해킹 기교를 **공유**하세요.

</details>


## smss.exe

**세션 관리자**.\
세션 0은 **csrss.exe**와 **wininit.exe**(**OS 서비스**)를 시작하고 세션 1은 **csrss.exe**와 **winlogon.exe**(**사용자 세션**)을 시작합니다. 그러나 프로세스 트리에서는 **하나의 이진 파일 프로세스만** 볼 수 있어야 합니다.

또한, 0과 1 이외의 세션은 RDP 세션이 발생 중임을 의미할 수 있습니다.


## csrss.exe

**클라이언트/서버 실행 서브시스템 프로세스**.\
프로세스와 스레드를 관리하며, 다른 프로세스에게 **Windows API**를 사용할 수 있도록 하고, **드라이브 문자**를 매핑하고, **임시 파일**을 생성하며, **종료 프로세스**를 처리합니다.

세션 0과 세션 1에서 각각 하나씩 실행됩니다(프로세스 트리에 2개의 프로세스가 있음). 새로운 세션마다 하나씩 생성됩니다.


## winlogon.exe

**Windows 로그온 프로세스**.\
사용자의 **로그온/로그오프**를 담당합니다. 사용자 이름과 암호를 요청하기 위해 **logonui.exe**를 실행한 후, 이를 확인하기 위해 **lsass.exe**를 호출합니다.

그런 다음 **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`**의 **Userinit** 키에 지정된 **userinit.exe**를 실행합니다.

또한, 이전 레지스트리에는 **Shell 키**에 **explorer.exe**가 있어야 하며, 그렇지 않으면 **악성 소프트웨어 지속성 방법**으로 악용될 수 있습니다.


## wininit.exe

**Windows 초기화 프로세스**.\
세션 0에서 **services.exe**, **lsass.exe**, **lsm.exe**를 시작합니다. 프로세스는 하나만 있어야 합니다.


## userinit.exe

**Userinit 로그온 응용 프로그램**.\
**HKCU**의 **ntuser.dat**를 로드하고 **사용자 환경**을 초기화하며, **로그온 스크립트**와 **GPO**를 실행합니다.

**explorer.exe**를 실행합니다.


## lsm.exe

**로컬 세션 관리자**.\
smss.exe와 함께 사용자 세션을 조작하는 데 사용됩니다: 로그온/로그오프, 셸 시작, 데스크톱 잠금/해제 등.

W7 이후로 lsm.exe는 서비스(lsm.dll)로 변환되었습니다.

W7에서는 하나의 프로세스만 있어야 하며, 그 중 하나는 DLL을 실행하는 서비스입니다.


## services.exe

**서비스 제어 관리자**.\
**자동 시작**으로 구성된 **서비스**와 **드라이버**를 **로드**합니다.

**svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** 등의 부모 프로세스입니다.

서비스는 `HKLM\SYSTEM\CurrentControlSet\Services`에 정의되며, 이 프로세스는 sc.exe로 쿼리할 수 있는 서비스 정보의 메모리 내 DB를 유지합니다.

일부 서비스는 **자체 프로세스**에서 실행되고, 다른 서비스는 **svchost.exe 프로세스를 공유**합니다.

하나의 프로세스만 있어야 합니다.


## lsass.exe

**로컬 보안 권한 서브시스템**.\
사용자 **인증**을 담당하고 **보안 토큰**을 생성합니다. 인증 패키지는 `HKLM\System\CurrentControlSet\Control\Lsa`에 위치한 인증 패키지를 사용합니다.

**보안 이벤트 로그**에 기록하며, 하나의 프로세스만 있어야 합니다.

이 프로세스는 패스워드 덤프를 위해 공격을 많이 받는다는 점을 유념하세요.


## svchost.exe

**일반 서비스 호스트 프로세스**.\
하나의 공유 프로세스에서 여러 DLL 서비스를 호스팅합니다.

일반적으로 **svchost.exe**는 `-k` 플래그와 함께 실행됩니다. 이는 레지스트리 **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost**에 쿼리를 실행하여 -k에 언급된 인수를 포함하는 키가 있으며, 동일한 프로세스에서 실행할 서비스가 포함됩니다.

예를 들어, `-k UnistackSvcGroup`은 다음을 실행합니다: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

**-s 플래그**도 인수와 함께 사용되면 svchost에게 이 인수에서 **지정된 서비스만 실행**하도록 요청합니다.

여러 개의 `svchost.exe` 프로세스가 있을 수 있습니다. 그 중 **-k 플래그를 사용하지 않는** 프로세스가 있다면 매우 의심스럽습니다. **services.exe가 부모가 아닌 경우**도 매우 의심스럽습니다.


## taskhost.exe

이 프로세스는 DLL에서 실행되는 프로세스의 호스트 역할을 합니다. 또한 DLL에서 실행되는 서비스를 로드합니다.

W8에서는 taskhostex.exe로, W10에서는 taskhostw.exe로 불립니다.


## explorer.exe

이 프로세스는 **사용자의 데스크톱**을 담당하고 파일 확장자를 통해 파일을 실행합니다.

**로그온한 사용자당 하나의** 프로세스가 생성되어야 합니다.

이는 **userinit.exe**에서 실행되며, 종료된 **userinit.exe**에 대한 부모가 나타나지 않아야 합니다.


# 악성 프로세스 탐지

* 예상된 경로에서 실행 중인가요? (Windows 이진 파일은 임시 위치에서 실행되지 않습니다)
* 이상한 IP와 통신 중인가요?
* 디지털 서명을 확인하세요 (Microsoft 아티팩트는 서명되어야 합니다)
* 철자가 올바른가요?
* 예상된 SID에서 실행 중인가요?
* 부모 프로세스가 예상된 것인가요 (있는 경우)?
* 자
