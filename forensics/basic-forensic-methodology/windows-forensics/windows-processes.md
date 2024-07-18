{% hint style="success" %}
**AWS 해킹 학습 및 실습:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**GCP 해킹 학습 및 실습:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소로 **PR 제출**하여 해킹 요령을 공유하세요.

</details>
{% endhint %}


## smss.exe

**세션 관리자**.\
세션 0은 **csrss.exe** 및 **wininit.exe** (**OS 서비스**)를 시작하고, 세션 1은 **csrss.exe** 및 **winlogon.exe** (**사용자 세션**)를 시작합니다. 그러나 프로세스 트리에서 **해당 이진 파일의 자식이 없는 프로세스**를 하나만 볼 수 있어야 합니다.

또한, 0과 1 이외의 세션은 RDP 세션이 발생 중임을 의미할 수 있습니다.


## csrss.exe

**클라이언트/서버 실행 서브시스템 프로세스**.\
**프로세스** 및 **스레드**를 관리하며 다른 프로세스에 **Windows API**를 제공하고 **드라이브 문자를 매핑**하고 **임시 파일을 생성**하며 **종료 프로세스를 처리**합니다.

세션 0 및 세션 1에서 각각 하나씩 실행됩니다 (프로세스 트리에 **2개의 프로세스**가 있어야 함). 새로운 세션마다 하나씩 생성됩니다.


## winlogon.exe

**Windows 로그온 프로세스**.\
사용자 **로그온**/**로그오프**를 담당합니다. 사용자 이름과 암호를 요청하기 위해 **logonui.exe**를 실행하고, 그런 다음 **lsass.exe**를 호출하여 이를 확인합니다.

그런 다음 **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`**의 **Userinit** 키로 지정된 **userinit.exe**를 실행합니다.

또한, 이전 레지스트리에는 **Shell 키**에 **explorer.exe**가 있어야 하며, 그렇지 않으면 **악성 코드 지속성 방법**으로 악용될 수 있습니다.


## wininit.exe

**Windows 초기화 프로세스**. \
세션 0에서 **services.exe**, **lsass.exe**, **lsm.exe**를 시작합니다. 하나의 프로세스만 있어야 합니다.


## userinit.exe

**사용자 로그온 응용 프로그램**.\
**HKCU의 ntduser.dat**를 로드하고 **사용자 환경**을 초기화하고 **로그온 스크립트** 및 **GPO**를 실행합니다.

**explorer.exe**를 실행합니다.


## lsm.exe

**로컬 세션 관리자**.\
사용자 세션을 조작하기 위해 smss.exe와 함께 작동합니다: 로그온/로그오프, 셸 시작, 데스크톱 잠금/해제 등.

W7 이후 lsm.exe는 서비스(lsm.dll)로 변환되었습니다.

W7에는 하나의 프로세스만 있어야 하며, 그 중 하나는 DLL을 실행하는 서비스입니다.


## services.exe

**서비스 제어 관리자**.\
**자동 시작으로 구성된 서비스** 및 **드라이버**를 **로드**합니다.

**svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** 및 기타 많은 프로세스의 상위 프로세스입니다.

서비스는 `HKLM\SYSTEM\CurrentControlSet\Services`에 정의되어 있으며, 이 프로세스는 메모리에 서비스 정보의 DB를 유지하고 sc.exe에서 쿼리할 수 있습니다.

일부 **서비스**는 **자체 프로세스에서 실행**되고 다른 서비스는 **svchost.exe 프로세스를 공유**할 것입니다.

하나의 프로세스만 있어야 합니다.


## lsass.exe

**로컬 보안 권한 서브시스템**.\
사용자 **인증**을 담당하고 **보안 토큰**을 생성합니다. `HKLM\System\CurrentControlSet\Control\Lsa`에 위치한 인증 패키지를 사용합니다.

**보안** **이벤트** **로그**에 기록하며, 하나의 프로세스만 있어야 합니다.

이 프로세스는 패스워드 덤프를 위해 공격을 많이 받는다는 점을 염두에 두세요.


## svchost.exe

**일반 서비스 호스트 프로세스**.\
여러 DLL 서비스를 하나의 공유 프로세스에 호스팅합니다.

일반적으로 **svchost.exe**가 `-k` 플래그와 함께 실행됩니다. 이는 레지스트리 **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost**로 쿼리를 시작하고, 여기에는 -k에 언급된 인수가 포함된 키가 있으며, 동일한 프로세스에서 실행할 서비스가 포함됩니다.

예: `-k UnistackSvcGroup`은 다음을 실행합니다: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

**-s 플래그**가 인수와 함께 사용되면 svchost에게 **지정된 서비스만 실행**하도록 요청됩니다.

`svchost.exe`의 여러 프로세스가 있을 것입니다. 그 중 하나라도 **`-k` 플래그를 사용하지 않는다면** 매우 의심스럽습니다. 또한 **상위 프로세스가 services.exe가 아니라면** 매우 의심스럽습니다.


## taskhost.exe

이 프로세스는 DLL에서 실행되는 프로세스를 호스팅하는 역할을 합니다. 또한 DLL에서 실행되는 서비스를 로드합니다.

W8에서는 taskhostex.exe로, W10에서는 taskhostw.exe로 불립니다.


## explorer.exe

이 프로세스는 **사용자 데스크톱**을 담당하고 파일 확장자를 통해 파일을 실행합니다.

**로그온한 사용자당 1개의** 프로세스가 생성되어야 합니다.

이는 **userinit.exe**에서 실행되며, 따라서 이 프로세스에 대한 **부모가 없어야** 합니다.


# 악성 프로세스 탐지

* 예상 경로에서 실행 중인가? (Windows 이진 파일은 임시 위치에서 실행되지 않음)
* 이상한 IP와 통신 중인가?
* 디지털 서명을 확인하세요 (Microsoft 아티팩트는 서명되어야 함)
* 철자가 올바른가?
* 예상 SID 하에서 실행 중인가?
* 부모 프로세스가 예상대로인가 (있는 경우)?
* 자식 프로세스가 예상대로인가? (cmd.exe, wscript.exe, powershell.exe가 없는지 확인하세요)


{% hint style="success" %}
**AWS 해킹 학습 및 실습:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**GCP 해킹 학습 및 실습:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소로 **PR 제출**하여 해킹 요령을 공유하세요.

</details>
{% endhint %}
