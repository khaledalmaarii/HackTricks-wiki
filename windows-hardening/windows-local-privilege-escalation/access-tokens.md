# Access Tokens

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


## Access Tokens

각 **사용자가 시스템에 로그인**하면 **해당 로그인 세션에 대한 보안 정보가 포함된 액세스 토큰을 보유**합니다. 사용자가 로그인할 때 시스템은 액세스 토큰을 생성합니다. **사용자를 대신하여 실행되는 모든 프로세스는** **액세스 토큰의 복사본을 가집니다**. 이 토큰은 사용자를 식별하고, 사용자의 그룹 및 사용자의 권한을 나타냅니다. 토큰에는 현재 로그인 세션을 식별하는 로그인 SID(보안 식별자)도 포함되어 있습니다.

이 정보를 보려면 `whoami /all`을 실행할 수 있습니다.
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![](<../../.gitbook/assets/image (772).png>)

### 로컬 관리자

로컬 관리자가 로그인할 때, **두 개의 액세스 토큰이 생성됩니다**: 하나는 관리자 권한을 가진 것이고, 다른 하나는 일반 권한을 가진 것입니다. **기본적으로**, 이 사용자가 프로세스를 실행할 때 **일반** (비관리자) **권한이 사용됩니다**. 이 사용자가 **관리자로서** 무엇인가를 **실행하려고** 할 때 ("관리자로 실행" 예를 들어) **UAC**가 권한을 요청하기 위해 사용됩니다.\
UAC에 대해 [**더 알아보려면 이 페이지를 읽어보세요**](../authentication-credentials-uac-and-efs/#uac)**.**

### 자격 증명 사용자 가장

다른 사용자의 **유효한 자격 증명이 있다면**, 해당 자격 증명으로 **새로운 로그온 세션을 생성**할 수 있습니다:
```
runas /user:domain\username cmd.exe
```
**액세스 토큰**은 **LSASS** 내의 로그온 세션에 대한 **참조**도 가지고 있습니다. 이는 프로세스가 네트워크의 일부 객체에 접근해야 할 때 유용합니다.\
네트워크 서비스에 접근하기 위해 **다른 자격 증명을 사용하는** 프로세스를 시작할 수 있습니다:
```
runas /user:domain\username /netonly cmd.exe
```
이것은 네트워크의 객체에 접근하기 위한 유용한 자격 증명이 있지만, 현재 호스트 내에서는 유효하지 않은 경우에 유용합니다(현재 호스트에서는 현재 사용자 권한이 사용됩니다).

### 토큰의 종류

사용 가능한 두 가지 유형의 토큰이 있습니다:

* **기본 토큰**: 프로세스의 보안 자격 증명을 나타냅니다. 기본 토큰의 생성 및 프로세스와의 연관은 권한 상승이 필요한 작업으로, 권한 분리 원칙을 강조합니다. 일반적으로 인증 서비스가 토큰 생성을 담당하고, 로그온 서비스가 사용자 운영 체제 셸과의 연관을 처리합니다. 프로세스는 생성 시 부모 프로세스의 기본 토큰을 상속받는다는 점도 주목할 만합니다.
* **임시 토큰**: 서버 애플리케이션이 클라이언트의 신원을 일시적으로 채택하여 보안 객체에 접근할 수 있도록 합니다. 이 메커니즘은 네 가지 운영 수준으로 나뉩니다:
* **익명**: 신원 불명의 사용자와 유사한 서버 접근을 허용합니다.
* **식별**: 서버가 객체 접근을 위해 클라이언트의 신원을 활용하지 않고 확인할 수 있도록 합니다.
* **임시**: 서버가 클라이언트의 신원으로 작동할 수 있게 합니다.
* **위임**: 임시와 유사하지만, 서버가 상호작용하는 원격 시스템에 이 신원 가정을 확장할 수 있는 능력을 포함하여 자격 증명을 보존합니다.

#### 임시 토큰

메타스플로잇의 _**incognito**_ 모듈을 사용하면 충분한 권한이 있을 경우 다른 **토큰**을 쉽게 **목록화**하고 **임시화**할 수 있습니다. 이는 **다른 사용자처럼 행동하는 작업을 수행하는 데 유용할 수 있습니다**. 이 기술로 **권한 상승**도 할 수 있습니다.

### 토큰 권한

어떤 **토큰 권한이 권한 상승에 악용될 수 있는지 알아보세요:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

[**모든 가능한 토큰 권한과 이 외부 페이지의 일부 정의를 확인하세요**](https://github.com/gtworek/Priv2Admin).

## 참고자료

이 튜토리얼에서 토큰에 대해 더 알아보세요: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) 및 [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)


{% hint style="success" %}
AWS 해킹 배우고 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우고 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
