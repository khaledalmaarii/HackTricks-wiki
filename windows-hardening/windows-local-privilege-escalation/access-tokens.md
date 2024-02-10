# 액세스 토큰

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출하세요.**

</details>

## 액세스 토큰

시스템에 **로그인한 각 사용자는 해당 로그온 세션에 대한 보안 정보를 포함한 액세스 토큰을 보유**합니다. 사용자가 로그인할 때 시스템은 액세스 토큰을 생성합니다. 사용자를 대신하여 실행되는 **각 프로세스는 액세스 토큰의 사본을 가지고** 있습니다. 토큰은 사용자, 사용자의 그룹 및 사용자의 권한을 식별합니다. 토큰에는 현재 로그온 세션을 식별하는 로그온 SID (보안 식별자)도 포함되어 있습니다.

이 정보는 `whoami /all`을 실행하여 확인할 수 있습니다.
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
또는 Sysinternals의 _Process Explorer_를 사용하여 (프로세스를 선택하고 "보안" 탭에 액세스):

![](<../../.gitbook/assets/image (321).png>)

### 로컬 관리자

로컬 관리자가 로그인하면 **두 개의 액세스 토큰이 생성**됩니다. 하나는 관리자 권한이 있고 다른 하나는 일반 권한이 있습니다. **기본적으로**, 이 사용자가 프로세스를 실행할 때는 **일반**(관리자가 아닌) **권한이 있는 토큰이 사용**됩니다. 이 사용자가 관리자로서 무언가를 실행하려고 할 때(예: "관리자로 실행"), **UAC**가 권한을 요청하기 위해 사용됩니다.\
[UAC에 대해 더 알아보려면 이 페이지를 읽어보세요](../authentication-credentials-uac-and-efs.md#uac)**.**

### 자격 증명 사용자 위장

다른 사용자의 **유효한 자격 증명**이 있다면 해당 자격 증명으로 **새로운 로그온 세션**을 생성할 수 있습니다:
```
runas /user:domain\username cmd.exe
```
**액세스 토큰**은 **LSASS** 내부의 로그온 세션에 대한 **참조(reference)**도 가지고 있습니다. 이는 프로세스가 네트워크의 일부 객체에 액세스해야 할 경우 유용합니다.\
네트워크 서비스에 액세스하기 위해 **다른 자격 증명(credentials)을 사용하는 프로세스**를 실행할 수 있습니다.
```
runas /user:domain\username /netonly cmd.exe
```
이것은 네트워크 내의 객체에 액세스하기 위한 유용한 자격 증명이 있지만, 현재 호스트 내에서는 해당 자격 증명이 유효하지 않은 경우에 유용합니다(현재 호스트에서는 현재 사용자 권한이 사용됩니다).

### 토큰의 종류

사용 가능한 두 가지 유형의 토큰이 있습니다:

* **기본 토큰**: 프로세스의 보안 자격 증명을 나타냅니다. 기본 토큰의 생성과 프로세스와의 연결은 권한 상승을 필요로 하는 작업으로, 권한 분리의 원칙을 강조합니다. 일반적으로 인증 서비스가 토큰 생성을 담당하고, 로그온 서비스가 사용자의 운영 체제 셸과의 연결을 처리합니다. 프로세스는 생성 시 부모 프로세스의 기본 토큰을 상속합니다.

* **가장하기 토큰**: 서버 응용 프로그램이 보안 객체에 임시로 클라이언트의 신원을 취할 수 있게 합니다. 이 메커니즘은 다음 네 가지 운영 수준으로 구성됩니다:
- **익명**: 식별되지 않은 사용자와 유사한 서버 액세스를 부여합니다.
- **식별**: 서버가 객체 액세스에 사용하지 않고 클라이언트의 신원을 확인할 수 있게 합니다.
- **가장하기**: 서버가 클라이언트의 신원으로 작동할 수 있게 합니다.
- **위임**: 가장하기와 유사하지만, 서버가 상호 작용하는 원격 시스템에 이 신원 가정을 확장할 수 있는 능력을 포함하여 자격 증명 보존을 보장합니다.


#### 토큰 가장하기

Metasploit의 _**incognito**_ 모듈을 사용하여 충분한 권한이 있다면 다른 **토큰**을 쉽게 **목록화**하고 **가장할** 수 있습니다. 이 기술을 사용하면 다른 사용자처럼 작업을 수행할 수 있으며, 이 기술을 사용하여 권한 상승도 가능합니다.

### 토큰 권한

권한 상승을 위해 **토큰 권한을 악용할 수 있는지 알아보세요:**

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

[**가능한 모든 토큰 권한과 이에 대한 정의를 이 외부 페이지에서 확인하세요**](https://github.com/gtworek/Priv2Admin).

## 참고 자료

다음 튜토리얼에서 토큰에 대해 자세히 알아보세요: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) 및 [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로에서 영웅까지 AWS 해킹을 배워보세요**!</summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 홍보**하거나 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **저를 팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **자신의 해킹 기법을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 PR을 제출**하세요.

</details>
