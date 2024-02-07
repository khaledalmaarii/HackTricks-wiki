# 滥用令牌

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在 HackTricks 中被广告**吗？ 或者您想要访问**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索我们的独家[NFTs 集合**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* 通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享您的黑客技巧。

</details>

## 令牌

如果您**不知道什么是 Windows 访问令牌**，请在继续之前阅读此页面：

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**也许您可以通过滥用您已有的令牌来提升权限**

### SeImpersonatePrivilege（3.1.1）

持有此特权的任何进程都可以**模拟**（但不能创建）其能够获取句柄的任何**令牌**。您可以从**Windows 服务**（DCOM）获取一个**特权令牌**，使其对漏洞执行**NTLM 认证**，然后以**SYSTEM**身份执行进程。使用 [juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（需要禁用 winrm）、[SweetPotato](https://github.com/CCob/SweetPotato)、[PrintSpoofer](https://github.com/itm4n/PrintSpoofer) 来利用它：

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege（3.1.2）

它与**SeImpersonatePrivilege**非常相似，将使用**相同的方法**获取特权令牌。\
然后，此特权允许**为新/挂起的进程分配主令牌**。使用特权模拟令牌，您可以派生主令牌（DuplicateTokenEx）。\
使用该令牌，您可以使用 'CreateProcessAsUser' 创建**新进程**，或创建一个挂起的进程并**设置令牌**（通常情况下，您无法修改正在运行进程的主令牌）。

### SeTcbPrivilege（3.1.3）

如果您启用了此令牌，您可以使用**KERB\_S4U\_LOGON**为任何其他用户获取**模拟令牌**，而无需知道凭据，将**任意组**（管理员）添加到令牌，将令牌的**完整性级别**设置为“**medium**”，并将此令牌分配给**当前线程**（SetThreadToken）。

### SeBackupPrivilege（3.1.4）

此特权导致系统授予对任何文件的**所有读取访问**权限（仅限读取）。\
使用它来从注册表中**读取本地管理员**帐户的密码哈希，然后使用“**psexec**”或“**wmicexec**”与哈希（PTH）。\
如果本地管理员已禁用，或者配置为远程连接时本地管理员不是管理员，则此攻击将无效。\
您可以使用以下工具**滥用此特权**：

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* 在以下链接中跟随**IppSec**：[https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* 或如在以下链接中所述，通过**使用备份操作员提升权限**部分：

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege（3.1.5）

对系统上的任何文件具有**写入访问**权限，无论文件的 ACL 如何。\
您可以**修改服务**、DLL 劫持、设置**调试器**（Image File Execution Options）... 有很多升级选项。

### SeCreateTokenPrivilege（3.1.6）

此令牌**仅当用户可以模拟**令牌时才能用作 EoP 方法（即使没有 SeImpersonatePrivilege）。\
在可能的情况下，如果用户可以模拟令牌且完整性级别小于或等于当前进程的完整性级别，则用户可以**创建模拟令牌**并向其添加一个特权组 SID。

### SeLoadDriverPrivilege（3.1.7）

**加载和卸载设备驱动程序。**\
您需要在注册表中创建具有 ImagePath 和 Type 值的条目。\
由于无法写入 HKLM，您必须**使用 HKCU**。 但是对于内核来说，HKCU 没有任何意义，引导内核的方法并使用预期的路径进行驱动程序配置的方式是使用路径：“\Registry\User\S-1-5-21-582075628-3447520101-2530640108-1003\System\CurrentControlSet\Services\DriverName”（ID 是当前用户的**RID**）。\
因此，您必须**在 HKCU 中创建所有这些路径，并设置 ImagePath**（要执行的二进制文件的路径）**和 Type**（SERVICE\_KERNEL\_DRIVER 0x00000001）。

{% content-ref url="abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

### SeTakeOwnershipPrivilege（3.1.8）

此特权与**SeRestorePrivilege**非常相似。\
它允许进程通过授予 WRITE\_OWNER 访问权限来“**接管对象**，而无需被授予自主访问”。\
首先，您必须**接管要写入的注册表键**，并**修改 DACL** 以便您可以在其上写入。
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege (3.1.9)

它允许持有者**调试另一个进程**，包括读取和**写入**该**进程的内存**。\
有许多各种**内存注入**策略可以利用这个特权，规避大多数 AV/HIPS 解决方案。

#### 转储内存

滥用这个特权的一个例子是运行[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)从[SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)来**转储进程内存**。例如，**本地安全性子系统服务（**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)** 进程，在用户登录系统后存储用户凭据。

然后，您可以加载此转储到 mimikatz 以获取密码：
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

如果您想要获取 `NT SYSTEM` shell，您可以使用:

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## 检查权限
```
whoami /priv
```
**出现为禁用状态的令牌**可以被启用，实际上您可以滥用_启用_和_禁用_令牌。

### 启用所有令牌

您可以使用脚本[**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)来启用所有令牌：
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
或者在这个[帖子](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)中嵌入的**脚本**。

## 表格

完整的令牌权限速查表在[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)，下面的摘要将只列出利用特权获取管理员会话或读取敏感文件的直接方法。\\

| 权限                      | 影响        | 工具                    | 执行路径                                                                                                                                                                                                                                                                                                                                     | 备注                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**管理员**_ | 第三方工具              | _"它允许用户模拟令牌并使用诸如potato.exe、rottenpotato.exe和juicypotato.exe等工具提升权限到nt系统"_                                                                                                                                                                                                      | 感谢[Aurélien Chalot](https://twitter.com/Defte\_)提供更新。我将尝试重新表达得更像食谱。                                                                                                                                                                                        |
| **`SeBackup`**             | **威胁**   | _**内置命令**_          | 使用`robocopy /b`读取敏感文件                                                                                                                                                                                                                                                                                                             | <p>- 如果可以读取%WINDIR%\MEMORY.DMP可能更有趣<br><br>- 当涉及到打开文件时，<code>SeBackupPrivilege</code>（和robocopy）并不有用。<br><br>- Robocopy需要同时具备SeBackup和SeRestore才能使用/b参数。</p>                                                                      |
| **`SeCreateToken`**        | _**管理员**_ | 第三方工具              | 使用`NtCreateToken`创建包括本地管理员权限在内的任意令牌。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**管理员**_ | **PowerShell**          | 复制`lsass.exe`的令牌。                                                                                                                                                                                                                                                                                                                   | 脚本可在[FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)找到                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**管理员**_ | 第三方工具              | <p>1. 加载有漏洞的内核驱动程序，如<code>szkg64.sys</code><br>2. 利用驱动程序漏洞<br><br>或者，该权限可用于使用内置命令<code>ftlMC</code>卸载与安全相关的驱动程序。例如：<code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code>漏洞列为<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <code>szkg64</code>的<a href="https://www.greyhathacker.net/?p=1025">利用代码</a>由<a href="https://twitter.com/parvezghh">Parvez Anwar</a>创建</p> |
| **`SeRestore`**            | _**管理员**_ | **PowerShell**          | <p>1. 使用具有SeRestore权限的PowerShell/ISE启动。<br>2. 使用<a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>启用权限。<br>3. 将utilman.exe重命名为utilman.old<br>4. 将cmd.exe重命名为utilman.exe<br>5. 锁定控制台，按Win+U</p> | <p>某些杀毒软件可能会检测到攻击。</p><p>替代方法依赖于使用相同权限替换存储在“Program Files”中的服务二进制文件</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**管理员**_ | _**内置命令**_          | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. 将cmd.exe重命名为utilman.exe<br>4. 锁定控制台，按Win+U</p>                                                                                                                                       | <p>某些杀毒软件可能会检测到攻击。</p><p>替代方法依赖于使用相同权限替换存储在“Program Files”中的服务二进制文件。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**管理员**_ | 第三方工具              | <p>操纵令牌以包含本地管理员权限。可能需要SeImpersonate。</p><p>待验证。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## 参考

* 查看定义Windows令牌的这个表格：[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* 查看关于令牌提权的[**这篇论文**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt)。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 **电报群** 或在**Twitter**上**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* 通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧。

</details>
