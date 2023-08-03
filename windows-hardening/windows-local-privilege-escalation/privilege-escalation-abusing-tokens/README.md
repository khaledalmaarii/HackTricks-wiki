# 滥用令牌

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享你的黑客技巧**。

</details>

## 令牌

如果你**不知道什么是 Windows 访问令牌**，请在继续之前阅读本页面：

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**也许你可以通过滥用你已有的令牌来提升权限**

### SeImpersonatePrivilege (3.1.1)

任何持有此权限的进程都可以**模拟**（但不能创建）其能够获取句柄的任何**令牌**。你可以通过使**Windows 服务**（DCOM）对漏洞执行**NTLM 认证**，然后以**SYSTEM**身份执行进程，从中获取一个**特权令牌**。使用 [juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（需要禁用 winrm）、[SweetPotato](https://github.com/CCob/SweetPotato)、[PrintSpoofer](https://github.com/itm4n/PrintSpoofer) 来利用它：

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege (3.1.2)

它与**SeImpersonatePrivilege**非常相似，它将使用**相同的方法**来获取特权令牌。\
然后，此权限允许**为新的/挂起的进程分配主令牌**。使用特权模拟令牌，你可以派生一个主令牌（DuplicateTokenEx）。\
有了令牌，你可以使用 'CreateProcessAsUser' 创建一个**新进程**，或者创建一个挂起的进程并**设置令牌**（通常情况下，你不能修改正在运行的进程的主令牌）。

### SeTcbPrivilege (3.1.3)

如果你启用了此令牌，你可以使用**KERB\_S4U\_LOGON**来获取任何其他用户的**模拟令牌**，而无需知道凭据，将一个**任意组**（管理员）添加到令牌中，将令牌的**完整性级别**设置为“**中等**”，并将此令牌分配给**当前线程**（SetThreadToken）。

### SeBackupPrivilege (3.1.4)

此权限会导致系统**授予对任何文件的所有读取访问权限**（仅限读取）。\
使用它可以从注册表中**读取本地管理员**帐户的密码哈希，然后使用哈希（PTH）使用“**psexec**”或“**wmicexec**”。\
如果本地管理员被禁用，或者配置为远程连接时本地管理员不是管理员，则此攻击将无效。\
你可以使用以下方法**滥用此权限**：

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* 在[https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)中关注**IppSec**
* 或者按照以下链接中的**使用备份操作员升级权限**部分的说明：

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}
### SeRestorePrivilege (3.1.5)

**具有写访问权限**，可以控制系统上的任何文件，而不考虑文件的访问控制列表（ACL）。\
您可以修改服务、DLL劫持、设置调试器（Image File Execution Options）... 有很多升级选项。

### SeCreateTokenPrivilege (3.1.6)

如果用户可以模拟令牌（即使没有SeImpersonatePrivilege），则此令牌**可以用作**EoP方法**仅限于**。\
在可能的情况下，如果令牌是为同一用户并且完整性级别小于或等于当前进程的完整性级别，则用户可以模拟该令牌。\
在这种情况下，用户可以**创建一个模拟令牌**并向其添加一个特权组SID。

### SeLoadDriverPrivilege (3.1.7)

**加载和卸载设备驱动程序**。\
您需要在注册表中创建一个条目，并为ImagePath和Type设置值。\
由于无法写入HKLM，您必须**使用HKCU**。但是对于内核来说，HKCU没有任何意义，指导内核在此处使用预期的驱动程序配置路径的方法是使用路径："\Registry\User\S-1-5-21-582075628-3447520101-2530640108-1003\System\CurrentControlSet\Services\DriverName"（ID是当前用户的**RID**）。\
因此，您必须**在HKCU中创建所有这些路径并设置ImagePath**（要执行的二进制文件的路径）**和Type**（SERVICE\_KERNEL\_DRIVER 0x00000001）。

{% content-ref url="abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

### SeTakeOwnershipPrivilege (3.1.8)

此特权与**SeRestorePrivilege**非常相似。\
它允许进程通过授予WRITE\_OWNER访问权限来“**接管对象的所有权**，而无需被授予自主访问权限”。\
首先，您必须**接管要写入的注册表键**，并**修改DACL**以便您可以对其进行写入。
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

它允许持有者**调试另一个进程**，包括读取和**写入**该进程的内存。\
有很多不同的**内存注入**策略可以利用这个权限，逃避大多数 AV/HIPS 解决方案。

#### 转储内存

滥用这个权限的一个例子是运行 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 来自 [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) 来**转储进程内存**。例如，**本地安全子系统服务（[LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)）**进程，在用户登录系统后存储用户凭据。

然后，您可以加载此转储文件到 mimikatz 中以获取密码：
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

如果你想获取一个 `NT SYSTEM` shell，你可以使用：

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## 检查权限

To escalate privileges on a Windows system, it is important to first check the current privileges of the user. This can be done using various methods:

### 1. Whoami

The `whoami` command can be used to display the current user and group information, including the privileges associated with the user.

```plaintext
whoami /priv
```

### 2. Systeminfo

The `systeminfo` command provides detailed information about the system, including the privileges of the current user.

```plaintext
systeminfo
```

### 3. PowerShell

PowerShell can also be used to check the privileges of the current user. The following command can be used:

```plaintext
(Get-Process -id $pid).StartInfo.EnvironmentVariables
```

### 4. AccessChk

AccessChk is a command-line tool that can be used to check the privileges of a user or process. It provides detailed information about the access rights and privileges associated with a user or process.

```plaintext
accesschk.exe -a <username>
```

By checking the privileges of the current user, you can identify potential vulnerabilities and determine the appropriate privilege escalation techniques to use.
```
whoami /priv
```
出现为“已禁用”的令牌可以被启用，实际上可以滥用“已启用”和“已禁用”令牌。

### 启用所有令牌

您可以使用脚本[**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)来启用所有令牌：
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
或者在这个[帖子](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)中嵌入的**脚本**。

## 表格

完整的令牌权限速查表请参考[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)，下面的摘要仅列出了直接利用权限以获取管理员会话或读取敏感文件的方法。

| 权限                      | 影响        | 工具                    | 执行路径                                                                                                                                                                                                                                                                                                                                         | 备注                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**管理员**_ | 第三方工具          | _"它允许用户模拟令牌并使用诸如potato.exe、rottenpotato.exe和juicypotato.exe之类的工具进行提权到nt系统"_                                                                                                                                                                                                      | 感谢[Aurélien Chalot](https://twitter.com/Defte_)的更新。我将尽快尝试将其重新表达为更像是配方的东西。                                                                                                                                                                                        |
| **`SeBackup`**             | **威胁**  | _**内置命令**_ | 使用`robocopy /b`读取敏感文件                                                                                                                                                                                                                                                                                                             | <p>- 如果您可以读取%WINDIR%\MEMORY.DMP，则可能更有趣<br><br>- <code>SeBackupPrivilege</code>（和robocopy）在打开文件时无效。<br><br>- Robocopy需要同时具备SeBackup和SeRestore权限才能使用/b参数。</p>                                                                      |
| **`SeCreateToken`**        | _**管理员**_ | 第三方工具          | 使用`NtCreateToken`创建任意令牌，包括本地管理员权限。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**管理员**_ | **PowerShell**          | 复制`lsass.exe`令牌。                                                                                                                                                                                                                                                                                                                   | 脚本可在[FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)找到。                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**管理员**_ | 第三方工具          | <p>1. 加载有漏洞的内核驱动程序，例如<code>szkg64.sys</code><br>2. 利用驱动程序漏洞<br><br>或者，该权限可以用于使用内置命令<code>ftlMC</code>卸载与安全相关的驱动程序，例如：<code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code>漏洞被列为<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <code>szkg64</code>的<a href="https://www.greyhathacker.net/?p=1025">利用代码</a>由<a href="https://twitter.com/parvezghh">Parvez Anwar</a>创建</p> |
| **`SeRestore`**            | _**管理员**_ | **PowerShell**          | <p>1. 使用具有SeRestore权限的PowerShell/ISE启动。<br>2. 使用<a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>启用权限。<br>3. 将utilman.exe重命名为utilman.old<br>4. 将cmd.exe重命名为utilman.exe<br>5. 锁定控制台并按Win+U</p> | <p>某些AV软件可能会检测到此攻击。</p><p>替代方法依赖于使用相同权限替换存储在“Program Files”中的服务二进制文件</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**管理员**_ | _**内置命令**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. 将cmd.exe重命名为utilman.exe<br>4. 锁定控制台并按Win+U</p>                                                                                                                                       | <p>某些AV软件可能会检测到此攻击。</p><p>替代方法依赖于使用相同权限替换存储在“Program Files”中的服务二进制文件。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**管理员**_ | 第三方工具          | <p>操纵令牌以包含本地管理员权限。可能需要SeImpersonate。</p><p>待验证。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## 参考资料

* 查看定义Windows令牌的表格：[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* 阅读关于使用令牌进行权限提升的[**这篇论文**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt)。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在一家**网络安全公司**工作吗？您想在HackTricks中**为您的公司做广告**吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
