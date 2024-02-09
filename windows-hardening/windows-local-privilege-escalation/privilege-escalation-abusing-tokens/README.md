# 滥用令牌

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中宣传**吗？ 或者想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>

## 令牌

如果您**不知道什么是Windows访问令牌**，请在继续之前阅读此页面：

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**也许您可以通过滥用您已有的令牌来提升特权**

### SeImpersonatePrivilege

这是由任何进程持有的特权，允许模拟（但不是创建）任何令牌，只要可以获得对其的句柄。可以通过诱使Windows服务（DCOM）执行NTLM身份验证来获取特权令牌，从而使得可以使用SYSTEM特权执行进程。可以使用各种工具利用此漏洞，例如[juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（需要禁用winrm）、[SweetPotato](https://github.com/CCob/SweetPotato)和[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)。

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

它与**SeImpersonatePrivilege**非常相似，将使用**相同的方法**获取特权令牌。\
然后，此特权允许**为新/挂起的进程分配主令牌**。使用特权模拟令牌，您可以派生主令牌（DuplicateTokenEx）。\
使用该令牌，您可以使用'CreateProcessAsUser'创建**新进程**，或创建一个挂起的进程并**设置令牌**（通常情况下，无法修改正在运行进程的主令牌）。

### SeTcbPrivilege

如果启用了此令牌，您可以使用**KERB\_S4U\_LOGON**获取任何其他用户的**模拟令牌**，而无需知道凭据，将**任意组**（管理员）添加到令牌，将令牌的**完整性级别**设置为“**medium**”，并将此令牌分配给**当前线程**（SetThreadToken）。

### SeBackupPrivilege

通过此特权，系统被迫授予对任何文件的所有读取访问权限（仅限读取操作）。它用于从注册表中**读取本地管理员**帐户的密码哈希，随后可以使用像“**psexec**”或“**wmicexec**”这样的工具与哈希一起使用（哈希传递技术）。但是，此技术在两种情况下失败：当本地管理员帐户被禁用时，或者当存在一个策略，从远程连接的本地管理员中删除管理权限。\
您可以使用以下方式**滥用此特权**：

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* 关注**IppSec**的[https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* 或如下所述在：

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

此特权允许对任何系统文件进行**写访问**，无论文件的访问控制列表（ACL）如何。这为提升提供了许多可能性，包括**修改服务**、执行DLL劫持以及通过Image File Execution Options设置**调试器**等各种技术。

### SeCreateTokenPrivilege

SeCreateTokenPrivilege是一种强大的权限，特别在用户具有模拟令牌的能力时非常有用，但在没有SeImpersonatePrivilege的情况下也很有用。此功能取决于能够模拟代表同一用户且完整性级别不超过当前进程的令牌。

**关键点：**
- **无需SeImpersonatePrivilege即可模拟：** 可以在特定条件下利用SeCreateTokenPrivilege进行EoP，通过模拟令牌。
- **令牌模拟的条件：** 成功的模拟需要目标令牌属于同一用户，并且具有小于或等于尝试模拟的进程完整性级别的完整性级别。
- **创建和修改模拟令牌：** 用户可以创建模拟令牌，并通过添加特权组的SID（安全标识符）来增强它。

### SeLoadDriverPrivilege

此特权允许**加载和卸载设备驱动程序**，并创建具有特定值的注册表条目`ImagePath`和`Type`。由于对`HKLM`（HKEY_LOCAL_MACHINE）的直接写访问受限，必须改为使用`HKCU`（HKEY_CURRENT_USER）。但是，为了使内核能够识别`HKCU`以进行驱动程序配置，必须遵循特定路径。

该路径为`\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中`<RID>`是当前用户的相对标识符。在`HKCU`中，必须创建整个路径，并设置两个值：
- `ImagePath`，即要执行的二进制文件的路径
- `Type`，值为`SERVICE_KERNEL_DRIVER`（`0x00000001`）。

**操作步骤：**
1. 由于受限制的写访问权限，访问`HKCU`而不是`HKLM`。
2. 在`HKCU`内创建路径`\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中`<RID>`表示当前用户的相对标识符。
3. 将`ImagePath`设置为二进制文件的执行路径。
4. 将`Type`分配为`SERVICE_KERNEL_DRIVER`（`0x00000001`）。
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
更多滥用这种特权的方法在[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

这类似于**SeRestorePrivilege**。其主要功能允许进程**承担对象的所有权**，绕过通过提供WRITE_OWNER访问权限的明确自主访问的要求。该过程首先确保拥有所需的注册表键的所有权以进行写入，然后修改DACL以启用写操作。
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
### SeDebugPrivilege

此特权允许**调试其他进程**，包括读写内存。可以利用此特权采用各种内存注入策略，能够规避大多数防病毒软件和主机入侵防护解决方案。

#### 转储内存

您可以使用[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)来**捕获进程的内存**。具体而言，这可以应用于**本地安全性子系统服务（[LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**进程，该进程负责在用户成功登录系统后存储用户凭据。

然后，您可以加载此转储文件到mimikatz以获取密码：
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

如果您的令牌被禁用，您可以使用脚本[**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)来启用所有令牌：
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
或者在这个[帖子](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)中嵌入的**脚本**。

## 表格

完整的令牌权限速查表在[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)，下面的摘要将只列出利用特权获取管理员会话或读取敏感文件的直接方法。

| 权限                      | 影响        | 工具                    | 执行路径                                                                                                                                                                                                                                                                                                                                     | 备注                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**管理员**_ | 第三方工具              | _"它允许用户模拟令牌并使用工具（如potato.exe、rottenpotato.exe和juicypotato.exe）提升权限到nt系统"_                                                                                                                                                                                                      | 感谢[Aurélien Chalot](https://twitter.com/Defte\_)提供更新。我将尝试重新表达得更像食谱。                                                                                                                                                                                        |
| **`SeBackup`**             | **威胁**   | _**内置命令**_          | 使用`robocopy /b`读取敏感文件                                                                                                                                                                                                                                                                                                             | <p>- 如果可以读取%WINDIR%\MEMORY.DMP可能更有趣<br><br>- 当涉及到打开文件时，`SeBackupPrivilege`（和robocopy）并不有用。<br><br>- Robocopy需要同时具备SeBackup和SeRestore才能使用/b参数。</p>                                                                      |
| **`SeCreateToken`**        | _**管理员**_ | 第三方工具              | 使用`NtCreateToken`创建包括本地管理员权限在内的任意令牌。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**管理员**_ | **PowerShell**          | 复制`lsass.exe`令牌。                                                                                                                                                                                                                                                                                                                   | 脚本可在[FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)找到                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**管理员**_ | 第三方工具              | <p>1. 加载有漏洞的内核驱动程序，如<code>szkg64.sys</code><br>2. 利用驱动程序漏洞<br><br>或者，该权限可用于使用内置命令<code>ftlMC</code>卸载与安全相关的驱动程序。例如：<code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code>漏洞被列为<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">漏洞代码</a>由<a href="https://twitter.com/parvezghh">Parvez Anwar</a>创建</p> |
| **`SeRestore`**            | _**管理员**_ | **PowerShell**          | <p>1. 启动带有SeRestore权限的PowerShell/ISE。<br>2. 使用<a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>启用权限。<br>3. 将utilman.exe重命名为utilman.old<br>4. 将cmd.exe重命名为utilman.exe<br>5. 锁定控制台，按Win+U</p> | <p>某些杀毒软件可能会检测到攻击。</p><p>替代方法依赖于使用相同权限替换存储在“Program Files”中的服务二进制文件</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**管理员**_ | _**内置命令**_          | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. 将cmd.exe重命名为utilman.exe<br>4. 锁定控制台，按Win+U</p>                                                                                                                                       | <p>某些杀毒软件可能会检测到攻击。</p><p>替代方法依赖于使用相同权限替换存储在“Program Files”中的服务二进制文件。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**管理员**_ | 第三方工具              | <p>操纵令牌以包含本地管理员权限。可能需要SeImpersonate。</p><p>待验证。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## 参考

* 查看定义Windows令牌的这个表格：[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* 查看关于令牌提权的[**这篇论文**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt)。
