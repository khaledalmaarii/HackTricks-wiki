# Access Tokens

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中宣传**吗？ 或者想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

## 访问令牌

每个**登录到系统的用户**都持有一个包含该登录会话安全信息的访问令牌。当用户登录时，系统会创建一个访问令牌。**代表用户执行的每个进程**都有访问令牌的副本。该令牌标识用户、用户所属的组以及用户的特权。令牌还包含一个标识当前登录会话的登录SID（安全标识符）。

您可以通过执行 `whoami /all` 查看此信息

```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

或者使用来自Sysinternals的\_Process Explorer\_（选择进程并访问“安全”选项卡）：

![](<../../.gitbook/assets/image (321).png>)

### 本地管理员

当本地管理员登录时，**会创建两个访问令牌**：一个具有管理员权限，另一个具有普通权限。**默认情况下**，当此用户执行进程时，将使用具有**常规**（非管理员）**权限的令牌**。当此用户尝试以管理员身份执行任何操作（例如“以管理员身份运行”）时，将使用**UAC**来请求权限。\
如果您想要[**了解更多关于UAC的信息，请阅读此页面**](../authentication-credentials-uac-and-efs/#uac)**。**

### 凭据用户模拟

如果您拥有**任何其他用户的有效凭据**，您可以使用这些凭据**创建**一个**新的登录会话**：

```
runas /user:domain\username cmd.exe
```

**访问令牌**还具有对**LSASS**中登录会话的**引用**，如果进程需要访问网络中的某些对象，这将非常有用。\
您可以启动一个进程，使用以下方法**使用不同的凭据访问网络服务**：

```
runas /user:domain\username /netonly cmd.exe
```

这在您拥有访问网络中对象的有效凭据，但这些凭据在当前主机内无效时非常有用（因为它们仅在网络中使用，在当前主机中将使用当前用户权限）。

### 令牌类型

有两种类型的令牌可用：

* **主令牌**：它作为进程安全凭据的表示。主令牌的创建和与进程的关联是需要提升的特权的操作，强调特权分离的原则。通常，认证服务负责令牌的创建，而登录服务处理其与用户操作系统 shell 的关联。值得注意的是，进程在创建时继承其父进程的主令牌。
* **模拟令牌**：使服务器应用程序能够暂时采用客户端的身份以访问安全对象。此机制分为四个操作级别：
* **匿名**：授予服务器访问权限，类似于未经识别的用户。
* **标识**：允许服务器验证客户端的身份，而无需将其用于对象访问。
* **模拟**：使服务器能够以客户端的身份运行。
* **委派**：类似于模拟，但包括将此身份假设扩展到服务器与之交互的远程系统的能力，确保凭据保留。

#### 模拟令牌

使用 metasploit 的 _**incognito**_ 模块，如果您拥有足够的权限，可以轻松**列出**和**模拟**其他**令牌**。这对于以其他用户身份执行操作非常有用。您还可以使用此技术**提升权限**。

### 令牌特权

了解可以被滥用以提升权限的**令牌特权**：

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

查看[**所有可能的令牌特权以及有关此外部页面的一些定义**](https://github.com/gtworek/Priv2Admin)。

## 参考资料

在这些教程中了解更多关于令牌的知识：[https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) 和 [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
