# 访问令牌

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 访问令牌

每个**登录到系统的用户**都持有一个包含安全信息的访问令牌。当用户登录时，系统会创建一个访问令牌。**代表用户执行的每个进程都有一个访问令牌的副本**。该令牌标识用户、用户所属的组以及用户的权限。令牌还包含一个登录SID（安全标识符），用于标识当前的登录会话。

你可以通过执行`whoami /all`命令查看这些信息。
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
或者使用Sysinternals的_Process Explorer_（选择进程并访问"Security"选项卡）：

![](<../../.gitbook/assets/image (321).png>)

### 本地管理员

当本地管理员登录时，**会创建两个访问令牌**：一个具有管理员权限，另一个具有普通权限。**默认情况下**，当该用户执行进程时，将使用具有**普通**（非管理员）**权限的令牌**。当该用户尝试以管理员身份执行任何操作（例如"以管理员身份运行"），将使用UAC请求权限。\
如果您想[**了解更多关于UAC的信息，请阅读此页面**](../authentication-credentials-uac-and-efs.md#uac)**。**

### 凭据用户模拟

如果您拥有**任何其他用户的有效凭据**，您可以使用这些凭据**创建**一个**新的登录会话**：
```
runas /user:domain\username cmd.exe
```
**访问令牌**还在**LSASS**中引用了登录会话，这对于进程需要访问网络对象非常有用。\
您可以使用以下方法启动一个进程，该进程使用不同的凭据访问网络服务：
```
runas /user:domain\username /netonly cmd.exe
```
这在你拥有访问网络中对象的有用凭据，但这些凭据在当前主机内无效时非常有用（因为它们只会在网络中使用，在当前主机上将使用当前用户权限）。

### 令牌的类型

有两种类型的令牌可用：

* **主令牌**：主令牌只能与进程关联，并表示进程的安全主体。创建主令牌和将其与进程关联都是特权操作，需要两个不同的特权，以实现特权分离 - 典型的情况是认证服务创建令牌，登录服务将其与用户的操作系统 shell 关联起来。进程最初继承父进程的主令牌的副本。
* **模拟令牌**：模拟是在Windows NT中实现的安全概念，允许服务器应用程序在访问安全对象方面**临时**“**成为**”**客户端**。模拟有**四个可能的级别**：

* **匿名**，使服务器具有匿名/未识别用户的访问权限
* **标识**，允许服务器检查客户端的身份，但不能使用该身份访问对象
* **模拟**，允许服务器代表客户端执行操作
* **委派**，与模拟相同，但扩展到服务器连接的远程系统（通过保留凭据）。

客户端可以选择作为连接参数提供给服务器的最大模拟级别（如果有）。委派和模拟是特权操作（模拟最初不是，但由于客户端API的实现历史上的疏忽，未能将默认级别限制为“标识”，导致非特权服务器冒充不愿意的特权客户端，因此需要它）。**模拟令牌只能与线程关联**，它们表示客户端进程的安全主体。模拟令牌通常是通过IPC机制（如DCE RPC、DDE和命名管道）隐式地创建并与当前线程关联的。

#### 模拟令牌

使用Metasploit的_incognito_模块，如果你拥有足够的特权，你可以轻松地**列出**和**模拟**其他**令牌**。这对于以其他用户的身份执行操作非常有用。你还可以通过这种技术**提升权限**。

### 令牌特权

了解可以滥用的**令牌特权以提升权限**：

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

查看[**所有可能的令牌特权以及有关此外部页面的一些定义**](https://github.com/gtworek/Priv2Admin)。

## 参考资料

在这些教程中了解更多关于令牌的知识：[https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) 和 [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
