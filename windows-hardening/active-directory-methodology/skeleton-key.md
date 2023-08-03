# 骷髅钥匙

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一个**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>

## **骷髅钥匙**

**来源：**[**https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/**](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)

攻击者在入侵您的域后，可以使用多种方法来提升权限并创建持久性，以威胁 Active Directory 帐户。骷髅钥匙是一种专门针对 Active Directory 域的恶意软件，使劫持任何帐户变得非常容易。该恶意软件**将自身注入到 LSASS 中，并创建一个可用于域中任何帐户的主密码**。现有密码也将继续有效，因此很难知道发生了这种攻击，除非你知道要寻找什么。

毫不奇怪，这是许多攻击之一，可以使用[Mimikatz](https://github.com/gentilkiwi/mimikatz)轻松执行。让我们看看它是如何工作的。

### 骷髅钥匙攻击的要求

为了进行这种攻击，**攻击者必须具有域管理员权限**。这种攻击必须**在每个域控制器上执行，以完全妥协，但即使针对单个域控制器也可能有效**。**重启**域控制器**将删除此恶意软件**，攻击者将不得不重新部署它。

### 执行骷髅钥匙攻击

执行此攻击非常简单。只需要在每个域控制器上运行以下**命令**：`misc::skeleton`。之后，您可以使用 Mimikatz 的默认密码进行任何用户的身份验证。

![使用 misc::skeleton 命令将骷髅钥匙注入到使用 Mimikatz 的域控制器中](https://blog.stealthbits.com/wp-content/uploads/2017/07/1-3.png)

这是使用骷髅钥匙作为密码进行身份验证，以获得对域控制器的管理员访问权限的域管理员成员的示例：

![使用骷髅钥匙作为密码，使用 misc::skeleton 命令获得对域控制器的管理员访问权限，使用 Mimikatz 的默认密码](https://blog.stealthbits.com/wp-content/uploads/2017/07/2-5.png)

注意：如果您收到“系统错误 86 已发生。指定的网络密码不正确”的消息，请尝试使用 domain\account 格式的用户名，它应该可以工作。

![如果收到“系统错误 86 已发生。指定的网络密码不正确”的消息，请尝试使用 domain\account 格式的用户名](https://blog.stealthbits.com/wp-content/uploads/2017/07/3-3.png)

如果 lsass 已经使用骷髅钥匙进行了**修补**，则会出现此**错误**：

![](<../../.gitbook/assets/image (160).png>)

### 缓解措施

* 事件：
* 系统事件 ID 7045 - 系统中安装了一个服务。（类型为内核模式驱动程序）
* 安全事件 ID 4673 - 敏感权限使用（必须启用“审核特权使用”）
* 事件 ID 4611 - 已向本地安全性机构注册了一个受信任的登录过程（必须启用“审核特权使用”）
* `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "`_`Kernel Mode Driver"}`_
* 这只能检测到 mimidrv `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$`_`.message -like "Kernel Mode Driver" -and $`_`.message -like "`_`mimidrv`_`"}`
* 缓解措施：
* 将 lsass.exe 作为受保护的进程运行，它会强制攻击者加载一个内核模式驱动程序
* `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`
* 重启后验证：`Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "`_`protected process"}`_

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一个**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
