# 骷髅钥匙

<details>

<summary><strong>从零开始学习AWS黑客技术，成为英雄级人物</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## **骷髅钥匙**

**来自：** [**https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/**](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)

攻击者有几种方法可以用来危害Active Directory账户，一旦他们在您的域中确立了自己，就可以提升权限并创建持久性。骷髅钥匙是一种特别可怕的针对Active Directory域的恶意软件，它使劫持任何账户变得极其容易。这种恶意软件**注入到LSASS中，并创建一个可以用于域中任何账户的主密码**。现有密码也将继续工作，所以除非你知道该寻找什么，否则很难知道这种攻击已经发生。

不出所料，这是许多攻击之一，使用[Mimikatz](https://github.com/gentilkiwi/mimikatz)打包并且非常容易执行。让我们来看看它是如何工作的。

### 骷髅钥匙攻击的要求

为了实施这种攻击，**攻击者必须拥有域管理员权限**。这种攻击必须**在每个域控制器上执行以完全危害，但即使只针对单个域控制器也是有效的**。**重启**域控制器**将删除这种恶意软件**，攻击者将不得不重新部署。

### 执行骷髅钥匙攻击

执行攻击非常直接。它只需要在每个域控制器上运行以下**命令**：`misc::skeleton`。之后，您可以使用Mimikatz的默认密码作为任何用户进行认证。

![使用misc::skeleton命令将骷髅钥匙注入域控制器，通过Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/1-3.png)

这是使用骷髅钥匙作为密码的域管理员成员的认证，以获取对域控制器的管理访问权限：

![使用骷髅钥匙作为密码，通过misc::skeleton命令和Mimikatz的默认密码获取对域控制器的管理访问权限](https://blog.stealthbits.com/wp-content/uploads/2017/07/2-5.png)

注意：如果您收到一条消息说，“系统错误86已发生。指定的网络密码不正确”，只需尝试使用域\账户格式的用户名，它应该就会工作。

![如果您收到一条消息说系统错误86已发生指定的网络密码不正确，就使用域\账户格式的用户名](https://blog.stealthbits.com/wp-content/uploads/2017/07/3-3.png)

如果lsass已经用骷髅钥匙**打过补丁**，那么将出现这个**错误**：

![](<../../.gitbook/assets/image (160).png>)

### 缓解措施

* 事件：
* 系统事件ID 7045 - 系统中安装了一个服务。（类型内核模式驱动程序）
* 安全事件ID 4673 – 敏感权限使用（必须启用“审计权限使用”）
* 事件ID 4611 – 一个可信登录过程已经在本地安全权限中注册（必须启用“审计权限使用”）
* `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "`_`Kernel Mode Driver"}`_
* 这只能检测mimidrv `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$`_`.message -like "Kernel Mode Driver" -and $`_`.message -like "`_`mimidrv`_`"}`
* 缓解：
* 将lsass.exe作为受保护的进程运行，它迫使攻击者加载一个内核模式驱动程序
* `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`
* 重启后验证：`Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "`_`protected process"}`_

<details>

<summary><strong>从零开始学习AWS黑客技术，成为英雄级人物</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
