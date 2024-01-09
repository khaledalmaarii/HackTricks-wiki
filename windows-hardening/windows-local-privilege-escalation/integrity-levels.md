<details>

<summary><strong>从零到英雄学习AWS黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 完整性级别

从Windows Vista开始，所有**受保护的对象都标有完整性级别**。系统上的大多数用户和系统文件以及注册表键默认标记为“中”完整性。主要例外是Internet Explorer 7以低完整性可写的特定文件夹和文件集。**大多数进程**由**标准用户**运行时标记为**中完整性**（即使是由管理员组内的用户启动的进程），而大多数**服务**则标记为**系统完整性**。根目录受到高完整性标签的保护。\
请注意，**较低完整性级别的进程无法写入具有较高完整性级别的对象。**\
完整性级别有几个：

* **不信任** - 自动将匿名登录的进程指定为不信任。_例子：Chrome_
* **低** - 低完整性级别是默认用于与互联网交互的级别。只要Internet Explorer以其默认状态运行，受保护模式，与它相关的所有文件和进程都被分配低完整性级别。一些文件夹，如**临时互联网文件夹**，也默认分配**低完整性**级别。但是，请注意，**低完整性进程**非常**受限**，它**不能**写入**注册表**，并且受限于写入当前用户配置文件中的**大多数位置**。_例子：Internet Explorer或Microsoft Edge_
* **中** - 中是**大多数对象将运行的上下文**。标准用户接收中完整性级别，任何未明确指定为较低或较高完整性级别的对象默认为中。请注意，默认情况下，管理员组内的用户将使用中完整性级别。
* **高** - **管理员**被授予高完整性级别。这确保管理员能够与分配有中或低完整性级别的对象进行交互和修改，但也可以对其他具有高完整性级别的对象进行操作，标准用户则无法做到这一点。_例子："以管理员身份运行"_
* **系统** - 顾名思义，系统完整性级别是为系统保留的。Windows内核和核心服务被授予系统完整性级别。即使是管理员，这个比高完整性级别还要高的级别也保护这些核心功能不受影响或妥协。例子：服务
* **安装程序** - 安装程序完整性级别是一个特殊情况，是所有完整性级别中最高的。由于与所有其他WIC完整性级别相等或更高，因此被分配安装程序完整性级别的对象也能够卸载所有其他对象。

您可以使用**Sysinternals**的**Process Explorer**获取进程的完整性级别，访问进程的**属性**并查看"**安全**"标签：

![](<../../.gitbook/assets/image (318).png>)

您还可以使用`whoami /groups`获取您的**当前完整性级别**：

![](<../../.gitbook/assets/image (319).png>)

## 文件系统中的完整性级别

文件系统中的对象可能需要**最低完整性级别要求**，如果进程没有这个完整性进程，它将无法与之交互。\
例如，让我们**从常规用户控制台创建一个常规文件并检查权限**：
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
现在，让我们为文件分配一个最低完整性级别**High**。这**必须在以**管理员**身份运行的控制台中完成**，因为**普通控制台**将以中等完整性级别运行，并且**不允许**将高完整性级别分配给对象：
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
这里的情况变得有趣了。你可以看到用户 `DESKTOP-IDJHTKP\user` 对文件拥有**完全权限**（实际上这是创建该文件的用户），然而，由于实施了最低完整性级别，除非他在高完整性级别下运行（注意，他将能够读取它），否则他将无法再修改文件：
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**因此，当一个文件有最低完整性等级时，要修改它，你至少需要在该完整性等级下运行。**
{% endhint %}

## 二进制文件中的完整性等级

我在 `C:\Windows\System32\cmd-low.exe` 复制了一个 `cmd.exe` 并且从管理员控制台设置了一个**低完整性等级：**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
现在，当我运行 `cmd-low.exe` 时，它将**以低完整性级别运行**，而不是中等完整性级别：

![](<../../.gitbook/assets/image (320).png>)

对于好奇的人来说，如果你为一个二进制文件分配高完整性级别（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`），它不会自动以高完整性级别运行（如果你从中等完整性级别--默认情况下--调用它，它将以中等完整性级别运行）。

## 进程中的完整性级别

并非所有文件和文件夹都有最低完整性级别，**但所有进程都在某个完整性级别下运行**。与文件系统发生的情况类似，**如果一个进程想要在另一个进程内部写入，它必须至少具有相同的完整性级别**。这意味着，一个低完整性级别的进程不能打开一个对中等完整性级别进程具有完全访问权限的句柄。

由于本节和前一节中评论的限制，从安全角度来看，始终**建议在尽可能低的完整性级别下运行进程**。


<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks 中看到你的公司广告** 或者 **下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享你的黑客技巧。**

</details>
