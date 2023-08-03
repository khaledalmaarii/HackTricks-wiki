<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**电报群组**](https://t.me/peass) 或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# 完整性级别

从Windows Vista开始，所有**受保护的对象都带有完整性级别标签**。系统上的大多数用户和系统文件以及注册表键都具有“中等”完整性的默认标签。主要例外是一组特定的文件夹和文件，这些文件夹和文件可由Internet Explorer 7以低完整性进行写入。**大多数由标准用户运行的进程**都带有**中等完整性**（即使是由管理员组内的用户启动的进程），而大多数**服务**都带有**系统完整性**。根目录受到高完整性标签的保护。\
请注意，**具有较低完整性级别的进程无法写入具有较高完整性级别的对象**。\
有几个完整性级别：

* **不受信任** - 匿名登录的进程会自动被指定为不受信任。_示例：Chrome_
* **低** - 低完整性级别是与互联网交互的默认级别。只要以其默认状态运行Internet Explorer（即受保护模式），与其关联的所有文件和进程都被分配为低完整性级别。某些文件夹（例如**临时互联网文件夹**）也默认分配为**低完整性**级别。但是，请注意，**低完整性进程**非常**受限**，它**无法**写入**注册表**，并且在当前用户配置文件的**大多数位置**上受到限制。_示例：Internet Explorer或Microsoft Edge_
* **中等** - 中等是**大多数对象将运行的上下文**。标准用户接收中等完整性级别，并且任何未明确指定较低或较高完整性级别的对象默认为中等级别。请注意，默认情况下，管理员组内的用户将使用中等完整性级别。
* **高** - **管理员**被授予高完整性级别。这确保管理员能够与分配为中等或低完整性级别的对象进行交互和修改，但也可以对具有高完整性级别的其他对象进行操作，而标准用户则无法执行此操作。_示例：“以管理员身份运行”_
* **系统** - 如其名称所示，系统完整性级别为系统保留。Windows内核和核心服务被授予系统完整性级别。比管理员的高完整性级别更高，这样可以保护这些核心功能免受管理员的影响或损害。示例：服务
* **安装程序** - 安装程序完整性级别是一种特殊情况，也是所有完整性级别中最高的级别。通过与所有其他WIC完整性级别相等或更高，被分配安装程序完整性级别的对象也能够卸载所有其他对象。

您可以使用**Sysinternals**的**Process Explorer**访问进程的**属性**并查看“**安全**”选项卡来获取进程的完整性级别：

![](<../../.gitbook/assets/image (318).png>)

您还可以使用`whoami /groups`命令获取**当前的完整性级别**。

![](<../../.gitbook/assets/image (319).png>)

## 文件系统中的完整性级别

文件系统中的对象可能需要**最低完整性级别要求**，如果进程没有此完整性级别，则无法与其进行交互。\
例如，让我们**从常规用户控制台创建一个文件并检查权限**：
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
现在，让我们将文件的最低完整性级别设置为**高**。这个操作**必须在以管理员身份运行的控制台**中进行，因为**普通控制台**运行在中等完整性级别，**无法**将高完整性级别分配给一个对象：
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
这就是事情变得有趣的地方。你可以看到用户`DESKTOP-IDJHTKP\user`对该文件拥有**完全权限**（确实是该用户创建了该文件），然而，由于实施了最低完整性级别，除非他在高完整性级别下运行，否则他将无法修改该文件（请注意，他仍然可以读取它）：
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**因此，当一个文件具有最低完整性级别时，为了修改它，你需要至少以该完整性级别运行。**
{% endhint %}

## 二进制文件的完整性级别

我在管理员控制台中将 `cmd.exe` 复制到 `C:\Windows\System32\cmd-low.exe` 并将其设置为**低完整性级别：**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
现在，当我运行`cmd-low.exe`时，它将以低完整性级别而不是中等级别运行：

![](<../../.gitbook/assets/image (320).png>)

对于好奇的人，如果你给一个二进制文件分配了高完整性级别（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`），它不会自动以高完整性级别运行（如果你从中等完整性级别调用它，默认情况下它将以中等完整性级别运行）。

## 进程中的完整性级别

并非所有文件和文件夹都有最低完整性级别，**但所有进程都在一个完整性级别下运行**。与文件系统发生的情况类似，**如果一个进程想要在另一个进程内写入，它必须至少具有相同的完整性级别**。这意味着具有低完整性级别的进程无法以完全访问权限打开具有中等完整性级别的进程的句柄。

基于安全性考虑，始终建议以尽可能低的完整性级别运行进程。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
