<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 完整性级别

在Windows Vista及更高版本中，所有受保护的项目都带有**完整性级别**标签。这种设置通常将“中等”完整性级别分配给文件和注册表键，除了某些文件夹和文件，Internet Explorer 7可以以低完整性级别写入。默认行为是由标准用户启动的进程具有中等完整性级别，而服务通常在系统完整性级别下运行。高完整性标签保护根目录。

一个关键规则是对象不能被具有低于对象级别的完整性级别的进程修改。完整性级别包括：

- **不受信任**：此级别适用于具有匿名登录的进程。 %%%示例：Chrome%%%
- **低**：主要用于互联网交互，特别是在Internet Explorer的受保护模式下，影响相关文件和进程，以及像**临时互联网文件夹**这样的特定文件夹。低完整性进程面临重大限制，包括无法写入注册表和有限的用户配置文件写入访问权限。
- **中等**：大多数活动的默认级别，分配给标准用户和没有特定完整性级别的对象。即使管理员组的成员也默认在此级别操作。
- **高**：保留给管理员，允许他们修改低完整性级别的对象，包括高级别对象本身。
- **系统**：Windows内核和核心服务的最高操作级别，即使对于管理员也无法接触，确保重要系统功能的保护。
- **安装程序**：一个独特的级别，高于所有其他级别，使得在此级别的对象能够卸载任何其他对象。

您可以使用**Sysinternals**的**Process Explorer**获取进程的完整性级别，访问进程的**属性**并查看“**安全**”选项卡：

![](<../../.gitbook/assets/image (318).png>)

您还可以使用`whoami /groups`获取您的**当前完整性级别**

![](<../../.gitbook/assets/image (319).png>)

## 文件系统中的完整性级别

文件系统中的对象可能需要一个**最低完整性级别要求**，如果进程没有这个完整性级别，它将无法与其交互。\
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
现在，让我们将文件的最低完整性级别设置为**高**。这**必须在作为**管理员**运行的**控制台**中完成，因为**普通控制台**将在中间完整性级别下运行，**无法**将高完整性级别分配给对象：
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
这就是事情变得有趣的地方。您可以看到用户`DESKTOP-IDJHTKP\user`对文件拥有**完全权限**（实际上这是创建文件的用户），但由于实施了最低完整性级别，他将无法修改文件，除非他在高完整性级别下运行（请注意他仍然可以读取文件）：
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**因此，当文件具有最低完整性级别时，为了修改它，您需要至少以该完整性级别运行。**
{% endhint %}

## 二进制文件中的完整性级别

我在管理员控制台中将`cmd.exe`的副本命名为`C:\Windows\System32\cmd-low.exe`，并将其设置为**低完整性级别：**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
现在，当我运行 `cmd-low.exe` 时，它将以**低完整性级别**而不是中等级别运行：

![](<../../.gitbook/assets/image (320).png>)

对于好奇的人，如果您将高完整性级别分配给一个二进制文件（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`），它不会自动以高完整性级别运行（如果您从中等完整性级别调用它--默认情况下--它将在中等完整性级别下运行）。

## 进程中的完整性级别

并非所有文件和文件夹都有最低完整性级别，**但所有进程都在一个完整性级别下运行**。与文件系统发生的情况类似，**如果一个进程想要在另一个进程内写入，它必须至少具有相同的完整性级别**。这意味着低完整性级别的进程无法以完全访问权限打开具有中等完整性级别的进程的句柄。

由于在本节和前一节中讨论的限制，从安全角度来看，始终**建议以尽可能低的完整性级别运行进程**。
