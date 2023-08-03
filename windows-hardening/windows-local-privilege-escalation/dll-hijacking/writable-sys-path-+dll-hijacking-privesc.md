# 可写的 Sys 路径 + Dll 劫持提权

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告** 吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF 版本** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 介绍

如果你发现你可以在一个**系统路径文件夹中写入**（请注意，如果你可以在用户路径文件夹中写入，这将不起作用），那么你可能可以在系统中**提升权限**。

为了做到这一点，你可以滥用**Dll 劫持**，你将会**劫持一个由比你拥有更高权限的服务或进程加载的库**，因为该服务正在加载一个在整个系统中可能甚至不存在的 Dll，它将尝试从你可以写入的系统路径加载它。

有关**什么是 Dll 劫持**的更多信息，请查看：

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## 使用 Dll 劫持进行提权

### 查找缺失的 Dll

首先，你需要**识别一个正在以比你更高的权限运行的进程**，该进程正在尝试从你可以写入的系统路径**加载一个 Dll**。

在这种情况下的问题是，可能这些进程已经在运行。为了找出哪些 Dll 缺失了服务，你需要尽快启动 procmon（在进程加载之前）。因此，要查找缺失的 .dll，请执行以下操作： 

* **创建**文件夹 `C:\privesc_hijacking` 并将路径 `C:\privesc_hijacking` 添加到**系统路径环境变量**中。你可以**手动**执行此操作，也可以使用**PS**：
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* 启动**`procmon`**并转到**`选项`** --> **`启用启动日志记录`**，然后在提示中按**`确定`**。
* 然后，**重新启动**。计算机重新启动后，**`procmon`**将立即开始记录事件。
* 一旦**Windows**启动，再次执行**`procmon`**，它会告诉你它一直在运行，并询问你是否要将事件存储在文件中。选择**是**，并将事件存储在文件中。
* **生成**文件**后**，关闭已打开的**`procmon`**窗口，并打开事件文件。
* 添加以下**过滤器**，你将找到所有从可写的系统路径文件夹中尝试加载的DLL：

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### 丢失的DLL

在一个免费的**虚拟（vmware）Windows 11机器**上运行此命令，我得到了以下结果：

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

在这种情况下，.exe 是无用的，所以忽略它们，丢失的DLL来自于：

| 服务                           | DLL                | CMD 行                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| 任务计划程序 (Schedule)         | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| 诊断策略服务 (DPS)               | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

找到这些信息后，我发现了这篇有趣的博客文章，它还解释了如何[**滥用 WptsExtensions.dll 进行权限提升**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll)。这正是我们**现在要做的**。

### 攻击

因此，为了**提升权限**，我们将劫持库**WptsExtensions.dll**。有了**路径**和**名称**，我们只需要**生成恶意 DLL**。

你可以[**尝试使用这些示例之一**](../dll-hijacking.md#creating-and-compiling-dlls)。你可以运行如下的有效载荷：获取反向 shell、添加用户、执行 beacon...

{% hint style="warning" %}
请注意，**并非所有的服务都以**`NT AUTHORITY\SYSTEM`**运行**，有些也以**`NT AUTHORITY\LOCAL SERVICE`**运行，它的权限较低，你将**无法创建新用户**来滥用其权限。\
然而，该用户具有**`seImpersonate`**权限，因此你可以使用[**potato suite 来提升权限**](../roguepotato-and-printspoofer.md)。所以，在这种情况下，反向 shell 是一个比尝试创建用户更好的选择。
{% endhint %}

在撰写本文时，**任务计划程序**服务以**Nt AUTHORITY\SYSTEM**运行。

生成了**恶意 DLL**（在我的情况下，我使用了 x64 反向 shell，我得到了一个 shell，但是因为它来自 msfvenom，所以被防御者杀掉了），将其保存在可写的系统路径中，文件名为**WptsExtensions.dll**，然后**重新启动**计算机（或重新启动服务或执行其他操作以重新运行受影响的服务/程序）。

当服务重新启动时，**dll 应该被加载和执行**（你可以**重用**procmon**技巧来检查库是否按预期加载**）。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得最新版本的 PEASS 或下载 HackTricks 的 PDF 吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass)，或在 **Twitter** 上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧**。

</details>
