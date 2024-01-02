# 可写的系统路径 + Dll劫持提权

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks中看到你的公司广告**或者**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>

## 介绍

如果你发现你可以**在系统路径文件夹中写入**（注意，如果你可以在用户路径文件夹中写入，这将不起作用），那么你可能可以在系统中**提升权限**。

为了做到这一点，你可以滥用**Dll劫持**，在这里你将**劫持一个被服务或进程加载的库**，这个服务或进程拥有比你**更高的权限**，因为该服务正在加载一个可能整个系统中都不存在的Dll，它将尝试从你可以写入的系统路径加载它。

有关**什么是Dll劫持**的更多信息，请查看：

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## 使用Dll劫持提权

### 查找缺失的Dll

你需要做的第一件事是**识别一个进程**，它运行着比你**更高的权限**，并且试图**从你可以写入的系统路径加载Dll**。

这种情况的问题在于，这些进程可能已经在运行了。为了找到服务缺少的Dlls，你需要尽快启动procmon（在进程加载之前）。因此，要找到缺少的.dlls，请执行以下操作：

* **创建**文件夹`C:\privesc_hijacking`并将路径`C:\privesc_hijacking`添加到**系统路径环境变量**中。你可以**手动**执行此操作，或者使用**PS**：
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
* 启动 **`procmon`** 并转到 **`Options`** --> **`Enable boot logging`**，然后在提示中按 **`OK`**。
* 然后，**重启**。当计算机重新启动时，**`procmon`** 将开始尽快**记录**事件。
* 一旦 **Windows** 启动后再次执行 **`procmon`**，它会告诉你它已经在运行，并且会**询问你是否想要将**事件保存在文件中。说**是**并**将事件保存在文件中**。
* **生成**文件**之后**，**关闭**打开的 **`procmon`** 窗口并**打开事件文件**。
* 添加这些**过滤器**，你将找到所有一些**进程尝试从可写的系统路径文件夹加载**的Dlls：

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### 未找到的 Dlls

在一个免费的**虚拟 (vmware) Windows 11 机器**上运行这个，我得到了这些结果：

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

在这种情况下，.exe 文件没有用，所以忽略它们，未找到的 DLLs 来自：

| 服务                             | Dll                | CMD 行                                                               |
| -------------------------------- | ------------------ | -------------------------------------------------------------------- |
| 任务计划程序 (Schedule)          | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| 诊断策略服务 (DPS)               | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                              | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

在找到这些之后，我发现了这篇有趣的博客文章，它还解释了如何[**滥用 WptsExtensions.dll 进行权限提升**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll)。这就是我们**现在要做的**。

### 利用

因此，为了**提升权限**，我们将劫持库 **WptsExtensions.dll**。有了**路径**和**名称**，我们只需要**生成恶意 dll**。

你可以[**尝试使用这些示例之一**](../dll-hijacking.md#creating-and-compiling-dlls)。你可以运行的有效载荷包括：获取反向 shell，添加用户，执行信标...

{% hint style="warning" %}
请注意，并非所有服务都是以 **`NT AUTHORITY\SYSTEM`** 运行的，有些还以 **`NT AUTHORITY\LOCAL SERVICE`** 运行，后者具有**较少的权限**，你**无法创建新用户**或滥用其权限。\
然而，该用户具有 **`seImpersonate`** 权限，因此你可以使用[**土豆套件来提升权限**](../roguepotato-and-printspoofer.md)。所以，在这种情况下，获取反向 shell 比尝试创建用户是一个更好的选择。
{% endhint %}

在写作时，**任务计划程序**服务是以 **Nt AUTHORITY\SYSTEM** 运行的。

生成了**恶意 Dll**（_在我的案例中，我使用了 x64 反向 shell 并且回传了 shell，但 defender 杀死了它，因为它来自 msfvenom_），将其保存在可写的系统路径中，命名为 **WptsExtensions.dll**，然后**重启**计算机（或重启服务或做任何需要的事情来重新运行受影响的服务/程序）。

当服务重新启动时，**dll 应该被加载并执行**（你可以**重用** **procmon** 技巧来检查**库是否如预期加载**）。

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 HackTricks 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享你的黑客技巧。

</details>
