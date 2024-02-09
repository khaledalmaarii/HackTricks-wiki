# 可写的 Sys 路径 + Dll 劫持提权

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

- 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
- 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) 上**关注**我们。
- 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

## 简介

如果您发现可以在**系统路径文件夹中写入**（请注意，如果您可以在用户路径文件夹中写入，则此方法将无效），则可能可以**提升系统权限**。

为了做到这一点，您可以滥用**Dll 劫持**，在这种情况下，您将**劫持一个由具有比您更高权限的服务或进程加载的库**，因为该服务正在加载一个在整个系统中可能甚至不存在的 Dll，它将尝试从您可以写入的系统路径中加载它。

有关**什么是 Dll 劫持**的更多信息，请查看：

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## 使用 Dll 劫持进行提权

### 查找缺失的 Dll

您需要做的第一件事是**识别一个正在以比您更高权限运行**的进程，该进程正在尝试**从您可以写入的系统路径中加载 Dll**。

在这种情况下的问题是，这些进程可能已经在运行。要找出哪些 Dll 缺少服务，您需要尽快启动 procmon（在进程加载之前）。因此，要查找缺少的 .dll，请执行以下操作：

- **创建**文件夹 `C:\privesc_hijacking` 并将路径 `C:\privesc_hijacking` 添加到**系统路径环境变量**。您可以**手动**执行此操作，也可以使用**PS**：
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
* 然后，**重新启动**。计算机重新启动后，**`procmon`** 将立即开始记录事件。
* 一旦 **Windows** 启动，请再次执行 `procmon`，它会告诉您它一直在运行，并询问您是否要将事件存储在文件中。选择 **yes** 并将事件存储在文件中。
* **文件** 生成后，**关闭** 打开的 **`procmon`** 窗口，并 **打开事件文件**。
* 添加以下 **过滤器**，您将找到所有一些 **进程尝试从可写的 System Path 文件夹加载** 的 Dlls：

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### 丢失的 Dlls

在一个免费的 **虚拟 (vmware) Windows 11 机器** 上运行此操作，我得到了以下结果：

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

在这种情况下，.exe 是无用的，所以请忽略它们，丢失的 DLL 来自于：

| 服务                         | Dll                | CMD 行                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| 任务计划程序 (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| 诊断策略服务 (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

找到这些后，我发现了这篇有趣的博客文章，也解释了如何 [**滥用 WptsExtensions.dll 进行权限提升**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll)。这就是我们 **现在要做的事情**。

### 利用

因此，为了 **提升权限**，我们将劫持库 **WptsExtensions.dll**。有了 **路径** 和 **名称**，我们只需要 **生成恶意 dll**。

您可以[**尝试使用这些示例之一**](../dll-hijacking.md#creating-and-compiling-dlls)。您可以运行有效载荷，如：获取反向 shell、添加用户、执行信标...

{% hint style="warning" %}
请注意，**并非所有服务都是** 使用 **`NT AUTHORITY\SYSTEM`** 运行的，有些也是使用 **`NT AUTHORITY\LOCAL SERVICE`** 运行的，后者权限较低，您 **无法创建新用户** 并滥用其权限。\
但是，该用户具有 **`seImpersonate`** 权限，因此您可以使用 [**potato 套件来提升权限**](../roguepotato-and-printspoofer.md)。因此，在这种情况下，获取反向 shell 是比尝试创建用户更好的选择。
{% endhint %}

在撰写本文时，**任务计划程序** 服务是以 **Nt AUTHORITY\SYSTEM** 运行的。

生成了恶意 Dll 后（在我的情况下，我使用了 x64 反向 shell，我得到了一个 shell，但是防御程序将其杀死，因为它来自 msfvenom），将其保存在可写的 System Path 中，并将其命名为 **WptsExtensions.dll**，然后 **重新启动** 计算机（或重新启动服务或执行必要的操作以重新运行受影响的服务/程序）。

当服务重新启动时，**dll 应该被加载和执行**（您可以**重复使用** **procmon** 技巧来检查库是否按预期加载）。

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的 **公司广告** 或 **下载 PDF 版本的 HackTricks**，请查看 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) 上 **关注** 我们。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
