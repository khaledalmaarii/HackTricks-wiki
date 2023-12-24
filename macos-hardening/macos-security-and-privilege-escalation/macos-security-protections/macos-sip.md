# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作？您想在**HackTricks**中看到您的**公司广告**？或者您想要访问**最新版本的PEASS或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方的PEASS & HackTricks周边商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

## **基本信息**

**系统完整性保护（SIP）**是macOS中的一项安全技术，它保护某些系统目录不受未经授权的访问，即使是root用户也不例外。它防止对这些目录的修改，包括创建、更改或删除文件。SIP保护的主要目录有：

* **/System**
* **/bin**
* **/sbin**
* **/usr**

这些目录及其子目录的保护规则在**`/System/Library/Sandbox/rootless.conf`**文件中指定。在此文件中，以星号(\*)开头的路径表示对SIP限制的例外。

例如，以下配置：
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
表明**`/usr`**目录通常受到SIP的保护。然而，在指定的三个子目录（`/usr/libexec/cups`、`/usr/local`和`/usr/share/man`）中允许修改，因为它们前面带有星号（\*）。

要验证目录或文件是否受到SIP保护，您可以使用**`ls -lOd`**命令检查是否存在**`restricted`**或**`sunlnk`**标志。例如：
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
在这种情况下，**`sunlnk`** 标志表示 `/usr/libexec/cups` 目录本身**不能被删除**，尽管其中的文件可以被创建、修改或删除。

另一方面：
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
这里，**`restricted`** 标志表明 `/usr/libexec` 目录受到 SIP 的保护。在 SIP 保护的目录中，文件不能被创建、修改或删除。

此外，如果一个文件包含了扩展 **属性** **`com.apple.rootless`**，那么该文件也将被 **SIP 保护**。

**SIP 还限制了其他 root 操作**，例如：

* 加载不受信任的内核扩展
* 获取 Apple 签名进程的 task-ports
* 修改 NVRAM 变量
* 允许内核调试

选项在 nvram 变量中以位标志的形式维护（在 Intel 上是 `csr-active-config`，在 ARM 上从启动的设备树中读取 `lp-sip0`）。您可以在 XNU 源代码的 `csr.sh` 中找到这些标志：

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### SIP 状态

您可以使用以下命令检查您的系统是否启用了 SIP：
```bash
csrutil status
```
```bash
csrutil disable
```
```bash
csrutil disable
```
如果您希望保持SIP启用状态，但移除调试保护，您可以使用以下方法：
```bash
csrutil enable --without debug
```
### 其他限制

SIP 还强加了一些其他限制。例如，它不允许**加载未签名的内核扩展**（kexts），并阻止对 macOS 系统进程的**调试**。它还阻止像 dtrace 这样的工具检查系统进程。

## SIP 绕过

如果攻击者设法绕过 SIP，他将能够做到以下事情：

* 读取所有用户的邮件、消息、Safari 历史记录等
* 授予摄像头、麦克风或任何东西的权限（通过直接覆盖受 SIP 保护的 TCC 数据库）
* 持久性：他可以将恶意软件保存在受 SIP 保护的位置，甚至 root 也无法删除它。他还可以篡改 MRT。
* 更容易加载内核扩展（尽管对此仍有其他严格的保护措施）。

### 安装程序包

**用苹果证书签名的安装程序包**可以绕过其保护。这意味着，即使是标准开发者签名的包，如果试图修改受 SIP 保护的目录，也会被阻止。

### 不存在的 SIP 文件

一个潜在的漏洞是，如果在 **`rootless.conf` 中指定了一个文件但该文件当前不存在**，则可以创建它。恶意软件可以利用这一点在系统上**建立持久性**。例如，恶意程序可以在 `/System/Library/LaunchDaemons` 中创建一个 .plist 文件，如果它在 `rootless.conf` 中列出但不存在。

### com.apple.rootless.install.heritable

{% hint style="danger" %}
权限 **`com.apple.rootless.install.heritable`** 允许绕过 SIP
{% endhint %}

[**来自这篇博客文章的研究人员**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) 发现了 macOS 的系统完整性保护（SIP）机制中的一个漏洞，被称为 'Shrootless' 漏洞。这个漏洞围绕着 **`system_installd`** 守护进程，它拥有一个权限，**`com.apple.rootless.install.heritable`**，允许其子进程绕过 SIP 的文件系统限制。

**`system_installd`** 守护进程将安装由 **苹果** 签名的包。

研究人员发现，在安装苹果签名的包（.pkg 文件）期间，**`system_installd`** **运行**包中包含的任何**安装后**脚本。这些脚本由默认 shell，**`zsh`** 执行，它会自动**运行**来自 **`/etc/zshenv`** 文件的命令（如果存在），即使在非交互模式下也是如此。攻击者可以利用这种行为：通过创建一个恶意的 `/etc/zshenv` 文件并等待 **`system_installd` 调用 `zsh`**，他们可以在设备上执行任意操作。

此外，还发现 **`/etc/zshenv` 可以作为一种通用攻击技术**，不仅仅是用于 SIP 绕过。每个用户配置文件都有一个 `~/.zshenv` 文件，其行为与 `/etc/zshenv` 相同，但不需要 root 权限。这个文件可以用作持久性机制，每次 `zsh` 启动时触发，或作为提升权限机制。如果管理员用户使用 `sudo -s` 或 `sudo <command>` 提升为 root，`~/.zshenv` 文件将被触发，有效地提升为 root。

在 [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) 中发现，同一个 **`system_installd`** 过程仍然可以被滥用，因为它将 **安装后脚本放在 `/tmp` 内由 SIP 保护的随机命名文件夹中**。问题是 **`/tmp` 本身并未受到 SIP 的保护**，因此可以在其上**挂载**一个**虚拟映像**，然后**安装程序**会将**安装后脚本**放在那里，**卸载**虚拟映像，**重新创建**所有**文件夹**并**添加**带有**有效载荷**的**安装后**脚本以执行。

### **com.apple.rootless.install**

{% hint style="danger" %}
权限 **`com.apple.rootless.install`** 允许绕过 SIP
{% endhint %}

来自 [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) 的系统 XPC 服务 `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` 拥有权限 **`com.apple.rootless.install`**，该权限授予进程绕过 SIP 限制的权限。它还**暴露了一个无任何安全检查的移动文件的方法。**

## 封闭系统快照

封闭系统快照是苹果在 **macOS Big Sur (macOS 11)** 中引入的一个功能，作为其**系统完整性保护（SIP）**机制的一部分，以提供额外的安全性和系统稳定性层。它们本质上是系统卷的只读版本。

以下是更详细的介绍：

1. **不可变系统**：封闭系统快照使 macOS 系统卷变为“不可变”，意味着它不能被修改。这防止了任何未授权或意外的系统变更，这些变更可能会危害安全性或系统稳定性。
2. **系统软件更新**：当您安装 macOS 更新或升级时，macOS 会创建一个新的系统快照。然后 macOS 启动卷使用 **APFS (苹果文件系统)** 切换到这个新快照。整个更新应用过程变得更加安全可靠，因为如果更新过程中出现问题，系统总是可以回退到之前的快照。
3. **数据分离**：结合 macOS Catalina 引入的数据和系统卷分离概念，封闭系统快照功能确保了所有数据和设置都存储在一个独立的“**数据**”卷上。这种分离使您的数据独立于系统，简化了系统更新过程并增强了系统安全性。

请记住，这些快照是由 macOS 自动管理的，并且由于 APFS 的空间共享能力，它们不会占用您磁盘上的额外空间。同样重要的是要注意，这些快照与**时间机器快照**不同，后者是用户可访问的整个系统的备份。

### 检查快照

命令 **`diskutil apfs list`** 列出了 **APFS 卷的详细信息**及其布局：

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   快照：FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   快照磁盘：disk3s1s1
<strong>|   |   快照挂载点：/
</strong><strong>|   |   快照封存：是
</strong>[...]
+-> 卷 disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS 卷磁盘（角色）：disk3s5（数据）
|   名称：Macintosh HD - Data（不区分大小写）
<strong>    |   挂载点：/System/Volumes/Data
</strong><strong>    |   已使用容量：412071784448 B（412.1 GB）
</strong>    |   封存：否
|   FileVault：是（已解锁）
</code></pre>

在上述输出中，可以看到**用户可访问位置**挂载在`/System/Volumes/Data`下。

此外，**macOS 系统卷快照**挂载在`/`，并且是**封存的**（由操作系统加密签名）。因此，如果绕过 SIP 并修改它，**操作系统将不再启动**。

还可以通过运行以下命令来**验证封存是否启用**：
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
此外，快照磁盘也被挂载为**只读**：
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作，想在**HackTricks**上看到您的**公司广告**，或者想要访问**最新版本的PEASS或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)。
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
