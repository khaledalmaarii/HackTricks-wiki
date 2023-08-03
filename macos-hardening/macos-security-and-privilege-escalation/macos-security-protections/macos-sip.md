# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## **基本信息**

**系统完整性保护（SIP）**是macOS中的一项安全技术，它保护某些系统目录免受未经授权的访问，即使对于root用户也是如此。它防止对这些目录进行修改，包括创建、修改或删除文件。SIP保护的主要目录包括：

* **/System**
* **/bin**
* **/sbin**
* **/usr**

这些目录及其子目录的保护规则在**`/System/Library/Sandbox/rootless.conf`**文件中指定。在该文件中，以星号（\*）开头的路径表示SIP限制的例外情况。

例如，以下配置：
```javascript
javascriptCopy code/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
表明**`/usr`**目录通常受到SIP的保护。然而，三个指定的子目录（`/usr/libexec/cups`，`/usr/local`和`/usr/share/man`）允许进行修改，因为它们在前面有一个星号（\*）。

要验证目录或文件是否受到SIP的保护，可以使用**`ls -lOd`**命令来检查是否存在**`restricted`**或**`sunlnk`**标志。例如：
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
在这种情况下，**`sunlnk`** 标志表示 `/usr/libexec/cups` 目录本身不能被删除，但其中的文件可以被创建、修改或删除。

另一方面：
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
这里，**`restricted`** 标志表示 `/usr/libexec` 目录受到 SIP 保护。在受 SIP 保护的目录中，文件无法被创建、修改或删除。

### SIP 状态

您可以使用以下命令检查系统是否启用了 SIP：
```bash
csrutil status
```
如果您需要禁用SIP，您必须在恢复模式下重新启动计算机（在启动过程中按下Command+R），然后执行以下命令：
```bash
csrutil disable
```
如果您希望保持SIP启用状态但移除调试保护，可以使用以下方法：
```bash
csrutil enable --without debug
```
### 其他限制

SIP还有一些其他限制。例如，它禁止加载未签名的内核扩展（kexts），并阻止对macOS系统进程进行调试。它还阻止像dtrace这样的工具检查系统进程。

## SIP绕过

### 价格

如果攻击者成功绕过SIP，他将获得以下收益：

* 阅读所有用户的邮件、消息、Safari历史记录等
* 授予摄像头、麦克风或其他权限（通过直接覆盖SIP保护的TCC数据库）
* 持久性：他可以将恶意软件保存在SIP保护的位置，甚至管理员也无法删除它。此外，他还可以篡改MRT。
* 更容易加载内核扩展（仍然有其他强大的保护措施）

### 安装程序包

**使用Apple的证书签名的安装程序包**可以绕过其保护。这意味着即使是由标准开发人员签名的包，如果它们试图修改SIP保护的目录，也将被阻止。

### 不存在的SIP文件

一个潜在的漏洞是，如果一个文件在**`rootless.conf`中被指定，但当前不存在**，它可以被创建。恶意软件可以利用这一点在系统上建立持久性。例如，如果在`rootless.conf`中列出了`/System/Library/LaunchDaemons`中的.plist文件但不存在，那么恶意程序可以在那里创建一个.plist文件。

### com.apple.rootless.install.heritable

{% hint style="danger" %}
权限**`com.apple.rootless.install.heritable`**可以绕过SIP
{% endhint %}

[**来自这篇博文的研究人员**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)发现了macOS的系统完整性保护（SIP）机制的一个漏洞，被称为“Shrootless”漏洞。这个漏洞围绕着`system_installd`守护程序展开，它具有一个名为**`com.apple.rootless.install.heritable`**的权限，允许其任何子进程绕过SIP的文件系统限制。

研究人员发现，在安装由苹果签名的包（.pkg文件）时，`system_installd`会运行包中包含的任何**post-install**脚本。这些脚本由默认的shell **`zsh`**执行，即使在非交互模式下，它也会自动运行**`/etc/zshenv`**文件中的命令，如果该文件存在。攻击者可以利用这个行为：通过创建一个恶意的`/etc/zshenv`文件，并等待`system_installd`调用`zsh`，他们可以在设备上执行任意操作。

此外，还发现**`/etc/zshenv`可以用作一般的攻击技术**，不仅仅是用于绕过SIP。每个用户配置文件都有一个`~/.zshenv`文件，它的行为与`/etc/zshenv`相同，但不需要root权限。这个文件可以用作持久性机制，每次`zsh`启动时触发，或者用作权限提升机制。如果管理员用户使用`sudo -s`或`sudo <command>`提升为root用户，`~/.zshenv`文件将被触发，有效地提升为root用户。

在[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)中发现，同样的**`system_installd`**进程仍然可以被滥用，因为它将**post-install脚本放在了SIP保护的随机命名文件夹中的`/tmp`**中。问题在于**`/tmp`本身没有受到SIP的保护**，所以可以在其上**挂载**一个**虚拟映像**，然后**安装程序**会将**post-install脚本**放在其中，**卸载**虚拟映像，**重新创建**所有**文件夹**，并**添加**带有**要执行的payload的post-installation脚本**。

### **com.apple.rootless.install**

{% hint style="danger" %}
权限**`com.apple.rootless.install`**可以绕过SIP
{% endhint %}

从[**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)中得知，系统XPC服务`/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`具有权限**`com.apple.rootless.install`**，它允许进程绕过SIP的限制。它还**公开了一种在没有任何安全检查的情况下移动文件的方法**。

## 封闭系统快照

封闭系统快照是苹果在**macOS Big Sur（macOS 11）**中引入的一个功能，作为其**系统完整性保护（SIP）**机制的一部分，提供了额外的安全性和系统稳定性。它们本质上是系统卷的只读版本。

以下是更详细的介绍：

1. **不可变系统**：封闭系统快照使macOS系统卷变为“不可变”，意味着它不能被修改。这可以防止任何未经授权或意外的对系统的更改，从而可能危及安全性或系统稳定性。
2. **系统软件更新**：当您安装macOS更新或升级时，macOS会创建一个新的系统快照。然后，macOS启动卷使用**APFS（Apple文件系统）**切换到这个新的快照。如果在更新过程中出现问题，系统始终可以恢复到先前的快照，使应用更新的整个过程更加安全可靠。
3. **数据分离**：结合在macOS Catalina中引入的数据和系统卷分离的概念，封闭系统快照功能确保所有数据和设置存储在单独的“**数据**”卷上。这种分离使您的数据与系统独立，简化了系统更新的过程，并增强了系统安全性。

请记住，这些快照由macOS自动管理，并且由于APFS的空间共享功能，它们不会占用额外的磁盘空间。还需要注意的是，这些快照与**Time Machine快照**不同，后者是用户可访问的整个系统的备份。

### 检查快照

命令**`diskutil apfs list`**列出了APFS卷的详细信息和布局：

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
|   |   APFS Volume Disk (Role):   disk3s1 (System)
|   |   Name:                      Macintosh HD (Case-insensitive)
|   |   Mount Point:               /System/Volumes/Update/mnt1
|   |   Capacity Consumed:         128192102
|   |   快照磁盘:             disk3s1s1
|   |   快照挂载点:      /
<strong>|   |   快照已封存:           是
</strong>[...]
</code></pre>

在上面的输出中，可以看到**macOS系统卷快照已被封存**（由操作系统进行了加密签名）。因此，如果绕过SIP并对其进行修改，**操作系统将无法启动**。

还可以通过运行以下命令来验证封存是否已启用：
```
csrutil authenticated-root status
Authenticated Root status: enabled
```
此外，它被挂载为**只读**：
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
