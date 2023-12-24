# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作，想在**HackTricks**上看到您的**公司广告**，或者想要获取**PEASS的最新版本或以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方PEASS & HackTricks周边商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

## **基本信息**

**系统完整性保护（SIP）**是macOS中的一项安全技术，它保护某些系统目录不受未经授权的访问，即使是root用户也不例外。它阻止对这些目录的修改，包括创建、更改或删除文件。SIP保护的主要目录有：

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
在这里，**`restricted`** 标志表明 `/usr/libexec` 目录受到 SIP 的保护。在 SIP 保护的目录中，文件不能被创建、修改或删除。

此外，如果文件包含扩展 **属性** **`com.apple.rootless`**，那么该文件也将被 **SIP 保护**。

**SIP 还限制了其他 root 操作**，例如：

* 加载不受信任的内核扩展
* 获取 Apple 签名进程的 task-ports
* 修改 NVRAM 变量
* 允许内核调试

选项在 nvram 变量中以位标志的形式维护（在 Intel 上是 `csr-active-config`，在 ARM 上从启动的设备树中读取 `lp-sip0`）。您可以在 XNU 源代码的 `csr.sh` 中找到这些标志：

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### SIP 状态

您可以使用以下命令检查系统上是否启用了 SIP：
```bash
csrutil status
```
```markdown
如果您需要禁用SIP，您必须在恢复模式下重启您的电脑（在启动期间按Command+R），然后执行以下命令：
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

[更多 SIP 信息在这个演讲中](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)。

## SIP 绕过

如果攻击者设法绕过 SIP，他将能够做到以下事情：

* 读取所有用户的邮件、消息、Safari 历史记录等
* 授予权限给网络摄像头、麦克风或任何东西（通过直接写入受 SIP 保护的 TCC 数据库）- TCC 绕过
* 持久性：他可以在受 SIP 保护的位置保存恶意软件，甚至 root 也无法删除它。他还可以篡改 MRT。
* 更容易加载内核扩展（尽管对此仍有其他严格的保护措施）。

### 安装包

**用苹果的证书签名的安装包**可以绕过其保护。这意味着，即使是由标准开发者签名的包，如果试图修改受 SIP 保护的目录，也会被阻止。

### 不存在的 SIP 文件

一个潜在的漏洞是，如果在 **`rootless.conf` 中指定了一个文件但当前不存在**，则可以创建它。恶意软件可以利用这一点在系统上**建立持久性**。例如，恶意程序可以在 `/System/Library/LaunchDaemons` 中创建一个 .plist 文件，如果它在 `rootless.conf` 中列出但不存在的话。

### com.apple.rootless.install.heritable

{% hint style="danger" %}
权限 **`com.apple.rootless.install.heritable`** 允许绕过 SIP
{% endhint %}

#### Shrootless

[**这篇博客文章的研究人员**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) 发现了 macOS 的系统完整性保护（SIP）机制中的一个漏洞，被称为 'Shrootless' 漏洞。这个漏洞围绕着 **`system_installd`** 守护进程，它拥有一个权限，**`com.apple.rootless.install.heritable`**，允许其子进程绕过 SIP 的文件系统限制。

**`system_installd`** 守护进程将安装由 **苹果** 签名的包。

研究人员发现，在安装苹果签名的包（.pkg 文件）期间，**`system_installd`** **运行** 包中包含的任何**安装后**脚本。这些脚本由默认 shell，**`zsh`** 执行，它会自动**运行**来自 **`/etc/zshenv`** 文件的命令（如果存在的话），即使在非交互模式下也是如此。攻击者可以利用这种行为：通过创建一个恶意的 `/etc/zshenv` 文件并等待 **`system_installd` 调用 `zsh`**，他们可以在设备上执行任意操作。

此外，还发现 **`/etc/zshenv` 可以作为一种通用攻击技术**，不仅仅是用于 SIP 绕过。每个用户配置文件都有一个 `~/.zshenv` 文件，其行为与 `/etc/zshenv` 相同，但不需要 root 权限。这个文件可以用作持久性机制，每次 `zsh` 启动时触发，或作为权限提升机制。如果管理员用户使用 `sudo -s` 或 `sudo <command>` 提升为 root，`~/.zshenv` 文件将被触发，有效地提升为 root。

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

在 [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) 中发现，同一个 **`system_installd`** 进程仍然可以被滥用，因为它将**安装后脚本放在 `/tmp` 内由 SIP 保护的随机命名文件夹中**。问题是 **`/tmp` 本身并不受 SIP 保护**，所以可以在其上**挂载**一个**虚拟镜像**，然后**安装程序**会将**安装后脚本**放在那里，**卸载**虚拟镜像，**重新创建**所有**文件夹**并**添加**带有**有效载荷**的**安装后**脚本以执行。

#### [fsck\_cs 工具](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

这个绕过利用了 **`fsck_cs`** 会跟随**符号链接**并尝试修复呈现给它的文件系统的事实。

因此，攻击者可以创建一个从 _`/dev/diskX`_ 指向 `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` 的符号链接，并在前者上调用 **`fsck_cs`**。由于 `Info.plist` 文件被损坏，操作系统将**无法控制内核扩展排除**，从而绕过 SIP。

{% code overflow="wrap" %}
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
{% endcode %}

上述已被破坏的 Info.plist 文件，通常被 **SIP 用来将某些内核扩展列入白名单** 并特别**阻止** **其他**的加载。它通常会把苹果自己的内核扩展 **`AppleHWAccess.kext`** 加入黑名单，但随着配置文件的破坏，我们现在可以加载它，并随意从系统 RAM 读写数据。

#### [覆盖 SIP 保护的文件夹](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

可以通过挂载一个新的文件系统覆盖 **SIP 保护的文件夹来绕过保护**。
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [升级器绕过 (2016)](https://objective-see.org/blog/blog\_0x14.html)

当执行时，升级/安装器应用程序（即 `Install macOS Sierra.app`）设置系统从安装器磁盘映像启动（该映像嵌入在已下载的应用程序中）。这个安装器磁盘映像包含升级操作系统的逻辑，例如从 OS X El Capitan 升级到 macOS Sierra。

为了让系统从升级/安装器映像（`InstallESD.dmg`）启动，`Install macOS Sierra.app` 使用了 **`bless`** 工具（它继承了权限 `com.apple.rootless.install.heritable`）：

{% code overflow="wrap" %}
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
{% endcode %}

因此，如果攻击者能在系统从其启动之前修改升级映像（`InstallESD.dmg`），他就可以绕过SIP。

修改映像以感染它的方法是替换动态加载器（dyld），它会天真地加载并执行恶意的动态链接库（dylib），就像 **`libBaseIA`** 动态链接库一样。因此，每当用户启动安装程序（即升级系统）时，我们的恶意动态链接库（名为libBaseIA.dylib）也会在安装程序中加载并执行。

现在在安装程序内部，我们可以控制升级过程的这一阶段。由于安装程序会“祝福”映像，我们所要做的就是在使用之前篡改映像，**`InstallESD.dmg`**。通过方法交换挂钩 **`extractBootBits`** 方法，这是可能的。\
在磁盘映像被使用之前执行恶意代码，现在是感染它的时候了。

在 `InstallESD.dmg` 内部，有另一个嵌入的磁盘映像 `BaseSystem.dmg`，它是升级代码的“根文件系统”。可以将动态链接库注入到 `BaseSystem.dmg` 中，这样恶意代码就会在可以修改操作系统级文件的进程上下文中运行。

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

在 [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) 的这次演讲中，展示了 **`systemmigrationd`**（可以绕过SIP）执行 **bash** 和 **perl** 脚本，这可以通过环境变量 **`BASH_ENV`** 和 **`PERL5OPT`** 来滥用。

### **com.apple.rootless.install**

{% hint style="danger" %}
权限 **`com.apple.rootless.install`** 允许绕过SIP
{% endhint %}

来自 [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) 系统XPC服务 `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` 拥有权限 **`com.apple.rootless.install`**，它授予进程权限绕过SIP限制。它还 **暴露了一个无任何安全检查的移动文件的方法。**

## 封闭系统快照

封闭系统快照是苹果在 **macOS Big Sur (macOS 11)** 中引入的一个特性，作为其 **系统完整性保护 (SIP)** 机制的一部分，以提供额外的安全性和系统稳定性层。它们本质上是系统卷的只读版本。

这里是更详细的介绍：

1. **不可变系统**：封闭系统快照使macOS系统卷“不可变”，意味着它不能被修改。这防止了任何未授权或意外的系统变更，这些变更可能会危害安全性或系统稳定性。
2. **系统软件更新**：当你安装macOS更新或升级时，macOS会创建一个新的系统快照。然后macOS启动卷使用 **APFS (Apple文件系统)** 切换到这个新快照。应用更新的整个过程变得更加安全可靠，因为如果更新过程中出现问题，系统总是可以回退到之前的快照。
3. **数据分离**：结合在macOS Catalina中引入的数据和系统卷分离概念，封闭系统快照功能确保所有数据和设置都存储在一个独立的“**Data**”卷上。这种分离使您的数据独立于系统，简化了系统更新过程并增强了系统安全性。

请记住，这些快照是由macOS自动管理的，并且由于APFS的空间共享能力，它们不会占用您磁盘上的额外空间。同样重要的是要注意，这些快照与 **Time Machine快照** 不同，后者是整个系统的用户可访问备份。

### 检查快照

命令 **`diskutil apfs list`** 列出了 **APFS卷的详细信息** 及其布局：

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
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

在上面的输出中，可以看到 **用户可访问的位置** 被挂载在 `/System/Volumes/Data` 下。

此外，**macOS系统卷快照** 被挂载在 `/` 并且是 **封闭的**（由操作系统加密签名）。所以，如果SIP被绕过并修改了它，**操作系统将不再启动**。

还可以通过运行以下命令来 **验证封印是否启用**：
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

* 如果您在**网络安全公司**工作？您想在**HackTricks**中看到您的**公司广告**？或者您想要访问**最新版本的PEASS或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
