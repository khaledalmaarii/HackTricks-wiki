# macOS SIP

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) 上**关注**我。
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## **基本信息**

macOS中的**系统完整性保护（SIP）**是一种机制，旨在防止即使是最特权的用户也无法对关键系统文件夹进行未经授权的更改。此功能通过限制在受保护区域添加、修改或删除文件等操作，对系统的完整性起着至关重要的作用。SIP保护的主要文件夹包括：

- **/System**
- **/bin**
- **/sbin**
- **/usr**

SIP行为的规则定义在位于**`/System/Library/Sandbox/rootless.conf`**的配置文件中。在此文件中，以星号（*）为前缀的路径被标记为SIP限制的例外情况。

考虑下面的示例：
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
这段代码暗示，虽然SIP通常保护**`/usr`**目录，但在特定子目录（`/usr/libexec/cups`、`/usr/local`和`/usr/share/man`）中，修改是允许的，这可以通过路径前面的星号（*）来表示。

要验证目录或文件是否受SIP保护，可以使用**`ls -lOd`**命令来检查**`restricted`**或**`sunlnk`**标志的存在。例如：
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
在这种情况下，**`sunlnk`**标志表示`/usr/libexec/cups`目录本身**不能被删除**，但其中的文件可以被创建、修改或删除。

另一方面：
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
在这里，**`restricted`**标志表示`/usr/libexec`目录受SIP保护。在受SIP保护的目录中，文件无法被创建、修改或删除。

此外，如果文件包含属性**`com.apple.rootless`**扩展**属性**，那么该文件也将受到**SIP的保护**。

**SIP还限制其他root操作**，如：

- 加载不受信任的内核扩展
- 为苹果签名的进程获取任务端口
- 修改NVRAM变量
- 允许内核调试

选项以位标志形式保存在nvram变量中（在Intel上为`csr-active-config`，在ARM上从引导的设备树中读取为`lp-sip0`）。您可以在XNU源代码中的`csr.sh`中找到这些标志：

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### SIP状态

您可以使用以下命令检查系统是否启用了SIP：
```bash
csrutil status
```
如果您需要禁用SIP，您必须在恢复模式下重新启动计算机（在启动过程中按下Command+R），然后执行以下命令：
```bash
csrutil disable
```
如果您希望保持SIP启用但移除调试保护，可以执行以下操作：
```bash
csrutil enable --without debug
```
### 其他限制

- **禁止加载未签名的内核扩展**（kext），确保只有经过验证的扩展与系统内核交互。
- **防止调试** macOS 系统进程，保护核心系统组件免受未经授权的访问和修改。
- **阻止工具**如 dtrace 检查系统进程，进一步保护系统操作的完整性。

**[在这个讲座中了解更多关于 SIP 信息](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship).**

## SIP 绕过

绕过 SIP 使攻击者能够：

- **访问用户数据**：从所有用户帐户中读取敏感用户数据，如邮件、消息和 Safari 历史记录。
- **TCC 绕过**：直接操纵 TCC（透明度、同意和控制）数据库，以授予对网络摄像头、麦克风和其他资源的未经授权访问。
- **建立持久性**：将恶意软件放置在受 SIP 保护的位置，使其难以被移除，即使使用 root 权限也无法移除。这还包括潜在地篡改恶意软件移除工具（MRT）。
- **加载内核扩展**：尽管有额外的保护措施，绕过 SIP 简化了加载未签名内核扩展的过程。

### 安装程序包

**使用 Apple 证书签名的安装程序包** 可以绕过其保护措施。这意味着即使标准开发人员签名的程序包也会被阻止，如果它们试图修改受 SIP 保护的目录。

### 不存在的 SIP 文件

一个潜在的漏洞是，如果一个文件在 **`rootless.conf` 中被指定但当前不存在**，它可以被创建。恶意软件可以利用这一点在系统上 **建立持久性**。例如，如果在 `rootless.conf` 中列出但不存在，恶意程序可以在 `/System/Library/LaunchDaemons` 中创建一个 .plist 文件。

### com.apple.rootless.install.heritable

{% hint style="danger" %}
授权 **`com.apple.rootless.install.heritable`** 允许绕过 SIP
{% endhint %}

#### Shrootless

[**这篇博文的研究人员**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) 发现了 macOS 的系统完整性保护（SIP）机制中的一个漏洞，被称为 'Shrootless' 漏洞。这个漏洞围绕着 **`system_installd`** 守护程序展开，它具有一个授权 **`com.apple.rootless.install.heritable`**，允许其任何子进程绕过 SIP 的文件系统限制。

**`system_installd`** 守护程序将安装由 **Apple** 签名的程序包。

研究人员发现，在安装一个由 Apple 签名的程序包（.pkg 文件）时，**`system_installd`** 会 **运行** 包中包含的任何 **post-install** 脚本。这些脚本由默认 shell **`zsh`** 执行，它会自动从 **`/etc/zshenv`** 文件中运行命令，如果存在的话，即使在非交互模式下也会运行。攻击者可以利用这种行为：通过创建一个恶意的 `/etc/zshenv` 文件，并等待 **`system_installd` 调用 `zsh`**，他们可以在设备上执行任意操作。

此外，发现 **`/etc/zshenv` 可以用作一般攻击技术**，不仅仅是用于绕过 SIP。每个用户配置文件都有一个 `~/.zshenv` 文件，它的行为方式与 `/etc/zshenv` 相同，但不需要 root 权限。这个文件可以用作持久性机制，每次 `zsh` 启动时触发，或者用作权限提升机制。如果管理员用户使用 `sudo -s` 或 `sudo <command>` 提升到 root，`~/.zshenv` 文件将被触发，有效地提升到 root。

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

在 [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) 中发现，同一个 **`system_installd`** 进程仍然可以被滥用，因为它将 **post-install 脚本放在了受 SIP 保护的随机命名文件夹内的 `/tmp`** 中。问题在于 **`/tmp` 本身并没有受到 SIP 保护**，因此可以在其上 **挂载** 一个 **虚拟镜像**，然后 **安装程序** 会将 **post-install 脚本** 放在其中，**卸载** 虚拟镜像，**重新创建** 所有 **文件夹**，并添加 **包含** 执行 **payload** 的 **post installation** 脚本。 

#### [fsck\_cs 实用程序](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

发现了一个漏洞，其中 **`fsck_cs`** 被误导以跟随 **符号链接**，导致其损坏一个关键文件。具体来说，攻击者从 _`/dev/diskX`_ 制作了一个链接到文件 `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`。在 _`/dev/diskX`_ 上执行 **`fsck_cs`** 导致 `Info.plist` 的损坏。这个文件的完整性对于操作系统的 SIP（系统完整性保护）至关重要，它控制内核扩展的加载。一旦损坏，SIP 管理内核排除的能力就会受到影响。
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
这个漏洞的利用有严重的影响。通常负责管理内核扩展权限的 `Info.plist` 文件变得无效。这包括无法将某些扩展列入黑名单，比如 `AppleHWAccess.kext`。因此，由于 SIP 的控制机制失效，这个扩展可以被加载，从而授予对系统 RAM 的未经授权读写访问。

#### [在 SIP 受保护的文件夹上挂载](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

可以在**SIP 受保护的文件夹上挂载一个新的文件系统以绕过保护**。
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [升级程序绕过（2016）](https://objective-see.org/blog/blog\_0x14.html)

系统被设置为从`Install macOS Sierra.app`中的嵌入式安装程序磁盘映像启动以升级操作系统，利用`bless`实用程序。使用的命令如下：
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
### macOS SIP绕过攻击

该过程的安全性可能会受到损害，如果攻击者在引导前更改升级镜像（`InstallESD.dmg`）。该策略涉及用恶意版本（`libBaseIA.dylib`）替换动态加载器（dyld）。此替换导致在启动安装程序时执行攻击者的代码。

攻击者的代码在升级过程中获得控制权，利用系统对安装程序的信任。攻击通过方法混淆来修改`InstallESD.dmg`镜像，特别是针对`extractBootBits`方法。这允许在磁盘映像被使用之前注入恶意代码。

此外，在`InstallESD.dmg`中，有一个`BaseSystem.dmg`，用作升级代码的根文件系统。将动态库注入其中允许恶意代码在能够修改操作系统级文件的进程中运行，显著增加了系统被妥协的可能性。

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

在[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk)的演讲中展示了**`systemmigrationd`**（可以绕过SIP）如何执行**bash**和**perl**脚本，可以通过环境变量**`BASH_ENV`**和**`PERL5OPT`**进行滥用。

### **com.apple.rootless.install**

{% hint style="danger" %}
权限**`com.apple.rootless.install`**允许绕过SIP
{% endhint %}

权限`com.apple.rootless.install`已知可以绕过macOS上的系统完整性保护（SIP）。这在与[**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)相关的情况下被特别提到。

在这种特定情况下，位于`/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`的系统XPC服务具有此权限。这允许相关进程绕过SIP的限制。此外，该服务显著提供了一个允许在不执行任何安全措施的情况下移动文件的方法。

## 封闭系统快照

封闭系统快照是苹果在**macOS Big Sur（macOS 11）**中引入的功能，作为其**系统完整性保护（SIP）**机制的一部分，提供了额外的安全层和系统稳定性。它们本质上是系统卷的只读版本。

以下是更详细的介绍：

1. **不可变系统**：封闭系统快照使macOS系统卷“不可变”，意味着它无法被修改。这可以防止任何未经授权或意外更改系统，可能危及安全性或系统稳定性。
2. **系统软件更新**：当您安装macOS更新或升级时，macOS会创建一个新的系统快照。然后，macOS启动卷使用**APFS（Apple文件系统）**切换到这个新快照。应用更新的整个过程变得更安全、更可靠，因为系统始终可以在更新过程中出现问题时恢复到先前的快照。
3. **数据分离**：结合在macOS Catalina中引入的数据和系统卷分离概念，封闭系统快照功能确保所有数据和设置存储在单独的“**数据**”卷上。这种分离使您的数据独立于系统，简化了系统更新过程，并增强了系统安全性。

请记住，这些快照由macOS自动管理，不会占用磁盘上的额外空间，这要归功于APFS的空间共享功能。还要注意，这些快照与**Time Machine快照**不同，后者是整个系统的用户可访问备份。

### 检查快照

命令**`diskutil apfs list`**列出了**APFS卷的详细信息**及其布局：
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

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
