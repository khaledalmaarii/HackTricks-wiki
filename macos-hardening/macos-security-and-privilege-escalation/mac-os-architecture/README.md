# macOS内核与系统扩展

<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## XNU内核

**macOS的核心是XNU**，代表“X不是Unix”。这个内核基本上由**Mach微内核**（稍后讨论）和来自伯克利软件分发（**BSD**）的元素组成。XNU还通过一个称为I/O Kit的系统为**内核驱动程序提供平台**。XNU内核是Darwin开源项目的一部分，这意味着**其源代码可以自由访问**。

从安全研究员或Unix开发者的角度看，**macOS**与带有优雅GUI和大量定制应用程序的**FreeBSD**系统非常**相似**。大多数为BSD开发的应用程序可以在macOS上编译和运行，无需修改，因为Unix用户熟悉的命令行工具在macOS中都存在。然而，由于XNU内核融合了Mach，它与传统的类Unix系统之间存在一些显著的差异，这些差异可能会引起潜在的问题或提供独特的优势。

XNU开源版本：[https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach是一个**微内核**，设计为**与UNIX兼容**。其关键设计原则之一是**最小化**在**内核**空间运行的**代码**量，而允许许多典型的内核功能，如文件系统、网络和I/O，**以用户级任务运行**。

在XNU中，Mach负责许多内核通常处理的关键低级操作，如处理器调度、多任务处理和虚拟内存管理。

### BSD

XNU**内核**还**整合**了大量源自**FreeBSD**项目的代码。这些代码**与Mach一起作为内核的一部分运行**，在同一地址空间中。然而，XNU中的FreeBSD代码可能与原始的FreeBSD代码有很大的不同，因为需要进行修改以确保其与Mach的兼容性。FreeBSD对许多内核操作做出了贡献，包括：

* 进程管理
* 信号处理
* 基本安全机制，包括用户和组管理
* 系统调用基础设施
* TCP/IP堆栈和套接字
* 防火墙和数据包过滤

理解BSD和Mach之间的交互可能很复杂，因为它们有不同的概念框架。例如，BSD使用进程作为其基本执行单元，而Mach基于线程操作。在XNU中，这种差异通过**将每个BSD进程与包含一个Mach线程的Mach任务关联起来**来调和。当BSD的fork()系统调用被使用时，内核中的BSD代码使用Mach函数来创建一个任务和一个线程结构。

此外，**Mach和BSD各自维护不同的安全模型**：**Mach的**安全模型基于**端口权限**，而BSD的安全模型基于**进程所有权**。这两种模型之间的差异偶尔会导致本地权限提升漏洞。除了典型的系统调用外，还有**Mach陷阱允许用户空间程序与内核交互**。这些不同的元素共同构成了macOS内核的多面性、混合架构。

### I/O Kit - 驱动程序

I/O Kit是XNU内核中的开源、面向对象的**设备驱动程序框架**，负责添加和管理**动态加载的设备驱动程序**。例如，这些驱动程序允许将模块化代码动态添加到内核中，以用于不同的硬件。

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - 进程间通信

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

**kernelcache**是**预编译和预链接的XNU内核版本**，包括必要的设备**驱动程序**和**内核扩展**。它以**压缩**格式存储，并在启动过程中解压缩到内存中。kernelcache通过提供一个随时可运行的内核和关键驱动程序版本，从而促进了**更快的启动时间**，减少了否则在启动时动态加载和链接这些组件所需的时间和资源。

在iOS中，它位于**`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**；在macOS中，您可以使用**`find / -name kernelcache 2>/dev/null`**找到它。

#### IMG4

IMG4文件格式是Apple在其iOS和macOS设备中用于安全**存储和验证固件**组件（如**kernelcache**）的容器格式。IMG4格式包括一个头部和几个封装不同数据片段的标签，包括实际的有效载荷（如内核或引导加载程序）、签名和一组清单属性。该格式支持加密验证，允许设备在执行固件组件之前确认其真实性和完整性。

它通常由以下组件组成：

* **有效载荷（IM4P）**：
* 经常压缩（LZFSE4、LZSS等）
* 可选加密
* **清单（IM4M）**：
* 包含签名
* 附加键/值字典
* **恢复信息（IM4R）**：
* 也称为APNonce
* 防止重放某些更新
* 可选：通常不会找到这个

解压Kernelcache：
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### 内核缓存符号

有时苹果会发布带有**符号**的**内核缓存**。你可以通过在[https://theapplewiki.com](https://theapplewiki.com/)上的链接下载一些带有符号的固件。

### IPSW

这些是你可以从 [**https://ipsw.me/**](https://ipsw.me/) 下载的苹果**固件**。它包含了其他文件，其中就有**内核缓存**。\
要**提取**文件，你可以直接**解压**它。

提取固件后，你会得到像这样的文件：**`kernelcache.release.iphone14`**。它是**IMG4**格式的，你可以用以下工具提取有用信息：

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
```markdown
您可以使用以下命令检查提取的kernelcache中的符号：**`nm -a kernelcache.release.iphone14.e | wc -l`**

通过这个我们现在可以**提取所有的扩展**或者**您感兴趣的那一个：**
```
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## macOS内核扩展

macOS对加载内核扩展（.kext）**极为限制**，因为代码将以高权限运行。实际上，默认情况下几乎是不可能的（除非找到了绕过方法）。

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS系统扩展

macOS创建了系统扩展，而不是使用内核扩展，它在用户级别提供了与内核交互的API。这样，开发者可以避免使用内核扩展。

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## 参考资料

* [**Mac黑客手册**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧**。

</details>
