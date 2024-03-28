# macOS内核与系统扩展

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## XNU内核

**macOS的核心是XNU**，代表“X不是Unix”。该内核基本上由**Mach微内核**（稍后将讨论）和来自伯克利软件发行版（**BSD**）的元素组成。XNU还通过名为I/O Kit的系统为**内核驱动程序提供平台**。XNU内核是达尔文开源项目的一部分，这意味着**其源代码是免费可访问的**。

从安全研究人员或Unix开发人员的角度来看，**macOS**可能会感觉与具有优雅GUI和大量自定义应用程序的**FreeBSD**系统非常**相似**。大多数为BSD开发的应用程序在macOS上编译和运行时无需修改，因为Unix用户熟悉的命令行工具都存在于macOS中。然而，由于XNU内核整合了Mach，因此传统的类Unix系统与macOS之间存在一些重要差异，这些差异可能会导致潜在问题或提供独特优势。

XNU的开源版本：[https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach是一个**微内核**，旨在**兼容UNIX**。其关键设计原则之一是**最小化**在**内核**空间中运行的**代码**量，而是允许许多典型的内核功能，如文件系统、网络和I/O，以**用户级任务**的形式运行。

在XNU中，Mach负责许多内核通常处理的关键低级操作，如处理器调度、多任务处理和虚拟内存管理。

### BSD

XNU **内核**还**整合**了大量源自**FreeBSD**项目的代码。这些代码与Mach一起作为内核的一部分运行在相同的地址空间中。但是，XNU内部的FreeBSD代码可能与原始FreeBSD代码有很大不同，因为必须对其进行修改以确保与Mach的兼容性。FreeBSD对许多内核操作做出贡献，包括：

- 进程管理
- 信号处理
- 基本安全机制，包括用户和组管理
- 系统调用基础设施
- TCP/IP堆栈和套接字
- 防火墙和数据包过滤

理解BSD和Mach之间的交互可能会很复杂，因为它们具有不同的概念框架。例如，BSD使用进程作为其基本执行单元，而Mach基于线程运行。在XNU中，通过**将每个BSD进程与包含一个Mach线程的Mach任务相关联**来协调这种差异。当使用BSD的fork()系统调用时，内核中的BSD代码使用Mach函数创建任务和线程结构。

此外，**Mach和BSD各自维护不同的安全模型**：**Mach**的安全模型基于**端口权限**，而BSD的安全模型基于**进程所有权**。这两种模型之间的差异有时会导致本地特权升级漏洞。除了典型的系统调用外，还有**Mach陷阱允许用户空间程序与内核交互**。这些不同的元素共同构成了macOS内核的多面体混合架构。

### I/O Kit - 驱动程序

I/O Kit是XNU内核中的一个开源、面向对象的**设备驱动程序框架**，处理**动态加载的设备驱动程序**。它允许将模块化代码动态添加到内核中，支持各种硬件。

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - 进程间通信

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

**Kernelcache**是XNU内核的**预编译和预链接版本**，以及必要的设备**驱动程序**和**内核扩展**。它以**压缩**格式存储，并在引导过程中解压缩到内存中。Kernelcache通过提供一个准备就绪的内核版本和关键驱动程序，减少了在引导时动态加载和链接这些组件所需的时间和资源，从而实现**更快的启动时间**。

在iOS中，它位于**`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**，在macOS中，您可以使用**`find / -name kernelcache 2>/dev/null`**或**`mdfind kernelcache | grep kernelcache`**找到它。

可以运行**`kextstat`**来检查加载的内核扩展。

#### IMG4

IMG4文件格式是苹果在其iOS和macOS设备中使用的容器格式，用于安全地**存储和验证固件**组件（如**kernelcache**）。IMG4格式包括一个头部和几个标签，这些标签封装了不同的数据部分，包括实际有效载荷（如内核或引导加载程序）、签名和一组清单属性。该格式支持加密验证，允许设备在执行之前确认固件组件的真实性和完整性。

通常由以下组件组成：

- **有效载荷（IM4P）**：
  - 通常是压缩的（LZFSE4、LZSS等）
  - 可选加密
- **清单（IM4M）**：
  - 包含签名
  - 附加键/值字典
- **恢复信息（IM4R）**：
  - 也称为APNonce
  - 防止某些更新的重放
  - 可选：通常找不到

解压Kernelcache:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### 内核缓存符号

有时苹果会发布带有符号的**内核缓存**。您可以通过访问[https://theapplewiki.com](https://theapplewiki.com/)上的链接下载带有符号的一些固件。

### IPSW

这些是您可以从[**https://ipsw.me/**](https://ipsw.me/)下载的苹果**固件**。在其他文件中，它将包含**内核缓存**。\
要**提取**文件，您只需将其解压缩。

提取固件后，您将获得一个类似于：**`kernelcache.release.iphone14`**的文件。它采用**IMG4**格式，您可以使用以下工具提取有趣的信息：

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
您可以使用以下命令检查提取的内核缓存中的符号：**`nm -a kernelcache.release.iphone14.e | wc -l`**

有了这个，现在我们可以**提取所有的扩展**或者**您感兴趣的一个：**
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

macOS对加载内核扩展（.kext）非常严格，因为该代码将以高特权运行。实际上，默认情况下几乎不可能加载内核扩展（除非找到了绕过方法）。

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS系统扩展

macOS创建了系统扩展，而不是使用内核扩展，它提供了用户级API与内核进行交互。这样，开发人员可以避免使用内核扩展。

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## 参考资料

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
