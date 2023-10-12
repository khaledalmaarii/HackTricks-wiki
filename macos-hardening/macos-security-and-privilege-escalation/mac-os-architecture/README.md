# macOS内核和系统扩展

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## XNU内核

**macOS的核心是XNU**，它代表着“X不是Unix”。这个内核基本上由**Mach微内核**（稍后将讨论）和来自Berkeley Software Distribution（**BSD**）的元素组成。XNU还通过一个名为I/O Kit的系统为**内核驱动程序提供平台**。XNU内核是Darwin开源项目的一部分，这意味着**它的源代码是免费可访问的**。

从安全研究人员或Unix开发人员的角度来看，**macOS**可能会感觉非常**类似**于一个带有优雅GUI和许多自定义应用程序的**FreeBSD**系统。大多数为BSD开发的应用程序在macOS上编译和运行时不需要修改，因为Unix用户熟悉的命令行工具在macOS上都存在。然而，由于XNU内核包含了Mach，传统的类Unix系统和macOS之间存在一些重要的差异，这些差异可能会导致潜在的问题或提供独特的优势。

XNU的开源版本：[https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach是一个设计为**与UNIX兼容**的**微内核**。它的一个关键设计原则是**最小化**在**内核**空间中运行的**代码**量，而是允许许多典型的内核功能（如文件系统、网络和I/O）作为用户级任务运行。

在XNU中，Mach负责许多典型的内核操作，如处理器调度、多任务处理和虚拟内存管理。

### BSD

XNU内核还**整合了**大量来自**FreeBSD**项目的代码。这些代码与Mach一起在同一地址空间中作为内核的一部分运行。然而，XNU中的FreeBSD代码可能与原始的FreeBSD代码有很大的不同，因为需要对其进行修改以确保与Mach的兼容性。FreeBSD对许多内核操作做出了贡献，包括：

* 进程管理
* 信号处理
* 基本安全机制，包括用户和组管理
* 系统调用基础设施
* TCP/IP堆栈和套接字
* 防火墙和数据包过滤

理解BSD和Mach之间的交互可能是复杂的，因为它们具有不同的概念框架。例如，BSD使用进程作为其基本执行单元，而Mach基于线程运行。在XNU中，通过将每个BSD进程与包含一个Mach线程的Mach任务相关联来解决这个差异。当使用BSD的fork()系统调用时，内核中的BSD代码使用Mach函数创建一个任务和一个线程结构。

此外，**Mach和BSD各自维护不同的安全模型**：**Mach的**安全模型基于**端口权限**，而BSD的安全模型基于**进程所有权**。这两个模型之间的差异有时会导致本地特权提升漏洞。除了典型的系统调用外，还有**Mach陷阱允许用户空间程序与内核进行交互**。这些不同的元素共同构成了macOS内核的多面、混合架构。

### I/O Kit - 驱动程序

I/O Kit是XNU内核中的开源、面向对象的**设备驱动程序框架**，负责添加和管理**动态加载的设备驱动程序**。这些驱动程序允许将模块化代码动态添加到内核中，以便与不同的硬件一起使用，例如。

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - 进程间通信

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

**Kernelcache**是XNU内核的**预编译和预链接版本**，以及必要的设备**驱动程序**和**内核扩展**。它以**压缩**格式存储，并在启动过程中解压缩到内存中。通过具有可运行版本的内核和关键驱动程序的kernelcache，可以实现更快的启动时间，减少在启动时动态加载和链接这些组件所需的时间和资源。

在iOS中，它位于**`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**，在macOS中，可以使用**`find / -name kernelcache 2>/dev/null`**找到它。
#### IMG4

IMG4文件格式是苹果在其iOS和macOS设备中用于安全地存储和验证固件组件（如kernelcache）的容器格式。IMG4格式包括一个头部和几个标签，这些标签封装了不同的数据片段，包括实际的载荷（如内核或引导加载程序）、签名和一组清单属性。该格式支持加密验证，使设备能够在执行固件组件之前确认其真实性和完整性。

通常由以下组件组成：

- **载荷（IM4P）**：
  - 经常被压缩（LZFSE4，LZSS，...）
  - 可选加密
- **清单（IM4M）**：
  - 包含签名
  - 附加的键/值字典
- **恢复信息（IM4R）**：
  - 也称为APNonce
  - 防止某些更新的重放攻击
  - 可选：通常不会找到

解压Kernelcache：
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Kernelcache符号

有时，苹果会发布带有符号的**kernelcache**。您可以通过在[https://theapplewiki.com](https://theapplewiki.com/)上的链接上下载一些带有符号的固件。

### IPSW

这些是您可以从[**https://ipsw.me/**](https://ipsw.me/)下载的苹果**固件**。除了其他文件之外，它还包含**kernelcache**。\
要**提取**文件，您只需将其解压缩即可。

提取固件后，您将获得一个类似于**`kernelcache.release.iphone14`**的文件。它以**IMG4**格式存储，您可以使用以下方法提取有趣的信息：

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

通过这个命令，我们现在可以**提取所有的扩展**或者**您感兴趣的一个扩展：**
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

由于代码将以高权限运行，macOS对加载内核扩展（.kext）非常严格，实际上，默认情况下几乎不可能加载（除非找到了绕过方法）。

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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
