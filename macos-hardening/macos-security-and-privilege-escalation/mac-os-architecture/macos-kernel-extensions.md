# macOS内核扩展

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？想要在HackTricks上宣传您的**公司**吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索我们独家的[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取官方的[PEASS和HackTricks**周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord群**或[**电报群**](https://t.me/peass)，或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)。
* 通过向[**hacktricks repo**](https://github.com/carlospolop/hacktricks)和[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)发送PR来分享您的黑客技巧。

</details>

## 基本信息

内核扩展（Kexts）是具有**`.kext`**扩展名的**软件包**，直接加载到macOS内核空间中，为主操作系统提供额外功能。

### 要求

显然，这是如此强大，以至于**加载内核扩展**变得**复杂**。这是内核扩展必须满足的**要求**：

* **进入恢复模式**时，必须**允许加载内核扩展**：

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* 内核扩展必须使用**内核代码签名证书**进行**签名**，这只能由**苹果**授予。苹果将详细审查公司和所需原因。
* 内核扩展还必须经过**公证**，苹果将检查其是否含有恶意软件。
* 然后，**root**用户是可以**加载内核扩展**的用户，软件包中的文件必须**属于root**。
* 在上传过程中，软件包必须准备在**受保护的非root位置**：`/Library/StagedExtensions`（需要`com.apple.rootless.storage.KernelExtensionManagement`授权）。
* 最后，在尝试加载时，用户将收到[**确认请求**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html)，如果接受，必须**重新启动**计算机以加载它。

### 加载过程

在Catalina中是这样的：有趣的是**验证**过程发生在**用户空间**。但是，只有具有**`com.apple.private.security.kext-management`**授权的应用程序才能**请求内核加载扩展**：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cli **启动**加载扩展的**验证**过程
* 它将通过**Mach服务**与**`kextd`**通信。
2. **`kextd`** 将检查多个内容，如**签名**
* 它将与**`syspolicyd`**通信以**检查**是否可以**加载**扩展。
3. **`syspolicyd`** 将**提示用户**，如果扩展之前未加载。
* **`syspolicyd`** 将结果报告给**`kextd`**
4. **`kextd`** 最终可以告诉内核**加载**扩展

如果**`kextd`**不可用，**`kextutil`**可以执行相同的检查。

## References

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？想要在HackTricks上宣传您的**公司**吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索我们独家的[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取官方的[PEASS和HackTricks**周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord群**或[**电报群**](https://t.me/peass)，或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)。
* 通过向[**hacktricks repo**](https://github.com/carlospolop/hacktricks)和[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)发送PR来分享您的黑客技巧。

</details>
