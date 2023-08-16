# macOS内核扩展

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks上宣传你的公司吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索我们独家的[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* 获得[**PEASS和HackTricks的官方商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) **Discord群**或[**Telegram群**](https://t.me/peass)，或在**Twitter**上**关注我**[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)。
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧**。

</details>

## 基本信息

内核扩展（Kexts）是具有**`.kext`**扩展名的**包**，直接加载到macOS的内核空间中，为主要操作系统提供额外的功能。

### 要求

显然，加载内核扩展是一项强大的功能。以下是加载内核扩展所需满足的要求：

* 在**恢复模式**下，内核扩展必须被**允许加载**：

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* 内核扩展必须使用**内核代码签名证书进行签名**，该证书只能由**Apple**颁发。Apple将详细审查**公司**和**所需原因**。
* 内核扩展还必须经过**公证**，Apple可以检查其中是否存在恶意软件。
* 然后，**root用户**可以加载内核扩展，包中的文件必须属于root。
* 在加载过程中，包必须准备在受保护的非根目录位置：`/Library/StagedExtensions`（需要授予`com.apple.rootless.storage.KernelExtensionManagement`权限）
* 最后，在尝试加载时，[**用户将收到确认请求**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html)，如果确认，计算机必须**重新启动**以加载它。

### 加载过程

在Catalina中是这样的：值得注意的是，**验证**过程发生在**用户空间**中。然而，只有具有**`com.apple.private.security.kext-management`**权限的应用程序才能**请求内核**加载扩展：kextcache、kextload、kextutil、kextd、syspolicyd

1. **`kextutil`**命令行工具**启动**验证过程以加载扩展

* 通过Mach服务与**`kextd`**通信

2. **`kextd`**将检查各种事项，如签名

* 通过与**`syspolicyd`**通信，检查是否可以加载扩展

3. **`syspolicyd`**将向**用户**询问是否先前未加载扩展

* **`syspolicyd`**将结果告知**`kextd`**

4. **`kextd`**最终可以通知内核加载扩展

如果kextd不可用，kextutil可以执行相同的检查。

## 参考资料

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks上宣传你的公司吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索我们独家的[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* 获得[**PEASS和HackTricks的官方商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) **Discord群**或[**Telegram群**](https://t.me/peass)，或在**Twitter**上**关注我**[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)。
* **通过向** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **发送PR来分享你的黑客技巧。**

</details>
