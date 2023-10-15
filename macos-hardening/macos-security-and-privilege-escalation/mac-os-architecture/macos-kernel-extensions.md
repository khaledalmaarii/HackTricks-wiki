# macOS内核扩展

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks上宣传你的公司吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们独家的[**The PEASS Family**](https://opensea.io/collection/the-peass-family) NFT收藏品
* 获得[**PEASS和HackTricks的官方商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) **Discord群**或[**Telegram群**](https://t.me/peass)，或在**Twitter**上**关注我**[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)。
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **发送PR来分享你的黑客技巧**。

</details>

## 基本信息

内核扩展（Kexts）是具有**`.kext`**扩展名的**包**，直接加载到macOS内核空间中，为主操作系统提供额外的功能。

### 要求

显然，这是非常强大的，因此**加载内核扩展**是很**复杂**的。以下是内核扩展必须满足的**要求**：

* 在**进入恢复模式**时，必须**允许加载内核扩展**：

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* 内核扩展必须使用**内核代码签名证书**进行**签名**，该证书只能由**Apple**授予。Apple将详细审查公司和所需原因。
* 内核扩展还必须经过**公证**，Apple将对其进行恶意软件检查。
* 然后，**root**用户是可以**加载内核扩展**的用户，包中的文件必须**属于root**。
* 在上传过程中，包必须准备在**受保护的非root位置**：`/Library/StagedExtensions`（需要`com.apple.rootless.storage.KernelExtensionManagement`授权）。
* 最后，在尝试加载时，用户将[**收到确认请求**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html)，如果接受，则必须**重新启动**计算机以加载它。

### 加载过程

在Catalina中是这样的：有趣的是，**验证**过程发生在**用户空间**中。然而，只有具有**`com.apple.private.security.kext-management`**授权的应用程序才能**请求内核加载扩展**：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`**命令行**启动**加载扩展的**验证**过程
* 它将通过使用**Mach服务**与**`kextd`**通信。
2. **`kextd`**将检查多个事项，如**签名**
* 它将与**`syspolicyd`**通信以**检查**是否可以**加载**扩展。
3. **`syspolicyd`**将在扩展未被先前加载时**提示用户**
* **`syspolicyd`**将结果报告给**`kextd`**
4. **`kextd`**最终可以**告诉内核加载**扩展

如果**`kextd`**不可用，**`kextutil`**可以执行相同的检查。

## 参考资料

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks上宣传你的公司吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们独家的[**The PEASS Family**](https://opensea.io/collection/the-peass-family) NFT收藏品
* 获得[**PEASS和HackTricks的官方商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) **Discord群**或[**Telegram群**](https://t.me/peass)，或在**Twitter**上**关注我**[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)。
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **发送PR来分享你的黑客技巧**。

</details>
