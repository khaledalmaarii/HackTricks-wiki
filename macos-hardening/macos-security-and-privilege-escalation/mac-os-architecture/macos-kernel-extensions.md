# macOS内核扩展

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云平台 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Are you working in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## 基本信息

内核扩展（Kexts）是具有 **`.kext`** 扩展名的 **包**，直接加载到 macOS 内核空间中，为主操作系统提供额外的功能。

### 要求

显然，这是非常强大的，因此加载内核扩展是 **复杂的**。以下是内核扩展必须满足的要求：

* 在 **进入恢复模式** 时，必须允许加载内核扩展：

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* 内核扩展必须使用内核代码签名证书进行签名，该证书只能由 **Apple** 颁发。Apple 将详细审查公司和所需原因。
* 内核扩展还必须经过 **公证**，Apple 将检查其中是否存在恶意软件。
* 然后，**root** 用户是可以 **加载内核扩展** 的用户，包中的文件必须属于 root。
* 在上传过程中，包必须准备在受保护的非根位置：`/Library/StagedExtensions`（需要 `com.apple.rootless.storage.KernelExtensionManagement` 授权）。
* 最后，在尝试加载时，用户将会收到 [**确认请求**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html)，如果接受，则需要 **重新启动** 计算机以加载它。

### 加载过程

在 Catalina 中是这样的：有趣的是，**验证** 过程发生在 **用户空间** 中。然而，只有具有 **`com.apple.private.security.kext-management`** 授权的应用程序才能 **请求内核加载扩展**：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** 命令行界面 **启动** 内核扩展加载的 **验证** 过程
* 它将通过使用 **Mach 服务** 与 **`kextd`** 进行通信。
2. **`kextd`** 将检查多个事项，例如 **签名**
* 它将与 **`syspolicyd`** 进行通信以 **检查** 是否可以 **加载** 扩展。
3. **`syspolicyd`** 将在扩展未被先前加载时 **提示** **用户**
* **`syspolicyd`** 将结果报告给 **`kextd`**
4. **`kextd`** 最终可以 **告诉内核加载** 扩展

如果 **`kextd`** 不可用，则 **`kextutil`** 可以执行相同的检查。

## 参考资料

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云平台 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Are you working in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
