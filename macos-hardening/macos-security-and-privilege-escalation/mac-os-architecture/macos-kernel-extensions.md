# macOS内核扩展

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## 基本信息

内核扩展（Kexts）是带有 **`.kext`** 扩展名的**包**，它们**直接加载到macOS内核空间**中，为主操作系统提供额外的功能。

### 要求

显然，这是非常强大的，因此**加载内核扩展**是**复杂的**。内核扩展必须满足以下**要求**才能被加载：

* 在**进入恢复模式**时，必须**允许**内核**扩展被加载**：

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* 内核扩展必须用内核代码签名证书**签名**，这只能由**苹果公司授予**。苹果会详细审查公司及其需要此证书的原因。
* 内核扩展还必须**公证**，苹果将能够检查它是否有恶意软件。
* 然后，**root**用户是可以**加载内核扩展**的用户，包内的文件必须**属于root**。
* 在上传过程中，包必须准备在一个**受保护的非root位置**：`/Library/StagedExtensions`（需要`com.apple.rootless.storage.KernelExtensionManagement`授权）。
* 最后，在尝试加载时，用户将[**收到确认请求**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html)，如果接受，计算机必须**重新启动**以加载它。

### 加载过程

在Catalina中是这样的：值得注意的是，**验证**过程发生在**用户空间**。然而，只有拥有**`com.apple.private.security.kext-management`** 授权的应用程序才能**请求内核加载扩展**：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cli **开始**加载扩展的**验证**过程
* 它将通过使用**Mach服务**与**`kextd`**通信。
2. **`kextd`** 将检查几件事，如**签名**
* 它将与**`syspolicyd`**通信以**检查**是否可以**加载**扩展。
3. 如果之前没有加载过扩展，**`syspolicyd`** 将**提示**用户。
* **`syspolicyd`** 将向**`kextd`**报告结果
4. **`kextd`** 最终将能够**告诉内核加载**扩展

如果**`kextd`**不可用，**`kextutil`**可以执行相同的检查。

## 参考资料

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
