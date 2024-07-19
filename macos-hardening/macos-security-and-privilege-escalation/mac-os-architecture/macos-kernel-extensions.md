# macOS Kernel Extensions

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## 基本信息

内核扩展（Kexts）是带有 **`.kext`** 扩展名的 **包**，它们被 **直接加载到 macOS 内核空间**，为主操作系统提供额外功能。

### 要求

显然，这非常强大，以至于 **加载内核扩展** 是 **复杂的**。内核扩展必须满足以下 **要求** 才能被加载：

* 当 **进入恢复模式** 时，必须允许加载内核 **扩展**：

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* 内核扩展必须 **使用内核代码签名证书签名**，该证书只能由 **Apple** 授予。谁将详细审查公司及其所需的原因。
* 内核扩展还必须 **经过公证**，Apple 将能够检查其是否含有恶意软件。
* 然后，**root** 用户是唯一可以 **加载内核扩展** 的人，包内的文件必须 **属于 root**。
* 在上传过程中，包必须准备在 **受保护的非 root 位置**：`/Library/StagedExtensions`（需要 `com.apple.rootless.storage.KernelExtensionManagement` 授权）。
* 最后，当尝试加载时，用户将 [**收到确认请求**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html)，如果接受，计算机必须 **重启** 以加载它。

### 加载过程

在 Catalina 中是这样的：有趣的是，**验证** 过程发生在 **用户空间**。然而，只有具有 **`com.apple.private.security.kext-management`** 授权的应用程序才能 **请求内核加载扩展**：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cli **启动** 加载扩展的 **验证** 过程
* 它将通过发送 **Mach 服务** 与 **`kextd`** 进行通信。
2. **`kextd`** 将检查多个内容，例如 **签名**
* 它将与 **`syspolicyd`** 进行通信以 **检查** 扩展是否可以 **加载**。
3. **`syspolicyd`** 将 **提示** **用户** 如果扩展尚未被加载。
* **`syspolicyd`** 将结果报告给 **`kextd`**
4. **`kextd`** 最终将能够 **告诉内核加载** 扩展

如果 **`kextd`** 不可用，**`kextutil`** 可以执行相同的检查。

## 参考文献

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
