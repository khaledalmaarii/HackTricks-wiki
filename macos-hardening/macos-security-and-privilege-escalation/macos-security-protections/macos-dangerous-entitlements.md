# macOS危险权限

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFT收藏品The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

{% hint style="warning" %}
请注意，以**`com.apple`**开头的权限不可供第三方使用，只有Apple可以授予。
{% endhint %}

## 高级

### `com.apple.security.get-task-allow`

此权限允许获取由具有此权限的二进制文件运行的进程的任务端口，并对其进行**代码注入**。查看[**此处了解更多信息**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### **`com.apple.system-task-ports`（以前称为`task_for_pid-allow`）**

此权限允许获取**任何**进程的任务端口，但不包括内核。查看[**此处了解更多信息**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.cs.debugger`

具有调试工具权限的应用程序可以调用`task_for_pid()`来检索未签名和第三方应用程序的有效任务端口，前提是这些应用程序具有设置为`true`的`Get Task Allow`权限。然而，即使具有调试工具权限，调试器也无法获取没有`Get Task Allow`权限的进程的任务端口，因此受系统完整性保护的保护。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger)。

### `com.apple.security.cs.disable-library-validation`

此权限允许**加载未由Apple签名或使用相同的Team ID签名的框架、插件或库**，因此攻击者可以滥用某些任意库加载来注入代码。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)。

### `com.apple.security.cs.allow-dyld-environment-variables`

此权限允许**使用DYLD环境变量**，这些变量可以用于注入库和代码。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)。

## 中级

### `com.apple.security.cs.allow-jit`

此权限允许通过向`mmap()`系统函数传递`MAP_JIT`标志来创建可写和可执行的内存。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

此权限允许**覆盖或修补C代码**，使用长期弃用的**`NSCreateObjectFileImageFromMemory`**（基本上是不安全的），或使用**DVDPlayback**框架。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory)。

{% hint style="danger" %}
包含此权限会使您的应用程序面临内存不安全代码语言的常见漏洞。请仔细考虑您的应用程序是否需要此例外。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

此权限允许**修改自己的可执行文件**上的部分内容以强制退出。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection)。

{% hint style="danger" %}
禁用可执行内存保护权限是一项极端的权限，它会从您的应用程序中删除基本的安全保护，使攻击者能够在不被检测到的情况下重写您的应用程序的可执行代码。如果可能，请优先选择更窄的权限。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO
* **加入** [💬](https://emojipedia.org/speech-balloon/) [Discord 群组](https://discord.gg/hRep4RUj7f) 或 [Telegram 群组](https://t.me/peass) 或 **关注**我的 **Twitter** [🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[@carlospolopm](https://twitter.com/hacktricks\_live)**。**
* **通过向** [hacktricks 仓库](https://github.com/carlospolop/hacktricks) **和** [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
