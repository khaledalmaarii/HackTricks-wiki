# macOS Dangerous Entitlements & TCC perms

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

{% hint style="warning" %}
请注意，以 **`com.apple`** 开头的权限不对第三方开放，只有 Apple 可以授予它们。
{% endhint %}

## 高危

### `com.apple.rootless.install.heritable`

权限 **`com.apple.rootless.install.heritable`** 允许 **绕过 SIP**。查看 [此处获取更多信息](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

权限 **`com.apple.rootless.install`** 允许 **绕过 SIP**。查看 [此处获取更多信息](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports` (之前称为 `task_for_pid-allow`)**

此权限允许获取 **任何** 进程的 **任务端口**，除了内核。查看 [**此处获取更多信息**](../macos-proces-abuse/macos-ipc-inter-process-communication/)。

### `com.apple.security.get-task-allow`

此权限允许具有 **`com.apple.security.cs.debugger`** 权限的其他进程获取由具有此权限的二进制文件运行的进程的任务端口并 **注入代码**。查看 [**此处获取更多信息**](../macos-proces-abuse/macos-ipc-inter-process-communication/)。

### `com.apple.security.cs.debugger`

具有调试工具权限的应用可以调用 `task_for_pid()` 来检索未签名和第三方应用的有效任务端口，这些应用的 `Get Task Allow` 权限设置为 `true`。然而，即使具有调试工具权限，调试器 **无法获取** 没有 `Get Task Allow` 权限的进程的任务端口，因此这些进程受到系统完整性保护的保护。查看 [**此处获取更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger)。

### `com.apple.security.cs.disable-library-validation`

此权限允许 **加载框架、插件或库，而不需要由 Apple 签名或与主可执行文件具有相同的团队 ID**，因此攻击者可以利用某些任意库加载来注入代码。查看 [**此处获取更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)。

### `com.apple.private.security.clear-library-validation`

此权限与 **`com.apple.security.cs.disable-library-validation`** 非常相似，但 **而不是** **直接禁用** 库验证，它允许进程 **调用 `csops` 系统调用来禁用它**。\
查看 [**此处获取更多信息**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)。

### `com.apple.security.cs.allow-dyld-environment-variables`

此权限允许 **使用 DYLD 环境变量**，这些变量可用于注入库和代码。查看 [**此处获取更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)。

### `com.apple.private.tcc.manager` 或 `com.apple.rootless.storage`.`TCC`

[**根据这篇博客**](https://objective-see.org/blog/blog\_0x4C.html) **和** [**这篇博客**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)，这些权限允许 **修改** **TCC** 数据库。

### **`system.install.apple-software`** 和 **`system.install.apple-software.standar-user`**

这些权限允许 **在不询问用户权限的情况下安装软件**，这对于 **权限提升** 很有帮助。

### `com.apple.private.security.kext-management`

请求 **内核加载内核扩展** 所需的权限。

### **`com.apple.private.icloud-account-access`**

权限 **`com.apple.private.icloud-account-access`** 使得与 **`com.apple.iCloudHelper`** XPC 服务进行通信成为可能，该服务将 **提供 iCloud 令牌**。

**iMovie** 和 **Garageband** 拥有此权限。

有关 **从该权限获取 iCloud 令牌** 的漏洞的更多 **信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: 我不知道这允许做什么

### `com.apple.private.apfs.revert-to-snapshot`

TODO: 在 [**这份报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **中提到这可能用于** 在重启后更新 SSV 保护的内容。如果你知道如何，请发送 PR！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: 在 [**这份报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **中提到这可能用于** 在重启后更新 SSV 保护的内容。如果你知道如何，请发送 PR！

### `keychain-access-groups`

此权限列出了应用可以访问的 **钥匙串** 组：
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

授予**完全磁盘访问**权限，这是TCC可以拥有的最高权限之一。

### **`kTCCServiceAppleEvents`**

允许应用程序向其他常用于**自动化任务**的应用程序发送事件。通过控制其他应用程序，它可以滥用授予这些其他应用程序的权限。

例如，让它们要求用户输入密码： 

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

或者让它们执行**任意操作**。

### **`kTCCServiceEndpointSecurityClient`**

允许在其他权限中**写入用户的 TCC 数据库**。

### **`kTCCServiceSystemPolicySysAdminFiles`**

允许**更改**用户的**`NFSHomeDirectory`**属性，从而更改其主文件夹路径，因此允许**绕过 TCC**。

### **`kTCCServiceSystemPolicyAppBundles`**

允许修改应用程序包内的文件（在 app.app 内），这在默认情况下是**不允许的**。

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

可以在 _系统设置_ > _隐私与安全_ > _应用管理_ 中检查谁拥有此访问权限。

### `kTCCServiceAccessibility`

该进程将能够**滥用 macOS 辅助功能**，这意味着例如它将能够按下按键。因此，它可以请求控制像 Finder 这样的应用程序并批准此权限的对话框。

## 中等

### `com.apple.security.cs.allow-jit`

此权限允许通过将 `MAP_JIT` 标志传递给 `mmap()` 系统函数来**创建可写和可执行的内存**。查看 [**更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

此权限允许**覆盖或修补 C 代码**，使用长期弃用的 **`NSCreateObjectFileImageFromMemory`**（这在根本上是不安全的），或使用 **DVDPlayback** 框架。查看 [**更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory)。

{% hint style="danger" %}
包括此权限会使您的应用程序暴露于内存不安全代码语言中的常见漏洞。仔细考虑您的应用程序是否需要此例外。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

此权限允许**修改其自身可执行文件**在磁盘上的部分以强制退出。查看 [**更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection)。

{% hint style="danger" %}
禁用可执行内存保护权限是一种极端权限，它从您的应用程序中移除了基本的安全保护，使攻击者能够在不被检测的情况下重写您应用程序的可执行代码。如果可能，优先选择更窄的权限。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

待办事项

### `com.apple.private.nullfs_allow`

此权限允许挂载 nullfs 文件系统（默认情况下被禁止）。工具：[**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master)。

### `kTCCServiceAll`

根据这篇博客文章，这个 TCC 权限通常以以下形式出现：
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
允许进程**请求所有TCC权限**。

### **`kTCCServicePostEvent`**
{% hint style="success" %}
学习与实践AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家(ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家(GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我们在**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR分享黑客技巧。

</details>
{% endhint %}
</details>
