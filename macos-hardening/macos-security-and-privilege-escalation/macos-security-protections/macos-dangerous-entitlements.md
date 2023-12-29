# macOS 危险权限 & TCC 权限

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在**HackTricks**中看到您的**公司广告**吗？或者您想要访问**最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在**推特**上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享您的黑客技巧。**

</details>

{% hint style="warning" %}
请注意，以 **`com.apple`** 开头的权限不向第三方开放，只有苹果公司可以授予它们。
{% endhint %}

## 高危

### `com.apple.rootless.install.heritable`

权限 **`com.apple.rootless.install.heritable`** 允许**绕过 SIP**。查看[此处了解更多信息](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

权限 **`com.apple.rootless.install`** 允许**绕过 SIP**。查看[此处了解更多信息](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports`（之前称为 `task_for_pid-allow`）**

此权限允许获取**任何**进程的**任务端口**，除了内核。查看[**此处了解更多信息**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.get-task-allow`

此权限允许拥有 **`com.apple.security.cs.debugger`** 权限的其他进程获取此权限二进制文件运行的进程的任务端口并**注入代码**。查看[**此处了解更多信息**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.cs.debugger`

拥有调试工具权限的应用可以调用 `task_for_pid()` 来检索未签名和第三方应用的有效任务端口，这些应用设置了 `Get Task Allow` 权限为 `true`。然而，即使拥有调试工具权限，调试器**无法获取**没有 `Get Task Allow` 权限的进程的任务端口，因此受到系统完整性保护的保护。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger)。

### `com.apple.security.cs.disable-library-validation`

此权限允许**加载框架、插件或库，而无需由苹果签名或与主执行文件具有相同的团队 ID 签名**，因此攻击者可以滥用某些任意库加载来注入代码。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)。

### `com.apple.private.security.clear-library-validation`

此权限与 **`com.apple.security.cs.disable-library-validation`** 非常相似，但**不是**直接**禁用**库验证，而是允许进程**调用 `csops` 系统调用来禁用它**。\
查看[**此处了解更多信息**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)。

### `com.apple.security.cs.allow-dyld-environment-variables`

此权限允许**使用 DYLD 环境变量**，这些变量可以用来注入库和代码。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)。

### `com.apple.private.tcc.manager` 或 `com.apple.rootless.storage`.`TCC`

[**根据这篇博客**](https://objective-see.org/blog/blog\_0x4C.html) **和** [**这篇博客**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)，这些权限允许**修改** **TCC** 数据库。

### **`system.install.apple-software`** 和 **`system.install.apple-software.standar-user`**

这些权限允许**安装软件而不需要向用户请求权限**，这对于**权限提升**可能很有帮助。

### `com.apple.private.security.kext-management`

需要此权限才能请求**内核加载内核扩展**。

### **`com.apple.private.icloud-account-access`**

拥有 **`com.apple.private.icloud-account-access`** 权限的话，可以与 **`com.apple.iCloudHelper`** XPC 服务通信，它将**提供 iCloud 令牌**。

**iMovie** 和 **Garageband** 拥有此权限。

有关利用该权限**获取 icloud 令牌**的漏洞的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

待办事项：我不知道这允许做什么

### `com.apple.private.apfs.revert-to-snapshot`

待办事项：在[**这份报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)中**提到这可以用来**在重启后更新受 SSV 保护的内容。如果您知道如何操作，请提交 PR！

### `com.apple.private.apfs.create-sealed-snapshot`

待办事项：在[**这份报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)中**提到这可以用来**在重启后更新受 SSV 保护的内容。如果您知道如何操作，请提交 PR！

### `keychain-access-groups`

此权限列出了应用程序可以访问的**钥匙串**组：
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

授予**完全磁盘访问**权限，这是 TCC 中你可以拥有的最高权限之一。

### **`kTCCServiceAppleEvents`**

允许应用程序向其他通常用于**自动执行任务**的应用程序发送事件。通过控制其他应用程序，它可以滥用这些其他应用程序被授予的权限。

比如让它们向用户请求密码：

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

或使它们执行**任意操作**。

### **`kTCCServiceEndpointSecurityClient`**

允许包括**写用户TCC数据库**在内的其他权限。

### **`kTCCServiceSystemPolicySysAdminFiles`**

允许更改用户的**`NFSHomeDirectory`** 属性，这会改变他的家目录路径，因此允许**绕过TCC**。

### **`kTCCServiceSystemPolicyAppBundles`**

允许修改应用程序包内的文件（在app.app内），这通常是**默认不允许**的。

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

可以在_系统设置_ > _隐私与安全_ > _应用管理_中检查谁拥有此访问权限。

### `kTCCServiceAccessibility`

该进程将能够**滥用macOS辅助功能**，这意味着例如它将能够按键。所以它可以请求控制像Finder这样的应用程序，并使用此权限批准对话框。

## 中等

### `com.apple.security.cs.allow-jit`

此权限允许通过向`mmap()`系统函数传递`MAP_JIT`标志来**创建可写且可执行的内存**。查看[**这里了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

此权限允许**覆盖或修补C代码**，使用长期废弃的**`NSCreateObjectFileImageFromMemory`**（本质上不安全），或使用**DVDPlayback**框架。查看[**这里了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory)。

{% hint style="danger" %}
包含此权限会使您的应用程序暴露于内存不安全代码语言中常见的漏洞。仔细考虑您的应用程序是否需要此例外。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

此权限允许**修改其自己可执行文件的部分**以强制退出。查看[**这里了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection)。

{% hint style="danger" %}
禁用可执行内存保护权限是一种极端的权限，它从您的应用程序中移除了一个基本的安全保护，使攻击者有可能在不被检测的情况下重写您的应用程序的可执行代码。如果可能，优先考虑更窄的权限。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

待办

### `com.apple.private.nullfs_allow`

此权限允许挂载nullfs文件系统（默认禁止）。工具：[**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master)。

### `kTCCServiceAll`

根据这篇博客文章，这个TCC权限通常以以下形式出现：
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
允许进程**请求所有TCC权限**。

### **`kTCCServicePostEvent`**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果你在一家**网络安全公司**工作，想在**HackTricks**中看到你的**公司广告**，或者想要获取**PEASS最新版本或下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)。
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**hacktricks repo**](https://github.com/carlospolop/hacktricks)和[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)提交PR，**分享你的黑客技巧**。

</details>
