# macOS 危险权限 & TCC 权限

<details>

<summary><strong>从零到英雄学习 AWS 黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

{% hint style="warning" %}
请注意，以 **`com.apple`** 开头的权限不向第三方开放，只有 Apple 可以授予它们。
{% endhint %}

## 高危

### `com.apple.rootless.install.heritable`

权限 **`com.apple.rootless.install.heritable`** 允许**绕过 SIP**。查看[此处了解更多信息](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

权限 **`com.apple.rootless.install`** 允许**绕过 SIP**。查看[此处了解更多信息](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports`（之前称为 `task_for_pid-allow`）**

此权限允许获取**任何**进程的**任务端口**，除了内核。查看[**此处了解更多信息**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.get-task-allow`

此权限允许拥有 **`com.apple.security.cs.debugger`** 权限的其他进程获取此权限二进制文件运行的进程的任务端口，并**注入代码**。查看[**此处了解更多信息**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.cs.debugger`

拥有调试工具权限的应用可以调用 `task_for_pid()` 来检索未签名和第三方应用的有效任务端口，这些应用设置了 `Get Task Allow` 权限为 `true`。然而，即使拥有调试工具权限，调试器**无法获取**没有 `Get Task Allow` 权限的进程的任务端口，因此受到系统完整性保护的保护。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)。

### `com.apple.security.cs.disable-library-validation`

此权限允许**加载框架、插件或库，而无需由 Apple 签名或与主执行文件具有相同的团队 ID 签名**，因此攻击者可以滥用某些任意库加载来注入代码。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)。

### `com.apple.private.security.clear-library-validation`

此权限与 **`com.apple.security.cs.disable-library-validation`** 非常相似，但**不是**直接**禁用**库验证，而是允许进程**调用 `csops` 系统调用来禁用它**。\
查看[**此处了解更多信息**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)。

### `com.apple.security.cs.allow-dyld-environment-variables`

此权限允许**使用 DYLD 环境变量**，这些变量可以用来注入库和代码。查看[**此处了解更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)。

### `com.apple.private.tcc.manager` 或 `com.apple.rootless.storage`.`TCC`

[**根据这篇博客**](https://objective-see.org/blog/blog_0x4C.html) **和** [**这篇博客**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)，这些权限允许**修改** **TCC** 数据库。

### **`system.install.apple-software`** 和 **`system.install.apple-software.standar-user`**

这些权限允许**安装软件而不需要向用户请求权限**，这对于**权限提升**可能很有帮助。

### `com.apple.private.security.kext-management`

需要此权限才能请求**内核加载内核扩展**。

### **`com.apple.private.icloud-account-access`**

拥有 **`com.apple.private.icloud-account-access`** 权限的话，可以与 **`com.apple.iCloudHelper`** XPC 服务通信，它将**提供 iCloud 令牌**。

**iMovie** 和 **Garageband** 拥有此权限。

有关利用该权限**获取 icloud 令牌**的漏洞的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

待办事项：我不知道这允许做什么

### `com.apple.private.apfs.revert-to-snapshot`

待办事项：在[**这份报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)中提到，这可以用来在重启后更新受 SSV 保护的内容。如果您知道如何操作，请提交 PR！

### `com.apple.private.apfs.create-sealed-snapshot`

待办事项：在[**这份报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)中提到，这可以用来在重启后更新受 SSV 保护的内容。如果您知道如何操作，请提交 PR！

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

允许应用程序向其他通常用于**自动执行任务**的应用程序发送事件。通过控制其他应用程序，它可以滥用这些应用程序被授予的权限。

比如让它们向用户请求密码：

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

或使它们执行**任意操作**。

### **`kTCCServiceEndpointSecurityClient`**

允许包括其他权限在内的**写入用户的TCC数据库**。

### **`kTCCServiceSystemPolicySysAdminFiles`**

允许**更改**用户的**`NFSHomeDirectory`** 属性，这会改变他的家目录路径，因此允许**绕过TCC**。

### **`kTCCServiceSystemPolicyAppBundles`**

允许修改应用程序包内的文件（在app.app内），这通常是**默认不允许**的。

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

可以在_系统设置_ > _隐私与安全_ > _应用管理_中检查谁拥有此访问权限。

### `kTCCServiceAccessibility`

该进程将能够**滥用macOS辅助功能**，这意味着例如它将能够按键。因此，它可以请求控制像Finder这样的应用程序，并使用此权限批准对话框。

## 中等

### `com.apple.security.cs.allow-jit`

此权限允许通过向`mmap()`系统函数传递`MAP_JIT`标志来**创建可写且可执行的内存**。查看[**这里获取更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

此权限允许**覆盖或修补C代码**，使用长期废弃的**`NSCreateObjectFileImageFromMemory`**（本质上不安全），或使用**DVDPlayback**框架。查看[**这里获取更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)。

{% hint style="danger" %}
包含此权限会使您的应用程序暴露于内存不安全代码语言中常见的漏洞。仔细考虑您的应用程序是否需要此例外。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

此权限允许**修改其自己可执行文件的部分**以强制退出。查看[**这里获取更多信息**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)。

{% hint style="danger" %}
禁用可执行内存保护权限是一个极端的权限，它从您的应用程序中移除了一个基本的安全保护，使攻击者有可能在不被检测的情况下重写您的应用程序的可执行代码。如果可能，优先考虑更窄的权限。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

待办

### `com.apple.private.nullfs_allow`

此权限允许挂载nullfs文件系统（默认禁止）。工具：[**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)。

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

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
