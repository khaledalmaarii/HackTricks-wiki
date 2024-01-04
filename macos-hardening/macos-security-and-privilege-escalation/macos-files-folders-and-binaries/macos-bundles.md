# macOS Bundles

<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

基本上，bundle是文件系统内的**目录结构**。有趣的是，默认情况下，这个目录在Finder中**看起来像一个单一对象**。

我们经常遇到的**常见**bundle是**`.app` bundle**，但许多其他可执行文件也被打包成bundle，例如**`.framework`** 和 **`.systemextension`** 或 **`.kext`**。

bundle内包含的资源类型可能包括应用程序、库、图像、文档、头文件等。所有这些文件都在 `<application>.app/Contents/` 内。
```bash
ls -lR /Applications/Safari.app/Contents
```
* `Contents/_CodeSignature` -> 包含应用程序的**代码签名信息**（例如，哈希等）。
* `openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64`
* `Contents/MacOS` -> 包含**应用程序的二进制文件**（当用户在UI中双击应用程序图标时执行）。
* `Contents/Resources` -> 包含应用程序的**UI元素**，如图片、文档和nib/xib文件（描述各种用户界面）。
* `Contents/Info.plist` -> 应用程序的主要“**配置文件**”。苹果指出，“系统依赖于此文件的存在来识别有关\[应用程序\]及任何相关文件的信息”。
* **Plist文件**包含配置信息。您可以在[https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)找到有关plist键含义的信息。
*   在分析应用程序时可能感兴趣的键值对包括：

* **CFBundleExecutable**

包含**应用程序二进制文件的名称**（位于Contents/MacOS中）。

* **CFBundleIdentifier**

包含应用程序的捆绑标识符（系统经常用它来**全局** **识别**应用程序）。

* **LSMinimumSystemVersion**

包含应用程序兼容的**最旧**的**macOS**版本。

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
