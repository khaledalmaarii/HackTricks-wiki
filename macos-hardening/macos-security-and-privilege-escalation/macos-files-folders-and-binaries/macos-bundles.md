# macOS捆绑包

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

macOS中的捆绑包用作各种资源（包括应用程序、库和其他必要文件）的容器，使它们在Finder中显示为单个对象，例如熟悉的`*.app`文件。最常见的捆绑包是`.app`捆绑包，但其他类型如`.framework`、`.systemextension`和`.kext`也很常见。

### 捆绑包的基本组件

在捆绑包中，特别是在`<application>.app/Contents/`目录中，存放着各种重要资源：

- **_CodeSignature**：此目录存储了验证应用程序完整性所必需的代码签名详细信息。您可以使用以下命令检查代码签名信息：
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**：包含应用程序的可执行二进制文件，用户交互时运行。
- **Resources**：存储应用程序的用户界面组件，包括图像、文档和界面描述（nib/xib文件）。
- **Info.plist**：作为应用程序的主要配置文件，对于系统识别和与应用程序交互至关重要。

#### Info.plist中的重要键

`Info.plist`文件是应用程序配置的基石，包含诸如以下键的内容：

- **CFBundleExecutable**：指定位于`Contents/MacOS`目录中的主可执行文件的名称。
- **CFBundleIdentifier**：为应用程序提供全局标识符，macOS广泛使用它进行应用程序管理。
- **LSMinimumSystemVersion**：指示应用程序运行所需的macOS最低版本。

### 探索捆绑包

要探索捆绑包的内容，例如`Safari.app`，可以使用以下命令：
```bash
ls -lR /Applications/Safari.app/Contents
```

此探索会显示诸如`_CodeSignature`、`MacOS`、`Resources`等目录，以及诸如`Info.plist`等文件，每个都具有从保护应用程序到定义其用户界面和操作参数的独特目的。

#### 其他捆绑包目录

除了常见目录外，捆绑包还可能包括：

- **Frameworks**：包含应用程序使用的捆绑框架。
- **PlugIns**：用于增强应用程序功能的插件和扩展的目录。
- **XPCServices**：保存应用程序用于进程间通信的XPC服务。

这种结构确保了所有必要组件都封装在捆绑包中，促进了模块化和安全的应用程序环境。

有关`Info.plist`键及其含义的更详细信息，苹果开发者文档提供了广泛的资源：[Apple Info.plist键参考](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)。

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
