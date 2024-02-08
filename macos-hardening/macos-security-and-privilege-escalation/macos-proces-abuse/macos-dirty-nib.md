# macOS Dirty NIB

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

**有关该技术的更多详细信息，请查看原始帖子：[https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)。**以下是摘要：

NIB文件是苹果开发生态系统的一部分，用于定义应用程序中的**UI元素**及其交互。它们包含诸如窗口和按钮之类的序列化对象，并在运行时加载。尽管它们仍在使用中，但苹果现在倡导使用Storyboards来更全面地可视化UI流程。

### NIB文件的安全问题
需要注意的是**NIB文件可能存在安全风险**。它们有可能**执行任意命令**，而对应用程序中NIB文件的更改不会阻止Gatekeeper执行该应用程序，构成重大威胁。

### Dirty NIB注入过程
#### 创建和设置NIB文件
1. **初始设置**：
- 使用XCode创建一个新的NIB文件。
- 向界面添加一个对象，并将其类设置为`NSAppleScript`。
- 通过用户定义的运行时属性配置初始`source`属性。

2. **代码执行小工具**：
- 该设置便于按需运行AppleScript。
- 集成一个按钮来激活`Apple Script`对象，特别触发`executeAndReturnError:`选择器。

3. **测试**：
- 用于测试目的的简单Apple Script：
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- 在XCode调试器中运行并单击按钮进行测试。

#### 针对应用程序的攻击（示例：Pages）
1. **准备**：
- 将目标应用程序（例如Pages）复制到一个单独的目录中（例如`/tmp/`）。
- 启动应用程序以规避Gatekeeper问题并缓存它。

2. **覆盖NIB文件**：
- 用精心制作的DirtyNIB文件替换现有的NIB文件（例如About Panel NIB）。

3. **执行**：
- 通过与应用程序交互（例如选择`About`菜单项）来触发执行。

#### 概念验证：访问用户数据
- 修改AppleScript以访问和提取用户数据，例如照片，而无需用户同意。

### 代码示例：恶意.xib文件
- 访问并查看一个[**恶意.xib文件的示例**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)，演示执行任意代码。

### 处理启动约束
- 启动约束阻止应用程序从意外位置（例如`/tmp`）执行。
- 可以识别未受启动约束保护的应用程序，并针对它们进行NIB文件注入。

### 其他macOS保护措施
从macOS Sonoma开始，限制了App捆绑包内部的修改。但是，早期的方法涉及：
1. 将应用程序复制到不同位置（例如`/tmp/`）。
2. 重命名应用程序捆绑包中的目录以绕过初始保护。
3. 运行应用程序以向Gatekeeper注册后，修改应用程序捆绑包（例如用Dirty.nib替换MainMenu.nib）。
4. 将目录重新命名并重新运行应用程序以执行注入的NIB文件。

**注意**：最近的macOS更新通过防止Gatekeeper缓存后的应用程序捆绑包内文件修改来减轻了此漏洞，使其失效。
