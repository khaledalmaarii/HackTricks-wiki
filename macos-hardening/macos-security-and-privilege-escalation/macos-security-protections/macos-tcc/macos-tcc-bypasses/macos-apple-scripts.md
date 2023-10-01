# macOS苹果脚本

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 苹果脚本

这是一种用于任务自动化的脚本语言，用于与远程进程进行交互。它可以很容易地**请求其他进程执行某些操作**。**恶意软件**可能会滥用这些功能来滥用其他进程导出的函数。\
例如，恶意软件可以**在打开的浏览器页面中注入任意的JS代码**。或者**自动点击**用户请求的某些权限。
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
以下是一些示例：[https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
在[**这里**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)可以找到有关使用AppleScript进行恶意软件攻击的更多信息。

Apple脚本可以很容易地进行“**编译**”。这些版本可以使用`osadecompile`轻松地进行“**反编译**”。

然而，这些脚本也可以导出为“只读”（通过“导出...”选项）：

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
在这种情况下，即使使用`osadecompile`也无法反编译内容。

然而，仍然有一些工具可以用来理解这种可执行文件，[**阅读此研究以获取更多信息**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)。工具[**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler)和[**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile)将非常有用，以了解脚本的工作原理。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
