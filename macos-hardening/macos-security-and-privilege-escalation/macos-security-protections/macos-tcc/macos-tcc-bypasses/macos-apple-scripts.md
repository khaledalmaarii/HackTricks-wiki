# macOS苹果脚本

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 苹果脚本

这是一种用于任务自动化的脚本语言，**与远程进程进行交互**。它可以很容易地**要求其他进程执行某些操作**。**恶意软件**可能会滥用这些功能来滥用其他进程导出的功能。\
例如，恶意软件可以**在打开的浏览器页面中注入任意JS代码**。或者**自动点击**用户请求的权限允许。
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
以下是一些示例：[https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
查找有关使用AppleScripts的恶意软件的更多信息[**在这里**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)。

Apple脚本可能很容易被“**编译**”。这些版本可以很容易地通过`osadecompile`进行“**反编译**”。

然而，这些脚本也可以被导出为“只读”（通过“导出...”选项）：

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
在这种情况下，即使使用 `osadecompile` 也无法反编译内容。

然而，仍然有一些工具可以用来理解这种可执行文件，[**阅读此研究以获取更多信息**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)。工具 [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) 与 [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) 将非常有用，以了解脚本的工作原理。

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的 **公司在 HackTricks 中被广告** 或 **下载 PDF 版本的 HackTricks**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向 **HackTricks** 和 **HackTricks Cloud** github 仓库提交 PR 来 **分享您的黑客技巧**。

</details>
