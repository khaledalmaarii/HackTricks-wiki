# macOS Apple 脚本

<details>

<summary><strong>从零到英雄学习 AWS 黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧。

</details>

## Apple 脚本

这是一种用于任务自动化的脚本语言，**与远程进程交互**。它使得**请求其他进程执行某些操作**变得非常容易。**恶意软件**可能会滥用这些功能来滥用其他进程导出的函数。\
例如，恶意软件可以**在浏览器打开的页面中注入任意 JS 代码**。或者**自动点击**请求用户允许的一些权限；
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
以下是一些示例：[https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
有关使用applescripts的恶意软件的更多信息请点击[**这里**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)。

Apple 脚本可以很容易地被“**编译**”。这些版本可以通过 `osadecompile` 轻松“**反编译**”。

然而，这些脚本也可以通过“导出...”选项以“**只读**”形式**导出**：

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
```markdown
即使使用 `osadecompile` 也无法反编译此类内容。

然而，仍有一些工具可以用来理解这类可执行文件，[**阅读此研究以获取更多信息**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/))。工具 [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) 和 [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) 将非常有助于理解脚本的工作原理。

<details>

<summary><strong>从零到英雄学习 AWS 黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。**

</details>
```
