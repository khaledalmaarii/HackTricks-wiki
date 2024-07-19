# macOS Apple Scripts

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Apple Scripts

这是一种用于任务自动化的脚本语言，**与远程进程交互**。它使得**请求其他进程执行某些操作**变得相当简单。**恶意软件**可能会滥用这些功能，以利用其他进程导出的功能。\
例如，恶意软件可以**在浏览器打开的页面中注入任意的JS代码**。或者**自动点击**用户请求的某些允许权限；
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
这里有一些示例: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
有关使用苹果脚本的恶意软件的更多信息 [**在这里**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)。

苹果脚本可以很容易地 "**编译**"。这些版本可以通过 `osadecompile` 很容易地 "**反编译**"。

然而，这些脚本也可以 **导出为“只读”**（通过“导出...”选项）：

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
在这种情况下，即使使用 `osadecompile` 也无法反编译内容。

然而，仍然有一些工具可以用来理解这种可执行文件，[**阅读这项研究以获取更多信息**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)。工具 [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) 和 [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) 将非常有助于理解脚本的工作原理。

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
