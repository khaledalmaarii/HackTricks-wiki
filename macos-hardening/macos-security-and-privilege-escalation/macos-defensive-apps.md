# macOS 防御应用

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在 Twitter 上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## 防火墙

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html)：它将监控每个进程所建立的每个连接。根据模式（静默允许连接、静默拒绝连接和警报），每当建立新连接时，它将**向您显示警报**。它还有一个非常好的 GUI 来查看所有这些信息。
* [**LuLu**](https://objective-see.org/products/lulu.html)：Objective-See 防火墙。这是一个基本的防火墙，会对可疑连接发出警报（它有一个 GUI，但没有 Little Snitch 的那么花哨）。

## 持久性检测

* [**KnockKnock**](https://objective-see.org/products/knockknock.html)：Objective-See 应用程序，将在多个位置搜索 **恶意软件可能存在的地方**（这是一个一次性工具，而不是监控服务）。
* [**BlockBlock**](https://objective-see.org/products/blockblock.html)：像 KnockKnock 一样，通过监控生成持久性的进程。

## 键盘记录器检测

* [**ReiKey**](https://objective-see.org/products/reikey.html)：Objective-See 应用程序，用于查找安装键盘“事件捕获”的 **键盘记录器**。
