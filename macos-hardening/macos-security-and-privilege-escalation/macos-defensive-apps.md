# macOS 防御应用程序

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 防火墙

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html)：它会监控每个进程所建立的连接。根据模式（静默允许连接、静默拒绝连接和警报），每当建立新连接时，它都会**显示警报**。它还有一个非常好的图形界面，可以查看所有这些信息。
* [**LuLu**](https://objective-see.org/products/lulu.html)：Objective-See 防火墙。这是一个基本的防火墙，会对可疑连接发出警报（它有一个图形界面，但不像 Little Snitch 那样花哨）。

## 持久化检测

* [**KnockKnock**](https://objective-see.org/products/knockknock.html)：Objective-See 应用程序，将搜索可能存在**恶意软件持久化**的几个位置（它是一个一次性工具，不是监控服务）。
* [**BlockBlock**](https://objective-see.org/products/blockblock.html)：通过监控生成持久化的进程，类似于 KnockKnock。

## 键盘记录器检测

* [**ReiKey**](https://objective-see.org/products/reikey.html)：Objective-See 应用程序，用于查找安装键盘“事件捕捉”的**键盘记录器**。

## 勒索软件检测

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html)：Objective-See 应用程序，用于检测**文件加密**操作。

## 麦克风和摄像头检测

* [**OverSight**](https://objective-see.org/products/oversight.html)：Objective-See 应用程序，用于检测**使用摄像头和麦克风的应用程序**。

## 进程注入检测

* [**Shield**](https://theevilbit.github.io/shield/)：应用程序，**检测不同的进程注入**技术。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
