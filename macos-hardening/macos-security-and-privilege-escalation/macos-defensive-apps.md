# macOS 防御应用程序

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 PDF 版的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) 上**关注**我们。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

## 防火墙

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html)：它将监视每个进程所建立的每个连接。根据模式（静默允许连接、静默拒绝连接和警报），每次建立新连接时都会**向您显示警报**。它还有一个非常好的 GUI 来查看所有这些信息。
* [**LuLu**](https://objective-see.org/products/lulu.html)：Objective-See 防火墙。这是一个基本防火墙，会为可疑连接提供警报（它有 GUI，但不像 Little Snitch 那样花哨）。

## 持久性检测

* [**KnockKnock**](https://objective-see.org/products/knockknock.html)：Objective-See 应用程序，将搜索**恶意软件可能持续存在的**几个位置（这是一个一次性工具，不是监控服务）。
* [**BlockBlock**](https://objective-see.org/products/blockblock.html)：通过监视生成持久性的进程，类似于 KnockKnock。

## 键盘记录检测

* [**ReiKey**](https://objective-see.org/products/reikey.html)：Objective-See 应用程序，用于查找安装键盘“事件捕捉”的**键盘记录器**。

## 勒索软件检测

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html)：Objective-See 应用程序，用于检测**文件加密**操作。

## 麦克风和摄像头检测

* [**OverSight**](https://objective-see.org/products/oversight.html)：Objective-See 应用程序，用于检测**启动使用摄像头和麦克风的应用程序**。

## 进程注入检测

* [**Shield**](https://theevilbit.github.io/shield/)：检测不同**进程注入**技术的应用程序。
