# Android 取证

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

## 锁定设备

要开始从 Android 设备提取数据，设备必须是解锁状态。如果设备被锁定，您可以：

* 检查设备是否激活了 USB 调试。
* 检查可能的[污迹攻击](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
* 尝试使用[暴力破解](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## 数据获取

使用 adb 创建[android 备份](mobile-pentesting/android-app-pentesting/adb-commands.md#backup)并使用 [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) 提取：`java -jar abe.jar unpack file.backup file.tar`

### 如果有 root 权限或物理连接到 JTAG 接口

* `cat /proc/partitions`（搜索闪存的路径，通常第一个条目是 _mmcblk0_，对应整个闪存）。
* `df /data`（发现系统的块大小）。
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096（使用从块大小收集的信息执行）。

### 内存

使用 Linux Memory Extractor (LiME) 提取 RAM 信息。它是一个内核扩展，应通过 adb 加载。

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
