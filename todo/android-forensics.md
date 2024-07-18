# Android 取证

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

## 锁定设备

要开始从 Android 设备提取数据，设备必须解锁。如果设备被锁定，您可以：

* 检查设备是否已通过 USB 激活调试。
* 检查可能的 [污迹攻击](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
* 尝试 [暴力破解](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## 数据获取

使用 adb 创建 [android 备份](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) 并使用 [Android 备份提取器](https://sourceforge.net/projects/adbextractor/) 提取：`java -jar abe.jar unpack file.backup file.tar`

### 如果有 root 访问或物理连接到 JTAG 接口

* `cat /proc/partitions`（搜索闪存的路径，通常第一个条目是 _mmcblk0_，对应整个闪存）。
* `df /data`（发现系统的块大小）。
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096（使用从块大小收集的信息执行）。

### 内存

使用 Linux 内存提取器 (LiME) 提取 RAM 信息。它是一个应该通过 adb 加载的内核扩展。
