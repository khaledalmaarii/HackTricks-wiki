# iButton

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**吗？或者想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 简介

iButton 是一个通用的电子身份识别钥匙，包装在一个**硬币形状的金属容器**中。它也被称为**达拉斯触摸**存储器或接触存储器。尽管它经常被错误地称为“磁性”钥匙，但实际上它里面没有**任何磁性**。事实上，隐藏在里面的是一个完整的**微芯片**，它运行在数字协议上。

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### 什么是 iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常，iButton 指的是钥匙和读卡器的物理形式 - 一个带有两个接触点的圆形硬币。对于围绕它的框架，有很多变种，从最常见的带有孔的塑料支架到戒指、吊坠等。

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

当钥匙到达读卡器时，**接触点接触**，钥匙被供电以**传输**其 ID。有时候钥匙**不能立即读取**，因为**对讲机的接触 PSD 大于**它应该有的大小。所以钥匙的外轮廓和读卡器的外轮廓不能接触。如果是这种情况，你将不得不将钥匙按在读卡器的墙壁之一上。

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **1-Wire 协议** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

达拉斯钥匙使用 1-Wire 协议进行数据交换。在双向数据传输中，只有一个用于数据传输的接触点（!!），从主设备到从设备以及反之。1-Wire 协议按照主从模型工作。在这种拓扑结构中，主设备始终发起通信，从设备则遵循其指令。

当钥匙（从设备）与对讲机（主设备）接触时，钥匙内部的芯片被打开，由对讲机供电，并初始化钥匙。随后，对讲机请求钥匙的 ID。接下来，我们将更详细地了解这个过程。

Flipper 可以同时在主设备和从设备模式下工作。在读取钥匙模式下，Flipper 作为读卡器工作，也就是说它作为主设备工作。而在钥匙仿真模式下，Flipper 假装成为一个钥匙，它处于从设备模式。

### 达拉斯、Cyfral 和 Metakom 钥匙

有关这些钥匙的工作原理的信息，请查看页面[https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### 攻击

iButton 可以使用 Flipper Zero 进行攻击：

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## 参考资料

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**吗？或者想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
