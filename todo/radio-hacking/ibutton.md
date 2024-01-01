# iButton

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 简介

iButton是一个电子识别钥匙的通用名称，它被封装在一个**硬币形状的金属容器**中。它也被称为**Dallas Touch** Memory或接触记忆。尽管它经常被错误地称为“磁性”钥匙，但实际上它里面**没有磁性**成分。事实上，里面隐藏着一个基于数字协议运作的完整**微芯片**。

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### 什么是iButton？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常，iButton指的是钥匙和读卡器的物理形态——一个带有两个触点的圆形硬币。对于围绕它的框架，有很多变体，从最常见的带孔塑料支架到戒指、吊坠等。

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

当钥匙接触到读卡器时，**触点接触**，钥匙被激活以**传输**其ID。有时钥匙**不会立即被读取**，因为对讲机的**接触PSD比应有的大**。所以钥匙和读卡器的外轮廓不能接触。如果是这种情况，您将不得不将钥匙按在读卡器的一面上。

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **1-Wire协议** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Dallas钥匙使用1-Wire协议交换数据。只有一个用于数据传输(!!)的触点，方向从主设备到从设备，反之亦然。1-Wire协议根据主从模型工作。在这种拓扑结构中，主设备总是发起通信，从设备遵循其指令。

当钥匙（从设备）接触到对讲机（主设备）时，钥匙内的芯片被对讲机激活，并初始化钥匙。接着对讲机请求钥匙ID。接下来，我们将更详细地查看这个过程。

Flipper可以以主设备和从设备模式工作。在读取钥匙模式下，Flipper充当读卡器，即它作为主设备。而在钥匙模拟模式下，flipper假装是一把钥匙，它处于从设备模式。

### Dallas, Cyfral & Metakom钥匙

有关这些钥匙如何工作的信息，请查看页面 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### 攻击

可以使用Flipper Zero攻击iButtons：

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## 参考资料

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
