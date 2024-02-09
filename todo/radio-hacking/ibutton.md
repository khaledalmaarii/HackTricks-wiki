# iButton

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中被广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 简介

iButton是一个电子识别钥匙的通用名称，包装在一个**硬币形状的金属容器**中。它也被称为**达拉斯触摸**存储器或接触存储器。尽管它经常被错误地称为“磁性”钥匙，但实际上里面**没有磁性**。事实上，里面隐藏着一个完整的**微芯片**，运行在数字协议上。

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### 什么是iButton？<a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常，iButton意味着钥匙和读卡器的物理形式 - 一个圆形硬币带有两个接触点。对于围绕它的框架，有许多变体，从最常见的带有孔的塑料支架到戒指、吊坠等。

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

当钥匙到达读卡器时，**接触点接触**，钥匙被供电以**传输**其ID。有时，钥匙**不能立即读取**，因为**对讲机的接触PSD比应该的大**。因此，钥匙和读卡器的外轮廓无法接触。如果是这种情况，您将不得不将钥匙按在读卡器的墙壁之一上。

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **1-Wire协议**<a href="#1-wire-protocol" id="1-wire-protocol"></a>

达拉斯钥匙使用1-Wire协议交换数据。只有一个用于数据传输的接触点（！！）在主从两个方向上，从主设备到从设备，反之亦然。1-Wire协议按照主从模型工作。在这种拓扑结构中，主设备始终发起通信，从设备遵循其指令。

当钥匙（从设备）接触对讲机（主设备）时，钥匙内部的芯片打开，由对讲机供电，钥匙被初始化。随后，对讲机请求钥匙ID。接下来，我们将更详细地查看这个过程。

Flipper可以在主从模式下工作。在钥匙读取模式下，Flipper充当读卡器，也就是说它作为主设备工作。在钥匙仿真模式下，Flipper假装是一个钥匙，它处于从设备模式。

### 达拉斯、Cyfral和Metakom钥匙

有关这些钥匙如何工作的信息，请查看页面[https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### 攻击

iButton可以使用Flipper Zero进行攻击：

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## 参考资料

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)
