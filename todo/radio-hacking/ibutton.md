# iButton

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

## 介绍

iButton 是一种通用名称，指的是装在 **硬币形金属容器** 中的电子识别钥匙。它也被称为 **Dallas Touch** Memory 或接触式存储器。尽管它常常被错误地称为“磁性”钥匙，但它里面 **没有任何磁性**。实际上，里面隐藏着一个完整的 **微芯片**，它在数字协议上运行。

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### 什么是 iButton？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常，iButton 指的是钥匙和读卡器的物理形式 - 一个带有两个接触点的圆形硬币。围绕它的框架有很多变体，从最常见的带孔塑料支架到戒指、挂件等。

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

当钥匙接触到读卡器时，**接触点接触**，钥匙被供电以 **传输** 其 ID。有时钥匙不会立即被 **读取**，因为 **对讲机的接触 PSD 比应有的要大**。因此，钥匙和读卡器的外部轮廓无法接触。如果是这种情况，您需要将钥匙按在读卡器的一个墙面上。

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire 协议** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas 钥匙使用 1-wire 协议交换数据。仅用一个接触点进行数据传输 (!!)，双向传输，从主设备到从设备，反之亦然。1-wire 协议按照主从模型工作。在这种拓扑中，主设备始终发起通信，从设备遵循其指令。

当钥匙（从设备）接触到对讲机（主设备）时，钥匙内部的芯片开启，由对讲机供电，钥匙被初始化。随后，对讲机请求钥匙 ID。接下来，我们将更详细地查看这个过程。

Flipper 可以在主模式和从模式下工作。在钥匙读取模式下，Flipper 充当读卡器，也就是说它作为主设备工作。在钥匙仿真模式下，Flipper 假装是钥匙，处于从设备模式。

### Dallas、Cyfral 和 Metakom 钥匙

有关这些钥匙如何工作的更多信息，请查看页面 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### 攻击

iButtons 可以通过 Flipper Zero 进行攻击：

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## 参考

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
