# FZ - 红外线

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

## 介绍 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

有关红外线工作原理的更多信息，请查看：

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zero 中的红外信号接收器 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper 使用数字红外信号接收器 TSOP，**可以拦截红外遥控器的信号**。有些 **智能手机** 如小米也有红外端口，但请记住，**大多数只能发送** 信号，**无法接收**。

Flipper 的红外 **接收器非常灵敏**。您甚至可以在遥控器和电视之间的某个地方 **捕捉信号**。将遥控器直接指向 Flipper 的红外端口并不是必需的。这在某人站在电视附近切换频道时非常方便，而您和 Flipper 之间有一定距离。

由于 **红外信号的解码** 在 **软件** 端进行，Flipper Zero 潜在支持 **接收和发送任何红外遥控代码**。对于 **未知** 协议无法识别的情况，它会 **记录并回放** 原始信号，完全按照接收到的内容。

## 操作

### 通用遥控器

Flipper Zero 可以作为 **通用遥控器控制任何电视、空调或媒体中心**。在此模式下，Flipper **暴力破解** 所有支持制造商的 **已知代码**，**根据 SD 卡中的字典**。您无需选择特定的遥控器来关闭餐厅的电视。

只需在通用遥控器模式下按下电源按钮，Flipper 将 **依次发送所有已知电视的“关机”** 命令：索尼、三星、松下……等等。当电视接收到信号时，它将做出反应并关闭。

这种暴力破解需要时间。字典越大，完成所需的时间就越长。无法确定电视确切识别了哪个信号，因为电视没有反馈。

### 学习新遥控器

可以使用 Flipper Zero **捕获红外信号**。如果它 **在数据库中找到信号**，Flipper 将自动 **知道这是哪个设备** 并允许您与之交互。\
如果没有，Flipper 可以 **存储** 该 **信号** 并允许您 **重放** 它。

## 参考

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
