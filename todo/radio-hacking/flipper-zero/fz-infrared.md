# FZ - 红外线

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要在HackTricks中看到您的**公司广告**？ 或者想要访问**PEASS的最新版本或下载HackTricks的PDF**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上**关注**我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR**来分享您的黑客技巧。

</details>

## 简介 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

有关红外线如何工作的更多信息，请查看：

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zero中的红外信号接收器 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper使用数字红外信号接收器TSOP，**允许拦截来自红外遥控器的信号**。 有一些**智能手机**，如小米，也有红外端口，但请注意，**大多数只能发送**信号，无法接收。

Flipper的红外**接收器非常敏感**。 即使保持在遥控器和电视之间的某个位置，也可以**捕捉到信号**。 将遥控器直接对准Flipper的红外端口是不必要的。 当有人站在电视附近换台时，您和Flipper都相距一段距离时，这将很方便。

由于红外信号的**解码**发生在**软件**端，Flipper Zero可能支持**接收和传输任何红外遥控器代码**。 对于**无法识别**的协议，它会**记录并回放**接收到的原始信号。

## 操作

### 通用遥控器

Flipper Zero可以用作**通用遥控器来控制任何电视，空调或媒体中心**。 在此模式下，Flipper会**暴力破解**所有支持制造商的所有已知代码**，根据SD卡中的字典**。 您无需选择特定的遥控器来关闭餐厅的电视。

在通用遥控器模式下，只需按下电源按钮，Flipper将**顺序发送“关闭电源”**命令给它所知道的所有电视：索尼，三星，松下...等等。 当电视接收到信号时，它将做出反应并关闭。

这种暴力破解需要时间。 字典越大，完成所需的时间就越长。 由于电视没有反馈，无法找出电视确切识别的信号。

### 学习新遥控器

可以使用Flipper Zero**捕获红外信号**。 如果它在数据库中**找到信号**，Flipper将自动**知道这是哪个设备**，并允许您与其交互。\
如果没有找到，Flipper可以**存储**该**信号**，并允许您**重放**它。

## 参考

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
