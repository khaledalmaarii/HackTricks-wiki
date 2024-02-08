# FZ - 红外线

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要看到你的**公司在HackTricks中被宣传**吗？或者想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**上关注**我。

* 通过向**hacktricks仓库**和**hacktricks-cloud仓库**提交PR来分享你的黑客技巧。

</details>

## 简介 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

有关红外线如何工作的更多信息，请查看：

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zero中的红外线信号接收器 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper使用数字红外线信号接收器TSOP，**允许拦截来自红外线遥控器的信号**。有一些**智能手机**，如小米，也有红外端口，但请注意，**大多数只能发送**信号，无法接收。

Flipper的红外线**接收器非常敏感**。即使保持在遥控器和电视机之间的某个位置，也可以**捕捉到信号**。将遥控器直接对准Flipper的红外端口是不必要的。当有人站在电视机附近换台时，你和Flipper都相距一段距离，这将非常方便。

由于红外信号的解码发生在**软件**端，Flipper Zero可能支持**接收和传输任何红外遥控器代码**。对于**无法识别**的协议，它会**记录并回放**接收到的原始信号。

## 操作

### 通用遥控器

Flipper Zero可以用作**通用遥控器来控制任何电视、空调或媒体中心**。在此模式下，Flipper会**暴力破解**所有支持制造商的所有已知代码，**根据SD卡中的字典**。你不需要选择特定的遥控器来关闭餐厅的电视。

在通用遥控器模式下，只需按下电源按钮，Flipper将**顺序发送“关闭电源”**命令给它所知道的所有电视：索尼、三星、松下...等等。当电视接收到信号时，它会做出反应并关闭。

这种暴力破解需要时间。字典越大，完成所需的时间就越长。由于电视没有反馈，无法找出电视确切识别的信号。

### 学习新遥控器

可以使用Flipper Zero**捕获红外信号**。如果在数据库中**找到信号**，Flipper将自动**知道这是哪个设备**，并允许你与之交互。\
如果没有找到，Flipper可以**存储**该**信号**，并允许你**重放**它。

## 参考

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/) 

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要看到你的**公司在HackTricks中被宣传**吗？或者想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**上关注**我。

* 通过向**hacktricks仓库**和**hacktricks-cloud仓库**提交PR来分享你的黑客技巧。

</details>
