# FZ - 红外线

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**吗？或者想要**获取 PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注**我在**推特**上的 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 简介 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

有关红外线的工作原理的更多信息，请查看：

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zero 中的红外线信号接收器 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper 使用数字红外线信号接收器 TSOP，它**允许拦截来自红外线遥控器的信号**。有一些**智能手机**，如小米，也有红外线端口，但请记住，**大多数智能手机只能发送**信号，**无法接收**信号。

Flipper 的红外线接收器非常敏感。即使你站在遥控器和电视之间的某个地方，你也可以**捕捉到信号**。不需要直接将遥控器对准 Flipper 的红外线端口。当有人站在电视旁边切换频道时，你和 Flipper 都可以离电视有一段距离。

由于红外线信号的解码发生在**软件**端，Flipper Zero 可能支持**接收和发送任何红外线遥控器代码**。对于**无法识别**的协议，它会**记录并回放**接收到的原始信号。

## 操作

### 通用遥控器

Flipper Zero 可以用作**通用遥控器，控制任何电视、空调或媒体中心**。在此模式下，Flipper 会根据 SD 卡中的字典**暴力破解**所有支持的制造商的**已知代码**。你不需要选择特定的遥控器来关闭餐厅的电视。

只需在通用遥控器模式下按下电源按钮，Flipper 将**顺序发送“关闭电源”**命令给它所知道的所有电视：索尼、三星、松下...等等。当电视接收到它的信号时，它会做出反应并关闭。

这种暴力破解需要时间。字典越大，完成所需的时间就越长。由于电视没有反馈，无法确定电视确切识别了哪个信号。

### 学习新遥控器

可以使用 Flipper Zero **捕捉红外线信号**。如果 Flipper 在数据库中**找到该信号**，它将自动**知道这是哪个设备**并允许你与之交互。\
如果没有找到，Flipper 可以**存储**该**信号**，并允许你**重放**它。

## 参考资料

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**吗？或者想要**获取 PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注**我在**推特**上的 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
