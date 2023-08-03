# 红外线

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 红外线的工作原理 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**红外线对人类是不可见的**。红外线波长范围为**0.7到1000微米**。家用遥控器使用红外信号进行数据传输，工作在0.75到1.4微米的波长范围内。遥控器中的微控制器通过特定频率使红外LED闪烁，将数字信号转换为红外信号。

接收红外信号使用**光电接收器**。它将红外光转换为电压脉冲，这些脉冲已经是**数字信号**。通常，接收器内部有一个**暗光滤波器**，只允许所需波长通过，并消除噪声。

### 多种红外协议 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

红外协议在以下三个因素上有所不同：

* 位编码
* 数据结构
* 载波频率 - 通常在36到38 kHz范围内

#### 位编码方式 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. 脉冲距离编码**

通过调制脉冲之间的间隔持续时间来编码位。脉冲本身的宽度是恒定的。

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. 脉冲宽度编码**

通过调制脉冲宽度来编码位。脉冲爆发后的间隔宽度是恒定的。

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. 相位编码**

也称为曼彻斯特编码。逻辑值由脉冲爆发和间隔之间的极性转换来定义。 "间隔到脉冲爆发"表示逻辑 "0"，"脉冲爆发到间隔"表示逻辑 "1"。

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. 结合前面的编码方式和其他特殊编码方式**

{% hint style="info" %}
有些红外协议试图成为适用于多种设备的**通用协议**。最著名的是 RC5 和 NEC。不幸的是，最著名的**并不意味着最常见**。在我的环境中，我只遇到过两个 NEC 遥控器，没有遇到过 RC5 遥控器。

制造商喜欢在同一类型的设备（例如电视盒子）中使用自己独特的红外协议。因此，来自不同公司的遥控器，有时甚至来自同一公司的不同型号，无法与其他相同类型的设备配合使用。
{% endhint %}

### 探索红外信号

查看遥控器红外信号的最可靠方法是使用示波器。它不会解调或反转接收到的信号，只是按原样显示。这对于测试和调试非常有用。我将以 NEC 红外协议的示例展示预期的信号。

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

通常，在编码数据包的开头有一个前导码。这使接收器能够确定增益和背景的水平。也有一些没有前导码的协议，例如 Sharp。

然后传输数据。结构、前导码和位编码方法由具体的协议确定。

**NEC 红外协议**包含一个短命令和一个重复码，在按下按钮时发送。命令和重复码都具有相同的前导码。

NEC **命令**除了前导码外，还包括一个地址字节和一个命令号字节，设备通过它们理解需要执行的操作。地址和命令号字节是具有相反值的重复值，用于检查传输的完整性。命令的末尾还有一个额外的停止位。

**重复码**在前导码后有一个 "1"，它是一个停止位。

对于逻辑 "0" 和 "1"，NEC 使用脉冲距离编码：首先传输一个脉冲爆发，然后是一个暂停，其长度设置了位的值。
### 空调

与其他遥控器不同，**空调不仅传输按下按钮的代码**，还会**传输所有信息**，以确保**空调机器和遥控器同步**。\
这样可以避免一个机器被设置为20ºC，然后用另一个遥控器增加温度时，另一个遥控器仍将温度设置为20ºC，它会将温度“增加”到21ºC（而不是以为它在21ºC时增加到22ºC）。

### 攻击

您可以使用Flipper Zero对红外进行攻击：

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## 参考资料

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
