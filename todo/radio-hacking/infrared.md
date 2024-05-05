# 红外线

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 红外线工作原理 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**红外光对人类是不可见的**。红外波长范围为**0.7到1000微米**。家用遥控器使用红外信号进行数据传输，工作波长范围为0.75..1.4微米。遥控器中的微控制器会以特定频率使红外LED闪烁，将数字信号转换为红外信号。

为了接收红外信号，使用**光接收器**。它将**红外光转换为电压脉冲**，这些脉冲已经是**数字信号**。通常，接收器内部有一个**暗光滤波器**，只允许**所需波长通过**，并消除噪音。

### 各种红外协议 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

红外协议在3个因素上有所不同：

* 位编码
* 数据结构
* 载波频率 — 通常在36..38千赫范围内

#### 位编码方式 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. 脉冲距离编码**

通过调制脉冲之间的间隔持续时间来对位进行编码。脉冲本身的宽度是恒定的。

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. 脉冲宽度编码**

通过调制脉冲宽度来对位进行编码。脉冲爆发后的间隔宽度是恒定的。

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. 相位编码**

也称为曼彻斯特编码。逻辑值由脉冲爆发和间隔之间的极性转换来定义。"间隔到脉冲爆发"表示逻辑"0"，"脉冲爆发到间隔"表示逻辑"1"。

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 前述方法的组合和其他特殊方法**

{% hint style="info" %}
有些红外协议**试图成为多种设备的通用协议**。最著名的是RC5和NEC。不幸的是，最著名的**并不意味着最常见**。在我的环境中，我只遇到了两个NEC遥控器，没有遇到RC5遥控器。

制造商喜欢在同一范围内的设备（例如电视盒）中使用自己独特的红外协议。因此，来自不同公司的遥控器，有时甚至来自同一公司的不同型号，无法与同类型的其他设备配合使用。
{% endhint %}

### 探索红外信号

查看遥控器红外信号外观最可靠的方法是使用示波器。它不会解调或反转接收到的信号，只是“原样”显示。这对于测试和调试很有用。我将以NEC红外协议为例展示预期信号。

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

通常，在编码数据包的开头会有一个前导码。这使接收器能够确定增益和背景水平。也有一些没有前导码的协议，例如Sharp。

然后传输数据。结构、前导码和位编码方法由具体协议确定。

**NEC红外协议**包含一个简短的命令和一个重复码，在按下按钮时发送。命令和重复码在开头都有相同的前导码。

NEC的**命令**除了前导码外，还包括地址字节和命令号字节，设备通过这些字节了解需要执行什么操作。地址和命令号字节是具有相反值的重复值，以检查传输的完整性。命令末尾还有一个额外的停止位。

**重复码**在前导码后有一个“1”，这是一个停止位。

对于逻辑“0”和“1”，NEC使用脉冲距离编码：首先传输脉冲爆发，然后是一个间隔，其长度设置位的值。

### 空调

与其他遥控器不同，**空调不仅传输按下按钮的代码**。它们还在按下按钮时**传输所有信息**，以确保**空调机器和遥控器同步**。\
这将避免一个设定为20ºC的机器被一个遥控器增加到21ºC，然后当另一个遥控器，仍将温度设定为20ºC，用于进一步增加温度时，它会“增加”到21ºC（而不是以为是在21ºC时增加到22ºC）。

### 攻击

您可以使用Flipper Zero对红外线进行攻击：

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## 参考资料

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
