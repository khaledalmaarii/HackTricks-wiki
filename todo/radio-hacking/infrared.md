# 红外线

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 红外线工作原理 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**红外线对人类是不可见的**。红外线波长从 **0.7到1000微米**。家用遥控器使用红外信号进行数据传输，操作波长范围为0.75..1.4微米。遥控器中的微控制器使红外LED以特定频率闪烁，将数字信号转换为红外信号。

为了接收红外信号，使用了**光接收器**。它**将红外光转换为电压脉冲**，这些已经是**数字信号**。通常，接收器内部有一个**暗光滤波器**，它**只允许所需波长通过**，并滤除噪声。

### 红外协议的多样性 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

红外协议在3个因素上有所不同：

* 位编码
* 数据结构
* 载波频率 — 通常在36..38 kHz范围内

#### 位编码方式 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. 脉冲距离编码**

通过调制脉冲之间的间隔持续时间来编码位。脉冲本身的宽度是恒定的。

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. 脉冲宽度编码**

通过调制脉冲宽度来编码位。脉冲后的空间宽度是恒定的。

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. 相位编码**

也称为曼彻斯特编码。逻辑值由脉冲爆发和空间之间的过渡极性定义。"空间到脉冲爆发"表示逻辑"0"，"脉冲爆发到空间"表示逻辑"1"。

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. 结合前述方法和其他特殊方法**

{% hint style="info" %}
有些红外协议**试图成为**多种设备的**通用协议**。最著名的是RC5和NEC。不幸的是，最著名**并不意味着最常见**。在我的环境中，我只遇到过两个NEC遥控器，没有遇到RC5的。

制造商喜欢使用他们自己独特的红外协议，即使是在同一系列的设备中（例如，电视盒）。因此，不同公司的遥控器，有时甚至同一公司不同型号的遥控器，无法与同类型的其他设备配合使用。
{% endhint %}

### 探索红外信号

查看遥控器红外信号的最可靠方法是使用示波器。它不会解调或反转接收到的信号，只是"原样"显示。这对于测试和调试很有用。我将以NEC红外协议为例展示预期的信号。

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

通常，在编码包的开头有一个前导码。这允许接收器确定增益水平和背景。也有没有前导码的协议，例如Sharp。

然后传输数据。结构、前导码和位编码方法由特定协议确定。

**NEC红外协议**包含一个短命令和一个重复代码，当按钮被按下时发送。命令和重复代码在开头都有相同的前导码。

NEC **命令**，除了前导码外，还包括一个地址字节和一个命令号字节，设备通过这些字节了解需要执行的操作。地址和命令号字节都有反向值的副本，以检查传输的完整性。命令的末尾有一个额外的停止位。

**重复代码**在前导码后有一个"1"，这是一个停止位。

对于**逻辑"0"和"1"**，NEC使用脉冲距离编码：首先传输一个脉冲爆发，然后是一个暂停，其长度设置了位的值。

### 空调

与其他遥控器不同，**空调不仅仅传输按下按钮的代码**。当按下按钮时，它们还**传输所有信息**，以确保**空调机和遥控器同步**。\
这将避免空调机设定为20ºC，用一个遥控器增加到21ºC，然后当另一个仍将温度设为20ºC的遥控器用来进一步增加温度时，它会将温度"增加"到21ºC（而不是认为它在21ºC时增加到22ºC）。

### 攻击

您可以使用Flipper Zero攻击红外线：

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## 参考资料

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
