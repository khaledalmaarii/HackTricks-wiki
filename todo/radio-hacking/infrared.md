# 红外线

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

## 红外线的工作原理 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**红外线光对人类是不可见的**。红外线波长范围为 **0.7 到 1000 微米**。家用遥控器使用红外信号进行数据传输，工作波长范围为 0.75..1.4 微米。遥控器中的微控制器使红外 LED 以特定频率闪烁，将数字信号转换为红外信号。

接收红外信号使用 **光接收器**。它 **将红外光转换为电压脉冲**，这些脉冲已经是 **数字信号**。通常，接收器内部有一个 **暗光滤波器**，只允许 **所需波长通过**，并过滤掉噪声。

### 红外协议的多样性 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

红外协议在三个因素上有所不同：

* 位编码
* 数据结构
* 载波频率 — 通常在 36..38 kHz 范围内

#### 位编码方式 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. 脉冲间距编码**

通过调制脉冲之间的间隔持续时间来编码位。脉冲本身的宽度是恒定的。

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. 脉冲宽度编码**

通过调制脉冲宽度来编码位。脉冲爆发后的间隔宽度是恒定的。

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. 相位编码**

也称为曼彻斯特编码。逻辑值由脉冲爆发与间隔之间的过渡极性定义。“间隔到脉冲爆发”表示逻辑“0”，“脉冲爆发到间隔”表示逻辑“1”。

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 之前编码方式的组合和其他特殊方式**

{% hint style="info" %}
有些红外协议 **试图成为多种设备的通用协议**。最著名的有 RC5 和 NEC。不幸的是，最著名的 **并不意味着最常见**。在我的环境中，我只遇到过两个 NEC 遥控器，而没有 RC5 遥控器。

制造商喜欢使用自己独特的红外协议，即使在同一系列设备中（例如，电视盒）。因此，不同公司的遥控器，有时同一公司的不同型号，无法与同类型的其他设备配合使用。
{% endhint %}

### 探索红外信号

查看遥控器红外信号的最可靠方法是使用示波器。它不会解调或反转接收到的信号，而是“原样”显示。这对于测试和调试非常有用。我将以 NEC 红外协议为例展示预期信号。

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

通常，编码数据包的开头有一个前导码。这使接收器能够确定增益和背景水平。也有没有前导码的协议，例如，夏普。

然后传输数据。结构、前导码和位编码方法由特定协议决定。

**NEC 红外协议**包含一个短命令和一个重复代码，在按下按钮时发送。命令和重复代码在开头都有相同的前导码。

NEC **命令**除了前导码外，还由一个地址字节和一个命令编号字节组成，设备通过这些字节理解需要执行的操作。地址和命令编号字节用反向值进行重复，以检查传输的完整性。命令末尾有一个额外的停止位。

**重复代码**在前导码后有一个“1”，这是一个停止位。

对于 **逻辑“0”和“1”**，NEC 使用脉冲间距编码：首先传输一个脉冲爆发，然后是一个暂停，其长度设置位的值。

### 空调

与其他遥控器不同，**空调不仅仅传输按下按钮的代码**。它们还 **在按下按钮时传输所有信息**，以确保 **空调和遥控器同步**。\
这将避免将设置为 20ºC 的机器用一个遥控器增加到 21ºC，然后当使用另一个仍将温度设置为 20ºC 的遥控器进一步增加温度时，它会“增加”到 21ºC（而不是 22ºC，认为它在 21ºC）。

### 攻击

您可以使用 Flipper Zero 攻击红外线：

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## 参考文献

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

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
