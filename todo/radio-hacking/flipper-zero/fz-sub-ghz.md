# FZ - Sub-GHz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 简介 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero可以使用其内置模块在300-928 MHz的无线电频率范围内接收和发送信号，可以读取、保存和模拟遥控器。这些遥控器用于与门、栅栏、无线锁、遥控开关、无线门铃、智能灯等进行交互。Flipper Zero可以帮助您了解您的安全性是否受到威胁。

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz硬件 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero内置了一个基于[﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101芯片](https://www.ti.com/lit/ds/symlink/cc1101.pdf)和一个无线电天线的次1 GHz模块（最大范围为50米）。CC1101芯片和天线均设计用于在300-348 MHz、387-464 MHz和779-928 MHz频段工作。

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## 操作

### 频率分析仪

{% hint style="info" %}
如何找到遥控器使用的频率
{% endhint %}

在分析过程中，Flipper Zero会在频率配置中扫描信号强度（RSSI）。Flipper Zero显示具有最高RSSI值的频率，信号强度大于-90 [dBm](https://en.wikipedia.org/wiki/DBm)。

要确定遥控器的频率，请执行以下操作：

1. 将遥控器放在Flipper Zero的左侧非常靠近的位置。
2. 转到**主菜单** **→ Sub-GHz**。
3. 选择**频率分析仪**，然后按住要分析的遥控器上的按钮。
4. 在屏幕上查看频率值。

### 读取

{% hint style="info" %}
查找使用的频率的信息（也是查找使用的频率的另一种方法）
{% endhint %}

**读取**选项**监听配置的频率**上的指定调制方式：默认为433.92 AM。如果在读取时**发现了某些内容**，屏幕上会显示相关信息。这些信息可以用于将来复制信号。

在使用读取时，可以按下**左侧按钮**并进行**配置**。\
此时有**4种调制方式**（AM270、AM650、FM328和FM476），以及**存储的几个相关频率**：

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

您可以设置**任何您感兴趣的频率**，但是，如果您**不确定遥控器使用的是哪个频率**，请将Hopping设置为ON（默认为Off），然后按下按钮多次，直到Flipper捕获到并提供您设置频率所需的信息。

{% hint style="danger" %}
在切换频率之间需要一些时间，因此在切换时发送的信号可能会被错过。为了获得更好的信号接收效果，请设置由频率分析仪确定的固定频率。
{% endhint %}

### **读取原始数据**

{% hint style="info" %}
在配置的频率上窃取（和重放）信号
{% endhint %}

**读取原始数据**选项**记录在监听频率上发送的信号**。这可以用于**窃取**信号并**重放**它。

默认情况下，**读取原始数据**也是在433.92 AM650上进行的，但是如果使用读取选项发现您感兴趣的信号在**不同的频率/调制方式**上，您也可以通过按下左侧按钮（在读取原始数据选项中）进行修改。

### 暴力破解

如果您知道例如车库门使用的协议，可以**生成所有的代码并使用Flipper Zero发送它们**。这是一个支持常见类型的车库的示例：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*
### 手动添加

{% hint style="info" %}
从配置的协议列表中添加信号
{% endhint %}

#### [支持的协议列表](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (适用于大多数静态代码系统) | 433.92 | 静态 |
| ---------------------------------------- | ------ | ---- |
| Nice Flo 12bit\_433                      | 433.92 | 静态 |
| Nice Flo 24bit\_433                      | 433.92 | 静态 |
| CAME 12bit\_433                          | 433.92 | 静态 |
| CAME 24bit\_433                          | 433.92 | 静态 |
| Linear\_300                              | 300.00 | 静态 |
| CAME TWEE                                | 433.92 | 静态 |
| Gate TX\_433                             | 433.92 | 静态 |
| DoorHan\_315                             | 315.00 | 动态 |
| DoorHan\_433                             | 433.92 | 动态 |
| LiftMaster\_315                          | 315.00 | 动态 |
| LiftMaster\_390                          | 390.00 | 动态 |
| Security+2.0\_310                        | 310.00 | 动态 |
| Security+2.0\_315                        | 315.00 | 动态 |
| Security+2.0\_390                        | 390.00 | 动态 |

### 支持的Sub-GHz供应商

请查看[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)中的列表

### 按地区支持的频率

请查看[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)中的列表

### 测试

{% hint style="info" %}
获取保存频率的dBm值
{% endhint %}

## 参考

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)
*

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
