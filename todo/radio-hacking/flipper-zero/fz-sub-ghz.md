# FZ - Sub-GHz

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

发现最重要的漏洞，以便更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 简介 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero可以使用其内置模块在300-928 MHz范围内**接收和发送无线电频率**，可以读取、保存和模拟遥控器。这些遥控器用于与门、栅栏、无线电锁、遥控开关、无线门铃、智能灯等进行交互。Flipper Zero可以帮助您了解您的安全是否受到威胁。

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz硬件 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero具有内置的基于[CC1101芯片](https://www.ti.com/lit/ds/symlink/cc1101.pdf)和无线电天线（最大范围为50米）的次1 GHz模块。CC1101芯片和天线均设计用于在300-348 MHz、387-464 MHz和779-928 MHz频段上运行。

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## 操作

### 频率分析仪

{% hint style="info" %}
如何找到遥控器使用的频率
{% endhint %}

在分析时，Flipper Zero会在频率配置中提供的所有频率上扫描信号强度（RSSI）。Flipper Zero会显示具有最高RSSI值的频率，信号强度高于-90 [dBm](https://en.wikipedia.org/wiki/DBm)。

要确定遥控器的频率，请执行以下操作：

1. 将遥控器放置在Flipper Zero的左侧非常近的位置。
2. 转到**主菜单** **→ Sub-GHz**。
3. 选择**频率分析仪**，然后按住要分析的遥控器上的按钮。
4. 查看屏幕上的频率值。

### 读取

{% hint style="info" %}
查找使用的频率的信息（也是找到使用的频率的另一种方法）
{% endhint %}

**读取**选项会**监听配置频率**上的指定调制：默认为433.92 AM。如果在读取时**发现了什么**，屏幕上会提供**信息**。此信息可用于将来复制信号。

在使用读取时，可以按**左侧按钮**并**进行配置**。\
此时有**4种调制**（AM270、AM650、FM328和FM476），以及**存储的几个相关频率**：

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

您可以设置**您感兴趣的任何频率**，但是，如果您**不确定遥控器使用的是哪个频率**，请将Hopping设置为ON（默认为关闭），然后多次按按钮，直到Flipper捕获并提供您设置频率所需的信息。

{% hint style="danger" %}
在频率之间切换需要一些时间，因此在切换时传输的信号可能会被错过。为了获得更好的信号接收，请设置由频率分析仪确定的固定频率。
{% endhint %}

### **读取原始**

{% hint style="info" %}
在配置的频率上记录信号（并重放）
{% endhint %}

**读取原始**选项会在监听频率上记录发送的信号。这可用于**窃取**信号并**重放**。

默认情况下，**读取原始也是在433.92的AM650中**，但是如果使用读取选项找到您感兴趣的信号在**不同的频率/调制**上，您也可以通过按左键（在读取原始选项内）进行修改。

### 暴力破解

如果您知道例如车库门使用的协议，可以**生成所有代码并使用Flipper Zero发送它们**。这是一个支持常见类型的车库的示例：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### 手动添加

{% hint style="info" %}
从配置的协议列表中添加信号
{% endhint %}

#### [支持的协议列表](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433（适用于大多数静态代码系统） | 433.92 | 静态  |
| ----------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                       | 433.92 | 静态  |
| Nice Flo 24bit\_433                       | 433.92 | 静态  |
| CAME 12bit\_433                           | 433.92 | 静态  |
| CAME 24bit\_433                           | 433.92 | 静态  |
| Linear\_300                               | 300.00 | 静态  |
| CAME TWEE                                 | 433.92 | 静态  |
| Gate TX\_433                              | 433.92 | 静态  |
| DoorHan\_315                              | 315.00 | 动态  |
| DoorHan\_433                              | 433.92 | 动态  |
| LiftMaster\_315                           | 315.00 | 动态  |
| LiftMaster\_390                           | 390.00 | 动态  |
| Security+2.0\_310                         | 310.00 | 动态  |
| Security+2.0\_315                         | 315.00 | 动态  |
| Security+2.0\_390                         | 390.00 | 动态  |

### 支持的Sub-GHz供应商

请查看[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)中的列表。

### 区域支持的频率

请查看[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)中的列表。

### 测试

{% hint style="info" %}
获取保存频率的dBm
{% endhint %}

## 参考

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

发现最重要的漏洞，以便更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
