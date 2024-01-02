# FZ - Sub-GHz

<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便您能更快修复它们。Intruder追踪您的攻击面，运行主动威胁扫描，在您的整个技术栈中找到问题，从API到Web应用程序和云系统。[**今天就免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 简介 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero可以使用其内置模块在300-928 MHz范围内**接收和发送无线电频率**，该模块可以读取、保存和模拟遥控器。这些控制器用于与大门、障碍物、无线电锁、遥控开关、无线门铃、智能灯等互动。Flipper Zero可以帮助您了解您的安全是否受到威胁。

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz硬件 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero内置了基于[CC1101芯片](https://www.ti.com/lit/ds/symlink/cc1101.pdf)的sub-1 GHz模块和无线电天线（最大范围为50米）。CC1101芯片和天线都设计用于在300-348 MHz、387-464 MHz和779-928 MHz频段操作。

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## 操作

### 频率分析器

{% hint style="info" %}
如何找到遥控器使用的频率
{% endhint %}

在分析时，Flipper Zero会扫描频率配置中所有可用频率的信号强度（RSSI）。Flipper Zero会显示RSSI值最高的频率，信号强度高于-90 [dBm](https://en.wikipedia.org/wiki/DBm)。

要确定遥控器的频率，请执行以下操作：

1. 将遥控器非常靠近Flipper Zero的左侧。
2. 转到**主菜单** **→ Sub-GHz**。
3. 选择**频率分析器**，然后按住您要分析的遥控器上的按钮。
4. 查看屏幕上的频率值。

### 读取

{% hint style="info" %}
找到关于使用频率的信息（也是找到使用频率的另一种方式）
{% endhint %}

**读取**选项会**在配置的频率上监听**指示的调制：默认为433.92 AM。如果在读取时**发现了某些内容**，屏幕上会**给出信息**。这些信息可以用来在未来复制信号。

使用Read时，可以按下**左按钮**并**配置它**。\
目前它有**4种调制**（AM270、AM650、FM328和FM476），以及**几个相关的存储频率**：

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

您可以设置**任何您感兴趣的**，但是，如果您**不确定**哪个频率可能是您手中遥控器使用的，**将跳频设置为ON**（默认为Off），并多次按下按钮，直到Flipper捕获它并给您需要设置频率的信息。

{% hint style="danger" %}
切换频率需要一些时间，因此在切换时传输的信号可能会丢失。为了更好地接收信号，请设置由频率分析器确定的固定频率。
{% endhint %}

### **读取原始数据**

{% hint style="info" %}
窃取（并重放）配置频率中的信号
{% endhint %}

**读取原始数据**选项会**记录**在监听频率中发送的信号。这可以用来**窃取**信号并**重复**它。

默认情况下**读取原始数据也在433.92的AM650**，但是如果通过读取选项您发现您感兴趣的信号在**不同的频率/调制**，您也可以修改它，只需在读取原始数据选项内按左键即可。

### 暴力破解

如果您知道例如车库门使用的协议，可以**生成所有代码并使用Flipper Zero发送它们。** 这是一个支持常见类型车库的示例：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### 手动添加

{% hint style="info" %}
从配置的协议列表中添加信号
{% endhint %}

#### [支持的协议](https://docs.flipperzero.one/sub-ghz/add-new-remote)列表 <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (适用于大多数静态代码系统) | 433.92 | 静态  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | 静态  |
| Nice Flo 24bit\_433                                             | 433.92 | 静态  |
| CAME 12bit\_433                                                 | 433.92 | 静态  |
| CAME 24bit\_433                                                 | 433.92 | 静态  |
| Linear\_300                                                     | 300.00 | 静态  |
| CAME TWEE                                                       | 433.92 | 静态  |
| Gate TX\_433                                                    | 433.92 | 静态  |
| DoorHan\_315                                                    | 315.00 | 动态 |
| DoorHan\_433                                                    | 433.92 | 动态 |
| LiftMaster\_315                                                 | 315.00 | 动态 |
| LiftMaster\_390                                                 | 390.00 | 动态 |
| Security+2.0\_310                                               | 310.00 | 动态 |
| Security+2.0\_315                                               | 315.00 | 动态 |
| Security+2.0\_390                                               | 390.00 | 动态 |

### 支持的Sub-GHz供应商

查看列表在 [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### 按地区支持的频率

查看列表在 [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### 测试

{% hint style="info" %}
获取保存频率的dBms
{% endhint %}

## 参考

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便您能更快修复它们。Intruder追踪您的攻击面，运行主动威胁扫描，在您的整个技术栈中找到问题，从API到Web应用程序和云系统。[**今天就免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
