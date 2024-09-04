# FZ - Sub-GHz

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}


## 介绍 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero 可以 **接收和发送 300-928 MHz 范围内的无线频率**，其内置模块可以读取、保存和模拟遥控器。这些遥控器用于与门、障碍物、无线锁、遥控开关、无线门铃、智能灯等进行交互。Flipper Zero 可以帮助您了解您的安全性是否受到威胁。

<figure><img src="../../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz 硬件 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero 具有基于 [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 芯片](https://www.ti.com/lit/ds/symlink/cc1101.pdf) 的内置 sub-1 GHz 模块和一根无线天线（最大范围为 50 米）。CC1101 芯片和天线均设计用于在 300-348 MHz、387-464 MHz 和 779-928 MHz 频段内工作。

<figure><img src="../../../.gitbook/assets/image (923).png" alt=""><figcaption></figcaption></figure>

## 操作

### 频率分析仪

{% hint style="info" %}
如何找到遥控器使用的频率
{% endhint %}

在分析时，Flipper Zero 正在扫描频率配置中所有可用频率的信号强度 (RSSI)。Flipper Zero 显示 RSSI 值最高的频率，信号强度高于 -90 [dBm](https://en.wikipedia.org/wiki/DBm)。

要确定遥控器的频率，请执行以下操作：

1. 将遥控器放置在 Flipper Zero 左侧非常靠近的位置。
2. 转到 **主菜单** **→ Sub-GHz**。
3. 选择 **频率分析仪**，然后按住您想要分析的遥控器上的按钮。
4. 查看屏幕上的频率值。

### 读取

{% hint style="info" %}
查找使用的频率信息（也是查找使用的频率的另一种方法）
{% endhint %}

**读取** 选项 **在指定调制下监听配置频率**：默认情况下为 433.92 AM。如果在读取时 **找到某些内容**，则 **屏幕上会显示信息**。这些信息可以用于将来复制信号。

在使用读取时，可以按 **左按钮** 并 **进行配置**。\
此时它有 **4 种调制**（AM270、AM650、FM328 和 FM476），以及 **存储的多个相关频率**：

<figure><img src="../../../.gitbook/assets/image (947).png" alt=""><figcaption></figcaption></figure>

您可以设置 **任何您感兴趣的频率**，但是，如果您 **不确定哪个频率** 可能是您拥有的遥控器使用的频率，请 **将跳频设置为开启**（默认关闭），并多次按下按钮，直到 Flipper 捕获到它并提供您设置频率所需的信息。

{% hint style="danger" %}
在频率之间切换需要一些时间，因此在切换时传输的信号可能会丢失。为了更好的信号接收，请设置由频率分析仪确定的固定频率。
{% endhint %}

### **读取原始信号**

{% hint style="info" %}
窃取（并重放）配置频率上的信号
{% endhint %}

**读取原始信号** 选项 **记录在监听频率上发送的信号**。这可以用于 **窃取** 信号并 **重复** 它。

默认情况下，**读取原始信号也在 433.92 AM650**，但如果通过读取选项发现您感兴趣的信号在 **不同的频率/调制下，您也可以通过按左键进行修改**（在读取原始信号选项内）。

### 暴力破解

如果您知道例如车库门使用的协议，可以 **生成所有代码并通过 Flipper Zero 发送它们**。这是一个支持一般常见类型车库的示例：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### 手动添加

{% hint style="info" %}
从配置的协议列表中添加信号
{% endhint %}

#### [支持的协议列表](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433（与大多数静态代码系统兼容） | 433.92 | 静态  |
| ------------------------------------------------ | ------ | ----- |
| Nice Flo 12bit\_433                              | 433.92 | 静态  |
| Nice Flo 24bit\_433                              | 433.92 | 静态  |
| CAME 12bit\_433                                  | 433.92 | 静态  |
| CAME 24bit\_433                                  | 433.92 | 静态  |
| Linear\_300                                      | 300.00 | 静态  |
| CAME TWEE                                        | 433.92 | 静态  |
| Gate TX\_433                                     | 433.92 | 静态  |
| DoorHan\_315                                     | 315.00 | 动态  |
| DoorHan\_433                                     | 433.92 | 动态  |
| LiftMaster\_315                                  | 315.00 | 动态  |
| LiftMaster\_390                                  | 390.00 | 动态  |
| Security+2.0\_310                                | 310.00 | 动态  |
| Security+2.0\_315                                | 315.00 | 动态  |
| Security+2.0\_390                                | 390.00 | 动态  |

### 支持的 Sub-GHz 供应商

查看 [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors) 中的列表

### 按区域支持的频率

查看 [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies) 中的列表

### 测试

{% hint style="info" %}
获取保存频率的 dBms
{% endhint %}

## 参考

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
