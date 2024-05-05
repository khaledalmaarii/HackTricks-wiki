# 无线电

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)是一个免费的数字信号分析器，适用于GNU/Linux和macOS，旨在提取未知无线电信号的信息。它通过SoapySDR支持各种SDR设备，并允许调整FSK、PSK和ASK信号的解调，解码模拟视频，分析突发信号并实时收听模拟语音频道。

### 基本配置

安装后，有一些配置可以考虑。\
在设置中（第二个选项卡按钮），您可以选择**SDR设备**或**选择文件**以读取和合成频率以及采样率（如果您的PC支持，建议最高为2.56Msps）\\

![](<../../.gitbook/assets/image (245).png>)

在GUI行为中，建议启用一些功能，如果您的PC支持：

![](<../../.gitbook/assets/image (472).png>)

{% hint style="info" %}
如果您发现您的PC没有捕获到信号，请尝试禁用OpenGL并降低采样率。
{% endhint %}

### 用途

* 只需**捕获一段时间的信号并分析**，只需按住“按下以捕获”按钮直到您需要的时间。

![](<../../.gitbook/assets/image (960).png>)

* SigDigger的**调谐器有助于捕获更好的信号**（但也可能使其变差）。理想情况下，从0开始，不断**增大直到**发现引入的**噪音**比您需要的**信号改进**更**大**为止。

![](<../../.gitbook/assets/image (1099).png>)

### 与无线电频道同步

使用[**SigDigger** ](https://github.com/BatchDrake/SigDigger)与您想要收听的频道同步，配置“基带音频预览”选项，配置带宽以获取发送的所有信息，然后将调谐器设置为在噪音真正开始增加之前的级别：

![](<../../.gitbook/assets/image (585).png>)

## 有趣的技巧

* 当设备发送信息突发时，通常**第一部分将是前导码**，因此如果您在那里**找不到信息**或者有一些错误，**不用担心**。
* 在信息帧中，通常应该**找到不同的帧并对齐它们**：

![](<../../.gitbook/assets/image (1076).png>)

![](<../../.gitbook/assets/image (597).png>)

* **恢复位后，您可能需要以某种方式处理它们**。例如，在曼彻斯特编码中，上+下将是1或0，下+上将是另一个。因此，一对1和0（上和下）将是真正的1或真正的0。
* 即使信号使用曼彻斯特编码（不可能连续找到两个0或1），您可能会在前导码中**找到几个连续的1或0**！

### 使用IQ揭示调制类型

信号中有3种存储信息的方式：调制**幅度**、**频率**或**相位**。\
如果您正在检查信号，有不同的方法可以尝试弄清楚存储信息的方式（在下面找到更多方法），但一个好方法是检查IQ图。

![](<../../.gitbook/assets/image (788).png>)

* **检测AM**：如果在IQ图中出现例如**2个圆圈**（可能一个在0，另一个在不同的幅度），这可能意味着这是一个AM信号。这是因为在IQ图中，0和圆圈之间的距离是信号的幅度，因此很容易看到不同的幅度被使用。
* **检测PM**：就像在前一个图像中一样，如果您发现小圆圈彼此不相关，这可能意味着使用了相位调制。这是因为在IQ图中，点与0,0之间的角度是信号的相位，这意味着使用了4个不同的相位。
* 请注意，如果信息隐藏在相位的改变而不是相位本身中，您将看不到清晰区分的不同相位。
* **检测FM**：IQ图中没有用于识别频率的字段（到中心的距离是幅度，角度是相位）。\
因此，要识别FM，您应该在此图中**只看到基本上一个圆圈**。\
此外，IQ图中的不同频率通过圆圈上的**速度加速**来“表示”（因此在SysDigger中选择信号后，IQ图会填充，如果您在创建的圆圈中发现加速或方向变化，这可能意味着这是FM）：

## AM示例

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### 揭示AM

#### 检查包络

使用[**SigDigger** ](https://github.com/BatchDrake/SigDigger)检查AM信息，只需查看**包络**，您可以看到不同明显的幅度级别。使用的信号正在以AM发送带有信息的脉冲，这是一个脉冲的外观：

![](<../../.gitbook/assets/image (590).png>)

这是符号部分的波形外观：

![](<../../.gitbook/assets/image (734).png>)

#### 检查直方图

您可以**选择包含信息的整个信号**，选择**幅度**模式和**选择**，然后单击**直方图**。您会发现只有2个明显的级别

![](<../../.gitbook/assets/image (264).png>)

例如，如果您在此AM信号中选择频率而不是幅度，您只会找到一个频率（信息调制在频率上的方式只使用1个频率）。

![](<../../.gitbook/assets/image (732).png>)

如果发现许多频率，那么这可能不是FM，可能是信号频率仅因通道而发生变化。
#### 使用 IQ

在这个例子中，你可以看到有一个**大圆圈**，但也有**很多点在中心**。

![](<../../.gitbook/assets/image (222).png>)

### 获取符号速率

#### 使用一个符号

选择你能找到的最小符号（这样你就确定只有一个），并检查“选择频率”。在这种情况下，它将是1.013kHz（即1kHz）。

![](<../../.gitbook/assets/image (78).png>)

#### 使用一组符号

你也可以指定你要选择的符号数量，SigDigger将计算1个符号的频率（选择的符号数量越多，可能越好）。在这种情况下，我选择了10个符号，“选择频率”为1.004千赫：

![](<../../.gitbook/assets/image (1008).png>)

### 获取比特

已经找到这是一个**AM调制**信号和**符号速率**（并知道在这种情况下，上升表示1，下降表示0），很容易**获取信号中编码的比特**。因此，选择带有信息的信号并配置采样和决策，然后按下采样（检查已选择**幅度**，已发现的**符号速率**已配置，已选择**Gadner时钟恢复**）：

![](<../../.gitbook/assets/image (965).png>)

* **同步到选择间隔**表示如果你之前选择了间隔来找到符号速率，那么该符号速率将被使用。
* **手动**表示将使用指定的符号速率
* 在**固定间隔选择**中，你指定应该选择的间隔数量，它会从中计算符号速率
* **Gadner时钟恢复**通常是最佳选项，但你仍然需要指定一些近似的符号速率。

按下采样后，会出现这个：

![](<../../.gitbook/assets/image (644).png>)

现在，为了让SigDigger理解**信息传递级别的范围**，你需要点击**较低级别**，并保持点击直到最大级别：

![](<../../.gitbook/assets/image (439).png>)

如果例如有**4个不同的幅度级别**，你应该需要配置**每个符号的比特为2**，并从最小到最大选择。

最后，**增加****缩放**和**更改行大小**，你可以看到比特（你可以全选并复制以获取所有比特）：

![](<../../.gitbook/assets/image (276).png>)

如果每个符号有多于1个比特（例如2个），SigDigger**无法知道哪个符号是**00、01、10、11，因此它将使用不同的**灰度**来表示每个符号（如果你复制比特，它将使用**0到3的数字**，你需要处理它们）。

此外，使用**编码**，如**曼彻斯特编码**，**上升+下降**可以是**1或0**，下降+上升可以是1或0。在这些情况下，你需要**处理获得的上升（1）和下降（0）**，以替换01或10这样的对。

## FM示例

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### 揭示 FM

#### 检查频率和波形

发送信息调制在FM中的信号示例：

![](<../../.gitbook/assets/image (725).png>)

在上图中，你可以很清楚地看到**使用了2个频率**，但如果你**观察****波形**，你可能**无法正确识别这2个不同的频率**：

![](<../../.gitbook/assets/image (717).png>)

这是因为我在两个频率中捕获了信号，因此一个频率大致等于另一个频率的负值：

![](<../../.gitbook/assets/image (942).png>)

如果同步频率**更接近一个频率而不是另一个频率**，你可以很容易地看到这2个不同的频率：

![](<../../.gitbook/assets/image (422).png>)

![](<../../.gitbook/assets/image (488).png>)

#### 检查直方图

检查带有信息的信号的频率直方图，你可以很容易地看到2个不同的信号：

![](<../../.gitbook/assets/image (871).png>)

在这种情况下，如果你检查**幅度直方图**，你会发现**只有一个幅度**，所以它**不可能是AM**（如果你发现很多幅度，可能是因为信号在通道中失去了功率）：

![](<../../.gitbook/assets/image (817).png>)

这将是相位直方图（这清楚地表明信号不是相位调制）：

![](<../../.gitbook/assets/image (996).png>)

#### 使用 IQ

IQ没有一个字段来识别频率（到中心的距离是幅度，角度是相位）。\
因此，要识别FM，你应该在这个图中**基本上只看到一个圆圈**。\
此外，IQ图中的**不同频率**通过圆圈上的**速度加速**来“表示”（因此在SysDigger中选择信号后，IQ图会被填充，如果你在创建的圆圈中发现加速或方向变化，这可能意味着这是FM）：

![](<../../.gitbook/assets/image (81).png>)

### 获取符号速率

一旦找到携带符号的频率，你可以使用与AM示例中使用的**相同技术**来获取符号速率。

### 获取比特

一旦**发现信号是频率调制**的，以及**符号速率**，你可以使用与AM示例中使用的**相同技术**来获取比特。

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想看到你的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>
