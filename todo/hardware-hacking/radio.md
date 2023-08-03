# 无线电

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger)是一个免费的数字信号分析器，适用于GNU/Linux和macOS，旨在提取未知无线电信号的信息。它通过SoapySDR支持各种SDR设备，并允许可调制FSK、PSK和ASK信号，解码模拟视频，分析突发信号并收听模拟语音通道（实时）。

### 基本配置

安装完成后，您可以考虑进行一些配置。\
在设置中（第二个选项卡按钮），您可以选择**SDR设备**或**选择一个文件**进行读取，以及要同步的频率和采样率（如果您的PC支持，建议将其提高到2.56Msps）。

![](<../../.gitbook/assets/image (655) (1).png>)

在GUI行为中，如果您的PC支持，建议启用一些功能：

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
如果您发现您的PC没有捕获到信号，请尝试禁用OpenGL并降低采样率。
{% endhint %}

### 用途

* 只需**捕获一段时间的信号并分析**，只需按住"Push to capture"按钮即可。

![](<../../.gitbook/assets/image (631).png>)

* SigDigger的**调谐器**有助于**更好地捕获信号**（但也可能降低信号质量）。理想情况下，从0开始逐渐增加，直到发现引入的噪声比所需信号的改进更大。

![](<../../.gitbook/assets/image (658).png>)

### 与无线电频道同步

使用[**SigDigger**](https://github.com/BatchDrake/SigDigger)与您想要收听的频道同步，配置"Baseband audio preview"选项，配置带宽以获取发送的所有信息，然后将调谐器设置为噪声真正开始增加之前的水平：

![](<../../.gitbook/assets/image (389).png>)

## 有趣的技巧

* 当设备发送信息突发时，通常**首部将是前导码**，因此如果在那里找不到信息或者有一些错误，您不需要担心。
* 在信息帧中，通常应该**找到彼此对齐的不同帧**：

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **在恢复位之后，您可能需要以某种方式处理它们**。例如，在曼彻斯特编码中，上+下将是1或0，下+上将是另一个。因此，一对1和0（上和下）将是真正的1或真正的0。
* 即使信号使用曼彻斯特编码（不可能连续出现两个0或1），您可能会在前导码中**找到几个连续的1或0**！

### 使用IQ揭示调制类型

信号中有3种存储信息的方式：调制**幅度**、**频率**或**相位**。\
如果您正在检查一个信号，有不同的方法可以尝试弄清楚用于存储信息的方式（在下面找到更多方法），但一个好的方法是检查IQ图。

![](<../../.gitbook/assets/image (630).png>)

* **检测AM**：如果在IQ图中出现例如**2个圆圈**（可能一个在0，另一个在不同的幅度），这可能意味着这是一个AM信号。这是因为在IQ图中，0和圆圈之间的距离是信号的幅度，因此很容易可视化使用不同幅度。
* **检测PM**：与前一个图像类似，如果您发现小圆圈彼此之间没有关联，这可能意味着使用了相位调制。这是因为在IQ图中，点与0,0之间的角度是信号的相位，这意味着使用了4个不同的相位。
* 请注意，如果信息隐藏在相位的改变而不是相位本身中，您将无法清楚地区分不同的相位。
* **检测FM**：IQ图中没有用于识别频率的字段（到中心的距离是幅度，角度是相位）。\
因此，要识别FM，您应该在此图中**只能看到基本上是一个圆圈**。\
此外，通过IQ图中的**速度加速度**（因此在SysDigger中选择信号时，IQ图会填充，如果在创建的圆圈中发现加速度或方向变化，这可能意味着这是FM）来"表示"不同的频率。
## AM示例

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### 揭示AM

#### 检查包络

使用[**SigDigger**](https://github.com/BatchDrake/SigDigger)检查AM信息，只需查看**包络**，您可以看到不同的明显幅度级别。使用的信号以AM方式发送带有信息的脉冲，以下是一个脉冲的样子：

![](<../../.gitbook/assets/image (636).png>)

以下是符号的一部分的波形：

![](<../../.gitbook/assets/image (650) (1).png>)

#### 检查直方图

您可以选择包含信息的整个信号，选择**幅度**模式和**选择**，然后单击**直方图**。您可以观察到只有2个明显的幅度级别。

![](<../../.gitbook/assets/image (647) (1) (1).png>)

例如，如果您在此AM信号中选择频率而不是幅度，您将只找到1个频率（不可能使用1个频率来调制信息）。

![](<../../.gitbook/assets/image (637) (1) (1).png>)

如果发现了许多频率，那么可能不是FM，可能是由于信道的原因信号频率被修改了。

#### 使用IQ

在此示例中，您可以看到有一个**大圆圈**，但也有**很多点在中心**。

![](<../../.gitbook/assets/image (640).png>)

### 获取符号速率

#### 使用一个符号

选择您能找到的最小符号（以确保只有1个符号），然后检查“选择频率”。在这种情况下，它将是1.013kHz（即1kHz）。

![](<../../.gitbook/assets/image (638) (1).png>)

#### 使用一组符号

您还可以指示要选择的符号数量，SigDigger将计算1个符号的频率（选择的符号数量越多，可能越好）。在此场景中，我选择了10个符号，“选择频率”为1.004 kHz：

![](<../../.gitbook/assets/image (635).png>)

### 获取比特

已经确定这是一个**AM调制**的信号和**符号速率**（并且知道在这种情况下，上升表示1，下降表示0），很容易**获取编码在信号中的比特**。因此，选择带有信息的信号，并配置采样和决策，然后按下采样（检查是否选择了**幅度**，配置了发现的**符号速率**，并选择了**Gadner时钟恢复**）：

![](<../../.gitbook/assets/image (642) (1).png>)

* **同步到选择间隔**表示如果您之前选择了间隔以找到符号速率，则将使用该符号速率。
* **手动**表示将使用指定的符号速率。
* 在**固定间隔选择**中，您指示应选择的间隔数，并从中计算符号速率。
* **Gadner时钟恢复**通常是最佳选择，但您仍然需要指示一些近似的符号速率。

按下采样后，会出现以下内容：

![](<../../.gitbook/assets/image (659).png>)

现在，为了让SigDigger理解信息传递的**幅度范围**，您需要点击**较低的级别**并保持点击直到最大级别：

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

例如，如果有**4个不同的幅度级别**，您需要将**每个符号的比特数配置为2**，并从最小到最大进行选择。

最后，**增加****缩放**并**更改行大小**，您可以看到比特（您可以全部选择并复制以获取所有比特）：

![](<../../.gitbook/assets/image (649) (1).png>)

如果信号每个符号有多个比特（例如2个），SigDigger**无法知道哪个符号是**00、01、10、11，因此它将使用不同的**灰度**来表示每个符号（如果您复制比特，它将使用**0到3的数字**，您需要处理它们）。

此外，使用**曼彻斯特编码**等**编码**，上升+下降可以是1或0，下降+上升可以是1或0。在这些情况下，您需要**处理获得的上升（1）和下降（0）**，将01或10的配对替换为0或1。

## FM示例

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### 揭示FM

#### 检查频率和波形

示例信号以FM调制方式发送信息：

![](<../../.gitbook/assets/image (661) (1).png>)

在上图中，您可以明显看到**使用了2个频率**，但是如果您**观察****波形**，您可能无法正确识别2个不同的频率：

![](<../../.gitbook/assets/image (653).png>)

这是因为我在两个频率上捕获了信号，因此一个频率大致等于另一个频率的负数：

![](<../../.gitbook/assets/image (656).png>)

如果同步频率**更接近一个频率而不是另一个频率**，您可以轻松看到这2个不同的频率：

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### 检查直方图

检查带有信息的信号的频率直方图，您可以轻松看到2个不同的信号：

![](<../../.gitbook/assets/image (657).png>)

在这种情况下，如果检查**幅度直方图**，您将找到**只有一个幅度**，因此它**不能是AM**（如果您找到了许多幅度，可能是因为信号在信道上失去了功率）：

![](<../../.gitbook/assets/image (646).png>)

这将是相位直方图（非常清楚地表明信号没有调制相位）：

![](<../../.gitbook/assets/image (201) (2).png>)
#### 使用 IQ

IQ 没有一个用于识别频率的字段（距离中心的幅度和角度是相位）。\
因此，要识别 FM，你应该在这个图中**只看到一个基本的圆圈**。\
此外，不同的频率在 IQ 图中通过**圆圈上的速度加速度**来"表示"（因此在 SysDigger 中选择信号时，IQ 图会被填充，如果你在创建的圆圈中发现加速度或方向变化，这可能意味着这是 FM）：

![](<../../.gitbook/assets/image (643) (1).png>)

### 获取符号速率

一旦你找到了携带符号的频率，你可以使用**与 AM 示例中相同的技术**来获取符号速率。

### 获取比特位

一旦你发现信号被**调频调制**并且知道**符号速率**，你可以使用**与 AM 示例中相同的技术**来获取比特位。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在 HackTricks 中**为你的公司做广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
