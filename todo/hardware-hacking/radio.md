# 无线电

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger)是一个免费的数字信号分析器，适用于GNU/Linux和macOS，旨在提取未知无线电信号的信息。它通过SoapySDR支持多种SDR设备，并允许可调的FSK、PSK和ASK信号解调，解码模拟视频，分析突发信号，并实时收听模拟语音频道。

### 基本配置

安装后，有几件事情您可能会考虑配置。\
在设置中（第二个标签按钮），您可以选择**SDR设备**或**选择一个文件**来读取，以及要同步的频率和采样率（如果您的PC支持，建议提高到2.56Msps）\\

![](<../../.gitbook/assets/image (655) (1).png>)

在GUI行为中，如果您的PC支持，建议启用一些功能：

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
如果您发现您的PC没有捕获到东西，请尝试禁用OpenGL并降低采样率。
{% endhint %}

### 用途

* 只是为了**捕获一段时间的信号并分析它**，只需按住“按下以捕获”按钮，直到您需要为止。

![](<../../.gitbook/assets/image (631).png>)

* **SigDigger的调谐器**有助于**更好地捕获信号**（但也可能会降低信号质量）。理想情况下从0开始，不断**增大**，直到您发现引入的**噪声**大于您需要的信号**改善**为止。

![](<../../.gitbook/assets/image (658).png>)

### 与无线电频道同步

使用[**SigDigger**](https://github.com/BatchDrake/SigDigger)与您想要收听的频道同步，配置“基带音频预览”选项，配置带宽以获取所有被发送的信息，然后将调谐器设置到噪声真正开始增加之前的水平：

![](<../../.gitbook/assets/image (389).png>)

## 有趣的技巧

* 当设备发送信息突发时，通常**第一部分将是前导码**，所以如果您在那里**找不到信息**或存在一些错误，您**不需要担心**。
* 在信息帧中，您通常应该**找到不同的帧彼此对齐**：

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **恢复比特后，您可能需要以某种方式处理它们**。例如，在曼彻斯特编码中，上升+下降将是1或0，下降+上升将是另一个。因此，1和0的对（上升和下降）将是真正的1或0。
* 即使信号使用曼彻斯特编码（不可能连续找到超过两个0或1），您可能会在前导码中**找到几个连续的1或0**！

### 使用IQ揭示调制类型

有3种在信号中存储信息的方式：调制**幅度**、**频率**或**相位**。\
如果您正在检查一个信号，有不同的方法尝试弄清楚哪种方式被用来存储信息（下面有更多方法），但一个好方法是检查IQ图。

![](<../../.gitbook/assets/image (630).png>)

* **检测AM**：如果在IQ图中出现例如**两个圆圈**（可能一个在0处，另一个在不同的幅度处），这可能意味着这是一个AM信号。这是因为在IQ图中，0点和圆圈之间的距离是信号的幅度，因此很容易可视化正在使用的不同幅度。
* **检测PM**：如前图所示，如果您发现彼此不相关的小圆圈，这可能意味着使用了相位调制。这是因为在IQ图中，点和0,0之间的角度是信号的相位，所以这意味着使用了4个不同的相位。
* 请注意，如果信息隐藏在相位变化的事实中，而不是相位本身，您将不会清楚地看到不同的相位。
* **检测FM**：IQ没有识别频率的字段（中心距离是幅度，角度是相位）。\
因此，要识别FM，您应该**只在这个图中基本上看到一个圆圈**。\
此外，不同的频率在IQ图中是通过**圆圈上的速度加速**来“表示”的（所以在SysDigger中选择信号，IQ图被填充，如果您发现在创建的圆圈中有加速或方向变化，这可能意味着这是FM）：

## AM示例

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### 揭示AM

#### 检查包络

使用[**SigDigger**](https://github.com/BatchDrake/SigDigger)检查AM信息，只需查看**包络**，您就可以看到不同的清晰幅度级别。所使用的信号在AM中发送带有信息的脉冲，这是一个脉冲的样子：

![](<../../.gitbook/assets/image (636).png>)

这是符号部分的样子，带有波形：

![](<../../.gitbook/assets/image (650) (1).png>)

#### 检查直方图

您可以**选择整个信号**，其中包含信息，选择**幅度**模式和**选择**，然后点击**直方图**。您可以观察到只有2个清晰的级别

![](<../../.gitbook/assets/image (647) (1) (1).png>)

例如，如果您在这个AM信号中选择频率而不是幅度，您会发现只有1个频率（用一个频率调制的信息不可能只使用1个频率）。

![](<../../.gitbook/assets/image (637) (1) (1).png>)

如果您发现很多频率，这可能不是FM，可能是信号频率因为信道而被修改了。

#### 使用IQ

在这个例子中，您可以看到有一个**大圆圈**，但也有**很多点在中心**。

![](<../../.gitbook/assets/image (640).png>)

### 获取符号率

#### 一个符号

选择您能找到的最小的符号（这样您就可以确定它只是1个），并检查“选择频率”。在这种情况下，它将是1.013kHz（所以是1kHz）。

![](<../../.gitbook/assets/image (638) (1).png>)

#### 一组符号

您还可以指示您将选择的符号数量，SigDigger将计算1个符号的频率（选择的符号越多，可能越好）。在这种情况下，我选择了10个符号，“选择频率”是1.004 Khz：

![](<../../.gitbook/assets/image (635).png>)

### 获取比特

找到这是一个**AM调制**信号和**符号率**（并且知道在这种情况下，上升意味着1，下降意味着0），很容易**获取**信号中编码的比特。因此，选择带有信息的信号并配置采样和决策，然后按采样（检查是否选择了**幅度**，配置了发现的**符号率**，并且选择了**Gadner时钟恢复**）：

![](<../../.gitbook/assets/image (642) (1).png>)

* **同步到选择间隔**意味着如果您之前选择了间隔来找到符号率，那么将使用该符号率。
* **手动**意味着将使用指示的符号率
* 在**固定间隔选择**中，您指示应选择的间隔数量，它会从中计算符号率
* **Gadner时钟恢复**通常是最好的选择，但您仍然需要指示一些大致的符号率。

按下采样后，会出现这样的情况：

![](<../../.gitbook/assets/image (659).png>)

现在，为了让SigDigger理解**携带信息的级别范围在哪里**，您需要点击**较低级别**并保持点击，直到最大级别：

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

如果例如有**4个不同的幅度级别**，您应该需要将**每个符号的比特数配置为2**，并从最小到最大选择。

最后，**增加** **缩放**和**更改行大小**，您可以看到比特（您可以选择全部并复制以获取所有比特）：

![](<../../.gitbook/assets/image (649) (1).png>)

如果信号每个符号有多于1个比特（例如2个），SigDigger**无法知道哪个符号是** 00、01、10、11，所以它会使用不同的**灰度**来表示每个（如果您复制比特，它会使用**从0到3的数字**，您需要处理它们）。

此外，使用**编码**，如**曼彻斯特**，**上升+下降**可以是**1或0**，下降+上升可以是1或0。在这些情况下，您需要**处理获得的上升（1）和下降（0）**，将01或10的对替换为0或1。

## FM示例

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### 揭示FM

#### 检查频率和波形

发送FM调制信息的信号示例：

![](<../../.gitbook/assets/image (661) (1).png>)

在前面的图像中，您可以很好地观察到**使用了2个频率**，但如果您**观察** **波形**，您可能**无法正确识别2个不同的频率**：

![](<../../.gitbook/assets/image (653).png>)

这是因为我在两个频率上捕获了信号，因此一个大约是另一个的负数：

![](<../../.gitbook/assets/image (656).png>)

如果同步频率**更接近一个频率而不是另一个**，您可以很容易地看到2个不同的频率：

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### 检查直方图

检查带有信息的信号的频率直方图，您可以很容易地看到2个不同的信号：

![](<../../.gitbook/assets/image (657).png>)

在这种情况下，如果您检查**幅度直方图**，您会发现**只有一个幅度**，所以它**不能是AM**（如果您发现很多幅度，可能是因为信号在信道中失去了功率）：

![](<../../.gitbook/assets/image (646).png>)

这是相位直方图（非常清楚地表明信号没有在相位上调制）：

![](<../../.gitbook/assets/image (201) (2).png>)

#### 使用IQ

IQ没有识别频率的字段（中心距离是幅度，角度是相位）。\
因此，要识别FM，您应该**只在这个图中基本上看到一个圆圈**。\
此外，不同的频率在IQ图中是通过**圆圈上的速度加速**来“表示”的（所以在SysDigger中选择信号，IQ图被填充，如果您发现在创建的圆圈中有加速或方向变化，这可能意味着这是FM）：

![](<../../.gitbook/assets/image (643) (1).png>)

### 获取符号率

一旦您找到了携带符号的频率，您可以使用**与AM示例中相同的技术**来获取符号率。

### 获取比特

一旦您**发现信号是频率调制的**并且找到了**符号率**，您可以使用**与AM示例中相同的技术**来获取比特。

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/c
