<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击成为英雄！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>


#

# JTAG

JTAG允许执行边界扫描。边界扫描分析特定电路，包括嵌入式边界扫描单元和每个引脚的寄存器。

JTAG标准定义了**用于进行边界扫描的特定命令**，包括以下内容：

* **BYPASS** 允许您测试特定芯片，无需经过其他芯片的开销。
* **SAMPLE/PRELOAD** 在设备正常工作模式下，采样进入和离开设备的数据。
* **EXTEST** 设置并读取引脚状态。

它还可以支持其他命令，例如：

* **IDCODE** 用于识别设备
* **INTEST** 用于设备的内部测试

使用像JTAGulator这样的工具时，您可能会遇到这些指令。

## 测试访问端口

边界扫描包括对四线**测试访问端口（TAP）**的测试，这是一个通用端口，提供了对组件内置的**JTAG测试支持**功能的**访问**。TAP使用以下五个信号：

* 测试时钟输入（**TCK**）TCK是**时钟**，定义了TAP控制器多久采取一次动作（换句话说，跳转到状态机中的下一个状态）。
* 测试模式选择（**TMS**）输入 TMS控制**有限状态机**。在时钟的每个节拍上，设备的JTAG TAP控制器都会检查TMS引脚上的电压。如果电压低于某个阈值，则信号被认为是低电平并解释为0，而如果电压高于某个阈值，则信号被认为是高电平并解释为1。
* 测试数据输入（**TDI**）TDI是将**数据通过扫描单元发送到芯片内部**的引脚。每个供应商负责定义此引脚上的通信协议，因为JTAG没有定义这一点。
* 测试数据输出（**TDO**）TDO是将**数据从芯片发送出去**的引脚。
* 测试重置（**TRST**）输入 可选的TRST将有限状态机重置为**已知的良好状态**。或者，如果TMS连续五个时钟周期保持为1，则会调用重置，就像TRST引脚那样，这就是为什么TRST是可选的。

有时您会在PCB上找到这些引脚标记。在其他情况下，您可能需要**找到它们**。

## 识别JTAG引脚

检测JTAG端口的最快但最昂贵的方法是使用**JTAGulator**，这是一种专门为此目的创建的设备（尽管它也可以**检测UART引脚排列**）。

它有**24个通道**，您可以连接到板上的引脚。然后它执行**BF攻击**，发送**IDCODE**和**BYPASS**边界扫描命令的所有可能组合。如果它收到响应，它会显示对应于每个JTAG信号的通道

一种更便宜但速度慢得多的识别JTAG引脚排列的方法是使用加载在Arduino兼容微控制器上的[**JTAGenum**](https://github.com/cyphunk/JTAGenum/)。

使用**JTAGenum**，您首先需要**定义探测**设备的引脚，然后将这些引脚与目标设备的测试点连接起来。

**第三种**识别JTAG引脚的方法是**检查PCB**以寻找其中一个引脚排列。在某些情况下，PCB可能方便地提供**Tag-Connect接口**，这明确表明该板也有JTAG连接器。您可以在[https://www.tag-connect.com/info/](https://www.tag-connect.com/info/)查看该接口的样子。此外，检查PCB上芯片组的**数据手册**可能会揭示指向JTAG接口的引脚排列图。

# SDW

SWD是ARM特有的用于调试的协议。

SWD接口需要**两个引脚**：双向**SWDIO**信号，相当于JTAG的**TDI和TDO引脚和时钟**，以及**SWCLK**，相当于JTAG中的**TCK**。许多设备支持**串行线或JTAG调试端口（SWJ-DP）**，这是一个结合了JTAG和SWD接口的接口，使您可以将SWD或JTAG探针连接到目标设备。


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击成为英雄！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
