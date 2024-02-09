<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


#

# JTAG

JTAG允许执行边界扫描。边界扫描分析特定电路，包括每个引脚的嵌入式边界扫描单元和寄存器。

JTAG标准定义了进行边界扫描的**特定命令**，包括以下内容：

* **BYPASS** 允许您在不经过其他芯片的开销的情况下测试特定芯片。
* **SAMPLE/PRELOAD** 在设备处于正常工作模式时，获取进入和离开设备的数据样本。
* **EXTEST** 设置和读取引脚状态。

它还可以支持其他命令，例如：

* **IDCODE** 用于识别设备
* **INTEST** 用于设备的内部测试

当您使用类似JTAGulator的工具时，您可能会遇到这些指令。

## 测试访问端口

边界扫描包括对四线**测试访问端口（TAP）**的测试，这是一个通用端口，提供了内置于组件中的JTAG测试支持功能的**访问**。TAP使用以下五个信号：

* 测试时钟输入（**TCK**）TCK是定义TAP控制器何时执行单个操作（换句话说，在状态机中跳转到下一个状态）的**时钟**。
* 测试模式选择（**TMS**）输入TMS控制**有限状态机**。在每个时钟节拍中，设备的JTAG TAP控制器检查TMS引脚上的电压。如果电压低于某个阈值，则信号被视为低电平并解释为0，而如果电压高于某个阈值，则信号被视为高电平并解释为1。
* 测试数据输入（**TDI**）TDI是通过扫描单元将数据发送到芯片的引脚。每个供应商负责定义通过此引脚的通信协议，因为JTAG没有定义这一点。
* 测试数据输出（**TDO**）TDO是将数据发送**从芯片**输出的引脚。
* 测试复位（**TRST**）输入可选的TRST将有限状态机**重置为已知的良好状态**。或者，如果TMS保持在1状态下连续五个时钟周期，它会调用重置，就像TRST引脚一样，这就是为什么TRST是可选的。

有时您可以在PCB上找到标记了这些引脚。在其他情况下，您可能需要**找到它们**。

## 识别JTAG引脚

检测JTAG端口的最快但最昂贵的方法是使用**JTAGulator**，这是专门为此目的创建的设备（尽管它也可以**检测UART引脚布局**）。

它有**24个通道**，您可以连接到板上的引脚。然后，它对所有可能的组合执行**BF攻击**，发送**IDCODE**和**BYPASS**边界扫描命令。如果收到响应，它会显示与每个JTAG信号对应的通道。

识别JTAG引脚的更便宜但速度较慢的方法是使用加载在兼容Arduino微控制器上的[JTAGenum](https://github.com/cyphunk/JTAGenum/)。

使用**JTAGenum**，您首先需要**定义用于枚举的探测设备的引脚**。您需要参考设备的引脚图，并将这些引脚与目标设备上的测试点连接起来。

识别JTAG引脚的**第三种方法**是通过**检查PCB**以找到其中一个引脚布局。在某些情况下，PCB可能会方便地提供**Tag-Connect接口**，这清楚地表明该板具有JTAG连接器。您可以在[https://www.tag-connect.com/info/](https://www.tag-connect.com/info/)上查看该接口的外观。此外，检查PCB上芯片组的**数据表**可能会显示指向JTAG接口的引脚布局。

# SDW

SWD是专为调试而设计的ARM特定协议。

SWD接口需要**两个引脚**：一个是双向**SWDIO**信号，相当于JTAG的**TDI和TDO引脚和一个时钟**，即**SWCLK**，相当于JTAG中的**TCK**。许多设备支持**串行线或JTAG调试端口（SWJ-DP）**，这是一个结合了JTAG和SWD接口的接口，使您可以将SWD或JTAG探针连接到目标设备。

</details>
