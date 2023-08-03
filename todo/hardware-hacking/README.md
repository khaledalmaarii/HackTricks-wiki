<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家 **网络安全公司** 工作吗？想要在 HackTricks 中看到你的 **公司广告**吗？或者想要获得 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass)，或者在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>


#

# JTAG

JTAG 允许进行边界扫描。边界扫描分析特定电路，包括每个引脚的嵌入式边界扫描单元和寄存器。

JTAG 标准定义了进行边界扫描的**特定命令**，包括以下内容：

* **BYPASS** 允许你在不经过其他芯片的开销下测试特定芯片。
* **SAMPLE/PRELOAD** 在设备处于正常工作模式时，对进出设备的数据进行采样。
* **EXTEST** 设置和读取引脚状态。

它还可以支持其他命令，例如：

* **IDCODE** 用于识别设备
* **INTEST** 用于对设备进行内部测试

当你使用 JTAGulator 等工具时，可能会遇到这些指令。

## 测试访问端口

边界扫描包括对四线 **测试访问端口 (TAP)** 进行测试，这是一个通用端口，提供对组件内置的 JTAG 测试支持功能的访问。TAP 使用以下五个信号：

* 测试时钟输入 (**TCK**) TCK 是定义 TAP 控制器何时执行单个操作（换句话说，跳转到状态机的下一个状态）的时钟。
* 测试模式选择 (**TMS**) 输入 TMS 控制有限状态机。在每个时钟节拍中，设备的 JTAG TAP 控制器检查 TMS 引脚上的电压。如果电压低于某个阈值，则将信号视为低电平并解释为 0，如果电压高于某个阈值，则将信号视为高电平并解释为 1。
* 测试数据输入 (**TDI**) TDI 是通过扫描单元将数据发送到芯片的引脚。每个供应商负责定义此引脚上的通信协议，因为 JTAG 不定义此协议。
* 测试数据输出 (**TDO**) TDO 是将数据发送到芯片外部的引脚。
* 测试复位 (**TRST**) 输入 可选的 TRST 将有限状态机重置为已知的良好状态。或者，如果 TMS 在连续五个时钟周期内保持为 1，则会调用重置，方式与 TRST 引脚相同，这就是 TRST 是可选的原因。

有时你可以在 PCB 上找到这些引脚的标记。在其他情况下，你可能需要**找到它们**。

## 识别 JTAG 引脚

检测 JTAG 端口最快但最昂贵的方法是使用专门用于此目的的设备 **JTAGulator**（尽管它也可以**检测 UART 引脚**）。

它有 **24 个通道**，你可以连接到电路板的引脚上。然后，它对所有可能的组合执行 **IDCODE** 和 **BYPASS** 边界扫描命令的 BF 攻击。如果收到响应，它会显示与每个 JTAG 信号对应的通道。

识别 JTAG 引脚的一种更便宜但速度较慢的方法是使用加载在兼容 Arduino 微控制器上的 [**JTAGenum**](https://github.com/cyphunk/JTAGenum/)。

使用 **JTAGenum**，你首先需要**定义探测设备的引脚**，这些引脚将用于枚举。你需要参考设备的引脚图，并将这些引脚与目标设备上的测试点连接起来。

识别 JTAG 引脚的第三种方法是通过**检查 PCB** 来找到其中一个引脚。在某些情况下，PCB 可能会方便地提供 **Tag-Connect 接口**，这清楚地表明该板子有一个 JTAG 连接器。你可以在 [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/) 上看到该接口的样子。此外，检查 PCB 上芯片组的 **数据手册**可能会揭示指向 JTAG 接口的引脚图。

# SDW

SWD 是一种专为调试而设计的 ARM 特定协议。

SWD 接口需要 **两个引脚**：一个双向的 **SWDIO** 信号，相当于 JTAG 的 **TDI 和 TDO 引脚**，以及一个时钟 **SWCLK**，相当于 JTAG 的 **TCK**。许多设备支持 **串行线或 JTAG 调试端口 (SWJ-DP)**，这是一个组合的 JTAG 和 SWD 接口，使你可以将 SWD 或 JTAG 探针连接到目标设备上。
- **加入** [💬](https://emojipedia.org/speech-balloon/) [Discord 群组](https://discord.gg/hRep4RUj7f) 或 [Telegram 群组](https://t.me/peass) 或在 Twitter 上 **关注我** [🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[@carlospolopm](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
