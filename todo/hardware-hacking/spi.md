<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 基本信息

SPI（串行外围接口）是一种用于嵌入式系统的同步串行通信协议，用于IC（集成电路）之间的短距离通信。SPI通信协议利用主从架构，由时钟和片选信号进行编排。主从架构包括一个主设备（通常是微处理器），管理外部外设如EEPROM、传感器、控制设备等，这些外设被视为从设备。

一个主设备可以连接多个从设备，但从设备之间无法通信。从设备由时钟和片选两个引脚管理。由于SPI是同步通信协议，输入和输出引脚遵循时钟信号。片选由主设备用于选择从设备并与其交互。当片选为高电平时，从设备未被选中，而当为低电平时，片选已被选中，主设备将与从设备交互。

MOSI（主设备输出，从设备输入）和MISO（主设备输入，从设备输出）负责发送和接收数据。数据通过MOSI引脚发送到从设备，同时片选保持低电平。输入数据包含指令、内存地址或根据从设备供应商的数据表。在有效输入后，MISO引脚负责向主设备传输数据。输出数据在输入结束后的下一个时钟周期准确发送。MISO引脚传输数据直到数据完全传输或主设备将片选引脚设为高电平（在这种情况下，从设备将停止传输，主设备在该时钟周期后将不再监听）。

# 转储Flash

## Bus Pirate + flashrom

![](<../../.gitbook/assets/image (201).png>)

请注意，即使Pirate Bus的PINOUT指示了用于连接SPI的**MOSI**和**MISO**引脚，但有些SPI可能将引脚标记为DI和DO。**MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (648) (1) (1).png>)

在Windows或Linux中，您可以使用程序[**`flashrom`**](https://www.flashrom.org/Flashrom)来转储闪存内存的内容，运行类似以下命令：
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索我们的独家[**NFTs**]收藏品，[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
