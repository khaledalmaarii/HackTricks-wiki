# SPI

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

SPI（串行外围接口）是一种用于嵌入式系统的同步串行通信协议，用于IC（集成电路）之间的短距离通信。SPI通信协议利用由时钟和片选信号编排的主从架构。主从架构包括一个主设备（通常是微处理器），负责管理外部外设，如EEPROM、传感器、控制设备等，这些外设被视为从设备。

一个主设备可以连接多个从设备，但从设备之间无法直接通信。从设备由时钟和片选两个引脚管理。由于SPI是一种同步通信协议，输入和输出引脚遵循时钟信号。片选由主设备用于选择从设备并与其交互。当片选为高电平时，从设备未被选中，而当片选为低电平时，片选已被选中，主设备将与从设备交互。

MOSI（主设备输出，从设备输入）和MISO（主设备输入，从设备输出）负责发送和接收数据。数据通过MOSI引脚发送到从设备，同时片选保持低电平。输入数据包含从设备供应商数据表中的指令、内存地址或数据。在接收到有效输入后，MISO引脚负责向主设备传输数据。输出数据将在输入结束后的下一个时钟周期准确发送。MISO引脚传输数据直到数据完全传输或主设备将片选引脚置为高电平（在这种情况下，从设备将停止传输，主设备在该时钟周期后将不再监听）。

## 从EEPROM中转储固件

从EEPROM中转储固件对于分析固件并发现其中的漏洞非常有用。通常情况下，固件在互联网上不可用，或者由于诸如型号、版本等因素的变化而变得无关紧要。因此，直接从物理设备中提取固件可以帮助在寻找威胁时更具体。

获取串行控制台可能很有帮助，但通常情况下，文件是只读的。由于各种原因，这会限制分析。例如，固件中可能没有发送和接收数据包所需的工具。因此，将二进制文件提取出来以进行逆向工程是不可行的。因此，在系统上转储整个固件并提取用于分析的二进制文件可能非常有帮助。

此外，在进行红队渗透测试并获得物理设备访问权限时，转储固件可以帮助修改文件或注入恶意文件，然后将其重新刷入内存，这有助于在设备中植入后门。因此，固件转储可以解锁许多可能性。

### CH341A EEPROM编程器和读卡器

该设备是一种廉价工具，可用于从EEPROM中转储固件，并使用固件文件重新刷写它们。这已成为处理计算机BIOS芯片（仅为EEPROM）的热门选择。该设备通过USB连接，需要最少的工具即可开始使用。此外，它通常可以快速完成任务，因此在物理设备访问中也可能很有帮助。

将EEPROM存储器与CH341a编程器连接，并将设备插入计算机。如果设备未被检测到，请尝试在计算机上安装驱动程序。此外，请确保EEPROM以正确的方向连接（通常，将VCC引脚放置在与USB连接器相反的方向）否则，软件将无法检测到芯片。如有需要，请参考下图：

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

最后，使用flashrom、G-Flash（GUI）等软件来转储固件。G-Flash是一个简单的GUI工具，快速检测EEPROM。这对于快速提取固件可能非常有帮助，而无需过多研究文档。

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

转储固件后，可以对二进制文件进行分析。可以使用诸如strings、hexdump、xxd、binwalk等工具来提取有关固件以及整个文件系统的大量信息。

要从固件中提取内容，可以使用binwalk。Binwalk分析十六进制签名并识别二进制文件中的文件，并能够提取它们。
```
binwalk -e <filename>
```
固件可以是根据使用的工具和配置而定的 .bin 或 .rom 文件。

{% hint style="danger" %}
请注意，固件提取是一个细致的过程，需要耐心等待。任何处理不当都有可能损坏固件，甚至完全擦除固件并使设备无法使用。建议在尝试提取固件之前先研究具体设备。
{% endhint %}

### 怪盗客 + flashrom

![](<../../.gitbook/assets/image (910).png>)

请注意，即使怪盗客的 PINOUT 指示了用于连接到 SPI 的 **MOSI** 和 **MISO** 引脚，但有些 SPI 可能将引脚标记为 DI 和 DO。**MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

在 Windows 或 Linux 中，您可以使用 [**`flashrom`**](https://www.flashrom.org/Flashrom) 程序来转储闪存内存的内容，运行类似以下命令：
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

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
