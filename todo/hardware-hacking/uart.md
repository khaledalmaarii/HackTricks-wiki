<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# 基本信息

UART是一种串行协议，意味着它以一位一次的方式在组件之间传输数据。相比之下，并行通信协议通过多个通道同时传输数据。常见的串行协议包括RS-232、I2C、SPI、CAN、Ethernet、HDMI、PCI Express和USB。

通常情况下，当UART处于空闲状态时，线路保持高电平（逻辑1）。然后，为了表示数据传输的开始，发送器向接收器发送一个起始位，此时信号保持低电平（逻辑0）。接下来，发送器发送包含实际消息的五到八个数据位，后跟一个可选的奇偶校验位和一个或两个停止位（逻辑1），具体取决于配置。奇偶校验位用于错误检查，在实践中很少见。停止位（或位）表示传输的结束。

我们将最常见的配置称为8N1：八个数据位，无奇偶校验，一个停止位。例如，如果我们想要在8N1 UART配置中发送字符C，或者在ASCII中表示为0x43，我们将发送以下位：0（起始位）；0、1、0、0、0、0、1、1（0x43的二进制值）；0（停止位）。

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

与UART通信的硬件工具：

* USB转串口适配器
* 带有CP2102或PL2303芯片的适配器
* 通用工具，如：Bus Pirate、Adafruit FT232H、Shikra或Attify Badge

## 识别UART端口

UART有4个端口：**TX**（发送）、**RX**（接收）、**Vcc**（电压）和**GND**（地线）。你可能能够在PCB上找到带有**`TX`**和**`RX`**字样的4个端口。但如果没有指示，你可能需要使用万用表或逻辑分析仪自己找到它们。

使用万用表和设备关闭电源：

* 使用**连续性测试**模式来识别**GND**引脚，将后导线放入地线并用红色导线进行测试，直到听到万用表发出声音。PCB上可能有多个GND引脚，所以你可能已经找到了UART引脚，也可能没有找到。
* 要识别**VCC端口**，设置**直流电压模式**并将其设置为20V电压。黑色探针接地，红色探针接引脚。打开设备电源。如果万用表测量到恒定的3.3V或5V电压，说明你找到了Vcc引脚。如果得到其他电压，请尝试其他端口。
* 要识别**TX端口**，将**直流电压模式**设置为20V电压，黑色探针接地，红色探针接引脚，并打开设备电源。如果你发现电压在几秒钟内波动，然后稳定在Vcc值上，那么你很可能找到了TX端口。这是因为在上电时，它会发送一些调试数据。
* **RX端口**将是离其他3个端口最近的一个，它的电压波动最小，所有UART引脚中的总体值最低。

你可以混淆TX和RX端口，不会发生任何事情，但如果混淆GND和VCC端口，可能会烧毁电路。

使用逻辑分析仪：

## 识别UART波特率

识别正确的波特率最简单的方法是查看**TX引脚的输出并尝试读取数据**。如果接收到的数据无法读取，请切换到下一个可能的波特率，直到数据可读为止。你可以使用USB转串口适配器或Bus Pirate等多功能设备，配合辅助脚本（例如[baudrate.py](https://github.com/devttys0/baudrate/)），来完成这个操作。最常见的波特率是9600、38400、19200、57600和115200。

{% hint style="danger" %}
重要提示：在此协议中，你需要将一个设备的TX连接到另一个设备的RX！
{% endhint %}
# 总线海盗

在这个场景中，我们将嗅探Arduino的UART通信，该通信将程序的所有打印信息发送到串行监视器。
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
