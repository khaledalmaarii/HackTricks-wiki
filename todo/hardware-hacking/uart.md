<details>

<summary><strong>从零到英雄学习AWS黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>


# 基本信息

UART是一种串行协议，这意味着它一次传输一个比特的数据。与此相反，并行通信协议通过多个通道同时传输数据。常见的串行协议包括RS-232、I2C、SPI、CAN、以太网、HDMI、PCI Express和USB。

通常情况下，当UART处于空闲状态时，线路保持高电平（逻辑1值）。然后，为了标志数据传输的开始，发送器向接收器发送一个开始位，在此期间信号保持低电平（逻辑0值）。接下来，发送器发送五到八个数据位，包含实际消息，然后是一个可选的奇偶校验位和一个或两个停止位（逻辑1值），具体取决于配置。奇偶校验位用于错误检查，在实践中很少见。停止位（或位）标志着传输的结束。

我们称最常见的配置为8N1：八个数据位，无奇偶校验，一个停止位。例如，如果我们想要以8N1 UART配置发送字符C，或ASCII中的0x43，我们将发送以下比特：0（开始位）；0, 1, 0, 0, 0, 0, 1, 1（0x43的二进制值），和1（停止位）。

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

与UART通信的硬件工具：

* USB转串行适配器
* 带有CP2102或PL2303芯片的适配器
* 多功能工具，如：Bus Pirate、Adafruit FT232H、Shikra或Attify Badge

## 识别UART端口

UART有4个端口：**TX**(发送)，**RX**(接收)，**Vcc**(电压)，和**GND**(地线)。您可能能够在PCB上找到带有**`TX`** 和 **`RX`** 字母**标记**的4个端口。但如果没有标示，您可能需要使用**万用表**或**逻辑分析仪**自己找到它们。

使用**万用表**且设备关闭时：

* 要识别**GND**引脚，请使用**连续性测试**模式，将黑色探头插入地线并用红色探头测试，直到您听到万用表发出声音。PCB上可以找到几个GND引脚，所以您可能找到了或没有找到属于UART的那个。
* 要识别**VCC端口**，设置**直流电压模式**并将其设置为20V电压。黑色探头接地，红色探头接引脚。打开设备电源。如果万用表测量到恒定的3.3V或5V电压，您就找到了Vcc引脚。如果您得到其他电压，请重试其他端口。
* 要识别**TX端口**，**直流电压模式**设置为20V电压，黑色探头接地，红色探头接引脚，并打开设备电源。如果您发现电压在几秒钟内波动然后稳定在Vcc值，您很可能找到了TX端口。这是因为在开机时，它会发送一些调试数据。
* **RX端口**将是最接近其他三个的，它有最小的电压波动和所有UART引脚中最低的总体值。

您可能会混淆TX和RX端口，而不会发生任何事情，但如果您混淆了GND和VCC端口，您可能会烧毁电路。

使用逻辑分析仪：

## 识别UART波特率

识别正确波特率的最简单方法是查看**TX引脚的输出并尝试读取数据**。如果您收到的数据不可读，请切换到下一个可能的波特率，直到数据变得可读。您可以使用USB转串行适配器或像Bus Pirate这样的多功能设备来做到这一点，配合辅助脚本，如[baudrate.py](https://github.com/devttys0/baudrate/)。最常见的波特率是9600、38400、19200、57600和115200。

{% hint style="danger" %}
重要的是要注意，在这个协议中，您需要将一个设备的TX连接到另一个设备的RX！
{% endhint %}

# Bus Pirate

在这个场景中，我们将嗅探Arduino的UART通信，它正在将程序的所有打印发送到串行监视器。
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

<summary><strong>从零开始学习AWS黑客攻击直至成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
