# UART

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)是一个由**暗网**推动的搜索引擎，提供**免费**功能，用于检查公司或其客户是否受到**窃取恶意软件**的**侵害**。

WhiteIntel的主要目标是打击由信息窃取恶意软件导致的账户劫持和勒索软件攻击。

您可以访问他们的网站并免费尝试他们的引擎：

{% embed url="https://whiteintel.io" %}

---

## 基本信息

UART是一种串行协议，意味着它一次传输一个比特的数据。相比之下，并行通信协议通过多个通道同时传输数据。常见的串行协议包括RS-232、I2C、SPI、CAN、Ethernet、HDMI、PCI Express和USB。

通常，在UART处于空闲状态时，线路保持高电平（逻辑1值）。然后，为了表示数据传输的开始，发送器向接收器发送起始位，在此期间信号保持低电平（逻辑0值）。接下来，发送器发送包含实际消息的五到八个数据位，然后是一个可选的奇偶校验位和一个或两个停止位（逻辑1值），具体取决于配置。奇偶校验位用于错误检查，在实践中很少见。停止位（或位）表示传输结束。

我们称最常见的配置为8N1：八个数据位，无奇偶校验，一个停止位。例如，如果我们想要在8N1 UART配置中发送字符C，或ASCII中的0x43，我们将发送以下位：0（起始位）；0、1、0、0、0、0、1、1（二进制0x43的值），以及0（停止位）。

![](<../../.gitbook/assets/image (761).png>)

与UART通信的硬件工具：

* USB转串口适配器
* 带有CP2102或PL2303芯片的适配器
* 多功能工具，如：Bus Pirate、Adafruit FT232H、Shikra或Attify Badge

### 识别UART端口

UART有4个端口：**TX**（发送）、**RX**（接收）、**Vcc**（电压）和**GND**（地）。您可能会在PCB上找到带有**`TX`**和**`RX`**字样的4个端口。但如果没有指示，您可能需要使用万用表或逻辑分析仪自行查找。

使用**万用表**和关闭设备：

* 使用**连续性测试**模式来识别**GND**引脚，将后端插入地线并用红色探针测试，直到听到万用表发出声音。PCB上可能有几个GND引脚，因此您可能已经找到或未找到属于UART的引脚。
* 要识别**VCC端口**，设置**直流电压模式**并将其设置为20V电压。黑色探针接地，红色探针接引脚。打开设备电源。如果万用表测量到3.3V或5V的恒定电压，则找到了Vcc引脚。如果获得其他电压，请尝试其他端口。
* 要识别**TX** **端口**，**直流电压模式**最高20V电压，黑色探针接地，红色探针接引脚，打开设备电源。如果发现电压在几秒钟内波动，然后稳定在Vcc值，您很可能找到了TX端口。这是因为在上电时，它会发送一些调试数据。
* **RX端口**将是其他3个端口中最接近的一个，其电压波动最小，总体值最低。

您可能会混淆TX和RX端口，什么也不会发生，但如果混淆GND和VCC端口，可能会烧毁电路。

在某些目标设备中，制造商通过禁用RX或TX甚至两者中的一个来禁用UART端口。在这种情况下，追踪电路板中的连接并找到一些分支点可能会有所帮助。关于确认未检测到UART和电路断开的一个强烈提示是检查设备保修。如果设备已经附带了一些保修，制造商会留下一些调试接口（在本例中为UART），因此必须已经断开了UART，并且在调试时会重新连接。这些分支引脚可以通过焊接或跳线线连接。

### 识别UART波特率

识别正确波特率的最简单方法是查看**TX引脚的输出并尝试读取数据**。如果收到的数据无法读取，请切换到下一个可能的波特率，直到数据可读。您可以使用USB转串口适配器或与辅助脚本配对的多功能设备（如Bus Pirate）来执行此操作，例如[baudrate.py](https://github.com/devttys0/baudrate/)。最常见的波特率是9600、38400、19200、57600和115200。

{% hint style="danger" %}
重要提示：在此协议中，您需要将一个设备的TX连接到另一个设备的RX！
{% endhint %}

## CP210X UART转TTY适配器

CP210X芯片用于许多原型板，如NodeMCU（带有esp8266）用于串行通信。这些适配器相对便宜，可用于连接到目标的UART接口。该设备有5个引脚：5V、GND、RXD、TXD、3.3V。确保将电压连接到目标支持的电压，以避免任何损坏。最后，将适配器的RXD引脚连接到目标的TXD，将适配器的TXD引脚连接到目标的RXD。

如果适配器未被检测到，请确保在主机系统中安装了CP210X驱动程序。一旦检测到并连接了适配器，可以使用picocom、minicom或screen等工具。

要列出连接到Linux/MacOS系统的设备：
```
ls /dev/
```
对于与UART接口的基本交互，请使用以下命令：
```
picocom /dev/<adapter> --baud <baudrate>
```
对于minicom，使用以下命令进行配置：
```
minicom -s
```
配置`串行端口设置`选项中的波特率和设备名称等设置。

配置完成后，使用`minicom`命令启动UART控制台。

## 通过Arduino UNO R3进行UART连接（可拆卸Atmel 328p芯片板）

如果没有UART串行到USB适配器可用，可以通过快速hack使用Arduino UNO R3。由于Arduino UNO R3通常随处可得，这可以节省大量时间。

Arduino UNO R3板上已经内置了USB到串行适配器。要获得UART连接，只需从板上拔下Atmel 328p微控制器芯片。这个hack适用于Arduino UNO R3变种，其上未焊接Atmel 328p芯片（SMD版本）。将Arduino的RX引脚（数字引脚0）连接到UART接口的TX引脚，将Arduino的TX引脚（数字引脚1）连接到UART接口的RX引脚。

最后，建议使用Arduino IDE获取串行控制台。在菜单中的`工具`部分中，选择`串行控制台`选项，并根据UART接口设置波特率。

## 怪盗船长

在这种情况下，我们将窃取Arduino的UART通信，该通信将所有程序打印发送到串行监视器。
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
## 使用UART控制台转储固件

UART控制台为在运行时环境中处理底层固件提供了一个很好的方式。但是当UART控制台访问是只读时，可能会引入很多限制。在许多嵌入式设备中，固件存储在EEPROM中，并在具有易失性内存的处理器中执行。因此，固件保持为只读，因为在制造过程中原始固件就在EEPROM中，任何新文件都会由于易失性内存而丢失。因此，在处理嵌入式固件时，转储固件是一项有价值的工作。

有很多方法可以做到这一点，SPI部分涵盖了使用各种设备直接从EEPROM提取固件的方法。尽管如此，建议首先尝试使用UART转储固件，因为使用物理设备和外部交互来转储固件可能存在风险。

从UART控制台转储固件需要首先访问引导加载程序。许多知名供应商使用<u>uboot</u>（通用引导加载程序）作为加载Linux的引导加载程序，因此访问<u>uboot</u>是必要的。

要访问<u>boot</u>引导加载程序，请将UART端口连接到计算机，并使用任何串行控制台工具，同时保持设备的电源断开。设置准备就绪后，按下回车键并保持按住。最后，连接设备的电源并让其引导。

这样做将中断<u>uboot</u>的加载并提供一个菜单。建议了解<u>uboot</u>命令并使用帮助菜单列出它们。这可能是`help`命令。由于不同供应商使用不同的配置，有必要分别了解每个配置。

通常，转储固件的命令是：
```
md
```
这代表“内存转储”。这将在屏幕上转储内存（EEPROM 内容）。建议在开始过程之前记录串行控制台输出以捕获内存转储。

最后，只需从日志文件中剥离所有不必要的数据，并将文件存储为 `filename.rom`，然后使用 binwalk 提取内容：
```
binwalk -e <filename.rom>
```
这将列出根据在十六进制文件中找到的签名可能的EEPROM内容。

尽管如此，需要注意的是，即使正在使用，也不总是情况下<b>uboot</b>已解锁。如果按Enter键没有任何反应，请检查不同的键，如空格键等。如果引导加载程序已锁定且未被中断，则此方法将无效。要检查<b>uboot</b>是否为设备的引导加载程序，请在设备启动时检查UART控制台上的输出。在启动时可能会提到<b>uboot</b>。

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)是一个由**暗网**推动的搜索引擎，提供**免费**功能，以检查公司或其客户是否已受到**窃取恶意软件**的**损害**。

WhiteIntel的主要目标是打击由窃取信息恶意软件导致的账户劫持和勒索软件攻击。

您可以访问他们的网站并免费尝试他们的引擎：

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
