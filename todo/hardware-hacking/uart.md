# UART

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}


## 基本信息

UART 是一种串行协议，这意味着它一次传输一个比特的数据。相比之下，平行通信协议通过多个通道同时传输数据。常见的串行协议包括 RS-232、I2C、SPI、CAN、以太网、HDMI、PCI Express 和 USB。

通常，在 UART 处于空闲状态时，线路保持高电平（逻辑 1 值）。然后，为了信号数据传输的开始，发射器向接收器发送一个起始位，此时信号保持低电平（逻辑 0 值）。接下来，发射器发送五到八个数据位，包含实际消息，后面跟着一个可选的奇偶校验位和一个或两个停止位（逻辑 1 值），具体取决于配置。用于错误检查的奇偶校验位在实际中很少见。停止位（或位）表示传输结束。

我们称最常见的配置为 8N1：八个数据位，无奇偶校验和一个停止位。例如，如果我们想在 8N1 UART 配置中发送字符 C，或 0x43 的 ASCII 码，我们将发送以下位：0（起始位）；0，1，0，0，0，0，1，1（0x43 的二进制值），和 0（停止位）。

![](<../../.gitbook/assets/image (764).png>)

与 UART 通信的硬件工具：

* USB 转串行适配器
* 带有 CP2102 或 PL2303 芯片的适配器
* 多功能工具，如：Bus Pirate、Adafruit FT232H、Shikra 或 Attify Badge

### 识别 UART 端口

UART 有 4 个端口：**TX**（发送）、**RX**（接收）、**Vcc**（电压）和 **GND**（接地）。您可能会在 PCB 上找到带有 **`TX`** 和 **`RX`** 字母的 4 个端口。但如果没有指示，您可能需要使用 **万用表** 或 **逻辑分析仪** 自行查找。

使用 **万用表** 并关闭设备电源：

* 要识别 **GND** 引脚，请使用 **连续性测试** 模式，将黑色引线放入接地，并用红色引线测试，直到听到万用表发出声音。PCB 上可以找到多个 GND 引脚，因此您可能找到或未找到属于 UART 的引脚。
* 要识别 **VCC 端口**，请设置 **直流电压模式** 并将其设置为 20 V 电压。黑色探头接地，红色探头接引脚。打开设备电源。如果万用表测量到恒定电压为 3.3 V 或 5 V，则您找到了 Vcc 引脚。如果您得到其他电压，请尝试其他端口。
* 要识别 **TX** **端口**，将 **直流电压模式** 设置为 20 V 电压，黑色探头接地，红色探头接引脚，并打开设备电源。如果您发现电压波动几秒钟后稳定在 Vcc 值，则您很可能找到了 TX 端口。这是因为在开机时，它会发送一些调试数据。
* **RX 端口** 将是与其他 3 个端口最接近的，它的电压波动最低，所有 UART 引脚中整体值最低。

您可以混淆 TX 和 RX 端口，没什么问题，但如果混淆 GND 和 VCC 端口，可能会烧毁电路。

在某些目标设备中，制造商通过禁用 RX 或 TX 或甚至两者来禁用 UART 端口。在这种情况下，追踪电路板中的连接并找到一些断点可能会有所帮助。确认没有检测到 UART 和电路断开的一个强烈提示是检查设备保修。如果设备附带某些保修，制造商会留下某些调试接口（在这种情况下是 UART），因此，必须断开 UART，并在调试时重新连接。这些断点引脚可以通过焊接或跳线连接。

### 识别 UART 波特率

识别正确波特率的最简单方法是查看 **TX 引脚的输出并尝试读取数据**。如果您收到的数据不可读，请切换到下一个可能的波特率，直到数据变得可读。您可以使用 USB 转串行适配器或像 Bus Pirate 这样的多功能设备来做到这一点，并配合一个辅助脚本，例如 [baudrate.py](https://github.com/devttys0/baudrate/)。最常见的波特率为 9600、38400、19200、57600 和 115200。

{% hint style="danger" %}
请注意，在此协议中，您需要将一个设备的 TX 连接到另一个设备的 RX！
{% endhint %}

## CP210X UART 到 TTY 适配器

CP210X 芯片广泛用于许多原型板，如 NodeMCU（带 esp8266）进行串行通信。这些适配器相对便宜，可以用于连接目标的 UART 接口。该设备有 5 个引脚：5V、GND、RXD、TXD、3.3V。确保根据目标支持的电压连接，以避免任何损坏。最后，将适配器的 RXD 引脚连接到目标的 TXD，引脚，将适配器的 TXD 引脚连接到目标的 RXD 引脚。

如果适配器未被检测到，请确保主机系统中已安装 CP210X 驱动程序。一旦适配器被检测到并连接，可以使用 picocom、minicom 或 screen 等工具。

要列出连接到 Linux/MacOS 系统的设备：
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
配置 `Serial port setup` 选项中的波特率和设备名称。

配置完成后，使用命令 `minicom` 启动 UART 控制台。

## 通过 Arduino UNO R3 的 UART（可拆卸的 Atmel 328p 芯片板）

如果没有 UART 串行到 USB 适配器，可以通过快速黑客技术使用 Arduino UNO R3。由于 Arduino UNO R3 通常随处可用，这可以节省很多时间。

Arduino UNO R3 板上内置了 USB 到串行适配器。要获取 UART 连接，只需将 Atmel 328p 微控制器芯片从板上拔出。此黑客技术适用于 Atmel 328p 未焊接在板上的 Arduino UNO R3 变体（使用的是 SMD 版本）。将 Arduino 的 RX 引脚（数字引脚 0）连接到 UART 接口的 TX 引脚，将 Arduino 的 TX 引脚（数字引脚 1）连接到 UART 接口的 RX 引脚。

最后，建议使用 Arduino IDE 获取串行控制台。在菜单的 `tools` 部分，选择 `Serial Console` 选项，并根据 UART 接口设置波特率。

## Bus Pirate

在这种情况下，我们将嗅探 Arduino 的 UART 通信，该通信将程序的所有打印信息发送到串行监视器。
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
## Dumping Firmware with UART Console

UART Console 提供了一种在运行时环境中与底层固件进行交互的好方法。但是，当 UART Console 访问为只读时，可能会引入许多限制。在许多嵌入式设备中，固件存储在 EEPROM 中，并在具有易失性内存的处理器中执行。因此，固件保持只读状态，因为制造时的原始固件就在 EEPROM 内部，任何新文件都将由于易失性内存而丢失。因此，在处理嵌入式固件时，转储固件是一项有价值的工作。

有很多方法可以做到这一点，SPI 部分涵盖了使用各种设备直接从 EEPROM 中提取固件的方法。尽管如此，建议首先尝试使用 UART 转储固件，因为使用物理设备和外部交互转储固件可能存在风险。

从 UART Console 转储固件需要首先获取对引导加载程序的访问。许多流行的供应商使用 uboot（通用引导加载程序）作为其引导加载程序来加载 Linux。因此，获取对 uboot 的访问是必要的。

要访问引导加载程序，请将 UART 端口连接到计算机，并使用任何串行控制台工具，并保持设备的电源断开。一旦设置完成，按下 Enter 键并保持。最后，连接设备的电源并让其启动。

这样做将中断 uboot 的加载并提供一个菜单。建议了解 uboot 命令并使用帮助菜单列出它们。这可能是 `help` 命令。由于不同的供应商使用不同的配置，因此有必要分别理解每个配置。

通常，转储固件的命令是：
```
md
```
which stands for "memory dump". 这将把内存（EEPROM 内容）转储到屏幕上。建议在开始程序之前记录串行控制台输出，以捕获内存转储。

最后，只需从日志文件中剥离所有不必要的数据，并将文件存储为 `filename.rom`，然后使用 binwalk 提取内容：
```
binwalk -e <filename.rom>
```
这将根据在十六进制文件中找到的签名列出 EEPROM 的可能内容。

尽管需要注意的是，即使正在使用 uboot，它也不一定是解锁的。如果 Enter 键没有任何反应，请检查其他键，如空格键等。如果引导加载程序被锁定且没有被中断，则此方法将无效。要检查 uboot 是否是设备的引导加载程序，请在设备启动时检查 UART 控制台的输出。它可能在启动时提到 uboot。

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
