# 固件分析

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## **介绍**

固件是一种基本软件，通过管理和促进硬件组件与用户交互的软件之间的通信，使设备能够正确运行。它存储在永久性存储器中，确保设备可以从通电时刻起访问重要指令，从而启动操作系统。检查和可能修改固件是识别安全漏洞的关键步骤。

## **收集信息**

**收集信息**是了解设备构成和使用的技术的关键初始步骤。这个过程涉及收集以下数据：

- CPU架构和运行的操作系统
- 引导加载程序的具体信息
- 硬件布局和数据表
- 代码库指标和源位置
- 外部库和许可证类型
- 更新历史和监管认证
- 架构和流程图
- 安全评估和已识别的漏洞

为此，**开源情报（OSINT）**工具是非常宝贵的，通过手动和自动审查过程分析任何可用的开源软件组件。像[Coverity Scan](https://scan.coverity.com)和[Semmle’s LGTM](https://lgtm.com/#explore)这样的工具提供免费的静态分析，可用于发现潜在问题。

## **获取固件**

获取固件可以通过各种方式进行，每种方式都有其自己的复杂程度：

- **直接**从源头（开发人员、制造商）
- 根据提供的说明**构建**固件
- 从官方支持站点**下载**
- 利用**Google dork**查询查找托管的固件文件
- 直接访问**云存储**，使用诸如[S3Scanner](https://github.com/sa7mon/S3Scanner)之类的工具
- 通过中间人技术拦截**更新**
- 通过**UART**、**JTAG**或**PICit**等连接从设备**提取**
- 在设备通信中**嗅探**更新请求
- 识别和使用**硬编码的更新端点**
- 从引导加载程序或网络**转储**
- 当一切失败时，**移除和读取**存储芯片，使用适当的硬件工具

## 分析固件

现在您**已经获得了固件**，您需要提取有关固件的信息，以了解如何处理它。您可以使用不同的工具进行此操作：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果使用这些工具没有找到太多信息，请使用 `binwalk -E <bin>` 检查图像的**熵**，如果熵低，则不太可能被加密。如果熵高，则很可能被加密（或以某种方式被压缩）。

此外，您可以使用这些工具来提取**嵌入在固件中的文件**：

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

或者使用 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) 来检查文件。

### 获取文件系统

通过之前提到的工具，如 `binwalk -ev <bin>`，您应该已经能够**提取文件系统**。\
Binwalk通常会将其提取到一个**以文件系统类型命名的文件夹**中，通常是以下之一：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk **在其签名中没有文件系统的魔术字节**。在这些情况下，使用binwalk来**找到文件系统的偏移量并从二进制文件中切割压缩的文件系统**，然后根据其类型**手动提取**文件系统，按照以下步骤操作。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
运行以下 **dd 命令** 对 Squashfs 文件系统进行切割。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatively, you can run the following command.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* 对于 squashfs（在上面的示例中使用）

`$ unsquashfs dir.squashfs`

文件将位于“`squashfs-root`”目录中。

* CPIO 存档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

* 对于 NAND 闪存的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`


## 分析固件

获取固件后，解剖固件以了解其结构和潜在漏洞至关重要。这个过程涉及使用各种工具来分析并从固件映像中提取有价值的数据。

### 初始分析工具

提供了一组命令，用于对二进制文件（称为 `<bin>`）进行初始检查。这些命令有助于识别文件类型，提取字符串，分析二进制数据，并了解分区和文件系统的详细信息：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
评估图像的加密状态，可以使用 `binwalk -E <bin>` 检查**熵**。低熵表明缺乏加密，而高熵则表明可能存在加密或压缩。

要提取**嵌入文件**，建议使用**file-data-carving-recovery-tools**文档和**binvis.io**进行文件检查。

### 提取文件系统

使用 `binwalk -ev <bin>`，通常可以提取文件系统，通常会提取到以文件系统类型命名的目录中（例如 squashfs、ubifs）。但是，当**binwalk**由于缺少魔术字节而无法识别文件系统类型时，就需要进行手动提取。这涉及使用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令切割出文件系统：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
### 文件系统分析

文件系统提取后，开始搜索安全漏洞。注意不安全的网络守护程序、硬编码凭据、API 端点、更新服务器功能、未编译代码、启动脚本以及用于离线分析的已编译二进制文件。

需要检查的**关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL 证书和密钥
- 潜在漏洞的配置和脚本文件
- 用于进一步分析的嵌入式二进制文件
- 常见物联网设备的 Web 服务器和二进制文件

有几种工具可帮助揭示文件系统中的敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker) 用于搜索敏感信息
- [**固件分析和比较工具 (FACT)**](https://github.com/fkie-cad/FACT\_core) 用于全面的固件分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba) 用于静态和动态分析

### 对已编译二进制文件进行安全检查

必须仔细审查文件系统中找到的源代码和已编译二进制文件以查找漏洞。像 **checksec.sh** 用于 Unix 二进制文件，**PESecurity** 用于 Windows 二进制文件等工具有助于识别可能被利用的未受保护的二进制文件。

## 模拟固件进行动态分析

模拟固件的过程使得可以对设备的操作或单个程序进行**动态分析**。这种方法可能会遇到硬件或架构依赖性的挑战，但将根文件系统或特定二进制文件传输到具有匹配架构和字节序的设备（如树莓派）或预构建的虚拟机，可以促进进一步测试。

### 模拟单个二进制文件

对于检查单个程序，识别程序的字节序和 CPU 架构至关重要。

#### MIPS 架构示例

要模拟 MIPS 架构二进制文件，可以使用以下命令：
```bash
file ./squashfs-root/bin/busybox
```
并安装必要的仿真工具：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
### MIPS架构仿真

对于MIPS（大端）架构，使用`qemu-mips`，对于小端二进制文件，选择`qemu-mipsel`。

### ARM架构仿真

对于ARM二进制文件，过程类似，使用`qemu-arm`仿真器进行仿真。

### 完整系统仿真

类似[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)等工具可实现完整固件仿真，自动化流程并协助动态分析。

### 实践中的动态分析

在此阶段，使用真实或仿真设备环境进行分析。保持对操作系统和文件系统的shell访问至关重要。仿真可能无法完全模拟硬件交互，可能需要偶尔重新启动仿真。分析应重新查看文件系统，利用暴露的网页和网络服务，探索引导加载程序漏洞。固件完整性测试对于识别潜在后门漏洞至关重要。

### 运行时分析技术

运行时分析涉及使用诸如gdb-multiarch、Frida和Ghidra等工具与进程或二进制文件在其操作环境中交互，通过模糊测试等技术设置断点并识别漏洞。

### 二进制利用和概念验证

为已识别的漏洞开发概念验证（PoC）需要深入了解目标架构并使用低级语言进行编程。嵌入式系统中的二进制运行时保护很少见，但存在时，可能需要使用Return Oriented Programming（ROP）等技术。

### 用于固件分析的准备操作系统

操作系统如[AttifyOS](https://github.com/adi0x90/attifyos)和[EmbedOS](https://github.com/scriptingxss/EmbedOS)提供了预配置的固件安全测试环境，配备必要工具。

### 用于分析固件的准备操作系统

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS是一个旨在帮助您执行物联网（IoT）设备的安全评估和渗透测试的发行版。通过提供预配置环境并加载所有必要工具，为您节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于Ubuntu 18.04的嵌入式安全测试操作系统，预装有固件安全测试工具。

### 用于练习的易受攻击固件

要练习在固件中发现漏洞，可以使用以下易受攻击的固件项目作为起点。

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

### 参考资料

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

### 培训和认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)
