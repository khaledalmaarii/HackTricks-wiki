# 固件分析

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>

## 介绍

固件是一种软件，它提供对设备硬件组件的通信和控制。它是设备运行的第一段代码。通常，它**引导操作系统**并通过**与各种硬件组件通信**为程序提供非常特定的运行时服务。大多数电子设备都有固件。

设备将固件存储在**非易失性存储器**中，如只读存储器（ROM）、可擦写可编程只读存储器（EPROM）或闪存。

检查固件并尝试对其进行修改非常重要，因为我们可以在此过程中发现许多安全问题。

## **信息收集和侦察**

在此阶段，尽可能收集有关目标的信息，以了解其整体构成和基础技术。尝试收集以下信息：

* 支持的 CPU 架构
* 操作系统平台
* 引导加载程序配置
* 硬件原理图
* 数据手册
* 代码行数（LoC）估计
* 源代码仓库位置
* 第三方组件
* 开源许可证（例如 GPL）
* 更改日志
* FCC ID
* 设计和数据流程图
* 威胁模型
* 以前的渗透测试报告
* 缺陷跟踪票（例如 Jira 和 BugCrowd 或 HackerOne 等漏洞赏金平台）

在可能的情况下，使用开源情报（OSINT）工具和技术获取数据。如果使用了开源软件，请下载仓库并对代码库进行手动和自动静态分析。有时，开源软件项目已经使用供应商提供的免费静态分析工具，这些工具提供扫描结果，如[Coverity Scan](https://scan.coverity.com)和[Semmle's LGTM](https://lgtm.com/#explore)。

## 获取固件

有不同的方法和不同的难度级别来下载固件

* 直接从开发团队、制造商/供应商或客户处获取
* 使用制造商提供的步骤进行**从头构建**
* 从**供应商的支持网站**获取
* 针对二进制文件扩展名和文件共享平台（如 Dropbox、Box 和 Google Drive）的**Google dork**查询
* 通常可以通过上传内容到论坛、博客或在与制造商联系以解决问题并通过邮件或闪存驱动器发送固件的网站上发表评论的客户来获取固件映像。
* 示例：`intitle:"Netgear" intext:"Firmware Download"`
* 从暴露的云提供商存储位置（如 Amazon Web Services (AWS) 的 S3 存储桶）下载构建（使用[https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner)等工具）
* 在**更新**期间通过**中间人**（MITM）设备通信
* 直接通过**UART**、**JTAG**、**PICit**等从硬件中提取
* 在硬件组件中嗅探**串行通信**以获取**更新服务器请求**
* 通过移动应用程序或厚应用程序中的**硬编码端点**
* 从**引导加载程序**（例如 U-boot）转储固件到闪存存储器或通过**tftp**通过**网络**传输
* 从板上移除**闪存芯片**（例如 SPI）或 MCU 进行离线分析和数据提取（最后的手段）。
* 对于闪存存储器和/或 MCU，您将需要一个支持的芯片编程器。

## 分析固件

现在，你**有了固件**，你需要提取关于它的信息，以了解如何处理它。你可以使用不同的工具来做到这一点：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果你用这些工具没有找到什么有用的信息，可以使用`binwalk -E <bin>`命令检查图像的**熵**。如果熵较低，则不太可能被加密。如果熵较高，则很可能被加密（或以某种方式进行了压缩）。

此外，你可以使用以下工具来提取**嵌入在固件中的文件**：

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

或者使用[**binvis.io**](https://binvis.io/#/)（[代码](https://code.google.com/archive/p/binvis/)）来检查文件。

### 获取文件系统

使用前面提到的工具，如`binwalk -ev <bin>`，你应该已经能够**提取文件系统**了。\
Binwalk通常会将其提取到一个**以文件系统类型命名的文件夹**中，通常是以下之一：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk的签名中**没有文件系统的魔术字节**。在这种情况下，使用binwalk来**找到文件系统的偏移量**，然后从二进制文件中**切割出压缩的文件系统**，并根据其类型手动提取文件系统，按照以下步骤进行。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
运行以下 **dd 命令** 对 Squashfs 文件系统进行刻录。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
或者，也可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* 对于squashfs（在上面的示例中使用）

`$ unsquashfs dir.squashfs`

文件将位于“`squashfs-root`”目录中。

* CPIO存档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* 对于jffs2文件系统

`$ jefferson rootfsfile.jffs2`

* 对于带有NAND闪存的ubifs文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 分析文件系统

现在，您已经获得了文件系统，是时候开始寻找不良实践，例如：

* 旧版的**不安全网络守护程序**，例如telnetd（有时制造商会重命名二进制文件以掩盖）
* **硬编码凭据**（用户名、密码、API密钥、SSH密钥和后门变体）
* **硬编码API**端点和后端服务器详细信息
* 可用作入口点的**更新服务器功能**
* **审查未编译的代码和启动脚本**以进行远程代码执行
* **提取已编译的二进制文件**以供离线分析和未来步骤中的反汇编器使用

在固件中寻找的一些**有趣的内容**：

* etc/shadow和etc/passwd
* 列出etc/ssl目录
* 搜索与SSL相关的文件，如.pem、.crt等
* 搜索配置文件
* 查找脚本文件
* 搜索其他.bin文件
* 查找关键字，如admin、password、remote、AWS keys等
* 搜索用于物联网设备的常见Web服务器
* 搜索常见的二进制文件，如ssh、tftp、dropbear等
* 搜索禁止使用的C函数
* 搜索常见的命令注入易受攻击函数
* 搜索URL、电子邮件地址和IP地址
* 等等...

搜索此类信息的工具（即使您始终应该查看文件系统结构并熟悉它，但工具可以帮助您找到**隐藏的内容**）：

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng)**：**这是一个令人惊叹的bash脚本，对于在文件系统中搜索**敏感信息**非常有用。只需**chroot进入固件文件系统并运行它**。
* [**Firmwalker**](https://github.com/craigz28/firmwalker)**：**用于搜索潜在敏感信息的bash脚本
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core)：
* 识别操作系统、CPU架构和第三方组件以及其相关版本信息
* 从映像中提取固件文件系统（s）
* 检测证书和私钥
* 检测映射到常见弱点枚举（CWE）的弱实现
* 基于Feed和签名的漏洞检测
* 基本静态行为分析
* 比较（diff）固件版本和文件
* 使用QEMU对文件系统二进制文件进行用户模式仿真
* 检测二进制缓解措施，如NX、DEP、ASLR、堆栈保护、RELRO和FORTIFY\_SOURCE
* REST API
* 等等...
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)：FwAnalyzer是一个用于分析（ext2/3/4）、FAT/VFat、SquashFS、UBIFS文件系统映像、cpio存档和目录内容的工具，使用一组可配置的规则。
* [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)：一个免费的物联网固件安全分析工具
* [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go)：这是对原始ByteSweep项目的完全重写，使用Go语言编写。
* [**EMBA**](https://github.com/e-m-b-a/emba)：_EMBA_是专为渗透测试人员设计的中央固件分析工具。它支持完整的安全分析流程，从_固件提取_过程开始，进行_静态分析_和_动态分析_（通过仿真），最后生成报告。_EMBA_会自动发现固件中的潜在弱点和漏洞。例如，不安全的二进制文件、旧的和过时的软件组件、潜在易受攻击的脚本或硬编码密码。

{% hint style="warning" %}
在文件系统中，您还可以找到程序的**源代码**（您应该始终**检查**），但也可以找到**已编译的二进制文件**。这些程序可能会以某种方式暴露，您应该对它们进行**反编译**和**检查**以寻找潜在的漏洞。

像[**checksec.sh**](https://github.com/slimm609/checksec.sh)这样的工具可以帮助您找到未受保护的二进制文件。对于Windows二进制文件，您可以使用[**PESecurity**](https://github.com/NetSPI/PESecurity)。
{% endhint %}

## 模拟固件

模拟固件的想法是能够对设备的**运行**或单个程序进行**动态分析**。

{% hint style="info" %}
有时，由于硬件或架构依赖关系，部分或完全模拟**可能无法正常工作**。如果架构和字节序与您拥有的设备（例如树莓派）匹配，可以将根文件系统或特定二进制文件传输到该设备进行进一步测试。此方法也适用于使用与目标相同的架构和字节序的预构建虚拟机。
{% endhint %}

### 二进制模拟

如果您只想模拟一个程序以搜索漏洞，首先需要确定其字节序和编译的CPU架构。

#### MIPS示例
```bash
file ./squashfs-root/bin/busybox
./squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```
现在你可以使用**QEMU**来**模拟**busybox可执行文件。
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
因为可执行文件是为MIPS编译的，并且遵循大端字节顺序，所以我们将使用QEMU的`qemu-mips`模拟器。要模拟小端字节顺序的可执行文件，我们需要选择带有`el`后缀的模拟器（`qemu-mipsel`）：
```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/ls
100              100.7z           15A6D2.squashfs  squashfs-root    squashfs-root-0
```
#### ARM 示例

```html
<details>
<summary>Click to expand!</summary>

##### Firmware Analysis

- **Firmware Extraction**: Extracting the firmware from the device is the first step in firmware analysis. This can be done by using tools like `binwalk`, `firmware-mod-kit`, or by directly dumping the firmware from the device's memory.

- **Firmware Reverse Engineering**: Once the firmware is extracted, it can be reverse engineered to understand its inner workings. Tools like `Ghidra`, `IDA Pro`, or `Radare2` can be used for this purpose.

- **Firmware Emulation**: Emulating the firmware can help in understanding its behavior without running it on the actual device. Tools like `QEMU` or `Unicorn` can be used for firmware emulation.

- **Firmware Patching**: Patching the firmware can be useful for modifying its behavior or removing security vulnerabilities. Tools like `BinPatch` or `Firmadyne` can be used for this purpose.

- **Firmware Analysis Tools**: There are several tools available for analyzing firmware, such as `Firmwalker`, `Firmware Analysis Toolkit (FAT)`, or `Firmware Security Toolkit (FST)`.

##### ARM Firmware Analysis

- **ARM Architecture**: ARM is a popular architecture used in many embedded devices. Understanding the ARM architecture is essential for analyzing ARM firmware.

- **ARM Assembly Language**: ARM firmware is typically written in ARM assembly language. Learning ARM assembly language is important for analyzing ARM firmware.

- **ARM Debugging**: Debugging ARM firmware can be done using tools like `GDB` or `OpenOCD`. These tools allow you to step through the firmware code and analyze its execution.

- **ARM Exploitation**: Exploiting vulnerabilities in ARM firmware can be done using techniques like buffer overflows, format string vulnerabilities, or code injection.

</details>
```

##### 固件分析

- **固件提取**：从设备中提取固件是固件分析的第一步。可以使用诸如 `binwalk`、`firmware-mod-kit` 的工具，或者直接从设备的内存中转储固件来完成此操作。

- **固件逆向工程**：一旦提取了固件，可以对其进行逆向工程以了解其内部工作原理。可以使用 `Ghidra`、`IDA Pro` 或 `Radare2` 等工具进行此操作。

- **固件仿真**：通过仿真固件，可以在不在实际设备上运行固件的情况下了解其行为。可以使用 `QEMU` 或 `Unicorn` 等工具进行固件仿真。

- **固件修补**：修补固件可以用于修改其行为或消除安全漏洞。可以使用 `BinPatch` 或 `Firmadyne` 等工具进行此操作。

- **固件分析工具**：有许多可用于分析固件的工具，例如 `Firmwalker`、`Firmware Analysis Toolkit (FAT)` 或 `Firmware Security Toolkit (FST)`。

##### ARM 固件分析

- **ARM 架构**：ARM 是许多嵌入式设备中常用的架构。了解 ARM 架构对于分析 ARM 固件至关重要。

- **ARM 汇编语言**：ARM 固件通常使用 ARM 汇编语言编写。学习 ARM 汇编语言对于分析 ARM 固件非常重要。

- **ARM 调试**：可以使用 `GDB` 或 `OpenOCD` 等工具对 ARM 固件进行调试。这些工具允许您逐步执行固件代码并分析其执行过程。

- **ARM 漏洞利用**：可以使用缓冲区溢出、格式化字符串漏洞或代码注入等技术来利用 ARM 固件中的漏洞。
```bash
file bin/busybox
bin/busybox: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-armhf.so.1, no section header
```
仿真：
```bash
qemu-arm -L ./squashfs-root/ ./squashfs-root/bin/ls
1C00000.squashfs  B80B6C            C41DD6.xz         squashfs-root     squashfs-root-0
```
### 全系统仿真

有几个基于**qemu**的工具可以让你仿真完整的固件：

* [**https://github.com/firmadyne/firmadyne**](https://github.com/firmadyne/firmadyne)**:**
* 需要安装一些东西，配置postgres，然后运行extractor.py脚本来提取固件，使用getArch.sh脚本获取架构。然后，使用tar2db.py和makeImage.sh脚本将从提取的镜像中的信息存储到数据库中，并生成一个可以仿真的QEMU镜像。然后，使用inferNetwork.sh脚本获取网络接口，最后使用run.sh脚本，在./scratch/1/folder中自动生成。
* [**https://github.com/attify/firmware-analysis-toolkit**](https://github.com/attify/firmware-analysis-toolkit)**:**
* 这个工具依赖于firmadyne，并自动化了使用firmadyne仿真固件的过程。在使用之前，你需要配置`fat.config`：`sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0`
* [**https://github.com/therealsaumil/emux**](https://github.com/therealsaumil/emux)
* [**https://github.com/getCUJO/MIPS-X**](https://github.com/getCUJO/MIPS-X)
* [**https://github.com/qilingframework/qiling#qltool**](https://github.com/qilingframework/qiling#qltool)

## **动态分析**

在这个阶段，你应该有一个运行固件的设备进行攻击，或者有一个仿真的固件进行攻击。无论哪种情况，都强烈建议你也要有**在运行的操作系统和文件系统中的shell**。

请注意，有时候如果你在仿真固件中，**仿真中的某些活动可能会失败**，你可能需要重新开始仿真。例如，一个Web应用可能需要从原始设备集成的设备获取信息，但是仿真没有进行仿真。

你应该像我们在之前的步骤中已经做过的那样，**重新检查文件系统**，因为在运行环境中可能可以访问到新的信息。

如果**网页**是公开的，阅读代码并访问它们，你应该**测试它们**。在hacktricks中，你可以找到关于不同Web攻击技术的大量信息。

如果**网络服务**是公开的，你应该尝试攻击它们。在hacktricks中，你可以找到关于不同网络服务攻击技术的大量信息。你还可以尝试使用网络和协议**模糊测试工具**，如[Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer)，[boofuzz](https://github.com/jtpereyda/boofuzz)和[kitty](https://github.com/cisco-sas/kitty)对它们进行模糊测试。

你应该检查是否可以**攻击引导加载程序**以获取root shell：

{% content-ref url="bootloader-testing.md" %}
[bootloader-testing.md](bootloader-testing.md)
{% endcontent-ref %}

你应该测试设备是否进行任何类型的**固件完整性测试**，如果没有，这将允许攻击者提供带有后门的固件，将它们安装在其他人拥有的设备上，甚至在存在任何固件更新漏洞的情况下远程部署它们：

{% content-ref url="firmware-integrity.md" %}
[firmware-integrity.md](firmware-integrity.md)
{% endcontent-ref %}

固件更新漏洞通常是因为**固件**的**完整性**可能**没有**得到**验证**，使用**未加密**的**网络**协议，使用**硬编码**的**凭据**，对托管固件的云组件进行**不安全的身份验证**，甚至过度和不安全的**日志记录**（敏感数据），允许**物理更新**而不进行验证。

## **运行时分析**

运行时分析涉及在设备正常运行或仿真环境中附加到正在运行的进程或二进制文件。以下是基本的运行时分析步骤：

1. `sudo chroot . ./qemu-arch -L <optionalLibPath> -g <gdb_port> <binary>`
2. 附加gdb-multiarch或使用IDA来仿真二进制文件
3. 为在步骤4中识别的函数设置断点，例如memcpy，strncpy，strcmp等
4. 使用模糊测试器执行大型负载字符串，以识别溢出或进程崩溃
5. 如果发现漏洞，则转到步骤8

以下工具可能有所帮助（非详尽列表）：

* gdb-multiarch
* [Peda](https://github.com/longld/peda)
* Frida
* ptrace
* strace
* IDA Pro
* Ghidra
* Binary Ninja
* Hopper

## **二进制利用**

在之前的步骤中识别出二进制文件中的漏洞后，需要一个适当的概念验证（PoC）来展示实际的影响和风险。开发利用代码需要具备低级语言（例如ASM，C/C++，shellcode等）的编程经验，以及特定目标架构（例如MIPS，ARM，x86等）的背景。PoC代码涉及通过控制内存中的指令，在设备或应用程序上获得任意执行。

在嵌入式系统中，通常不会使用二进制运行时保护（例如NX，DEP，ASLR等），但是当出现这种情况时，可能需要使用其他技术，例如返回导向编程（ROP）。ROP允许攻击者通过链接目标进程/二进制代码中的现有代码（称为gadgets）来实现任意恶意功能。需要采取措施来利用已识别的漏洞，例如缓冲区溢出，通过形成ROP链。在这种情况下，一个有用的工具是Capstone的gadget finder或ROPgadget- [https://github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget)。

请参考以下参考资料以获得进一步指导：

* [https://azeria-labs.com/writing-arm-shellcode/](https://azeria-labs.com/writing-arm-shellcode/)
* [https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/](https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/)

## 准备好的操作系统来分析固件

* [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS是一个旨在帮助你对物联网（IoT）设备进行安全评估和渗透测试的发行版。它通过提供预配置的环境和加载所有必要工具来节省你大量时间。
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于Ubuntu 18.04的嵌入式安全测试操作系统，预装了固件安全测试工具。
## 可用于练习的易受攻击固件

要练习发现固件漏洞，请使用以下易受攻击的固件项目作为起点。

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## 参考资料

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## 培训和认证

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
