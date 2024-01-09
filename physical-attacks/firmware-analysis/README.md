# 固件分析

<details>

<summary><strong>从零到英雄学习AWS黑客攻击，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 引言

固件是一种软件，它提供对设备硬件组件的通信和控制。它是设备运行的第一段代码。通常，它**启动操作系统**并为程序提供与各种硬件组件**通信的特定运行时服务**。大多数（如果不是全部）电子设备都有固件。

设备将固件存储在**非易失性存储器**中，如ROM、EPROM或闪存。

重要的是要**检查**固件，然后尝试**修改**它，因为我们可以在这个过程中发现许多安全问题。

## **信息收集和侦察**

在这个阶段，尽可能多地收集有关目标的信息，以了解其整体构成和底层技术。尝试收集以下信息：

* 支持的CPU架构
* 操作系统平台
* 引导加载程序配置
* 硬件原理图
* 数据表
* 代码行（LoC）估计
* 源代码仓库位置
* 第三方组件
* 开源许可证（例如GPL）
* 更新日志
* FCC ID
* 设计和数据流图
* 威胁模型
* 以前的渗透测试报告
* Bug跟踪票据（例如Jira和bug赏金平台，如BugCrowd或HackerOne）

在可能的情况下，使用开源情报（OSINT）工具和技术获取数据。如果使用开源软件，请下载仓库，并对代码库进行手动和自动的静态分析。有时，开源软件项目已经使用了供应商提供的免费静态分析工具，这些工具提供扫描结果，如[Coverity Scan](https://scan.coverity.com)和[Semmle的LGTM](https://lgtm.com/#explore)。

## 获取固件

下载固件有不同的方法，难度也不同

* **直接**从开发团队、制造商/供应商或客户那里
* **从头开始构建**，使用制造商提供的教程
* 从**供应商的支持网站**
* **Google dork**查询，针对二进制文件扩展名和文件共享平台，如Dropbox、Box和Google Drive
* 通常可以通过客户在论坛、博客上上传内容，或在他们联系制造商解决问题并通过zip或闪存驱动器获得固件的网站上发表评论时发现固件镜像。
* 示例：`intitle:"Netgear" intext:"Firmware Download"`
* 从暴露的云提供商存储位置下载构建，如Amazon Web Services (AWS) S3桶（使用工具如[https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner)）
* **中间人攻击**（MITM）设备通信，在**更新**过程中
* 通过**UART**、**JTAG**、**PICit**等直接**从硬件**提取
* 嗅探硬件组件内的**串行通信**，寻找**更新服务器请求**
* 通过移动或厚应用程序内的**硬编码端点**
* **从引导加载程序**（例如U-boot）**转储**固件到闪存存储或通过**网络**使用**tftp**
* 移除**闪存芯片**（例如SPI）或MCU，以便离线分析和数据提取（最后手段）。
* 您将需要一个支持的芯片编程器，用于闪存存储和/或MCU。

## 分析固件

现在您**拥有固件**，您需要提取有关它的信息，以了解如何处理它。您可以使用不同的工具来做到这一点：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果使用这些工具没有找到太多信息，请使用 `binwalk -E <bin>` 检查镜像的**熵**，如果熵低，则不太可能是加密的。如果熵高，很可能是加密的（或以某种方式压缩）。

此外，您可以使用这些工具提取**固件内嵌的文件**：

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

或使用 [**binvis.io**](https://binvis.io/#/) ([代码](https://code.google.com/archive/p/binvis/)) 来检查文件。

### 获取文件系统

使用之前提到的工具，如 `binwalk -ev <bin>`，您应该能够**提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹**中，这通常是以下之一：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动文件系统提取

有时，binwalk **可能没有文件系统的魔术字节在其签名中**。在这些情况下，使用 binwalk **找到文件系统的偏移量并从二进制文件中切割压缩的文件系统**，然后根据下面的步骤**手动提取**文件系统。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
执行以下 **dd 命令** 来提取 Squashfs 文件系统。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
以下命令也可以运行。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* 对于 squashfs（如上例所示）

`$ unsquashfs dir.squashfs`

之后文件将在 "`squashfs-root`" 目录中。

* CPIO 归档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

* 对于带有 NAND flash 的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 分析文件系统

现在您已经有了文件系统，是时候开始寻找不良实践，例如：

* 旧版**不安全的网络守护进程**，如 telnetd（有时制造商会重命名二进制文件以伪装）
* **硬编码的凭据**（用户名、密码、API 密钥、SSH 密钥和后门变体）
* **硬编码的 API** 端点和后端服务器详情
* **更新服务器功能**，可能被用作入口点
* **审查未编译的代码和启动脚本**，寻找远程代码执行
* **提取编译后的二进制文件**，用于离线分析，配合反汇编器进行后续步骤

固件内部一些**值得关注的事项**：

* etc/shadow 和 etc/passwd
* 列出 etc/ssl 目录
* 搜索与 SSL 相关的文件，如 .pem、.crt 等。
* 搜索配置文件
* 寻找脚本文件
* 搜索其他 .bin 文件
* 寻找关键词，如 admin、password、remote、AWS 密钥等。
* 搜索 IoT 设备上常用的网络服务器
* 搜索常见的二进制文件，如 ssh、tftp、dropbear 等。
* 搜索被禁用的 c 函数
* 搜索常见的命令注入漏洞函数
* 搜索 URL、电子邮件地址和 IP 地址
* 等等…

这些工具可以搜索这类信息（即使您应该始终手动查看并熟悉文件系统结构，这些工具可以帮助您发现**隐藏的东西**）：

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng)**:** 一个很棒的 bash 脚本，在这种情况下，用于搜索文件系统内的**敏感信息**。只需在固件文件系统内**chroot 然后运行它**。
* [**Firmwalker**](https://github.com/craigz28/firmwalker)**:** Bash 脚本，用于搜索潜在的敏感信息
* [**固件分析和比较工具 (FACT)**](https://github.com/fkie-cad/FACT_core):
* 识别软件组件，如操作系统、CPU 架构和第三方组件及其关联的版本信息
* 从镜像中提取固件文件系统
* 检测证书和私钥
* 检测弱实现，映射到常见弱点枚举（CWE）
* 基于 Feed 和签名的漏洞检测
* 基本静态行为分析
* 固件版本和文件的比较（差异）
* 使用 QEMU 对文件系统二进制文件进行用户模式仿真
* 检测二进制缓解措施，如 NX、DEP、ASLR、栈金丝雀、RELRO 和 FORTIFY_SOURCE
* REST API
* 等等...
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer): FwAnalyzer 是一个工具，用于使用一组可配置的规则分析 (ext2/3/4)、FAT/VFat、SquashFS、UBIFS 文件系统镜像、cpio 归档和目录内容。
* [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep): 一个免费的 IoT 固件安全分析工具
* [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go): 这是用 Go 完全重写的原始 ByteSweep 项目。
* [**EMBA**](https://github.com/e-m-b-a/emba): _EMBA_ 被设计为渗透测试人员的中心固件分析工具。它支持从 _固件提取_ 过程开始的完整安全分析过程，进行 _静态分析_ 和通过仿真进行 _动态分析_，最后生成报告。_EMBA_ 自动发现固件中可能的弱点和漏洞。示例包括不安全的二进制文件、旧的和过时的软件组件、可能存在漏洞的脚本或硬编码密码。

{% hint style="warning" %}
在文件系统内部，您还可以找到程序的**源代码**（您应该始终**检查**），但也有**编译后的二进制文件**。这些程序可能以某种方式暴露，您应该**反编译**并**检查**它们以寻找潜在的漏洞。

像 [**checksec.sh**](https://github.com/slimm609/checksec.sh) 这样的工具可以用来找到未受保护的二进制文件。对于 Windows 二进制文件，您可以使用 [**PESecurity**](https://github.com/NetSPI/PESecurity)。
{% endhint %}

## 仿真固件

仿真固件的想法是能够对设备**运行**或**单个程序**进行**动态分析**。

{% hint style="info" %}
有时，由于硬件或架构依赖，部分或全部仿真**可能无法工作**。如果架构和字节序与拥有的设备（如树莓派）匹配，则可以将根文件系统或特定二进制文件传输到设备上进行进一步测试。这种方法也适用于使用与目标相同的架构和字节序的预构建虚拟机。
{% endhint %}

### 二进制仿真

如果您只想仿真一个程序来搜索漏洞，首先需要确定其字节序和它编译的 CPU 架构。

#### MIPS 示例
```bash
file ./squashfs-root/bin/busybox
./squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```
现在您可以使用 **QEMU** 来**模拟** busybox 可执行文件。
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
由于可执行文件**是**为**MIPS**编译的，并遵循**big-endian**字节顺序，我们将使用 QEMU 的 **`qemu-mips`** 模拟器。要模拟**little-endian**可执行文件，我们需要选择带有 `el` 后缀的模拟器（`qemu-mipsel`）：
```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/ls
100              100.7z           15A6D2.squashfs  squashfs-root    squashfs-root-0
```
#### ARM 示例
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

有几种工具，通常基于 **qemu**，可以让你模拟完整的固件：

* [**https://github.com/firmadyne/firmadyne**](https://github.com/firmadyne/firmadyne)**：**
* 你需要安装几样东西，配置 postgres，然后运行 extractor.py 脚本提取固件，使用 getArch.sh 脚本获取架构。然后，使用 tar2db.py 和 makeImage.sh 脚本将提取的镜像信息存储在数据库中，并生成我们可以模拟的 QEMU 镜像。接着，使用 inferNetwork.sh 脚本获取网络接口，最后使用 run.sh 脚本，该脚本会自动在 ./scratch/1/folder 中创建。
* [**https://github.com/attify/firmware-analysis-toolkit**](https://github.com/attify/firmware-analysis-toolkit)**：**
* 这个工具依赖于 firmadyne 并自动化使用 firmadynee 模拟固件的过程。在使用它之前你需要配置 `fat.config`：`sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0`
* [**https://github.com/therealsaumil/emux**](https://github.com/therealsaumil/emux)
* [**https://github.com/getCUJO/MIPS-X**](https://github.com/getCUJO/MIPS-X)
* [**https://github.com/qilingframework/qiling#qltool**](https://github.com/qilingframework/qiling#qltool)

## **动态分析**

在这个阶段，你应该有一个运行固件的设备来攻击，或者模拟固件来攻击。无论哪种情况，都强烈建议你**同时拥有正在运行的操作系统和文件系统的 shell**。

请注意，如果你在模拟固件，**模拟中的某些活动可能会失败**，你可能需要重新开始模拟。例如，一个 web 应用可能需要从原始设备集成的设备获取信息，但模拟并未模拟该设备。

你应该**重新检查文件系统**，就像我们在**之前的步骤中已经做过的那样，因为在运行环境中可能会访问到新信息。**

如果**网页**被暴露，阅读代码并访问它们，你应该**测试它们**。在 hacktricks 中，你可以找到关于不同 web 黑客技术的大量信息。

如果**网络服务**被暴露，你应该尝试攻击它们。在 hacktricks 中，你可以找到关于不同网络服务黑客技术的大量信息。你也可以尝试使用网络和协议**fuzzers**，如 [Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer)，[boofuzz](https://github.com/jtpereyda/boofuzz)，和 [kitty](https://github.com/cisco-sas/kitty) 对它们进行 fuzz 测试。

你应该检查是否可以**攻击 bootloader**以获得 root shell：

{% content-ref url="bootloader-testing.md" %}
[bootloader-testing.md](bootloader-testing.md)
{% endcontent-ref %}

你应该测试设备是否进行任何类型的**固件完整性测试**，如果没有，这将允许攻击者提供后门固件，将它们安装在其他人拥有的设备上，甚至如果存在任何固件更新漏洞，可以远程部署它们：

{% content-ref url="firmware-integrity.md" %}
[firmware-integrity.md](firmware-integrity.md)
{% endcontent-ref %}

固件更新漏洞通常发生是因为，**固件**的**完整性**可能**未**被**验证**，使用**未加密**的**网络**协议，使用**硬编码**的**凭据**，一个**不安全的认证**到托管固件的云组件，甚至过度和不安全的**日志记录**（敏感数据），允许**物理更新**而不进行验证。

## **运行时分析**

运行时分析涉及在设备在其正常或模拟环境中运行时，附加到正在运行的进程或二进制文件。下面提供了基本的运行时分析步骤：

1. `sudo chroot . ./qemu-arch -L <optionalLibPath> -g <gdb_port> <binary>`
2. 附加 gdb-multiarch 或使用 IDA 模拟二进制文件
3. 为第 4 步中识别的函数设置断点，如 memcpy, strncpy, strcmp 等。
4. 使用 fuzzer 执行大型有效载荷字符串以识别溢出或进程崩溃
5. 如果识别出漏洞，继续执行步骤 8

以下是一些可能有用的工具（非详尽列表）：

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

在前面的步骤中识别出二进制文件中的漏洞后，需要一个适当的概念验证 (PoC)，以展示现实世界的影响和风险。开发利用代码需要在较低级别语言（例如 ASM, C/C++, shellcode 等）以及特定目标架构（例如 MIPS, ARM, x86 等）方面的编程经验。PoC 代码涉及通过控制内存中的指令，在设备或应用程序上获得任意执行。

在嵌入式系统中通常不会有二进制运行时保护（例如 NX, DEP, ASLR 等），但当这种情况发生时，可能需要额外的技术，如返回导向编程 (ROP)。ROP 允许攻击者通过链接目标进程/二进制代码中已知的代码片段（称为小工具）来实现任意恶意功能。需要采取步骤来利用识别出的漏洞，如缓冲区溢出，通过形成 ROP 链。在这种情况下可能有用的工具是 Capstone 的小工具查找器或 ROPGadget- [https://github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget)。

使用以下参考资料以获得进一步指导：

* [https://azeria-labs.com/writing-arm-shellcode/](https://azeria-labs.com/writing-arm-shellcode/)
* [https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/](https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/)

## 准备好的操作系统来分析固件

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS 是一个旨在帮助你对物联网 (IoT) 设备进行安全评估和渗透测试的发行版。它通过提供一个预配置的环境，装载了所有必要的工具，为你节省了大量时间。
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 基于 Ubuntu 18.04 的嵌入式安全测试操作系统，预装了固件安全测试工具。

## 易受攻击的固件进行练习

为了练习发现固件中的漏洞，使用以下易受攻击的固件项目作为起点。

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

<summary><strong>从零开始学习 AWS 黑客攻击，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>成为英雄！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks** 中看到你的**公司广告**或**下载 HackTricks 的 PDF** 版本，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享你的黑客技巧。**

</details>
