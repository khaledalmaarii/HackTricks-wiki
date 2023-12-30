# 分区/文件系统/数据挖掘

## 分区/文件系统/数据挖掘

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 分区

硬盘或**SSD磁盘可以包含不同的分区**，目的是物理上分隔数据。\
磁盘的**最小**单位是**扇区**（通常由512B组成）。因此，每个分区的大小需要是该大小的倍数。

### MBR（主引导记录）

它位于磁盘的**第一个扇区，引导代码的446B之后**。这个扇区对于指示PC应该从哪里挂载什么分区至关重要。\
它最多允许**4个分区**（最多**只有1个**可以是活动的/**可引导的**）。然而，如果您需要更多分区，您可以使用**扩展分区**。这个第一个扇区的**最后一个字节**是引导记录签名**0x55AA**。只有一个分区可以被标记为活动的。\
MBR允许的**最大容量为2.2TB**。

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

从MBR的**440到443字节**，您可以找到**Windows磁盘签名**（如果使用Windows）。硬盘的逻辑驱动器字母取决于Windows磁盘签名。更改此签名可能会阻止Windows启动（工具：[**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**。

![](<../../../.gitbook/assets/image (493).png>)

**格式**

| 偏移量      | 长度       | 项目                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | 引导代码           |
| 446 (0x1BE) | 16 (0x10)  | 第一分区           |
| 462 (0x1CE) | 16 (0x10)  | 第二分区           |
| 478 (0x1DE) | 16 (0x10)  | 第三分区           |
| 494 (0x1EE) | 16 (0x10)  | 第四分区           |
| 510 (0x1FE) | 2 (0x2)    | 签名 0x55 0xAA     |

**分区记录格式**

| 偏移量    | 长度     | 项目                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | 活动标志 (0x80 = 可引导)                              |
| 1 (0x01)  | 1 (0x01) | 起始头                                                 |
| 2 (0x02)  | 1 (0x01) | 起始扇区 (位0-5); 圆柱体上位 (6- 7)                   |
| 3 (0x03)  | 1 (0x01) | 起始圆柱体最低8位                                     |
| 4 (0x04)  | 1 (0x01) | 分区类型代码 (0x83 = Linux)                            |
| 5 (0x05)  | 1 (0x01) | 结束头                                                 |
| 6 (0x06)  | 1 (0x01) | 结束扇区 (位0-5); 圆柱体上位 (6- 7)                   |
| 7 (0x07)  | 1 (0x01) | 结束圆柱体最低8位                                     |
| 8 (0x08)  | 4 (0x04) | 分区前扇区数 (小端序)                                  |
| 12 (0x0C) | 4 (0x04) | 分区内扇区数                                           |

为了在Linux中挂载MBR，首先需要获取起始偏移量（您可以使用`fdisk`和`p`命令）

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

然后使用以下代码
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (逻辑块寻址)**

**逻辑块寻址**（**LBA**）是一种常用的方案，用于**指定存储在计算机存储设备上的数据块的位置**，通常是硬盘驱动器等二级存储系统。LBA是一种特别简单的线性寻址方案；**块通过整数索引定位**，第一个块是LBA 0，第二个是LBA 1，依此类推。

### GPT (GUID 分区表)

之所以称为GUID分区表，是因为驱动器上的每个分区都有一个**全局唯一标识符**。

就像MBR一样，它从**扇区0**开始。MBR占用32位，而**GPT**使用**64位**。\
GPT **允许在Windows中最多128个分区**，并支持高达**9.4ZB**。\
此外，分区可以有一个36个字符的Unicode名称。

在MBR磁盘上，分区和启动数据存储在一个位置。如果这些数据被覆盖或损坏，你就麻烦了。相比之下，**GPT在磁盘上多个位置存储这些数据的副本**，因此它更加健壮，并且如果数据损坏，GPT可以注意到问题并**尝试从磁盘上的另一个位置恢复损坏的数据**。

GPT还存储**循环冗余校验（CRC）**值以检查其数据是否完整。如果数据损坏，GPT可以发现问题并**尝试从磁盘上的另一个位置恢复损坏的数据**。

**保护性MBR (LBA0)**

为了有限的向后兼容性，GPT规范中仍保留了传统MBR的空间，但现在的使用方式是为了**防止基于MBR的磁盘工具错误识别并可能覆盖GPT磁盘**。这被称为保护性MBR。

![](<../../../.gitbook/assets/image (491).png>)

**混合MBR (LBA 0 + GPT)**

在支持通过BIOS服务而不是EFI的**基于GPT的启动**的操作系统中，第一个扇区也可能仍用于存储**引导加载程序**代码的第一阶段，但**修改**为识别**GPT** **分区**。MBR中的引导加载程序不得假设扇区大小为512字节。

**分区表头 (LBA 1)**

分区表头定义了磁盘上可用的块。它还定义了构成分区表的分区条目的数量和大小（表中的偏移量80和84）。

| 偏移量    | 长度   | 内容                                                                                                                                                                        |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 字节  | 签名（"EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h 或 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)在小端机器上） |
| 8 (0x08)  | 4 字节  | 版本 1.0 (00h 00h 01h 00h) 适用于UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 字节  | 头部大小以小端表示（以字节为单位，通常为5Ch 00h 00h 00h 或 92字节）                                                                                                    |
| 16 (0x10) | 4 字节  | 头部的[CRC32](https://en.wikipedia.org/wiki/CRC32)（从偏移量+0到头部大小）以小端表示，计算时此字段归零                                |
| 20 (0x14) | 4 字节  | 保留；必须为零                                                                                                                                                          |
| 24 (0x18) | 8 字节  | 当前LBA（此头部副本的位置）                                                                                                                                      |
| 32 (0x20) | 8 字节  | 备份LBA（另一个头部副本的位置）                                                                                                                                  |
| 40 (0x28) | 8 字节  | 分区的第一个可用LBA（主分区表最后一个LBA + 1）                                                                                                          |
| 48 (0x30) | 8 字节  | 最后一个可用LBA（次级分区表第一个LBA − 1）                                                                                                                       |
| 56 (0x38) | 16 字节 | 磁盘GUID以混合端表示                                                                                                                                                       |
| 72 (0x48) | 8 字节  | 分区条目数组的起始LBA（主副本中始终为2）                                                                                                        |
| 80 (0x50) | 4 字节  | 数组中分区条目的数量                                                                                                                                            |
| 84 (0x54) | 4 字节  | 单个分区条目的大小（通常为80h或128）                                                                                                                           |
| 88 (0x58) | 4 字节  | 分区条目数组的CRC32以小端表示                                                                                                                               |
| 92 (0x5C) | \*       | 保留；对于块的其余部分必须为零（对于扇区大小为512字节的为420字节；但对于更大的扇区大小可以更多）                                         |

**分区条目 (LBA 2–33)**

| GUID分区条目格式 |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| 偏移量                      | 长度   | 内容                                                                                                          |
| 0 (0x00)                    | 16 字节 | [分区类型GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs)（混合端表示） |
| 16 (0x10)                   | 16 字节 | 唯一分区GUID（混合端表示）                                                                              |
| 32 (0x20)                   | 8 字节  | 第一个LBA（[小端表示](https://en.wikipedia.org/wiki/Little\_endian)）                                         |
| 40 (0x28)                   | 8 字节  | 最后一个LBA（包含在内，通常为奇数）                                                                                 |
| 48 (0x30)                   | 8 字节  | 属性标志（例如，第60位表示只读）                                                                   |
| 56 (0x38)                   | 72 字节 | 分区名称（36个[UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE代码单元）                                   |

**分区类型**

![](<../../../.gitbook/assets/image (492).png>)

更多分区类型在 [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### 检查

在使用[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/)挂载取证映像后，您可以使用Windows工具[**Active Disk Editor**](https://www.disk-editor.org/index.html)**检查第一个扇区**。在下图中，检测到**MBR**位于**扇区0**并进行了解释：

![](<../../../.gitbook/assets/image (494).png>)

如果是**GPT表而不是MBR**，则应在**扇区1**出现签名_EFI PART_（在上图中为空）。

## 文件系统

### Windows文件系统列表

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

**FAT（文件分配表）**文件系统以其组织方法命名，即文件分配表，位于卷的开头。为了保护卷，**两份**表的副本被保留，以防其中一份受损。此外，文件分配表和根文件夹必须存储在**固定位置**，以便正确定位启动系统所需的文件。

![](<../../../.gitbook/assets/image (495).png>)

此文件系统使用的最小空间单位是**簇，通常为512B**（由多个扇区组成）。

早期的**FAT12**将**簇地址限制为12位**值，最多可达**4078** **簇**；在UNIX下允许最多4084个簇。更高效的**FAT16**增加到**16位**簇地址，允许每个卷最多**65,517个簇**。FAT32使用32位簇地址，允许每个卷最多**268,435,456个簇**。

**FAT允许的最大文件大小为4GB**（减去一个字节），因为文件系统使用32位字段以字节为单位存储文件大小，而2^32字节=4GiB。这适用于FAT12、FAT16和FAT32。

**根目录**对于FAT12和FAT16占据**特定位置**（在FAT32中它占据的位置像其他文件夹一样）。每个文件/文件夹条目包含以下信息：

* 文件/文件夹的名称（最多8个字符）
* 属性
* 创建日期
* 修改日期
* 最后访问日期
* FAT表中文件第一个簇的地址
* 大小

当使用FAT文件系统“删除”文件时，目录条目除了**文件名的第一个字符**（修改为0xE5）外，几乎保持**不变**，保留了大部分“已删除”文件的名称、时间戳、文件长度和 — 最重要的 — 其在磁盘上的物理位置。然而，文件占用的磁盘簇列表将从文件分配表中擦除，标记这些扇区可供以后创建或修改的其他文件使用。对于FAT32，还有一个负责文件起始簇值上16位的字段被擦除。

### **NTFS**

{% content-ref url="ntfs.md" %}
[ntfs.md](ntfs.md)
{% endcontent-ref %}

### EXT

**Ext2**是最常见的**非日志文件系统**（**不经常变化的分区**，如启动分区）。**Ext3/4**是**日志文件系统**，通常用于**其余分区**。

{% content-ref url="ext.md" %}
[ext.md](ext.md)
{% endcontent-ref %}

## **元数据**

一些文件包含元数据。这些信息是关于文件内容的，有时对分析师来说可能很有趣，因为根据文件类型，它可能包含像：

* 标题
* 使用的MS Office版本
* 作者
* 创建和最后修改日期
* 相机型号
* GPS坐标
* 图像信息

您可以使用像[**exiftool**](https://exiftool.org)和[**Metadiver**](https://www.easymetadata.com/metadiver-2/)这样的工具获取文件的元数据。

## **已删除文件恢复**

### 记录已删除文件

如前所述，通常文件从文件系统中被“删除”后，文件的记录仍然保存在原处。这是因为通常删除文件只是将其标记为已删除，但数据并未被触及。然后，可以检查文件的注册表（如MFT），找到已删除的文件。

此外，操作系统通常会保存大量关于文件系统更改和备份的信息，因此可以尝试使用它们来恢复文件或尽可能多的信息。

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **文件雕刻**

**文件雕刻**是一种尝试**在大量数据中找到文件的技术**。这类工具的工作方式有3种主要方法：**基于文件类型的头部和尾部**，基于文件类型的**结构**，以及基于**内容**本身。

请注意，这种技术**无法检索碎片化的文件**。如果文件**未存储在连续的扇区中**，那么这种技术将无法找到它或至少是它的一部分。

有几种工具可以用于文件雕刻，指示您要搜索的文件类型

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 数据流**雕刻**

数据流雕刻与文件雕刻类似，但**不是寻找完整的文件，而是寻找有趣的信息片段**。\
例如，不是寻找包含记录的URL的完整文件，而是搜索URL。

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 安全删除

显然，有方法可以**“安全地”删除文件和关于它们的日志部分**。例如，可以**多次用垃圾数据覆盖**文件的内容，然后**删除**来自**$MFT**和**$LOGFILE**的文件的**日志**，并**删除卷影副本**。\
您可能会注意到，即使执行了该操作，文件存在的其他部分可能仍然被记录下来，这是真的，取证专业人员的工作部分就是找到它们。

## 参考资料

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><strong>从零开始学习AWS黑客攻击到高手，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)上**关注**我。
* 通过向[**HackTricks**](https://github.com/c
