# 分区/文件系统/Carving

## 分区/文件系统/Carving

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 分区

硬盘或**SSD磁盘可以包含不同的分区**，目的是在物理上分隔数据。\
磁盘的**最小**单元是**扇区**（通常由512B组成）。因此，每个分区的大小都需要是该大小的倍数。

### MBR（主引导记录）

它分配在磁盘的**第一个扇区**，在引导代码的446B之后。这个扇区对于指示计算机应该挂载哪个分区以及从哪里挂载分区至关重要。\
它允许**最多4个分区**（最多**只能有1个**是活动的/**可引导的**）。但是，如果您需要更多分区，可以使用**扩展分区**。这个第一个扇区的最后一个字节是引导记录签名**0x55AA**。只能标记一个分区为活动的。\
MBR允许**最大2.2TB**。

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

从MBR的**字节440到443**，您可以找到**Windows磁盘签名**（如果使用Windows）。硬盘的逻辑驱动器字母取决于Windows磁盘签名。更改此签名可能会阻止Windows引导（工具：[**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**。

![](<../../../.gitbook/assets/image (493).png>)

**格式**

| 偏移量      | 长度       | 项目                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | 引导代码           |
| 446 (0x1BE) | 16 (0x10)  | 第一个分区         |
| 462 (0x1CE) | 16 (0x10)  | 第二个分区         |
| 478 (0x1DE) | 16 (0x10)  | 第三个分区         |
| 494 (0x1EE) | 16 (0x10)  | 第四个分区         |
| 510 (0x1FE) | 2 (0x2)    | 签名 0x55 0xAA |

**分区记录格式**

| 偏移量    | 长度     | 项目                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | 活动标志 (0x80 = 可引导)                              |
| 1 (0x01)  | 1 (0x01) | 起始磁头                                             |
| 2 (0x02)  | 1 (0x01) | 起始扇区 (位0-5); 柱面的高位 (6-7) |
| 3 (0x03)  | 1 (0x01) | 起始柱面的最低8位                           |
| 4 (0x04)  | 1 (0x01) | 分区类型代码 (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | 结束磁头                                               |
| 6 (0x06)  | 1 (0x01) | 结束扇区 (位0-5); 柱面的高位 (6-7)   |
| 7 (0x07)  | 1 (0x01) | 结束柱面的最低8位                             |
| 8 (0x08)  | 4 (0x04) | 分区前的扇区数 (小端)            |
| 12 (0x0C) | 4 (0x04) | 分区中的扇区数                                   |

要在Linux中挂载MBR，首先需要获取起始偏移量（您可以使用`fdisk`和`p`命令）

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

然后使用以下代码
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA（逻辑块寻址）**

**逻辑块寻址**（**LBA**）是一种常用的方案，用于指定存储在计算机存储设备上的数据块的位置，通常是硬盘驱动器等二级存储系统。LBA是一种特别简单的线性寻址方案；**通过整数索引来定位块**，第一个块为LBA 0，第二个为LBA 1，依此类推。

### GPT（GUID分区表）

GUID分区表，称为GPT，因其与MBR（主引导记录）相比增强的功能而备受青睐。GPT以几个方面脱颖而出，具有**全局唯一标识符**用于分区：

- **位置和大小**：GPT和MBR都从**扇区0**开始。但是，GPT使用**64位**，与MBR的32位形成对比。
- **分区限制**：GPT在Windows系统上支持**最多128个分区**，并可容纳**高达9.4ZB**的数据。
- **分区名称**：提供了使用最多36个Unicode字符命名分区的功能。

**数据弹性和恢复**：

- **冗余**：与MBR不同，GPT不将分区和引导数据限制在单个位置。它在磁盘上复制这些数据，增强数据完整性和弹性。
- **循环冗余校验（CRC）**：GPT使用CRC来确保数据完整性。它积极监视数据损坏，一旦检测到，GPT会尝试从另一个磁盘位置恢复损坏的数据。

**保护性MBR（LBA0）**：

- GPT通过保护性MBR实现向后兼容性。此功能位于传统MBR空间中，但旨在防止旧的基于MBR的实用程序错误地覆盖GPT磁盘，从而保护GPT格式化磁盘上的数据完整性。

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**混合MBR（LBA 0 + GPT）**

[来自维基百科](https://en.wikipedia.org/wiki/GUID_Partition_Table)

在支持**通过BIOS进行基于GPT的引导**的操作系统中，第一个扇区也可能仍然用于存储**引导加载程序**代码的第一阶段，但**修改**以识别**GPT分区**。MBR中的引导加载程序不应假定扇区大小为512字节。

**分区表头（LBA 1）**

[来自维基百科](https://en.wikipedia.org/wiki/GUID_Partition_Table)

分区表头定义了磁盘上可用的块。它还定义了组成分区表的分区条目的数量和大小（表中的偏移量80和84）。

| 偏移量    | 长度     | 内容                                                                                                                                                                          |
| --------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0（0x00） | 8字节    | 签名（“EFI PART”，45h 46h 49h 20h 50h 41h 52h 54h或0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)在小端机器上） |
| 8（0x08） | 4字节    | UEFI 2.8的修订版1.0（00h 00h 01h 00h）                                                                                                                                      |
| 12（0x0C）| 4字节    | 以小端表示的头部大小（以字节为单位，通常为5Ch 00h 00h 00h或92字节）                                                                                                         |
| 16（0x10）| 4字节    | 头部的CRC32（从偏移量+0到头部大小）以小端表示，在计算过程中将此字段清零                                                                                                    |
| 20（0x14）| 4字节    | 保留；必须为零                                                                                                                                                              |
| 24（0x18）| 8字节    | 当前LBA（此头部副本的位置）                                                                                                                                                  |
| 32（0x20）| 8字节    | 备份LBA（另一个头部副本的位置）                                                                                                                                              |
| 40（0x28）| 8字节    | 分区的第一个可用LBA（主分区表的最后一个LBA + 1）                                                                                                                              |
| 48（0x30）| 8字节    | 最后一个可用LBA（次要分区表的第一个LBA - 1）                                                                                                                                  |
| 56（0x38）| 16字节   | 混合大小端的磁盘GUID                                                                                                                                                         |
| 72（0x48）| 8字节    | 分区条目数组的起始LBA（主副本中始终为2）                                                                                                                                     |
| 80（0x50）| 4字节    | 数组中的分区条目数                                                                                                                                                            |
| 84（0x54）| 4字节    | 单个分区条目的大小（通常为80h或128）                                                                                                                                          |
| 88（0x58）| 4字节    | 以小端表示的分区条目数组的CRC32                                                                                                                                                |
| 92（0x5C）| \*       | 保留；对于块的其余部分必须为零（对于512字节的扇区大小为420字节；但对于更大的扇区大小可能会更多）                                                                           |

**分区条目（LBA 2–33）**

| GUID分区条目格式 |          |                                                                                                                 |
| ---------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| 偏移量           | 长度     | 内容                                                                                                            |
| 0（0x00）        | 16字节   | [分区类型GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs)（混合大小端）         |
| 16（0x10）       | 16字节   | 唯一分区GUID（混合大小端）                                                                                      |
| 32（0x20）       | 8字节    | 第一个LBA（[小端](https://en.wikipedia.org/wiki/Little\_endian)）                                                |
| 40（0x28）       | 8字节    | 最后一个LBA（包括，通常为奇数）                                                                                 |
| 48（0x30）       | 8字节    | 属性标志（例如，第60位表示只读）                                                                                |
| 56（0x38）       | 72字节   | 分区名称（36个[UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE代码单元）                                         |

**分区类型**

![](<../../../.gitbook/assets/image (492).png>)

更多分区类型请参阅[https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### 检查

在使用[ArsenalImageMounter](https://arsenalrecon.com/downloads/)挂载取证镜像后，您可以使用Windows工具[Active Disk Editor](https://www.disk-editor.org/index.html)**检查第一个扇区**。在下图中，检测到了**MBR**在**扇区0**上，并进行了解释：

![](<../../../.gitbook/assets/image (494).png>)

如果是**GPT表而不是MBR**，则应在**扇区1**中出现签名_EFI PART_（在上图中为空）。

## 文件系统

### Windows文件系统列表

* **FAT12/16**：MSDOS，WIN95/98/NT/200
* **FAT32**：95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**：2008/2012/2016/VISTA/7/8/10
* **NTFS**：XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**：2012/2016

### FAT

**FAT（文件分配表）**文件系统围绕其核心组件文件分配表设计，该表位于卷的开头。该系统通过维护**两份表的副本**来保护数据，即使其中一份损坏，也能确保数据完整性。表和根文件夹必须位于**固定位置**，对系统的启动过程至关重要。

该文件系统的基本存储单元是一个**簇，通常为512B**，包含多个扇区。FAT通过版本演变：

- **FAT12**，支持12位簇地址，处理高达4078个簇（UNIX为4084个）。
- **FAT16**，升级到16位地址，从而容纳高达65,517个簇。
- **FAT32**，进一步升级为32位地址，允许每个卷有令人印象深刻的268,435,456个簇。

FAT各版本的一个重要限制是**4GB的最大文件大小**，由用于文件大小存储的32位字段所限制。

根目录的关键组件，特别是对于FAT12和FAT16，包括：

- **文件/文件夹名称**（最多8个字符）
- **属性**
- **创建、修改和最后访问日期**
- **FAT表地址**（指示文件的起始簇）
- **文件大小**

### EXT

**Ext2**是**不具备日志记录**的分区（**不经常更改的分区**）上最常见的文件系统。**Ext3/4**是**具有日志记录**的，通常用于**其余分区**。

## **元数据**

一些文件包含元数据。这些信息是关于文件内容的信息，有时可能对分析人员很有趣，因为根据文件类型，它可能包含诸如：

* 标题
* 使用的MS Office版本
* 作者
* 创建和最后修改日期
* 相机型号
* GPS坐标
* 图像信息

您可以使用[**exiftool**](https://exiftool.org)和[**Metadiver**](https://www.easymetadata.com/metadiver-2/)等工具获取文件的元数据。

## **已删除文件恢复**

### 记录的已删除文件

正如之前所见，文件“删除”后仍然保存在几个位置。这是因为通常从文件系统中删除文件只是将其标记为已删除，但数据并未被删除。因此，可以检查文件的注册表（如MFT）并找到已删除的文件。

此外，操作系统通常保存有关文件系统更改和备份的大量信息，因此可以尝试使用它们来恢复文件或尽可能多地获取信息。

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **文件切割**

**文件切割**是一种尝试在大量数据中找到文件的技术。此类工具的主要工作方式有3种：**基于文件类型的头部和尾部**，基于文件类型的**结构**，以及基于**内容**本身。

请注意，此技术**无法用于检索分段的文件**。如果文件**未存储在连续扇区中**，则此技术将无法找到它或至少部分找到它。

有几种工具可用于文件切割，指定要搜索的文件类型。

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 数据流**切割**

数据流切割类似于文件切割，但**不是寻找完整文件，而是寻找有趣的信息片段**。\
例如，与寻找包含已记录URL的完整文件不同，此技术将搜索URL。

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 安全删除

显然，有方法可以**“安全地”删除文件和有关它们的部分日志**。例如，可以**多次覆盖文件内容**以垃圾数据，然后**从$MFT和$LOGFILE中删除**有关文件的日志，并**删除卷影副本**。\
您可能会注意到，即使执行了该操作，文件的存在仍可能被记录在其他地方，这是取证专业人员的工作的一部分，是找到它们的。

## 参考资料

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs认证数字取证Windows**
