# NTFS

## NTFS

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## **NTFS**

**NTFS**（新技术文件系统）是由Microsoft开发的专有日志文件系统。

在NTFS中，簇是最小的大小单位，簇的大小取决于分区的大小。

| 分区大小                | 每簇扇区数 | 簇大小    |
| ------------------------ | ------------------- | ------------ |
| 512MB或更小            | 1                   | 512字节    |
| 513MB-1024MB（1GB）     | 2                   | 1KB          |
| 1025MB-2048MB（2GB）    | 4                   | 2KB          |
| 2049MB-4096MB（4GB）    | 8                   | 4KB          |
| 4097MB-8192MB（8GB）    | 16                  | 8KB          |
| 8193MB-16,384MB（16GB） | 32                  | 16KB         |
| 16,385MB-32,768MB（32GB）| 64                  | 32KB         |
| 大于32,768MB           | 128                 | 64KB         |

### **松弛空间**

由于NTFS中最小的大小单位是**簇**。每个文件将占用多个完整的簇。因此，**每个文件占用的空间可能比必要的空间多**。这些文件**未使用的**空间**由文件预订**，称为**松弛**空间，人们可以利用这个区域来**隐藏**信息。

![](<../../../.gitbook/assets/image (498).png>)

### **NTFS引导扇区**

当格式化NTFS卷时，格式化程序为引导元数据文件分配了前16个扇区。第一个扇区是带有“引导加载程序”代码的引导扇区，接下来的15个扇区是引导扇区的IPL（初始程序加载器）。为了增加文件系统的可靠性，NTFS分区的最后一个扇区包含引导扇区的备用副本。

### **主文件表（MFT）**

NTFS文件系统包含一个称为主文件表（MFT）的文件。在NTFS文件系统卷上，至少有**一个MFT条目对应每个文件**，包括MFT本身。有关文件的所有信息，包括其**大小、时间戳、权限和数据内容**，都存储在MFT条目中或在MFT条目描述的MFT之外的空间中。

当**文件**添加到NTFS文件系统卷时，MFT中会添加更多条目，**MFT的大小会增加**。当从NTFS文件系统卷中**删除**文件时，它们的**MFT条目被标记为自由**，可以重新使用。但是，为这些条目分配的磁盘空间不会重新分配，MFT的大小也不会减小。

NTFS文件系统**保留空间用于MFT，以尽可能使MFT连续**。NTFS文件系统在每个卷中为MFT保留的空间称为**MFT区域**。文件和目录的空间也分配自此空间，但只有在MFT区域之外的所有卷空间分配完之后才会分配。

根据平均文件大小和其他变量，**在磁盘填满容量时，可能首先分配保留的MFT区域或磁盘上的未保留空间**。具有少量相对较大文件的卷将首先分配未保留的空间，而具有大量相对较小文件的卷将首先分配MFT区域。在任一情况下，当其中一个区域完全分配时，MFT的碎片化开始发生。如果未保留的空间完全分配，用户文件和目录的空间将从MFT区域分配。如果MFT区域完全分配，新MFT条目的空间将从未保留的空间分配。

NTFS文件系统还生成一个**$MFTMirror**。这是MFT的**前4个条目的副本**：$MFT、$MFT Mirror、$Log、$Volume。

NTFS为表的前16条记录保留了特殊信息：

| 系统文件           | 文件名 | MFT记录 | 文件用途                                                                                                                                                                                                           |
| --------------------- | --------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 主文件表     | $Mft      | 0          | 包含NTFS卷上每个文件和文件夹的一个基本文件记录。如果文件或文件夹的分配信息太大而无法适应单个记录，则还会分配其他文件记录。            |
| 主文件表2   | $MftMirr  | 1          | MFT的前四个记录的重复图像。在单个扇区故障的情况下，此文件保证访问MFT。                                                                                            |
| 日志文件              | $LogFile  | 2          | 包含用于NTFS可恢复性的事务步骤列表。日志文件大小取决于卷大小，最大可达4MB。Windows NT/2000在系统故障后使用它来恢复NTFS的一致性。 |
| 卷                | $Volume   | 3          | 包含有关卷的信息，如卷标签和卷版本。                                                                                                                                       |
| 属性定义 | $AttrDef  | 4          | 属性名称、编号和描述的表。                                                                                                                                                                        |
| 根文件名索引  | $         | 5          | 根文件夹。                                                                                                                                                                                                              |
| 簇位图        | $Bitmap   | 6          | 显示哪些簇正在使用的卷的表示。                                                                                                                                                             |
| 引导扇区           | $Boot     | 7          | 包括用于挂载卷的BPB和用于可引导卷的附加引导加载程序代码。                                                                                                                |
| 坏簇文件      | $BadClus  | 8          | 包含卷的坏簇。                                                                                                                                                                                         |
| 安全文件         | $Secure   | 9          | 包含卷内所有文件的唯一安全描述符。                                                                                                                                                           |
| 大写表          | $Upcase   | 10         | 将小写字符转换为匹配的Unicode大写字符。                                                                                                                                                       |
| NTFS扩展文件   | $Extend   | 11         | 用于各种可选扩展，如配额、重解析点数据和对象标识符。                                                                                                                              |
|                       |           | 12-15      | 保留供将来使用。                                                                                                                                                                                                      |
| 配额管理文件 | $Quota    | 24         | 包含用户分配的卷空间配额限制。                                                                                                                                                                      |
| 对象ID文件        | $ObjId    | 25         | 包含文件对象ID。                                                                                                                                                                                                     |
| 重解析点文件    | $Reparse  | 26         | 此文件包含有关卷上的文件和文件夹的信息，包括重解析点数据。                                                                                                                            |

### MFT的每个条目如下所示：

![](<../../../.gitbook/assets/image (499).png>)

请注意，每个条目以“FILE”开头。每个条目占据1024位。因此，在MFT条目的开始后1024位，您将找到下一个条目。

使用[**Active Disk Editor**](https://www.disk-editor.org/index.html)非常容易检查MFT中文件的条目。只需右键单击文件，然后单击“检查文件记录”

![](<../../../.gitbook/assets/image (500).png>)

![](<../../../.gitbook/assets/image (501).png>)

通过检查**“正在使用”**标志，很容易知道文件是否已删除（**0x0表示已删除**）。

![](<../../../.gitbook/assets/image (510).png>)

还可以使用FTKImager恢复已删除的文件：

![](<../../../.gitbook/assets/image (502).png>)

### MFT属性

每个MFT条目都有几个属性，如下图所示：

![](<../../../.gitbook/assets/image (506).png>)

每个属性表示一些由类型标识的条目信息：

| 类型标识符 | 名称                     | 描述                                                                                                       |
| --------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| 16              | $STANDARD\_INFORMATION   | 一般信息，如标志；最后访问、写入和创建时间；所有者和安全ID。 |
| 32              | $ATTRIBUTE\_LIST         | 可在其中找到文件的其他属性的列表。                                                              |
| 48              | $FILE\_NAME              | 文件名，以Unicode表示，以及最后访问、写入和创建时间。                                         |
| 64              | $VOLUME\_VERSION         | 卷信息。仅存在于版本1.2（Windows NT）。                                                      |
| 64              | $OBJECT\_ID              | 文件或目录的16字节唯一标识符。仅存在于版本3.0+之后（Windows 2000+）。    |
| 80              | $SECURITY\_ DESCRIPTOR   | 文件的访问控制和安全属性。                                                                      |
| 96              | $VOLUME\_NAME            | 卷名称。                                                                                                      |
| 112             | $VOLUME\_ INFORMATION    | 文件系统版本和其他标志。                                                                          |
| 128             | $DATA                    | 文件内容。                                                                                                    |
| 144             | $INDEX\_ROOT             | 索引树的根节点。                                                                                       |
| 160             | $INDEX\_ALLOCATION       | 以$INDEX\_ROOT属性为根的索引树的节点。                                                    |
| 176             | $BITMAP                  | 用于$MFT文件和索引的位图。                                                                       |
| 192             | $SYMBOLIC\_LINK          | 软链接信息。仅存在于版本1.2（Windows NT）。                                                |
| 192             | $REPARSE\_POINT          | 包含关于重解析点的数据，用作版本3.0+（Windows 2000+）中的软链接。                |
| 208             | $EA\_INFORMATION         | 用于与OS/2应用程序（HPFS）向后兼容。                                                        |
| 224             | $EA                      | 用于与OS/2应用程序（HPFS）向后兼容。                                                        |
| 256             | $LOGGED\_UTILITY\_STREAM | 包含版本3.0+（Windows 2000+）中加密属性的密钥和信息。                         |

例如，**类型48（0x30）**标识**文件名**：

![](<../../../.gitbook/assets/image (508).png>)

还有必要了解**这些属性可以是驻留的**（意味着它们存在于给定的MFT记录中）或**非驻留的**（意味着它们存在于MFT记录之外的磁盘的其他位置，并且仅在记录中引用）。例如，如果属性**$Data是驻留的**，这意味着**整个文件保存在MFT中**，如果是非驻留的，则文件内容位于文件系统的另一部分。

一些有趣的属性：

* [$STANDARD\_INFORMATION](https://flatcap.org/linux-ntfs/ntfs/attributes/standard\_information.html)（以及其他）：
* 创建日期
* 修改日期
* 访问日期
* MFT更新日期
* DOS文件权限
* [$FILE\_NAME](https://flatcap.org/linux-ntfs/ntfs/attributes/file\_name.html)（以及其他）：
* 文件名
* 创建日期
* 修改日期
* 访问日期
* MFT更新日期
* 分配大小
* 实际大小
* [文件引用](https://flatcap.org/linux-ntfs/ntfs/concepts/file\_reference.html)到父目录。
* [$Data](https://flatcap.org/linux-ntfs/ntfs/attributes/data.html)（以及其他）：
* 包含文件的数据或数据所在扇区的指示。在下面的示例中，属性数据不是驻留的，因此属性提供有关数据所在扇区的信息。

![](<../../../.gitbook/assets/image (507) (1) (1).png>)

![](<../../../.gitbook/assets/image (509).png>)

### NTFS时间戳

![](<../../../.gitbook/assets/image (512).png>)

分析MFT的另一个有用工具是[**MFT2csv**](https://github.com/jschicht/Mft2Csv)（选择mft文件或图像，然后按“dump all and extract”以提取所有对象）。\
该程序将提取所有MFT数据并以CSV格式呈现。还可用于转储文件。

![](<../../../.gitbook/assets/image (513).png>)

### $LOGFILE

文件**`$LOGFILE`**包含有关已对文件执行的**操作**的**日志**。它还**保存**了在发生错误时需要执行的**操作**以及需要执行的操作以**返回**到**先前**的**状态**。\
这些日志对于MFT在某种错误发生时重建文件系统很有用。此文件的最大大小为**65536KB**。

要检查`$LOGFILE`，您需要先提取它，然后使用[MFT2csv](https://github.com/jschicht/Mft2Csv)工具对先前检查的`$MFT`运行。\
然后针对此文件运行[**LogFileParser**](https://github.com/jschicht/LogFileParser)，选择导出的`$LOGFILE`文件和`$MFT`检查的CVS。您将获得一个包含由`$LOGFILE`日志记录的文件系统活动日志的CSV文件。

![](<../../../.gitbook/assets/image (515).png>)

通过文件名过滤，您可以查看**针对文件执行的所有操作**：

![](<../../../.gitbook/assets/image (514).png>)

### $USNJnrl

文件`$EXTEND/$USNJnrl/$J`是文件`$EXTEND$USNJnrl`的一个备用数据流。此工件包含在NTFS卷内产生的更详细的更改记录的注册表，比`$LOGFILE`更详细。

要检查此文件，可以使用工具[**UsnJrnl2csv**](https://github.com/jschicht/UsnJrnl2Csv)。

通过文件名过滤，可以查看**针对文件执行的所有操作**。此外，您还可以在父文件夹中找到`MFTReference`。然后查看该`MFTReference`，您可以找到**来自父文件夹的信息**。

![](<../../../.gitbook/assets/image (516).png>)

### $I
