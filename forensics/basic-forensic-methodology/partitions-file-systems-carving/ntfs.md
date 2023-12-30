# NTFS

## NTFS

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## **NTFS**

**NTFS**（**新技术文件系统**）是微软开发的专有日志文件系统。

簇是NTFS中最小的大小单位，簇的大小取决于分区的大小。

| 分区大小                   | 每簇扇区数 | 簇大小     |
| ------------------------ | ------- | -------- |
| 512MB或更小                | 1       | 512字节    |
| 513MB-1024MB (1GB)       | 2       | 1KB      |
| 1025MB-2048MB (2GB)      | 4       | 2KB      |
| 2049MB-4096MB (4GB)      | 8       | 4KB      |
| 4097MB-8192MB (8GB)      | 16      | 8KB      |
| 8193MB-16,384MB (16GB)   | 32      | 16KB     |
| 16,385MB-32,768MB (32GB) | 64      | 32KB     |
| 超过32,768MB             | 128     | 64KB     |

### **松弛空间**

由于NTFS中最小的大小单位是**簇**。每个文件将占用几个完整的簇。因此，**每个文件占用的空间很可能比必要的更多**。这些**未使用的**、被文件**预留**的空间称为**松弛空间**，人们可以利用这个区域来**隐藏信息**。

![](<../../../.gitbook/assets/image (498).png>)

### **NTFS启动扇区**

当您格式化NTFS卷时，格式化程序会为启动元数据文件分配前16个扇区。第一个扇区是带有"引导"代码的启动扇区，接下来的15个扇区是启动扇区的IPL（初始程序加载器）。为了提高文件系统的可靠性，NTFS分区的最后一个扇区包含启动扇区的备份副本。

### **主文件表（MFT）**

NTFS文件系统包含一个称为主文件表（MFT）的文件。NTFS文件系统卷上的每个文件，包括MFT本身，至少都有**一个MFT条目**。关于文件的所有信息，包括其**大小、时间和日期戳、权限和数据内容**，都存储在MFT条目中或由MFT条目描述的MFT外部空间中。

随着**文件被添加**到NTFS文件系统卷，MFT中添加了更多条目，**MFT的大小增加**。当**文件**从NTFS文件系统卷中**删除**时，它们的**MFT条目被标记为可用**，并可能被重用。然而，已分配给这些条目的磁盘空间不会被重新分配，MFT的大小不会减小。

NTFS文件系统**保留空间给MFT，以尽可能保持MFT的连续性**随着它的增长。NTFS文件系统为每个卷中的MFT保留的空间称为**MFT区域**。文件和目录的空间也从这个空间分配，但只有在MFT区域外的所有卷空间都被分配后才会这样做。

根据平均文件大小和其他变量，**随着磁盘填满，可能首先分配保留的MFT区域或未保留的磁盘空间**。具有少量相对较大文件的卷将首先分配未保留的空间，而具有大量相对较小文件的卷首先分配MFT区域。在任何一种情况下，当一个区域或另一个区域被完全分配时，MFT的碎片化开始发生。如果未保留的空间完全分配，用户文件和目录的空间将从MFT区域分配。如果MFT区域完全分配，新的MFT条目的空间将从未保留的空间分配。

NTFS文件系统还生成了一个**$MFTMirror**。这是MFT的**前4个条目的副本**：$MFT、$MFT Mirror、$Log、$Volume。

NTFS为表中的前16条记录保留了特殊信息：

| 系统文件               | 文件名      | MFT记录 | 文件用途                                                                                                                                                                                                           |
| --------------------- | --------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 主文件表               | $Mft      | 0    | 包含NTFS卷上每个文件和文件夹的一个基本文件记录。如果文件或文件夹的分配信息太大而无法适应单个记录，则会分配其他文件记录。                                                                                                  |
| 主文件表2              | $MftMirr  | 1    | MFT前四条记录的副本图像。这个文件保证了在单个扇区故障的情况下能够访问MFT。                                                                                                                                           |
| 日志文件               | $LogFile  | 2    | 包含用于NTFS可恢复性的事务步骤列表。日志文件的大小取决于卷的大小，最大可达4MB。它被Windows NT/2000用来在系统故障后恢复NTFS的一致性。                                                                                         |
| 卷                     | $Volume   | 3    | 包含有关卷的信息，如卷标签和卷版本。                                                                                                                                                                                   |
| 属性定义               | $AttrDef  | 4    | 属性名称、编号和描述的表格。                                                                                                                                                                                        |
| 根文件名索引             | $         | 5    | 根文件夹。                                                                                                                                                                                                          |
| 簇位图                 | $Bitmap   | 6    | 显示哪些簇正在使用的卷的表示。                                                                                                                                                                                       |
| 启动扇区                | $Boot     | 7    | 包括用于挂载卷的BPB和额外的引导加载器代码（如果卷是可启动的）。                                                                                                                                                          |
| 坏簇文件               | $BadClus  | 8    | 包含卷的坏簇。                                                                                                                                                                                                     |
| 安全文件                | $Secure   | 9    | 包含卷内所有文件的唯一安全描述符。                                                                                                                                                                                   |
| 大写表                  | $Upcase   | 10   | 将小写字符转换为匹配的Unicode大写字符。                                                                                                                                                                             |
| NTFS扩展文件             | $Extend   | 11   | 用于各种可选扩展，如配额、重解析点数据和对象标识符。                                                                                                                                                                  |
|                       |           | 12-15 | 保留供将来使用。                                                                                                                                                                                                    |
| 配额管理文件              | $Quota    | 24   | 包含用户在卷空间上分配的配额限制。                                                                                                                                                                                  |
| 对象ID文件              | $ObjId    | 25   | 包含文件对象ID。                                                                                                                                                                                                   |
| 重解析点文件             | $Reparse  | 26   | 包含有关卷上文件和文件夹的信息，包括重解析点数据。                                                                                                                                                                    |

### MFT的每个条目如下所示：

![](<../../../.gitbook/assets/image (499).png>)

注意每个条目都是以"FILE"开头的。每个条目占用1024位。所以从一个MFT条目的开始后1024位，你会找到下一个。

使用[**Active Disk Editor**](https://www.disk-editor.org/index.html)可以很容易地检查MFT中文件的条目。只需右键点击文件，然后点击"Inspect File Record"

![](<../../../.gitbook/assets/image (500).png>)

![](<../../../.gitbook/assets/image (501).png>)

检查**"In use"**标志可以很容易地知道文件是否被删除（**0x0表示已删除**）。

![](<../../../.gitbook/assets/image (510).png>)

也可以使用FTKImager恢复已删除的文件：

![](<../../../.gitbook/assets/image (502).png>)

### MFT属性

每个MFT条目都有几个属性，如下图所示：

![](<../../../.gitbook/assets/image (506).png>)

每个属性通过类型标识符指示一些条目信息：

| 类型标识符 | 名称                       | 描述                                                                                                       |
| ------- | ------------------------ | -------------------------------------------------------------------------------------------------------- |
| 16      | $STANDARD\_INFORMATION   | 一般信息，如标志；最后访问、写入和创建时间；以及所有者和安全ID。                                                                           |
| 32      | $ATTRIBUTE\_LIST         | 列出文件的其他属性可以在哪里找到。                                                                             |
| 48      | $FILE\_NAME              | 以Unicode格式的文件名，以及最后访问、写入和创建时间。                                                                                   |
| 64      | $VOLUME\_VERSION         | 卷信息。只存在于版本1.2（Windows NT）。                                                                           |
| 64      | $OBJECT\_ID              | 一个16字节的文件或目录唯一标识符。只存在于版本3.0+之后（Windows 2000+）。                                                                   |
| 80      | $SECURITY\_ DESCRIPTOR   | 文件的访问控制和安全属性。                                                                                         |
| 96      | $VOLUME\_NAME            | 卷名称。                                                                                                    |
| 112     | $VOLUME\_ INFORMATION    | 文件系统版本和其他标志。                                                                                         |
| 128     | $DATA                    | 文件内容。                                                                                                  |
| 144     | $INDEX\_ROOT             | 索引树的根节点。                                                                                             |
| 160     | $INDEX\_ALLOCATION       | 根植于$INDEX\_ROOT属性的索引树的节点。                                                                             |
| 176     | $BITMAP                  | $MFT文件和索引的位图。                                                                                         |
| 192     | $SYMBOLIC\_LINK          | 软链接信息。只存在于版本1.2（Windows NT）。                                                                       |
| 192     | $REPARSE\_POINT          | 包含有关重解析点的数据，这在版本3.0+（Windows 2000+）中用作软链接。                                                                         |
| 208     | $EA\_INFORMATION         | 用于与OS/2应用程序（HPFS）的向后兼容。                                                                               |
| 224     | $EA                      | 用于与OS/2应用程序（HPFS）的向后兼容。                                                                               |
| 256     | $LOGGED\_UTILITY\_STREAM | 包含有关版本3.0+（Windows 2000+）中加密属性的密钥和信息。                                                                 |

例如，**类型48 (0x30)** 标识**文件名**：

![](<../../../.gitbook/assets/image (508).png>)

了解这些属性可以是常驻的（意味着它们存在于给定的MFT记录中）或非常驻的（意味着它们存在于给定MFT记录之外的磁盘上的其他地方，并且仅在记录中被引用）也很有用。例如，如果属性**$Data是常驻的**，这意味着**整个文件保存在MFT中**，如果它是非常驻的，那么文件的内容在文件系统的另一个部分。

一些有趣的属性：

* [$STANDARD\_INFORMATION](https://flatcap.org/linux-ntfs/ntfs/attributes/standard\_information.html)（其中包括）：
* 创建日期
* 修改日期
* 访问日期
* MFT更新日期
* DOS文件权限
* [$FILE\_NAME](https://flatcap.org/linux-ntfs/ntfs/attributes/file\_name.html)（其中包括）：
* 文件名
* 创建日期
* 修改日期
* 访问日期
* MFT更新日期
* 已分配大小
* 实际大小
* [文件引用](https://flatcap.org/linux-ntfs/ntfs/concepts/file\_reference.html)到父目录。
* [$Data](https://flatcap.org/linux-ntfs/ntfs/attributes/data.html)（其中包括）：
* 包含文件数据或指示数据所在扇区的信息。在以下示例中，数据属性不是常驻的，所以属性提供了有关数据所在扇区的信息。

![](<../../../.gitbook/assets/image (507) (1) (1).png>)

![](<../../../.gitbook/assets/image (509).png>)

### NTFS时间戳

![](<../../../.gitbook/assets/image (512).png>)

分析MFT的另一个有用工具是[**MFT2csv**](https://github.com/jschicht/Mft2Csv)（选择mft文件或映像并按下dump all并提取以提取所有对象）。\
这个程序将提取所有MFT数据并以CSV格式呈现。它也可以用来转储文件。

![](<../../../.gitbook/assets/image (513).png>)

### $LOGFILE

文件**`$LOGFILE`**包含了对**文件执行的操作**的**日志**。它还**保存**了在**重做**的情况下需要执行的**操作**，以及需要执行的操作以**返回**到**之前的状态**。\
这些日志对于MFT在发生某种错误时重建文件系统很有用。这个文件的最大大小是**65536KB**。

要检查`$LOGFILE`，您需要先用[**MFT2csv**](https://github.com/jschicht/Mft2Csv)提取并检查`$MFT`。\
然后运行[**LogFileParser**](https://github.com/jschicht/LogFileParser)针对这个文件，并选择导出的`$LOGFILE`文件和`$MFT`检查的CVS。您将获得一个CSV文件，其中记录了`$LOGFILE`日志记录的文件系统活动。

![](<../../../.gitbook/assets/image (515).png>)

通过文件名过滤，您可以看到**对文件执行的所有操作**：

![](<../../../.gitbook/assets/image (514).png>)

### $USNJnrl

文件`$EXTEND/$USNJnrl/$J`是文件`$EXTEND$USNJnrl`的一个备用数据流。这个工件包含了一个**记录NTFS卷内变化的注册表，比`$LOGFILE`更详细**。

要检查这个文件，您可以使用工具[**UsnJrnl2csv**](https://github.com/jschicht/UsnJrnl2Csv)。

通过文件名过滤，可以看到**对文件执行的所有操作**。此外，您可以找到
