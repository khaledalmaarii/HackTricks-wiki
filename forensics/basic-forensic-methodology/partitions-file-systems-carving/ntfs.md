# NTFS

## NTFS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## **NTFS**

**NTFS**（**新技术文件系统**）是由Microsoft开发的专有日志文件系统。

在NTFS中，簇是最小的大小单位，簇的大小取决于分区的大小。

| 分区大小                | 每簇扇区数 | 簇大小   |
| ----------------------- | ---------- | -------- |
| 512MB或更小              | 1          | 512字节  |
| 513MB-1024MB（1GB）      | 2          | 1KB      |
| 1025MB-2048MB（2GB）     | 4          | 2KB      |
| 2049MB-4096MB（4GB）     | 8          | 4KB      |
| 4097MB-8192MB（8GB）     | 16         | 8KB      |
| 8193MB-16,384MB（16GB）  | 32         | 16KB     |
| 16,385MB-32,768MB（32GB）| 64         | 32KB     |
| 大于32,768MB             | 128        | 64KB     |

### **闲置空间**

由于NTFS的最小单位是**簇**，每个文件将占用多个完整的簇。因此，**每个文件占用的空间很可能比必要的空间多**。这些文件预留的**未使用空间**称为**闲置空间**，人们可以利用这个区域来**隐藏信息**。

![](<../../../.gitbook/assets/image (498).png>)

### **NTFS引导扇区**

当你格式化一个NTFS卷时，格式化程序会为引导元数据文件分配前16个扇区。第一个扇区是引导扇区，包含“引导程序”代码，接下来的15个扇区是引导扇区的IPL（初始程序加载器）。为了增加文件系统的可靠性，NTFS分区的最后一个扇区包含引导扇区的备用副本。

### **主文件表（MFT）**

NTFS文件系统包含一个称为主文件表（MFT）的文件。在NTFS文件系统卷上，至少有**一个MFT条目与每个文件对应**，包括MFT本身。关于文件的所有信息，包括**大小、时间和日期戳、权限和数据内容**，都存储在MFT条目或由MFT条目描述的MFT之外的空间中。

当文件被添加到NTFS文件系统卷时，MFT中会添加更多的条目，MFT的大小也会增加。当文件从NTFS文件系统卷中被删除时，它们的MFT条目被标记为可重用。然而，为这些条目分配的磁盘空间不会被重新分配，MFT的大小也不会减小。

NTFS文件系统为了尽可能地使MFT连续，保留了MFT的空间。NTFS文件系统在每个卷中为MFT保留的空间称为**MFT区域**。文件和目录的空间也从这个空间中分配，但只有在MFT区域之外的卷空间全部分配完之后才会分配。

根据平均文件大小和其他变量的不同，**在磁盘填满容量时，可能会首先分配保留的MFT区域或磁盘上的未保留空间**。具有相对较大文件数量的卷会首先分配未保留空间，而具有相对较小文件数量的卷会首先分配MFT区域。在任一情况下，当其中一个区域完全分配时，MFT的碎片化就开始发生。如果未保留空间完全分配，用户文件和目录的空间将从MFT区域分配。如果MFT区域完全分配，新的MFT条目的空间将从未保留空间分配。

NTFS文件系统还会生成一个**$MFTMirror**。这是MFT的**前4个条目的副本**：$MFT、$MFT Mirror、$Log、$Volume。

NTFS为表的前16个记录保留了特殊信息：

| 系统文件             | 文件名    | MFT记录 | 文件的目的                                                                                      |
| -------------------- | --------- | -------- | ----------------------------------------------------------------------------------------------- |
| 主文件表             | $Mft      | 0        | 包含NTFS卷上每个文件和文件夹的一个基本文件记录。如果一个文件或文件夹的分配信息太大，无法适应单个记录中，将分配其他文件记录。 |
| 主文件表2           | $MftMirr  | 1        | MFT的前四个记录的重复镜像。这个文件在单个扇区故障的情况下保证对MFT的访问。                          |
| 日志文件             | $LogFile  | 2        | 包含用于NTFS可恢复性的事务步骤列表。日志文件的大小取决于卷的大小，最大可以达到4MB。它被Windows NT/2000用于在系统故障后恢复NTFS的一致性。 |
| 卷                  | $Volume   | 3        | 包含有关卷的信息，如卷标和卷版本。                                                              |
| 属性定义             | $AttrDef  | 4        | 属性名称、编号和描述的表。                                                                      |
| 根文件名索引         | $         | 5        | 根文件夹。                                                                                      |
| 簇位图               | $Bitmap   | 6        | 表示卷中哪些簇正在使用的表示。                                                                  |
| 引导扇区              | $Boot     | 7          | 包含用于挂载卷的BPB以及如果卷可引导，则使用的附加引导加载程序代码。                                                                                                                |
| 坏簇文件              | $BadClus  | 8          | 包含卷的坏簇。                                                                                                                                                                      |
| 安全文件              | $Secure   | 9          | 包含卷内所有文件的唯一安全描述符。                                                                                                                                                  |
| 大写表                | $Upcase   | 10         | 将小写字符转换为相应的Unicode大写字符。                                                                                                                                             |
| NTFS扩展文件          | $Extend   | 11         | 用于各种可选扩展，如配额、重解析点数据和对象标识符。                                                                                                                                |
|                       |           | 12-15      | 保留供将来使用。                                                                                                                                                                    |
| 配额管理文件          | $Quota    | 24         | 包含用户分配的卷空间配额限制。                                                                                                                                                      |
| 对象ID文件            | $ObjId    | 25         | 包含文件对象ID。                                                                                                                                                                   |
| 重解析点文件          | $Reparse  | 26         | 此文件包含有关卷上的文件和文件夹的信息，包括重解析点数据。                                                                                                                            |

### MFT的每个条目如下所示：

![](<../../../.gitbook/assets/image (499).png>)

请注意，每个条目以"FILE"开头。每个条目占用1024位。因此，在MFT条目的开头后的1024位之后，您将找到下一个条目。

使用[**Active Disk Editor**](https://www.disk-editor.org/index.html)非常容易检查MFT中文件的条目。只需右键单击文件，然后单击"Inspect File Record"。

![](<../../../.gitbook/assets/image (500).png>)

![](<../../../.gitbook/assets/image (501).png>)

通过检查**"In use"**标志，可以很容易地知道文件是否已删除（值为**0x0表示已删除**）。

![](<../../../.gitbook/assets/image (510).png>)

还可以使用FTKImager恢复已删除的文件：

![](<../../../.gitbook/assets/image (502).png>)

### MFT属性

每个MFT条目都有多个属性，如下图所示：

![](<../../../.gitbook/assets/image (506).png>)

每个属性都表示某些由类型标识符标识的条目信息：

| 类型标识符 | 名称                     | 描述                                                                                                             |
| ---------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| 16         | $STANDARD\_INFORMATION   | 一般信息，如标志；最后访问、写入和创建时间；所有者和安全ID。                                                      |
| 32         | $ATTRIBUTE\_LIST         | 文件的其他属性所在的列表。                                                                                       |
| 48         | $FILE\_NAME              | 文件名，以Unicode表示，以及最后访问、写入和创建时间。                                                             |
| 64         | $VOLUME\_VERSION         | 卷信息。仅存在于版本1.2（Windows NT）。                                                                           |
| 64         | $OBJECT\_ID              | 文件或目录的16字节唯一标识符。仅存在于版本3.0+和之后（Windows 2000+）。                                             |
| 80         | $SECURITY\_ DESCRIPTOR   | 文件的访问控制和安全属性。                                                                                       |
| 96         | $VOLUME\_NAME            | 卷名称。                                                                                                          |
| 112        | $VOLUME\_ INFORMATION    | 文件系统版本和其他标志。                                                                                         |
| 128        | $DATA                    | 文件内容。                                                                                                        |
| 144        | $INDEX\_ROOT             | 索引树的根节点。                                                                                                 |
| 160        | $INDEX\_ALLOCATION       | 以$INDEX\_ROOT属性为根的索引树的节点。                                                                             |
| 176        | $BITMAP                  | 用于$MFT文件和索引的位图。                                                                                        |
| 192        | $SYMBOLIC\_LINK          | 软链接信息。仅存在于版本1.2（Windows NT）。                                                                       |
| 192        | $REPARSE\_POINT          | 包含有关重解析点的数据，用作版本3.0+（Windows 2000+）中的软链接。                                                  |
| 208        | $EA\_INFORMATION         | 用于与OS/2应用程序（HPFS）向后兼容。                                                                              |
| 224        | $EA                      | 用于与OS/2应用程序（HPFS）向后兼容。                                                                              |
| 256        | $LOGGED\_UTILITY\_STREAM | 包含版本3.0+（Windows 2000+）中加密属性的键和信息。                                                               |

例如，**类型48（0x30）**标识**文件名**：

![](<../../../.gitbook/assets/image (508).png>)

还有一点很有用，就是**这些属性可以是驻留的**（意味着它们存在于给定的MFT记录中），或者是**非驻留的**（意味着它们存在于磁盘上的MFT记录之外的其他位置，并且仅在记录中引用）。例如，如果属性**$Data是驻留的**，这意味着**整个文件保存在MFT中**，如果是非驻留的，则文件的内容在文件系统的其他部分。

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
* [文件引用](https://flatcap.org/linux-ntfs/ntfs/concepts/file\_reference.html)指向父目录。
* [$Data](https://flatcap.org/linux-ntfs/ntfs/attributes/data.html)（以及其他）：
* 包含文件的数据或数据所在扇区的指示。在下面的示例中，属性数据不是驻留的，因此属性提供了有关数据所在扇区的信息。

![](<../../../.gitbook/assets/image (507) (1) (1).png>)

![](<../../../.gitbook/assets/image (509).png>)
### NTFS时间戳

![](<../../../.gitbook/assets/image (512).png>)

分析MFT的另一个有用工具是[MFT2csv](https://github.com/jschicht/Mft2Csv)（选择mft文件或镜像，按下dump all and extract以提取所有对象）。\
该程序将以CSV格式提取所有MFT数据并呈现出来。它还可以用于转储文件。

![](<../../../.gitbook/assets/image (513).png>)

### $LOGFILE

文件**`$LOGFILE`**包含有关对文件执行的操作的日志。它还保存了在发生错误时需要执行的操作以及返回到先前状态所需的操作。\
这些日志对于MFT在发生某种错误时重建文件系统很有用。此文件的最大大小为**65536KB**。

要检查`$LOGFILE`，您需要先使用[MFT2csv](https://github.com/jschicht/Mft2Csv)提取并检查`$MFT`。\
然后运行[LogFileParser](https://github.com/jschicht/LogFileParser)对该文件进行操作，并选择导出的`$LOGFILE`文件和`$MFT`检查的CSV文件。您将获得一个包含由`$LOGFILE`日志记录的文件系统活动日志的CSV文件。

![](<../../../.gitbook/assets/image (515).png>)

通过文件名过滤，您可以查看**针对文件执行的所有操作**：

![](<../../../.gitbook/assets/image (514).png>)

### $USNJnrl

文件`$EXTEND/$USNJnrl/$J`是文件`$EXTEND$USNJnrl`的备用数据流。此工件包含比`$LOGFILE`更详细的NTFS卷内更改的注册表。

要检查此文件，您可以使用工具[UsnJrnl2csv](https://github.com/jschicht/UsnJrnl2Csv)。

通过文件名过滤，可以查看**针对文件执行的所有操作**。此外，您还可以在父文件夹中找到`MFTReference`。然后查看该`MFTReference`，您可以找到来自父文件夹的信息。

![](<../../../.gitbook/assets/image (516).png>)

### $I30

文件系统中的每个**目录**都包含一个必须在目录内容发生更改时维护的**`$I30`属性**。当文件或文件夹从目录中删除时，`$I30`索引记录将相应重新排列。然而，**重新排列索引记录可能会在未使用的空间中留下已删除的文件/文件夹条目的残留**。这对于鉴定可能存在于驱动器上的文件在取证分析中很有用。

您可以使用**FTK Imager**获取目录的`$I30`文件，并使用工具[Indx2Csv](https://github.com/jschicht/Indx2Csv)进行检查。

![](<../../../.gitbook/assets/image (519).png>)

通过这些数据，您可以找到**在文件夹内执行的文件更改的信息**，但请注意，文件的删除时间不会保存在此日志中。但是，您可以查看**`$I30`文件**的**最后修改日期**，如果对目录执行的**最后一个操作**是文件的**删除**，则时间可能相同。

### $Bitmap

**`$BitMap`**是NTFS文件系统中的一个特殊文件。该文件跟踪NTFS卷上所有已使用和未使用的簇。当文件占用NTFS卷上的空间时，所使用的位置将在`$BitMap`中标记出来。

![](<../../../.gitbook/assets/image (523).png>)

### ADS（备用数据流）

备用数据流允许文件包含多个数据流。每个文件至少有一个数据流。在Windows中，默认数据流称为`:$DATA`。\
在此[页面上，您可以查看有关如何在控制台中创建/访问/发现备用数据流](../../../windows-hardening/basic-cmd-for-pentesters.md#alternate-data-streams-cheatsheet-ads-alternate-data-stream)的不同方法。过去，这在IIS中导致了一个漏洞，因为人们可以通过访问`:$DATA`流（如`http://www.alternate-data-streams.com/default.asp::$DATA`）来访问页面的源代码。

使用工具[AlternateStreamView](https://www.nirsoft.net/utils/alternate\_data\_streams.html)，您可以搜索和导出所有带有某些ADS的文件。

![](<../../../.gitbook/assets/image (518).png>)

使用FTK Imager并双击带有ADS的文件，您可以**访问ADS数据**：

![](<../../../.gitbook/assets/image (517).png>)

如果您找到名为**`Zone.Identifier`**的ADS（请参见上图），通常会包含有关文件下载方式的信息。其中将有一个名为"ZoneId"的字段，其中包含以下信息：

* Zone ID = 0 -> Mycomputer
* Zone ID = 1 -> Intranet
* Zone ID = 2 -> Trusted
* Zone ID = 3 -> Internet
* Zone ID = 4 -> Untrusted

此外，不同的软件可能存储其他信息：

| 软件                                                               | 信息                                                                         |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| Google Chrome, Opera, Vivaldi,                                      | ZoneId=3, ReferrerUrl, HostUrl                                               |
| Microsoft Edge                                                      | ZoneId=3, LastWriterPackageFamilyName=Microsoft.MicrosoftEdge\_8wekyb3d8bbwe |
| Firefox, Tor browser, Outlook2016, Thunderbird, Windows Mail, Skype | ZoneId=3                                                                     |
| μTorrent                                                            | ZoneId=3, HostUrl=about:internet                                             |

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) **或者** [**telegram 群组**](https://t.me/peass) **或者在 Twitter 上关注我** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
