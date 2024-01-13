<details>

<summary><strong>零基础学习AWS黑客攻击到高手</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# Ext - 扩展文件系统

**Ext2** 是最常见的**非日志**文件系统（**不经常变化的分区**），如启动分区。**Ext3/4** 是**日志文件系统**，通常用于**其他分区**。

文件系统中的所有块组大小相同且顺序存储。这使得内核可以轻松地从其整数索引推导出磁盘中块组的位置。

每个块组包含以下信息：

* 文件系统超级块的副本
* 块组描述符的副本
* 数据块位图，用于识别组内的空闲块
* inode位图，用于识别组内的空闲inode
* inode表：它由一系列连续的块组成，每个块包含预定义的Ext2 inode数量。所有inode大小相同：128字节。1,024字节块包含8个inode，而4,096字节块包含32个inode。注意，在Ext2中，没有必要在磁盘上存储inode号码和相应块号码之间的映射，因为后者的值可以从块组号和inode表内的相对位置推导出来。例如，假设每个块组包含4,096个inode，我们想知道磁盘上inode 13,021的地址。在这种情况下，inode属于第三个块组，其磁盘地址存储在相应inode表的第733个条目中。如您所见，inode号码只是一个键，Ext2例程用它快速检索磁盘上的适当inode描述符
* 数据块，包含文件。任何不包含有意义信息的块都被认为是空闲的。

![](<../../../.gitbook/assets/image (406).png>)

## Ext 可选功能

**功能影响**数据的位置，**如何**将数据存储在inodes中，其中一些可能提供**额外的元数据**进行分析，因此Ext中的功能很重要。

Ext有可选功能，您的操作系统可能支持也可能不支持，有3种可能性：

* 兼容
* 不兼容
* 只读兼容：可以挂载但不用于写入

如果有**不兼容**的功能，您将无法挂载文件系统，因为操作系统不知道如何访问数据。

{% hint style="info" %}
怀疑的攻击者可能有非标准扩展
{% endhint %}

**任何工具**都能读取**超级块**，将能够指示**Ext文件系统**的**功能**，但您也可以使用`file -sL /dev/sd*`

## 超级块

超级块是从开始的第一个1024字节，并在每个组的第一个块中重复，包含：

* 块大小
* 总块数
* 每个块组的块数
* 第一个块组前的保留块
* 总inodes
* 每个块组的inodes
* 卷名
* 最后写入时间
* 最后挂载时间
* 文件系统最后挂载的路径
* 文件系统状态（干净？）

可以使用以下命令从Ext文件系统文件获取此信息：
```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```
您还可以使用免费的GUI应用程序：[https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
或者您也可以使用**python**来获取superblock信息：[https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

## inodes

**inodes**包含了**blocks**的列表，这些**blocks**实际上**包含**了**文件**的**数据**。\
如果文件很大，一个inode**可能包含指针**指向**其他inodes**，这些inode指向包含文件数据的blocks/更多inodes。

![](<../../../.gitbook/assets/image (416).png>)

在**Ext2**和**Ext3**中，inodes的大小为**128B**，**Ext4**目前使用**156B**，但在磁盘上分配了**256B**以便将来扩展。

Inode结构：

| 偏移量 | 大小 | 名称              | 描述                                           |
| ------ | ---- | ----------------- | ---------------------------------------------- |
| 0x0    | 2    | 文件模式         | 文件模式和类型                                 |
| 0x2    | 2    | UID               | 所有者ID的低16位                               |
| 0x4    | 4    | 大小Il           | 文件大小的低32位                               |
| 0x8    | 4    | 访问时间         | 自纪元以来的访问时间（秒）                     |
| 0xC    | 4    | 更改时间         | 自纪元以来的更改时间（秒）                     |
| 0x10   | 4    | 修改时间         | 自纪元以来的修改时间（秒）                     |
| 0x14   | 4    | 删除时间         | 自纪元以来的删除时间（秒）                     |
| 0x18   | 2    | GID               | 组ID的低16位                                   |
| 0x1A   | 2    | 硬链接计数       | 硬链接计数                                     |
| 0xC    | 4    | 块Io             | 块计数的低32位                                 |
| 0x20   | 4    | 标志             | 标志                                           |
| 0x24   | 4    | Union osd1        | Linux：I版本                                   |
| 0x28   | 69   | 块\[15]          | 15个指向数据块的点                             |
| 0x64   | 4    | 版本             | NFS的文件版本                                  |
| 0x68   | 4    | 文件ACL低        | 扩展属性（ACL等）的低32位                      |
| 0x6C   | 4    | 文件大小高       | 文件大小的高32位（仅限ext4）                   |
| 0x70   | 4    | 已废弃片段       | 一个废弃的片段地址                             |
| 0x74   | 12   | Osd 2             | 第二个操作系统依赖的联合体                     |
| 0x74   | 2    | 块高             | 块计数的高16位                                 |
| 0x76   | 2    | 文件ACL高        | 扩展属性（ACL等）的高16位                      |
| 0x78   | 2    | UID高            | 所有者ID的高16位                               |
| 0x7A   | 2    | GID高            | 组ID的高16位                                   |
| 0x7C   | 2    | 校验和Io         | inode校验和的低16位                            |

"修改"是文件_内容_最后一次被修改的时间戳。这通常被称为"_mtime_"。\
"更改"是文件_inode_最后一次被更改的时间戳，比如通过更改权限、所有权、文件名和硬链接数量。它通常被称为"_ctime_"。

Inode结构扩展（Ext4）：

| 偏移量 | 大小 | 名称         | 描述                                       |
| ------ | ---- | ------------ | ------------------------------------------ |
| 0x80   | 2    | 额外大小     | 标准128字节之外使用了多少字节              |
| 0x82   | 2    | 校验和高     | inode校验和的高16位                        |
| 0x84   | 4    | 更改时间额外 | 更改时间的额外位                           |
| 0x88   | 4    | 修改时间额外 | 修改时间的额外位                           |
| 0x8C   | 4    | 访问时间额外 | 访问时间的额外位                           |
| 0x90   | 4    | 创建时间     | 文件创建时间（自纪元以来的秒数）           |
| 0x94   | 4    | 创建时间额外 | 文件创建时间的额外位                       |
| 0x98   | 4    | 版本高       | 版本的高32位                               |
| 0x9C   |      | 未使用       | 为将来扩展保留的空间                       |

特殊inodes：

| Inode | 特殊用途                                            |
| ----- | --------------------------------------------------- |
| 0     | 不存在的inode，编号从1开始                          |
| 1     | 损坏块列表                                          |
| 2     | 根目录                                              |
| 3     | 用户配额                                            |
| 4     | 组配额                                              |
| 5     | 引导加载器                                          |
| 6     | 可恢复删除的目录                                    |
| 7     | 保留的组描述符（用于调整文件系统大小）              |
| 8     | 日志                                                |
| 9     | 排除inode（用于快照）                               |
| 10    | 副本inode                                           |
| 11    | 第一个非保留inode（通常是lost + found）             |

{% hint style="info" %}
请注意，创建时间仅在Ext4中出现。
{% endhint %}

通过知道inode编号，您可以轻松找到其索引：

* **块组**，inode所属的块组：(Inode编号 - 1) / (每组Inodes)
* **组内索引**：(Inode编号 - 1) mod(每组Inodes)
* **到inode表的偏移量**：Inode编号 * (Inode大小)
* "-1"是因为inode 0是未定义的（未使用）
```bash
ls -ali /bin | sort -n #Get all inode numbers and sort by them
stat /bin/ls #Get the inode information of a file
istat -o <start offset> /path/to/image.ext 657103 #Get information of that inode inside the given ext file
icat -o <start offset> /path/to/image.ext 657103 #Cat the file
```
文件模式

| 数字 | 描述                                                                                         |
| ---- | -------------------------------------------------------------------------------------------- |
| **15** | **Reg/Slink-13/Socket-14**                                                                          |
| **14** | **目录/块位13**                                                                          |
| **13** | **字符设备/块位14**                                                                        |
| **12** | **FIFO**                                                                                            |
| 11   | 设置UID                                                                                             |
| 10   | 设置GID                                                                                             |
| 9    | 粘滞位（没有它，任何对目录有写入和执行权限的人都可以删除和重命名文件）  |
| 8    | 所有者读取                                                                                          |
| 7    | 所有者写入                                                                                         |
| 6    | 所有者执行                                                                                          |
| 5    | 组读取                                                                                          |
| 4    | 组写入                                                                                         |
| 3    | 组执行                                                                                          |
| 2    | 其他读取                                                                                         |
| 1    | 其他写入                                                                                        |
| 0    | 其他执行                                                                                         |

粗体位（12, 13, 14, 15）表示文件的类型（目录、套接字等），只有一个粗体选项可能存在。

目录

| 偏移量 | 大小 | 名称      | 描述                                                                                                                                                  |
| ---- | ---- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0x0  | 4    | Inode     |                                                                                                                                                      |
| 0x4  | 2    | 记录长度   | 记录长度                                                                                                                                                |
| 0x6  | 1    | 名称长度  | 名称长度                                                                                                                                                  |
| 0x7  | 1    | 文件类型 | <p>0x00 未知<br>0x01 常规</p><p>0x02 目录</p><p>0x03 字符设备</p><p>0x04 块设备</p><p>0x05 FIFO</p><p>0x06 套接字</p><p>0x07 符号链接</p> |
| 0x8  |      | 名称      | 名称字符串（最多255个字符）                                                                                                                           |

**为了提高性能，可以使用根哈希目录块。**

**扩展属性**

可以存储在

* inode之间的额外空间（256 - inode大小，通常=100）
* 由inode中的file_acl指向的数据块

如果名称以"user"开头，则可以将任何内容作为用户属性存储。因此，数据可以以这种方式隐藏。

扩展属性条目

| 偏移量 | 大小 | 名称         | 描述                                                                                                                                                                                                        |
| ---- | ---- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0x0  | 1    | 名称长度     | 属性名称的长度                                                                                                                                                                                           |
| 0x1  | 1    | 名称索引   | <p>0x0 = 无前缀</p><p>0x1 = user. 前缀</p><p>0x2 = system.posix_acl_access</p><p>0x3 = system.posix_acl_default</p><p>0x4 = trusted.</p><p>0x6 = security.</p><p>0x7 = system.</p><p>0x8 = system.richacl</p> |
| 0x2  | 2    | 值偏移   | 从第一个inode条目或块的开始的偏移                                                                                                                                                                    |
| 0x4  | 4    | 值块 | 存储值的磁盘块或为此块为零                                                                                                                                                               |
| 0x8  | 4    | 值大小   | 值的长度                                                                                                                                                                                                    |
| 0xC  | 4    | 哈希         | 块中属性的哈希或如果在inode中则为零                                                                                                                                                                      |
| 0x10 |      | 名称         | 属性名称，不包括结尾的NULL                                                                                                                                                                                   |
```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```
## 文件系统视图

要查看文件系统的内容，您可以**使用免费工具**：[https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
或者您可以使用 `mount` 命令在您的linux中挂载它。

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.](https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.)


<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
