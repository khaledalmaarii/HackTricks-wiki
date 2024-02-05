<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# Ext - 扩展文件系统

**Ext2** 是最常见的**无日志**分区文件系统（**不经常更改的分区**，如引导分区）。**Ext3/4** 是**带日志**的，通常用于**其余分区**。

文件系统中的所有块组具有相同的大小并按顺序存储。这使得内核可以轻松地从整数索引推导出磁盘中块组的位置。

每个块组包含以下信息：

* 文件系统的超级块的副本
* 块组描述符的副本
* 数据块位图，用于标识组内的空闲块
* inode位图，用于标识组内的空闲inode
* inode表：由一系列连续的块组成，每个块包含预定义的图1 Ext2 inode数量的inode。所有inode的大小相同：128字节。一个1,024字节的块包含8个inode，而一个4,096字节的块包含32个inode。请注意，在Ext2中，无需在磁盘上存储inode号和相应块号之间的映射，因为后者的值可以从块组号和inode表内的相对位置推导出。例如，假设每个块组包含4,096个inode，并且我们想知道磁盘上inode 13,021的地址。在这种情况下，该inode属于第三个块组，其磁盘地址存储在相应inode表的第733个条目中。如您所见，inode号只是Ext2例程用于快速检索磁盘上正确inode描述符的关键
* 包含文件的数据块。任何不包含任何有意义信息的块被称为自由块。

![](<../../../.gitbook/assets/image (406).png>)

## Ext可选功能

**功能影响**数据的位置，**数据存储在inode中的方式，其中一些可能提供**附加元数据**进行分析，因此功能在Ext中很重要。

Ext具有可选功能，您的操作系统可能支持或不支持，有3种可能性：

* 兼容
* 不兼容
* 仅兼容读取：可以挂载但无法写入

如果存在**不兼容**功能，则无法挂载文件系统，因为操作系统不知道如何访问数据。

{% hint style="info" %}
疑似攻击者可能具有非标准扩展
{% endhint %}

**任何**读取**超级块**的实用程序都将能够指示**Ext文件系统**的**功能**，但您也可以使用`file -sL /dev/sd*`

## 超级块

超级块是从开头开始的前1024字节，它在每个组的第一个块中重复出现，并包含：

* 块大小
* 总块数
* 每个块组的块数
* 第一个块组之前的保留块
* 总inode数
* 每个块组的inode数
* 卷名称
* 最后写入时间
* 最后挂载时间
* 文件系统上次挂载的路径
* 文件系统状态（干净？）

可以使用以下方法从Ext文件系统文件中获取此信息：
```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```
您还可以使用免费的 GUI 应用程序：[https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
或者您也可以使用 **python** 来获取超级块信息：[https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

## inode

**inode** 包含**包含**文件实际**数据**的**块**列表。\
如果文件很大，inode **可能包含指针**指向**其他inode**，这些inode指向包含文件数据的块/更多inode。

![](<../../../.gitbook/assets/image (416).png>)

在 **Ext2** 和 **Ext3** 中，inode 的大小为 **128B**，**Ext4** 目前使用 **156B**，但在磁盘上分配 **256B** 以允许未来扩展。

Inode 结构：

| 偏移量 | 大小 | 名称              | 描述                                           |
| ------ | ---- | ----------------- | ---------------------------------------------- |
| 0x0    | 2    | 文件模式          | 文件模式和类型                                 |
| 0x2    | 2    | UID               | 所有者 ID 的低 16 位                           |
| 0x4    | 4    | Size Il           | 文件大小的低 32 位                              |
| 0x8    | 4    | Atime             | 自纪元以来的访问时间（秒）                     |
| 0xC    | 4    | Ctime             | 自纪元以来的更改时间（秒）                     |
| 0x10   | 4    | Mtime             | 自纪元以来的修改时间（秒）                     |
| 0x14   | 4    | Dtime             | 自纪元以来的删除时间（秒）                     |
| 0x18   | 2    | GID               | 组 ID 的低 16 位                               |
| 0x1A   | 2    | Hlink count       | 硬链接计数                                    |
| 0xC    | 4    | Blocks Io         | 块计数的低 32 位                              |
| 0x20   | 4    | Flags             | 标志                                           |
| 0x24   | 4    | Union osd1        | Linux：I 版本                                 |
| 0x28   | 69   | Block\[15]        | 指向数据块的 15 个指针                        |
| 0x64   | 4    | Version           | NFS 的文件版本                                |
| 0x68   | 4    | File ACL low      | 扩展属性（ACL 等）的低 32 位                   |
| 0x6C   | 4    | File size hi      | 文件大小的高 32 位（仅适用于 ext4）            |
| 0x70   | 4    | Obsolete fragment | 弃用的片段地址                                |
| 0x74   | 12   | Osd 2             | 第二个操作系统相关联合体                      |
| 0x74   | 2    | Blocks hi         | 块计数的高 16 位                              |
| 0x76   | 2    | File ACL hi       | 扩展属性（ACL 等）的高 16 位                   |
| 0x78   | 2    | UID hi            | 所有者 ID 的高 16 位                          |
| 0x7A   | 2    | GID hi            | 组 ID 的高 16 位                              |
| 0x7C   | 2    | Checksum Io       | inode 校验和的低 16 位                        |

"修改" 是文件内容最后一次修改的时间戳。这通常称为 "_mtime_"。\
"更改" 是文件 inode 最后一次更改的时间戳，例如通过更改权限、所有权、文件名和硬链接数。通常称为 "_ctime_"。

Inode 结构扩展（Ext4）：

| 偏移量 | 大小 | 名称         | 描述                                     |
| ------ | ---- | ------------ | ---------------------------------------- |
| 0x80   | 2    | 额外大小     | 使用标准 128 之外的字节数                |
| 0x82   | 2    | 校验和高     | inode 校验和的高 16 位                   |
| 0x84   | 4    | Ctime extra  | 更改时间额外位                          |
| 0x88   | 4    | Mtime extra  | 修改时间额外位                          |
| 0x8C   | 4    | Atime extra  | 访问时间额外位                          |
| 0x90   | 4    | Crtime       | 文件创建时间（自纪元以来的秒数）         |
| 0x94   | 4    | Crtime extra | 文件创建时间额外位                      |
| 0x98   | 4    | Version hi   | 版本的高 32 位                          |
| 0x9C   |      | 未使用       | 未来扩展的保留空间                    |

特殊 inode：

| Inode | 特殊目的                                           |
| ----- | -------------------------------------------------- |
| 0     | 不存在的 inode，编号从 1 开始                       |
| 1     | 有缺陷的块列表                                     |
| 2     | 根目录                                            |
| 3     | 用户配额                                           |
| 4     | 组配额                                            |
| 5     | 引导加载程序                                       |
| 6     | 未删除目录                                         |
| 7     | 保留的组描述符（用于调整文件系统大小）             |
| 8     | 日志                                               |
| 9     | 排除 inode（用于快照）                            |
| 10    | 复制 inode                                         |
| 11    | 第一个非保留 inode（通常是 lost + found）          |

{% hint style="info" %}
请注意，创建时间仅出现在 Ext4 中。
{% endhint %}

通过知道 inode 编号，您可以轻松找到其索引：

* inode 所属的**块组**：(Inode 编号 - 1) / (每组的 inode 数)
* 其组内的**索引**：(Inode 编号 - 1) mod(每组的 inode 数)
* 进入**inode 表**的**偏移量**：Inode 编号 \* (Inode 大小)
* "-1" 是因为 inode 0 未定义（未使用）
```bash
ls -ali /bin | sort -n #Get all inode numbers and sort by them
stat /bin/ls #Get the inode information of a file
istat -o <start offset> /path/to/image.ext 657103 #Get information of that inode inside the given ext file
icat -o <start offset> /path/to/image.ext 657103 #Cat the file
```
文件模式

| 编号 | 描述                                                                                               |
| ------ | --------------------------------------------------------------------------------------------------- |
| **15** | **Reg/Slink-13/Socket-14**                                                                          |
| **14** | **目录/块位 13**                                                                          |
| **13** | **字符设备/块位 14**                                                                        |
| **12** | **FIFO**                                                                                            |
| 11     | 设置UID                                                                                             |
| 10     | 设置GID                                                                                             |
| 9      | 粘着位（没有它，任何具有目录上写和执行权限的人都可以删除和重命名文件）  |
| 8      | 拥有者读取                                                                                          |
| 7      | 拥有者写入                                                                                         |
| 6      | 拥有者执行                                                                                          |
| 5      | 组读取                                                                                          |
| 4      | 组写入                                                                                         |
| 3      | 组执行                                                                                          |
| 2      | 其他人读取                                                                                         |
| 1      | 其他人写入                                                                                        |
| 0      | 其他人执行                                                                                         |

粗体位（12、13、14、15）指示文件的类型（目录、套接字...）只能存在一个粗体选项。

目录

| 偏移量 | 大小 | 名称      | 描述                                                                                                                                                  |
| ------ | ---- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 4    | 索引节点     |                                                                                                                                                              |
| 0x4    | 2    | 记录长度   | 记录长度                                                                                                                                                |
| 0x6    | 1    | 名称长度  | 名称长度                                                                                                                                                  |
| 0x7    | 1    | 文件类型 | <p>0x00 未知<br>0x01 常规</p><p>0x02 目录</p><p>0x03 字符设备</p><p>0x04 块设备</p><p>0x05 FIFO</p><p>0x06 套接字</p><p>0x07 符号链接</p> |
| 0x8    |      | 名称      | 名称字符串（最多255个字符）                                                                                                                           |

**为提高性能，可以使用根哈希目录块。**

**扩展属性**

可以存储在

* 索引节点之间的额外空间（256 - 索引节点大小，通常= 100）
* 由索引节点中的file_acl指向的数据块

如果名称以"user"开头，则可以用于存储任何用户属性。因此，数据可以通过这种方式隐藏。

扩展属性条目

| 偏移量 | 大小 | 名称         | 描述                                                                                                                                                                                                        |
| ------ | ---- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 1    | 名称长度     | 属性名称长度                                                                                                                                                                                           |
| 0x1    | 1    | 名称索引   | <p>0x0 = 无前缀</p><p>0x1 = user. 前缀</p><p>0x2 = system.posix_acl_access</p><p>0x3 = system.posix_acl_default</p><p>0x4 = trusted.</p><p>0x6 = security.</p><p>0x7 = system.</p><p>0x8 = system.richacl</p> |
| 0x2    | 2    | 值偏移   | 从第一个索引节点条目或块的起始处的偏移                                                                                                                                                                    |
| 0x4    | 4    | 值块 | 存储值的磁盘块或此块的零                                                                                                                                                               |
| 0x8    | 4    | 值大小   | 值的长度                                                                                                                                                                                                    |
| 0xC    | 4    | 哈希         | 块中属性的哈希或如果在索引节点中则为零                                                                                                                                                                      |
| 0x10   |      | 名称         | 不带尾随NULL的属性名称                                                                                                                                                                                   |
```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```
## 文件系统视图

要查看文件系统的内容，您可以**使用免费工具**：[https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
或者您可以在Linux中使用`mount`命令挂载它。

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.](https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.)
