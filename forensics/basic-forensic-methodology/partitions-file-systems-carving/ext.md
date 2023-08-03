<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# Ext - 扩展文件系统

**Ext2**是最常见的**无日志**分区文件系统（**不经常更改的分区**，如引导分区）。**Ext3/4**是**带日志**的文件系统，通常用于**其余分区**。

文件系统中的所有块组具有相同的大小并按顺序存储。这使得内核可以轻松地从整数索引中推导出磁盘上块组的位置。

每个块组包含以下信息：

* 文件系统的超级块的副本
* 块组描述符的副本
* 数据块位图，用于标识组内的空闲块
* inode位图，用于标识组内的空闲inode
* inode表：它由一系列连续的块组成，每个块都包含预定义的Figure 1 Ext2 inode数量的inode。所有inode的大小相同：128字节。1024字节的块包含8个inode，而4096字节的块包含32个inode。请注意，在Ext2中，无需在磁盘上存储inode号和相应块号之间的映射，因为后者的值可以从块组号和inode表中的相对位置推导出来。例如，假设每个块组包含4096个inode，并且我们想要知道inode 13,021在磁盘上的地址。在这种情况下，该inode属于第三个块组，其磁盘地址存储在相应inode表的第733个条目中。正如您所见，inode号只是Ext2例程用于快速检索磁盘上正确的inode描述符的关键
* 包含文件的数据块。不包含任何有意义信息的块被称为自由块。

![](<../../../.gitbook/assets/image (406).png>)

## Ext可选功能

**功能影响数据的位置**，**数据在inode中的存储方式**，其中一些功能可能为分析提供**附加元数据**，因此功能在Ext中非常重要。

Ext具有可选功能，您的操作系统可能支持或不支持，有3种可能性：

* 兼容
* 不兼容
* 仅兼容读取：可以挂载但无法写入

如果存在**不兼容**的功能，则无法挂载文件系统，因为操作系统不知道如何访问数据。

{% hint style="info" %}
可疑的攻击者可能具有非标准扩展
{% endhint %}

**任何读取超级块的实用程序**都可以指示**Ext文件系统的功能**，但您也可以使用`file -sL /dev/sd*`来获取此信息。

## 超级块

超级块是从开头开始的前1024字节，并在每个块组的第一个块中重复出现，包含以下内容：

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

可以使用以下命令从Ext文件系统文件中获取此信息：
```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```
你还可以使用免费的GUI应用程序：[https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
或者你也可以使用**python**来获取超级块信息：[https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

## inodes

**inodes** 包含了实际 **文件** 的 **数据** 所在的 **块** 的列表。\
如果文件很大，inode **可能包含指向** 指向包含文件数据的块/更多inode的指针。

![](<../../../.gitbook/assets/image (416).png>)

在 **Ext2** 和 **Ext3** 中，inode 的大小为 **128B**，**Ext4** 目前使用 **156B**，但在磁盘上分配了 **256B** 以允许未来扩展。

inode 结构：

| 偏移量 | 大小 | 名称              | 描述                                             |
| ------ | ---- | ----------------- | ------------------------------------------------ |
| 0x0    | 2    | 文件模式          | 文件模式和类型                                   |
| 0x2    | 2    | UID               | 所有者ID的低16位                                 |
| 0x4    | 4    | Size Il           | 文件大小的低32位                                 |
| 0x8    | 4    | Atime             | 自纪元以来的访问时间（以秒为单位）                 |
| 0xC    | 4    | Ctime             | 自纪元以来的更改时间（以秒为单位）                 |
| 0x10   | 4    | Mtime             | 自纪元以来的修改时间（以秒为单位）                 |
| 0x14   | 4    | Dtime             | 自纪元以来的删除时间（以秒为单位）                 |
| 0x18   | 2    | GID               | 组ID的低16位                                     |
| 0x1A   | 2    | Hlink count       | 硬链接计数                                       |
| 0xC    | 4    | Blocks Io         | 块计数的低32位                                   |
| 0x20   | 4    | Flags             | 标志                                             |
| 0x24   | 4    | Union osd1        | Linux: I 版本                                    |
| 0x28   | 69   | Block\[15]        | 指向数据块的15个指针                             |
| 0x64   | 4    | Version           | NFS 的文件版本                                   |
| 0x68   | 4    | File ACL low      | 扩展属性（ACL等）的低32位                         |
| 0x6C   | 4    | File size hi      | 文件大小的高32位（仅限 ext4）                     |
| 0x70   | 4    | Obsolete fragment | 废弃的片段地址                                   |
| 0x74   | 12   | Osd 2             | 第二个操作系统相关联的联合体                     |
| 0x74   | 2    | Blocks hi         | 块计数的高16位                                   |
| 0x76   | 2    | File ACL hi       | 扩展属性（ACL等）的高16位                         |
| 0x78   | 2    | UID hi            | 所有者ID的高16位                                 |
| 0x7A   | 2    | GID hi            | 组ID的高16位                                     |
| 0x7C   | 2    | Checksum Io       | inode 校验和的低16位                             |

"Modify" 是文件内容最后一次修改的时间戳，通常称为 "mtime"。\
"Change" 是文件inode最后一次更改的时间戳，例如更改权限、所有权、文件名和硬链接数。通常称为 "ctime"。

扩展的inode结构（Ext4）：

| 偏移量 | 大小 | 名称        | 描述                                 |
| ------ | ---- | ----------- | ------------------------------------ |
| 0x80   | 2    | Extra size  | 使用的标准128字节之外的字节数         |
| 0x82   | 2    | Checksum hi | inode校验和的高16位                   |
| 0x84   | 4    | Ctime extra | 更改时间的额外位                       |
| 0x88   | 4    | Mtime extra | 修改时间的额外位                       |
| 0x8C   | 4    | Atime extra | 访问时间的额外位                       |
| 0x90   | 4    | Crtime      | 文件创建时间（自纪元以来的秒数）       |
| 0x94   | 4    | Crtime extra| 文件创建时间的额外位                   |
| 0x98   | 4    | Version hi  | 版本的高32位                          |
| 0x9C   |      | Unused      | 未来扩展的保留空间                     |

特殊的inodes：

| Inode | 特殊用途                                          |
| ----- | ------------------------------------------------- |
| 0     | 不存在的inode，编号从1开始                         |
| 1     | 有缺陷的块列表                                    |
| 2     | 根目录                                            |
| 3     | 用户配额                                          |
| 4     | 组配额                                            |
| 5     | 引导加载程序                                      |
| 6     | 未删除的目录                                      |
| 7     | 保留的组描述符（用于调整文件系统大小）              |
| 8     | 日志                                              |
| 9     | 排除的inode（用于快照）                            |
| 10    | 副本inode                                         |
| 11    | 第一个非保留inode（通常是 lost+found 目录）         |

{% hint style="info" %}
需要注意的是，创建时间只出现在 Ext4 中。
{% endhint %}

通过知道inode编号，你可以轻松找到它的索引：

* inode 所属的 **块组**：(Inode编号 - 1) / (每个块组的Inodes数)
* 它所在 **块组** 的 **索引**：(Inode编号 - 1) mod(每个块组的Inodes数)
* **inode表** 中的 **偏移量**：Inode编号 \* (Inode大小)
* "-1" 是因为inode 0 是未定义的（未使用）
```bash
ls -ali /bin | sort -n #Get all inode numbers and sort by them
stat /bin/ls #Get the inode information of a file
istat -o <start offset> /path/to/image.ext 657103 #Get information of that inode inside the given ext file
icat -o <start offset> /path/to/image.ext 657103 #Cat the file
```
文件模式

| 数字  | 描述                                                                                                 |
| ------ | --------------------------------------------------------------------------------------------------- |
| **15** | **Reg/Slink-13/Socket-14**                                                                          |
| **14** | **Directory/Block Bit 13**                                                                          |
| **13** | **Char Device/Block Bit 14**                                                                        |
| **12** | **FIFO**                                                                                            |
| 11     | Set UID                                                                                             |
| 10     | Set GID                                                                                             |
| 9      | Sticky Bit（没有它，具有目录上写和执行权限的任何人都可以删除和重命名文件）                             |
| 8      | 所有者读取                                                                                          |
| 7      | 所有者写入                                                                                          |
| 6      | 所有者执行                                                                                          |
| 5      | 组读取                                                                                              |
| 4      | 组写入                                                                                              |
| 3      | 组执行                                                                                              |
| 2      | 其他人读取                                                                                          |
| 1      | 其他人写入                                                                                          |
| 0      | 其他人执行                                                                                          |

粗体位（12、13、14、15）表示文件的类型（目录、套接字...），只能存在粗体选项中的一个。

目录

| 偏移量 | 大小 | 名称      | 描述                                                                                                                                                         |
| ------ | ---- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0x0    | 4    | Inode     |                                                                                                                                                             |
| 0x4    | 2    | Rec len   | 记录长度                                                                                                                                                     |
| 0x6    | 1    | Name len  | 名称长度                                                                                                                                                     |
| 0x7    | 1    | File type | <p>0x00 未知<br>0x01 常规</p><p>0x02 目录</p><p>0x03 字符设备</p><p>0x04 块设备</p><p>0x05 FIFO</p><p>0x06 套接字</p><p>0x07 符号链接</p>                             |
| 0x8    |      | Name      | 名称字符串（最多255个字符）                                                                                                                                   |

**为了提高性能，可以使用根哈希目录块。**

**扩展属性**

可以存储在

* Inode 之间的额外空间（256 - inode 大小，通常为100）
* Inode 中的 file\_acl 指向的数据块

如果属性名称以 "user" 开头，则可以将任何数据存储为用户属性。因此，数据可以通过这种方式隐藏。

扩展属性条目

| 偏移量 | 大小 | 名称         | 描述                                                                                                                                                      |
| ------ | ---- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0x0    | 1    | Name len     | 属性名称的长度                                                                                                                                            |
| 0x1    | 1    | Name index   | <p>0x0 = 无前缀</p><p>0x1 = user. 前缀</p><p>0x2 = system.posix_acl_access</p><p>0x3 = system.posix_acl_default</p><p>0x4 = trusted.</p><p>0x6 = security.</p><p>0x7 = system.</p><p>0x8 = system.richacl</p> |
| 0x2    | 2    | Value offs   | 从第一个 inode 条目或块的起始位置的偏移量                                                                                                                 |
| 0x4    | 4    | Value blocks | 存储值的磁盘块，或者对于此块为零                                                                                                                          |
| 0x8    | 4    | Value size   | 值的长度                                                                                                                                                  |
| 0xC    | 4    | Hash         | 块中属性的哈希值，如果在 inode 中则为零                                                                                                                    |
| 0x10   |      | Name         | 属性名称（不包含尾部的 NULL 字符）                                                                                                                         |
```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```
## 文件系统视图

要查看文件系统的内容，您可以使用免费工具：[https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
或者您可以在Linux中使用`mount`命令挂载它。

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.](https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中**宣传您的公司**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFT收藏品-PEASS Family](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
