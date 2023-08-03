# 图像获取与挂载

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享你的黑客技巧**。

</details>

## 获取

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

dcfldd is a command-line tool that is used for creating and hashing disk images. It is an enhanced version of the dd command and provides additional features such as on-the-fly hashing, progress reporting, and error handling.

To acquire an image using dcfldd, you can use the following command:

```
dcfldd if=/dev/sda of=image.dd
```

In this command, `if` specifies the input file (in this case, the device `/dev/sda`), and `of` specifies the output file (in this case, `image.dd`). You can replace `/dev/sda` with the appropriate device or file path.

dcfldd also supports various hashing algorithms, such as MD5, SHA-1, and SHA-256. To calculate the hash of the acquired image, you can use the `hash=algorithm` option. For example:

```
dcfldd if=/dev/sda of=image.dd hash=md5
```

This command will calculate the MD5 hash of the acquired image and display it once the acquisition is complete.

Overall, dcfldd is a powerful tool for acquiring disk images and performing hashing operations, making it a valuable asset in forensic investigations.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

您可以从[这里下载FTK imager](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1)。
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

您可以使用[**ewf工具**](https://github.com/libyal/libewf)生成磁盘镜像。
```bash
ewfacquire /dev/sdb
#Name: evidence
#Case number: 1
#Description: A description for the case
#Evidence number: 1
#Examiner Name: Your name
#Media type: fixed
#Media characteristics: physical
#File format: encase6
#Compression method: deflate
#Compression level: fast

#Then use default values
#It will generate the disk image in the current directory
```
## 挂载

### 几种类型

在**Windows**中，您可以尝试使用Arsenal Image Mounter的免费版本（[https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)）来**挂载取证镜像**。

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

EWF（EnCase Evidence File）是一种常用的数字取证格式，用于创建和存储磁盘镜像。EWF格式支持多种压缩算法，可以有效地减小镜像文件的大小，并保持数据的完整性。EWF文件通常具有`.E01`或`.EWF`的扩展名。

#### EWF的获取和挂载

要获取EWF镜像，可以使用EnCase、FTK Imager或dcfldd等取证工具。这些工具提供了创建EWF镜像的选项，并允许指定压缩算法和输出文件的位置。

要挂载EWF镜像，可以使用`ewfmount`命令。该命令可用于将EWF镜像作为虚拟磁盘挂载到文件系统中。挂载后，可以像访问普通磁盘一样访问镜像中的文件和目录。

以下是使用`ewfmount`命令挂载EWF镜像的示例：

```bash
ewfmount image.E01 /mnt/ewf
```

在上述示例中，`image.E01`是要挂载的EWF镜像文件，`/mnt/ewf`是挂载点的路径。挂载点路径可以根据需要进行更改。

#### EWF的转换和提取

有时候，需要将EWF镜像转换为其他格式，以便在不同的取证工具之间共享或分析。可以使用`ewfexport`命令将EWF镜像转换为RAW、AFF或其他支持的格式。

以下是使用`ewfexport`命令将EWF镜像转换为RAW格式的示例：

```bash
ewfexport image.E01 image.raw
```

在上述示例中，`image.E01`是要转换的EWF镜像文件，`image.raw`是输出文件的名称。输出文件的名称可以根据需要进行更改。

要从EWF镜像中提取文件或目录，可以使用取证工具（如EnCase或FTK Imager）或使用`ewfmount`命令挂载镜像后，直接复制所需的文件或目录。

#### EWF的验证和分析

为了确保EWF镜像的完整性和准确性，可以使用`ewfverify`命令对镜像进行验证。该命令会检查镜像的哈希值和元数据，以确保数据没有被篡改或损坏。

以下是使用`ewfverify`命令验证EWF镜像的示例：

```bash
ewfverify image.E01
```

在上述示例中，`image.E01`是要验证的EWF镜像文件。

验证完成后，可以使用取证工具（如EnCase或FTK Imager）或其他分析工具对EWF镜像进行进一步的分析和调查。
```bash
#Get file type
file evidence.E01
evidence.E01: EWF/Expert Witness/EnCase image file format

#Transform to raw
mkdir output
ewfmount evidence.E01 output/
file output/ewf1
output/ewf1: Linux rev 1.0 ext4 filesystem data, UUID=05acca66-d042-4ab2-9e9c-be813be09b24 (needs journal recovery) (extents) (64bit) (large files) (huge files)

#Mount
mount output/ewf1 -o ro,norecovery /mnt
```
### ArsenalImageMounter

这是一个用于挂载卷的Windows应用程序。您可以在这里下载它[https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### 错误

* **`无法以只读方式挂载/dev/loop0`** 在这种情况下，您需要使用标志**`-o ro,norecovery`**
* **`错误的文件系统类型、错误的选项、/dev/loop0上的错误超级块、缺少代码页或辅助程序，或其他错误。`** 在这种情况下，挂载失败是因为文件系统的偏移量与磁盘映像的偏移量不同。您需要找到扇区大小和起始扇区：
```bash
fdisk -l disk.img
Disk disk.img: 102 MiB, 106954648 bytes, 208896 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00495395

Device        Boot Start    End Sectors  Size Id Type
disk.img1       2048 208895  206848  101M  1 FAT12
```
请注意扇区大小为**512**，起始位置为**2048**。然后按照以下方式挂载镜像：
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
