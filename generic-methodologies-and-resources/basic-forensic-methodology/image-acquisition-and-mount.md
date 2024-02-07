# 图像获取与挂载

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？想要在 HackTricks 中看到您的**公司广告**？或者想要访问**PEASS 的最新版本或下载 HackTricks 的 PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏品 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 上关注我 **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享您的黑客技巧**。

</details>

## 获取

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

### dcfldd
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

您可以从[**这里下载FTK Imager**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1)。
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

您可以使用[**ewf工具**](https://github.com/libyal/libewf)生成磁盘映像。
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

### EWF
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

这是一个用于挂载卷的Windows应用程序。您可以在这里下载它 [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### 错误

* **`无法以只读方式挂载 /dev/loop0`** 在这种情况下，您需要使用标志 **`-o ro,norecovery`**
* **`错误的文件系统类型，错误的选项，/dev/loop0 上的错误的超级块，缺少代码页或辅助程序，或其他错误。`** 在这种情况下，挂载失败是因为文件系统的偏移量与磁盘映像的偏移量不同。您需要找到扇区大小和起始扇区：
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
请注意，扇区大小为**512**，起始位置为**2048**。然后按照以下方式挂载镜像：
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要看到你的**公司在HackTricks中宣传**吗？或者想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们独家[NFTs的收藏品**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS & HackTricks周边**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
