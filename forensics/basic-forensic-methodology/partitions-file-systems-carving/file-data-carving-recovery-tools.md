<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# Carving & Recovery工具

更多工具请参考[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

在取证中，提取图像中的文件最常用的工具是[**Autopsy**](https://www.autopsy.com/download/)。下载并安装它，然后让它摄取文件以查找"隐藏"文件。请注意，Autopsy是用于支持磁盘映像和其他类型的映像，而不是简单文件。

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**是一种用于搜索嵌入文件和数据的二进制文件（如图像和音频文件）的工具。\
可以使用`apt`安装，但是[源代码](https://github.com/ReFirmLabs/binwalk)可以在github上找到。\
**有用的命令**：
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

另一个常用的查找隐藏文件的工具是 **foremost**。你可以在 `/etc/foremost.conf` 中找到 foremost 的配置文件。如果你只想搜索一些特定的文件，取消注释它们。如果你没有取消注释任何内容，foremost 将搜索其默认配置的文件类型。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel**是另一个可以用来查找和提取**嵌入在文件中的文件**的工具。在这种情况下，您需要从配置文件（_/etc/scalpel/scalpel.conf_）中取消注释您想要提取的文件类型。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

这个工具在kali中已经内置，但你也可以在这里找到它：[https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

这个工具可以扫描一个镜像，并从中提取出**pcap文件**、**网络信息（URL、域名、IP、MAC地址、邮件）**以及其他**文件**。你只需要执行以下操作：
```
bulk_extractor memory.img -o out_folder
```
浏览工具收集的**所有信息**（密码？），**分析**数据包（阅读[**Pcaps分析**](../pcap-inspection/)），搜索**奇怪的域名**（与**恶意软件**或**不存在**相关的域名）。

## PhotoRec

您可以在[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)找到它。

它有GUI和CLI版本。您可以选择要PhotoRec搜索的**文件类型**。

![](<../../../.gitbook/assets/image (524).png>)

## binvis

检查[代码](https://code.google.com/archive/p/binvis/)和[网页工具](https://binvis.io/#/)。

### BinVis的特点

* 可视化和活动的**结构查看器**
* 不同焦点的多个图表
* 集中在样本的部分上
* 在PE或ELF可执行文件中**查看字符串和资源**
* 获取用于文件密码分析的**模式**
* **识别**打包程序或编码器算法
* 通过模式**识别**隐写术
* **可视化**二进制差异

在黑盒测试场景中，BinVis是熟悉未知目标的**良好起点**。

# 特定数据恢复工具

## FindAES

通过搜索AES密钥的密钥计划来查找AES密钥。能够找到128、192和256位密钥，例如TrueCrypt和BitLocker使用的密钥。

在此处下载[here](https://sourceforge.net/projects/findaes/)。

# 补充工具

您可以使用[**viu**](https://github.com/atanunq/viu)在终端上查看图像。\
您可以使用Linux命令行工具**pdftotext**将PDF转换为文本并阅读。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得最新版本的PEASS或下载PDF版的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
