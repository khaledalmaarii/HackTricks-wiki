# 文件/数据切割和恢复工具

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## 切割和恢复工具

更多工具请查看[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

在取证中最常用的从镜像中提取文件的工具是[**Autopsy**](https://www.autopsy.com/download/)。下载、安装并让其摄取文件以查找“隐藏”文件。请注意，Autopsy旨在支持磁盘镜像和其他类型的镜像，而不是简单文件。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**是用于分析二进制文件以查找嵌入内容的工具。可通过`apt`安装，其源代码位于[GitHub](https://github.com/ReFirmLabs/binwalk)。

**有用的命令**：
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

另一个常用的查找隐藏文件的工具是**foremost**。您可以在`/etc/foremost.conf`中找到foremost的配置文件。如果您只想搜索一些特定文件，请取消注释。如果您不取消注释任何内容，foremost将搜索其默认配置的文件类型。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** 是另一个工具，可用于查找和提取**嵌入在文件中的文件**。在这种情况下，您需要取消配置文件（_/etc/scalpel/scalpel.conf_）中您希望提取的文件类型的注释。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

这个工具包含在kali中，但你也可以在这里找到它：[https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

这个工具可以扫描一个镜像，并且会**提取其中的pcaps**，**网络信息（URLs、域名、IP地址、MAC地址、邮件）**以及更多**文件**。你只需要执行以下操作：
```
bulk_extractor memory.img -o out_folder
```
### PhotoRec

您可以在[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)找到它。

它带有 GUI 和 CLI 版本。您可以选择要让 PhotoRec 搜索的**文件类型**。

![](<../../../.gitbook/assets/image (524).png>)

### binvis

检查[代码](https://code.google.com/archive/p/binvis/)和[网页工具](https://binvis.io/#/)。

#### BinVis 的特点

- 可视化和活跃的**结构查看器**
- 不同焦点的多个绘图
- 集中在样本的部分
- 在 PE 或 ELF 可执行文件中**查看字符串和资源**
- 从文件中获取用于密码分析的**模式**
- **发现**打包程序或编码器算法
- 通过模式**识别**隐写术
- **视觉**二进制差异

BinVis 是在黑盒测试场景中熟悉未知目标的**起点**。

## 特定数据刻录工具

### FindAES

通过搜索密钥计划来搜索 AES 密钥。能够找到 TrueCrypt 和 BitLocker 等使用的 128、192 和 256 位密钥。

在[此处](https://sourceforge.net/projects/findaes/)下载。

## 附加工具

您可以使用[**viu**](https://github.com/atanunq/viu)来在终端中查看图像。\
您可以使用 Linux 命令行工具**pdftotext**将 pdf 转换为文本并阅读它。
