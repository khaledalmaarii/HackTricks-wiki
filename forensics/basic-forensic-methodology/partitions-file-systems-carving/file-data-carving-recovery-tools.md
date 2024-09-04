# 文件/数据雕刻与恢复工具

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

## 雕刻与恢复工具

更多工具请访问 [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

在取证中提取图像文件的最常用工具是 [**Autopsy**](https://www.autopsy.com/download/)。下载并安装它，然后让它处理文件以查找“隐藏”文件。请注意，Autopsy 是为支持磁盘映像和其他类型的映像而构建的，但不支持简单文件。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** 是一个分析二进制文件以查找嵌入内容的工具。可以通过 `apt` 安装，其源代码在 [GitHub](https://github.com/ReFirmLabs/binwalk) 上。

**有用的命令**：
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

另一个常用的工具来查找隐藏文件是 **foremost**。您可以在 `/etc/foremost.conf` 中找到 foremost 的配置文件。如果您只想搜索某些特定文件，请取消注释它们。如果您不取消注释任何内容，foremost 将搜索其默认配置的文件类型。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** 是另一个可以用来查找和提取 **嵌入在文件中的文件** 的工具。在这种情况下，您需要从配置文件 (_/etc/scalpel/scalpel.conf_) 中取消注释您希望提取的文件类型。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

这个工具包含在kali中，但你可以在这里找到它: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

这个工具可以扫描一个镜像并将**提取pcaps**，**网络信息（URLs，域名，IP，MAC，邮件）**以及更多**文件**。你只需执行：
```
bulk_extractor memory.img -o out_folder
```
导航通过**工具收集的所有信息**（密码？），**分析** **数据包**（阅读[**Pcaps分析**](../pcap-inspection/)），搜索**奇怪的域名**（与**恶意软件**或**不存在**的域名相关）。

### PhotoRec

您可以在[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)找到它。

它提供GUI和CLI版本。您可以选择PhotoRec要搜索的**文件类型**。

![](<../../../.gitbook/assets/image (524).png>)

### binvis

查看[代码](https://code.google.com/archive/p/binvis/)和[网页工具](https://binvis.io/#/)。

#### BinVis的特点

* 视觉和主动的**结构查看器**
* 针对不同焦点的多个图
* 专注于样本的部分
* **查看PE或ELF可执行文件中的字符串和资源**
* 获取文件的**模式**以进行密码分析
* **识别**打包器或编码器算法
* 通过模式**识别**隐写术
* **视觉**二进制差异比较

BinVis是一个很好的**起点，以熟悉未知目标**在黑箱场景中。

## 特定数据雕刻工具

### FindAES

通过搜索其密钥调度来搜索AES密钥。能够找到128、192和256位密钥，例如TrueCrypt和BitLocker使用的密钥。

在[这里下载](https://sourceforge.net/projects/findaes/)。

## 补充工具

您可以使用[**viu**](https://github.com/atanunq/viu)从终端查看图像。\
您可以使用Linux命令行工具**pdftotext**将PDF转换为文本并阅读。

{% hint style="success" %}
学习和实践AWS黑客攻击：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客攻击：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR分享黑客技巧。

</details>
{% endhint %}
