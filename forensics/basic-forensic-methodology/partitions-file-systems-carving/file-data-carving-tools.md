<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# 文件数据恢复工具

## Autopsy

在取证中，最常用的从镜像中提取文件的工具是[**Autopsy**](https://www.autopsy.com/download/)。下载并安装它，然后让它分析文件以查找"隐藏"文件。请注意，Autopsy是用于支持磁盘镜像和其他类型镜像的，而不是简单的文件。

## Binwalk <a id="binwalk"></a>

**Binwalk**是一款用于搜索嵌入文件和数据的二进制文件（如图像和音频文件）的工具。
可以使用`apt`安装它，但是[源代码](https://github.com/ReFirmLabs/binwalk)可以在github上找到。
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

**Scalpel**是另一个可以用来查找和提取**嵌入在文件中的文件**的工具。在这种情况下，您需要取消注释配置文件（_/etc/scalpel/scalpel.conf_）中您想要提取的文件类型。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

这个工具在kali中已经内置，但你也可以在这里找到它：[https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

这个工具可以扫描一个镜像，并且会从中提取出**pcap文件**，**网络信息（URL、域名、IP、MAC地址、邮件）**以及更多的**文件**。你只需要执行以下操作：
```text
bulk_extractor memory.img -o out_folder
```
浏览工具收集的**所有信息**（密码？），**分析**数据包（阅读[**Pcaps分析**](../pcap-inspection/)），搜索**奇怪的域名**（与**恶意软件**或**不存在**相关的域名）。

## PhotoRec

您可以在[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)找到它。

它有GUI和CLI版本。您可以选择要PhotoRec搜索的**文件类型**。

![](../../../.gitbook/assets/image%20%28524%29.png)

# 特定数据刻录工具

## FindAES

通过搜索AES密钥的密钥计划来搜索AES密钥。能够找到128、192和256位密钥，例如TrueCrypt和BitLocker使用的密钥。

在此处下载[here](https://sourceforge.net/projects/findaes/)。

# 补充工具

您可以使用[**viu** ](https://github.com/atanunq/viu)在终端中查看图像。
您可以使用Linux命令行工具**pdftotext**将PDF转换为文本并阅读。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
