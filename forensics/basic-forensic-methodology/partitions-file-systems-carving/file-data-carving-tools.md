<details>

<summary><strong>从零到英雄学习AWS黑客攻击，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在 **HackTricks中看到您的公司广告** 或 **下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现 [**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 文件提取工具

## Autopsy

在取证中用于从镜像中提取文件的最常用工具是 [**Autopsy**](https://www.autopsy.com/download/)。下载并安装它，让它处理文件以找到“隐藏”的文件。请注意，Autopsy 支持磁盘镜像和其他类型的镜像，但不支持简单文件。

## Binwalk <a id="binwalk"></a>

**Binwalk** 是一个用于搜索二进制文件（如图像和音频文件）中嵌入的文件和数据的工具。
它可以通过 `apt` 安装，但源代码可以在github上找到。
**有用的命令**：
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

另一个常用的查找隐藏文件的工具是 **foremost**。你可以在 `/etc/foremost.conf` 中找到 foremost 的配置文件。如果你只想搜索某些特定的文件，取消注释它们。如果你什么都不取消注释，foremost 将搜索其默认配置的文件类型。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** 是另一个可以用来查找和提取**嵌入在文件中的文件**的工具。在这种情况下，你需要在配置文件（_/etc/scalpel/scalpel.conf_）中取消注释你希望它提取的文件类型。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

此工具包含在kali中，但您也可以在此处找到：[https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

此工具可以扫描映像，并将从中**提取pcaps**，**网络信息（URLs, 域名, IPs, MACs, 邮箱）**以及更多**文件**。您只需执行：
```text
bulk_extractor memory.img -o out_folder
```
浏览该工具收集的**所有信息**（密码？），**分析** **数据包**（阅读[**Pcaps分析**](../pcap-inspection/)），搜索**奇怪的域名**（与**恶意软件**或**不存在的**域名相关）。

## PhotoRec

您可以在[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)找到它

它提供了GUI和CLI版本。您可以选择希望PhotoRec搜索的**文件类型**。

![](../../../.gitbook/assets/image%20%28524%29.png)

# 特定数据雕刻工具

## FindAES

通过搜索它们的密钥调度来搜索AES密钥。能够找到128、192和256位密钥，例如TrueCrypt和BitLocker使用的密钥。

下载[这里](https://sourceforge.net/projects/findaes/)。

# 补充工具

您可以使用[**viu**](https://github.com/atanunq/viu)在终端查看图片。
您可以使用linux命令行工具**pdftotext**将pdf转换为文本并阅读。



<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
