# macOS内存转储

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 内存遗留物

### 交换文件

交换文件，例如`/private/var/vm/swapfile0`，在物理内存已满时充当**缓存**。当物理内存没有足够空间时，数据会被转移到交换文件中，然后根据需要重新转移到物理内存中。可能会存在多个交换文件，名称类似于swapfile0、swapfile1等。

### 休眠镜像

位于`/private/var/vm/sleepimage`的文件在**休眠模式**期间至关重要。**当OS X休眠时，内存中的数据存储在此文件中**。唤醒计算机时，系统会从此文件中检索内存数据，使用户可以继续之前的操作。

值得注意的是，在现代MacOS系统上，出于安全原因，此文件通常是加密的，使恢复变得困难。

* 要检查休眠镜像是否启用了加密，可以运行命令`sysctl vm.swapusage`。这将显示文件是否已加密。

### 内存压力日志

MacOS系统中另一个重要的与内存相关的文件是**内存压力日志**。这些日志位于`/var/log`中，包含有关系统内存使用情况和压力事件的详细信息。它们对于诊断与内存相关的问题或了解系统如何随时间管理内存非常有用。

## 使用osxpmem转储内存

要在MacOS机器中转储内存，可以使用[**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)。

**注意**：以下说明仅适用于具有Intel架构的Mac。该工具现已存档，最后一次发布是在2017年。使用以下说明下载的二进制文件针对Intel芯片，因为在2017年时Apple Silicon还不存在。可能可以为arm64架构编译二进制文件，但您需要自行尝试。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
如果你发现这个错误：`osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 你可以通过以下方式修复：
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**其他错误**可能通过在“安全性与隐私 --> 通用”中**允许加载kext**来修复，只需**允许**它。

您还可以使用这个**一行命令**来下载应用程序，加载kext并转储内存：

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
