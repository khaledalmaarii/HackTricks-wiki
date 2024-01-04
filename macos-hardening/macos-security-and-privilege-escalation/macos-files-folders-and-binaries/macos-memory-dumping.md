# macOS 内存转储

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

## 内存工件

### 交换文件

* **`/private/var/vm/swapfile0`**: 当物理内存填满时，此文件被用作**缓存**。物理内存中的数据会被推送到交换文件中，然后在需要时再交换回物理内存。这里可能存在多个文件。例如，您可能会看到 swapfile0、swapfile1 等。
*   **`/private/var/vm/sleepimage`**: 当 OS X 进入**休眠**状态时，存储在内存中的**数据会被放入 sleepimage 文件**。当用户回来并唤醒计算机时，内存会从 sleepimage 恢复，用户可以继续之前的工作。

在现代 MacOS 系统中，默认情况下此文件将被加密，因此可能无法恢复。

* 然而，这个文件的加密可能被禁用。检查 `sysctl vm.swapusage` 的输出。

### 使用 osxpmem 转储内存

为了在 MacOS 机器上转储内存，您可以使用 [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)。

**注意**：以下指令只适用于搭载 Intel 架构的 Mac。这个工具现已存档，最后一次发布是在 2017 年。下面的指令下载的二进制文件针对的是 Intel 芯片，因为 2017 年还没有 Apple Silicon。可能可以为 arm64 架构编译二进制文件，但您需要自己尝试。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
如果您遇到此错误：`osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)`，您可以通过以下方式修复它：
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**其他错误** 可能通过在 "安全性与隐私 --> 通用" 中**允许加载 kext** 来修复，只需**允许**即可。

您也可以使用这个**单行命令**来下载应用程序，加载 kext 并转储内存：

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
```markdown
{% endcode %}

<details>

<summary><strong>从零到英雄学习AWS黑客技术，参加</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
```
