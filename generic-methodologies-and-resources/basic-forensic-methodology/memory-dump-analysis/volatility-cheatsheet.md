# Volatility - 速查表

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点聚会。

{% embed url="https://www.rootedcon.com/" %}

如果您想要**快速疯狂**地同时运行多个Volatility插件，可以使用：[https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## 安装

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{% tabs %}
{% tab title="方法1" %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="方法2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Volatility Commands

访问[Volatility命令参考](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)中的官方文档。

### “list”与“scan”插件的说明

Volatility有两种主要的插件方法，有时可以从它们的名称中反映出来。“list”插件将尝试浏览Windows内核结构，以检索诸如进程（在内存中定位和遍历`_EPROCESS`结构的链接列表）、操作系统句柄（定位和列出句柄表，取消引用找到的任何指针等）等信息。它们的行为几乎与请求Windows API列出进程时的行为相同。

这使得“list”插件非常快速，但与Windows API一样容易受到恶意软件的操纵。例如，如果恶意软件使用DKOM从`_EPROCESS`链接列表中取消链接进程，则该进程不会显示在任务管理器中，pslist中也不会显示。

另一方面，“scan”插件将采用类似于在内存中雕刻可能在解除引用为特定结构时有意义的内容的方法。例如，`psscan`将读取内存并尝试从中创建`_EPROCESS`对象（它使用池标签扫描，搜索指示感兴趣结构存在的4字节字符串）。优点是它可以挖掘已退出的进程，即使恶意软件篡改了`_EPROCESS`链接列表，插件仍将在内存中找到该结构（因为该结构仍然需要存在以使进程运行）。缺点是，“scan”插件比“list”插件慢一些，有时可能产生误报（进程已退出太久，其结构的部分被其他操作覆盖）。

来源：[http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## 操作系统配置文件

### Volatility3

如readme中所述，您需要将要支持的操作系统的**符号表**放入_volatility3/volatility/symbols_中。\
各种操作系统的符号表包可在以下位置下载：

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### 外部配置文件

您可以执行以下操作获取支持的配置文件列表：
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
如果要使用**您已下载的新配置文件**（例如Linux配置文件），您需要在某处创建以下文件夹结构：_plugins/overlays/linux_，并将包含配置文件的zip文件放入此文件夹中。然后，使用以下命令获取配置文件的编号：
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
您可以从[https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)下载Linux和Mac配置文件。

在前面的片段中，您可以看到配置文件被称为`LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`，您可以使用它执行类似以下操作：
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### 发现配置文件
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo 与 kdbgscan 的区别**

[**从这里**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)：与仅提供配置文件建议的 imageinfo 相反，**kdbgscan** 旨在积极识别正确的配置文件和正确的 KDBG 地址（如果存在多个）。该插件扫描与 Volatility 配置文件相关联的 KDBGHeader 签名，并应用合理性检查以减少误报。输出的详细程度和可以执行的合理性检查数量取决于 Volatility 是否能够找到 DTB，因此，如果您已经知道正确的配置文件（或者从 imageinfo 获得了配置文件建议），请确保使用它。

始终查看 **kdbgscan 找到的进程数量**。有时，imageinfo 和 kdbgscan 可能会找到 **多个**适合的 **配置文件**，但只有 **有效的配置文件** 才会有一些与进程相关的内容（这是因为提取进程需要正确的 KDBG 地址）。
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

**内核调试器块**，由Volatility称为**KDBG**，对于Volatility和各种调试器执行的取证任务至关重要。被标识为`KdDebuggerDataBlock`，类型为`_KDDEBUGGER_DATA64`，其中包含诸如`PsActiveProcessHead`之类的基本引用。这个特定引用指向进程列表的头部，使得能够列出所有进程，这对于彻底的内存分析至关重要。

## 操作系统信息
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
插件`banners.Banners`可在**vol3中用于尝试在转储文件中查找Linux横幅**。

## Hashes/密码

提取SAM哈希、[域缓存凭据](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials)和[lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets)。

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `voljson -f <memory_dump> --profile=<profile> dlllist`

- **Dumping a DLL**
     - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **User Accounts**
  - `volatility -f <memory_dump> --profile=<profile> useraccounts`

- **Dumping Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Dumping SAM**
  - `voljson -f <memory_dump> --profile=<profile> sam`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password History**
  - `volatility -f <memory_dump> --profile=<profile> hashdump --dump-dir=<output_directory>`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## 内存转储

进程的内存转储将提取进程当前状态的所有内容。**procdump** 模块将仅提取**代码**。
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的之一。以**促进技术知识**为使命，这个大会是技术和网络安全专业人士在各个领域的热点交流之地。

{% embed url="https://www.rootedcon.com/" %}

## 进程

### 列出进程

尝试查找**可疑**进程（按名称）或**意外**的子**进程**（例如，cmd.exe 作为 iexplorer.exe 的子进程）。\
比较 pslist 的结果和 psscan 的结果以识别隐藏进程可能会很有趣。

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheatsheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing a Malicious DLL**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`
  - `volatility -f <memory_dump> --profile=<profile> dlldump -b <base_address> -D <output_directory>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Hidden Modules**
  - `voljson -f <memory_dump> --profile=<profile>`

- **Analyzing Suspicious Drivers**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Extracting Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> moddump -b <base_address> -D <output_directory>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining Information**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> mpparser`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyifying Process GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Process SSDT**
  - `voljson -f <memory_dump> --profile=<profile> --output-file=<output_file> ssdt`

- **Analyzing Process IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Process LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Process EPROCESS**
  - `volatility -f <memory_dump> --profile=<profile> eprocess`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process Vad Tagging**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing Process Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyizing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process VADs**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analy
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### 转储进程

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Forensic Methodology

1. **Memory Dump Analysis**
   - **volatility.exe -f memory\_dump.img imageinfo**
     - *Identify profile to use*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName command**
     - *Analyze memory dump with specific profile*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName consoles**
     - *Extract command history and console output*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName cmdscan**
     - *Extract command history*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName consoles**
     - *Extract command history and console output*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName malfind**
     - *Find hidden or injected code*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName filescan**
     - *Scan for file handles*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName getsids**
     - *List Security Identifiers (SIDs)*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName hivelist**
     - *Identify registry hives*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName hivescan**
     - *Recover registry data*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName netscan**
     - *Investigate network connections*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName pslist**
     - *List running processes*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName pstree**
     - *Display process list as a tree*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName cmdline**
     - *Display process command-line arguments*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName connections**
     - *List open connections*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName sockets**
     - *List open sockets*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName svcscan**
     - *Identify Windows services*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName userassist**
     - *Recover user assist information*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName vadinfo**
     - *Display Virtual Address Descriptor (VAD) information*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName cmdline**
     - *Display process command-line arguments*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName connections**
     - *List open connections*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName sockets**
     - *List open sockets*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName svcscan**
     - *Identify Windows services*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName userassist**
     - *Recover user assist information*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName vadinfo**
     - *Display Virtual Address Descriptor (VAD) information*

2. **File Analysis**
   - **volatility.exe -f memory\_dump.img --profile=ProfileName filescan**
     - *Scan for file handles*
   - **volvolatility.exe -f memory\_dump.img --profile=ProfileName dumpfiles -Q 0xADDRESS -D dump\_directory/**
     - *Extract specific file*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName dumpfiles -Q 0xADDRESS -D dump\_directory/**
     - *Extract specific file*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName dumpfiles -Q 0xADDRESS -D dump\_directory/**
     - *Extract specific file*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName dumpfiles -Q 0xADDRESS -D dump\_directory/**
     - *Extract specific file*

3. **Registry Analysis**
   - **volatility.exe -f memory\_dump.img --profile=ProfileName hivelist**
     - *Identify registry hjson**
   - **volatility.exe -f memory\_dump.img --profile=ProfileName hivelist**
     - *Identify registry hives*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName printkey -o OFFSET**
     - *Print key at offset*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName printkey -K KEY**
     - *Print key by name*
   - **voljson**
     - *Identify registry hives*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName printkey -o OFFSET**
     - *Print key at offset*
  json**
     - *Print key by name*

4. **Network Analysis**
   - **volatility.exe -f memory\_dump.img --profile=ProfileName netscan**
     - *Investigate network connections*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName connscan**
     - *Investigate network connections*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName sockets**
     - *List open sockets*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName sockets**
     - *List open sockets*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName sockets**
     - *List open sockets*

5. **Process Analysis**
   - **volatility.exe -f memory\_dump.img --profile=ProfileName pslist**
     - *List running processes*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName pstree**
     - *Display process list as a tree*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName cmdline**
     - *Display process command-line arguments*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName cmdline**
     - *Display process command-line arguments*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName cmdline**
     - *Display process command-line arguments*

6. **Malware Analysis**
   - **volatility.exe -f memory\_dump.img --profile=ProfileName malfind**
     - *Find hidden or injected code*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName malfind**
     - *Find hidden or injected code*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName malfind**
     - *Find hidden or injected code*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName malfind**
     - *Find hidden or injected code*

7. **User Activity Analysis**
   - **volatility.exe -f memory\_dump.img --profile=ProfileName userassist**
     - *Recover user assist information*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName userassist**
     - *Recover user assist information*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName userassist**
     - *Recover user assist information*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName userassist**
     - *Recover user assist information*

8. **Other Commands**
   - **volatility.exe -f memory\_dump.img --profile=ProfileName apihooks**
     - *Detect API hooks*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName callbacks**
     - *List kernel callbacks*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName driverirp**
     - *List drivers and IRP handlers*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName ssdt**
     - *Display SSDT entries*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName threads**
     - *List threads*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName timers**
     - *List timers*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName idt**
     - *Display IDT entries*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName gdt**
     - *Display GDT entries*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName handles**
     - *List handles*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName mutantscan**
     - *List mutant objects*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName ldrmodules**
     - *List loaded DLLs*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName modscan**
     - *List kernel modules*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName atomscan**
     - *List atom tables*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName deskscan**
     - *List desktops*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName devicetree**
     - *Display device tree*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName driverirp**
     - *List drivers and IRP handlers*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName ssdt**
     - *Display SSDT entries*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName threads**
     - *List threads*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName timers**
     - *List timers*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName idt**
     - *Display IDT entries*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName gdt**
     - *Display GDT entries*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName handles**
     - *List handles*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName mutantscan**
     - *List mutant objects*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName ldrmodules**
     - *List loaded DLLs*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName modscan**
     - *List kernel modules*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName atomscan**
     - *List atom tables*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName deskscan**
     - *List desktops*
   - **volatility.exe -f memory\_dump.img --profile=ProfileName devicetree**
     - *Display device tree*

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
### 命令行

是否执行了任何可疑操作？
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}

## Volatility Cheatsheet

### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `voljson -f <memory_dump> --profile=<profile> netscan`

- **Dumping Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping a Registry Hive**
 json
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Recovering Deleted Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Dumping a File**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

### Advanced Commands

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Extracting DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing a Malicious DLL**
  - `voljson -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Registry Transactions**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyarching Malicious Processes**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

在`cmd.exe`中执行的命令由**`conhost.exe`**（或在Windows 7之前的系统上为`csrss.exe`）管理。这意味着，如果在获取内存转储之前攻击者终止了**`cmd.exe`**，仍然可以从**`conhost.exe`**的内存中恢复会话的命令历史记录。要做到这一点，如果检测到控制台模块中的异常活动，应该转储相关**`conhost.exe`**进程的内存。然后，通过在此转储中搜索**字符串**，可以潜在地提取会话中使用的命令行。 

### 环境

获取每个运行进程的环境变量。可能会有一些有趣的值。
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `voljson -f <memory_dump> --profile=<profile> netscan`

- **Dumping a File**
 json
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> --dump-dir=<output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Process Memory**
  - `voljson -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Extracting Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> moddump -D <output_directory>`

- **Analyzing Malware Artifacts**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Extracting Cached Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Plugin Development

- **Creating a New Plugin**
  - Refer to the official Volatility documentation for detailed instructions on creating custom plugins.

{% endtab %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### 令牌权限

检查意外服务中的特权令牌。\
列出使用某些特权令牌的进程可能很有趣。
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volmemory_dump> --profile=<profile> file -S <start_address> -E <end_address> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Hidden Modules**
  - `voljsonmemory_dump> --profile=<profile> modscan`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Extracting Deleted Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan --dump`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handle`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing User Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> usermode`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callback Hooks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Shadow Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdtshadow`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Analyifying Kernel Pool**
  - `volatility -f <memory_dump> --profile=<profile> pool`

- **Analyzing VAD Tree**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Process Handles**
  - `voljsonmemory_dump> --profile=<profile> handle`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **AnalyAnalyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Vad**
  - `volatility -f <memory_dump> --profile=<profile>
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
### SIDs

检查每个进程拥有的SSID。\
列出使用特权SID的进程（以及使用某些服务SID的进程）可能会很有趣。
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volfile -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Rootkit Detection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Processes**
 json
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> --output-file=<output_file>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> mpp`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handle`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing Process Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Process Dump**
  - `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`

- **Analyzing Process Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind -p <pid>`

- **Analyizing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets -p <pid>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry**
  - `volatility -
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### 句柄

有助于了解进程打开了哪些其他文件、密钥、线程、进程等的**句柄**。
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping Registry Hives**
  - `voljson -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Extracting DLLs**
     - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

#### Plugin Options

- **Plugin Help**
  - `volatility --info | grep <plugin_name>`

- **Plugin Syntax**
  - `volatility --info | grep -A 2 <plugin_name>`

- **Running a Plugin**
  - `volatility -f <memory_dump> --profile=<profile> <plugin_name>`

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
### 动态链接库

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volmemory_dump> --profile=<profile> file -S <start_address> -E <end_address> -O <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Hidden Modules**
  - `voljson --output-file=<output_file>`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Extracting Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> moddump -o <output_directory>`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> mpp`

- **Analyzing Suspicious Processes**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyifying Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volvolatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Memory Maps**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Memory Maps**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Memory Maps**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Memory Maps**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Memory Maps**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Memory Maps**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Memory Maps**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
### 每个进程的字符串

Volatility允许我们检查字符串属于哪个进程。
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheatsheet

#### Basic Forensic Methodology

1. **Identify Profile**: `volatility -f <memory_dump> imageinfo`

2. **List Processes**: `volatility -f <memory_dump> --profile=<profile> pslist`

3. **Dump Process**: `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

4. **List Network Connections**: `volatility -f <memory_dump> --profile=<profile> connections`

5. **Analyze Registry**: `volatility -f <memory_dump> --profile=<profile> hivelist`

6. **Dump Registry Hive**: `voljson -f <memory_dump> --profile=<profile> printkey -o <output_directory> -K <hive_offset>`

7. **Extract Files**: `volatility -f <memory_dump> --profile=<profile> filescan`

8. **Analyze Malware**: `volatility -f <memory_dump> --profile=<profile> malfind`

9. **Identify Hidden Processes**: `volatility -f <memory_dump> --profile=<profile> psxview`

10. **Analyze Drivers**: `volatility -f <memory_dump> --profile=<profile> driverscan`

11. **Detect Rootkits**: `volatility -f <memory_dump> --profile=<profile> ldrmodules`

12. **Analyze DLLs**: `voljson -f <memory_dump> --profile=<profile> dlllist`

13. **Extract Command History**: `volatility -f <memory_dump> --profile=<profile> cmdscan`

14. **Analyze Sockets**: `volatility -f <memory_dump> --profile=<profile> sockets`

15. **Analyze Timelining**: `volatility -f <memory_dump> --profile=<profile> timeliner`

16. **Analyze Packed Binaries**: `volatility -f <memory_dump> --profile=<profile> yarascan`

17. **Analyze User Assist**: `volatility -f <memory_dump> --profile=<profile> userassist`

18. **Analyze Shimcache**: `volatility -f <memory_dump> --profile=<profile> shimcache`

19. **Analyze LSA Secrets**: `volatility -f <memory_dump> --profile=<profile> lsadump`

20. **Analyze API Hooks**: `volatility -f <memory_dump> --profile=<profile> apihooks`

21. **Analyze Handles**: `volatility -f <memory_dump> --profile=<profile> handles`

22. **Analyze Mutants**: `volatility -f <memory_dump> --profile=<profile> mutantscan`

23. **Analyze Yara Rules**: `volatility -f <memory_dump> --profile=<profile> yarascan`

24. **Analyze Desktops**: `volatility -f <memory_dump> --profile=<profile> desktops`

25. **Analyze Printers**: `volatility -f <memory_dump> --profile=<profile> printers`

26. **Analyze Services**: `volatility -f <memory_dump> --profile=<profile> getservicesids`

27. **Analyze Privileges**: `volatility -f <memory_dump> --profile=<profile> privs`

28. **Analyze Crashes**: `volatility -f <memory_dump> --profile=<profile> crashinfo`

29. **Analyze Kernel Modules**: `volatility -f <memory_dump> --profile=<profile> modscan`

30. **Analyze SSDT**: `volatility -f <memory_dump> --profile=<profile> ssdt`

31. **Analyze GDT**: `volatility -f <memory_dump> --profile=<profile> gdt`

32. **Analyze IDT**: `volatility -f <memory_dump> --profile=<profile> idt`

33. **Analyze CSRSS**: `volatility -f <memory_dump> --profile=<profile> csrss`

34. **Analyze Service Descriptor Table**: `volatility -f <memory_dump> --profile=<profile> servicedescriptortable`

35. **Analyze Hashes**: `volatility -f <memory_dump> --profile=<profile> hashdump`

36. **Analyze User Sessions**: `volatility -f <memory_dump> --profile=<profile> sessions`

37. **Analyze User Handles**: `volatility -f <memory_dump> --profile=<profile> userhandles`

38. **Analyze User Objects**: `volatility -f <memory_dump> --profile=<profile> userobjects`

39. **Analyze GDI Tables**: `volatility -f <memory_dump> --profile=<profile> gditables`

40. **Analyze Atom Tables**: `volatility -f <memory_dump> --profile=<profile> atomscan`

41. **Analyze Desktop Heaps**: `volatility -f <memory_dump> --profile=<profile> desktopheaps`

42. **Analyze Windows Stations**: `volatility -f <memory_dump> --profile=<profile> windows`

43. **Analyze Handles and Objects**: `volatility -f <memory_dump> --profile=<profile> handles`

44. **Analyze Driver Modules**: `volatility -f <memory_dump> --profile=<profile> modules`

45. **AnAnalyzealyze SSDT Hooks**: `volatility -f <memory_dump> --profile=<profile> ssdt`

46. **Analyze IRP Hooks**: `volatility -f <memory_dump> --profile=<profile> irp`

47. **Analyze Driver Imports**: `volatility -f <memory_dump> --profile=<profile> driverirp`

48. **Analyze Driver Inline Hooks**: `voljson -f <memory_dump> --profile=<profile> driverirp`

49. **Analyze Driver Ports**: `volatility -f <memory_dump> --profile=<profile> driverports`

50. **Analyze Driver Dispatchers**: `volatility -f <memory_dump> --profile=<profile> driverdispatch`

51. **Analyze Driver IRP Hooks**: `volatility -f <memory_dump> --profile=<profile> driverirp`

52. **Analyze Driver EAT Hooks**: `volatility -f <memory_dump> --profile=<profile> driverirp`

53. **Analyze Driver IDT Hooks**: `volatility -f <memory_dump> --profile=<profile> driverirp`

54. **Analyze Driver Inline IRP Hooks**: `volatility -f <memory_dump> --profile=<profile> driverirp`

55. **Analyze Driver Object Headers**: `volatility -f <memory_dump> --profile=<profile> driverirp`

56. **Analyze Driver Object Types**: `volatility -f <memory_dump> --profile=<profile> driverirp`

57. **Analyze Driver Device Objects**: `volatility -f <memory_dump> --profile=<profile> driverirp`

58. **Analyze Driver Device Object Names**: `volatility -f <memoryjson_dump> --profile=<profile> driverirp`

59. **Analyze Driver Device Object Flags**: `volatility -f <memory_dump> --profile=<profile> driverirp`

60. **Analyze Driver Device Object Characteristics**: `volatility -f <memory_dump> --profile=<profile> driverirp`

61. **Analyze Driver Device Object Attached Devices**: `volatility -f <memory_dump> --profile=<profile> driverirp`

62. **Analyze Driver Device Object Attached Device Names**: `volatility -f <memory_dump> --profile=<profile> driverirp`

63. **Analyze Driver Device Object Attached Device Flags**: `volatility -f <memory_dump> --profile=<profile> driverirp`

64. **Analyze Driver Device Object Attached Device Characteristics**: `volatility -f <memory_dump> --profile=<profile> driverirp`

65. **Analyze Driver Device Object Attached Device Attached Devices**: `volatility -f <memory_dump> --profile=<profile> driverirp`

66. **Analyze Driver Device Object Attached Device Attached Device Names**: `volatility -f <memory_dump> --profile=<profile> driverirp`

67. **Analyze Driver Device Object Attached Device Attached Device Flags**: `volatility -f <memory_dump> --profile=<profile> driverirp`

68. **Analyze Driver Device Object Attached Device Attached Device Characteristics**: `volatility -f <memory_dump> --profile=<profile> driverirp`

69. **Analyze Driver Device Object Attached Device Attached Device Attached Devices**: `volatility -f <memory_dump> --profile=<profile> driverirp`

70. **Analyze Driver Device Object Attached Device Attached Device Attached Device Names**: `volatility -f <memory_dump> --profile=<profile> driverirp`

71. **Analyze Driver Device Object Attached Device Attached Device Attached Device Flags**: `volatility -f <memory_dump> --profile=<profile> driverirp`

72. **Analyze Driver Device Object Attached Device Attached Device Attached Device Characteristics**: `volatility -f <memory_dump> --profile=<profile> driverirp`

73. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Devices**: `volatility -f <memory_dump> --profile=<profile> driverirp`

74. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Names**: `volatility -f <memory_dump> --profile=<profile> driverirp`

75. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Flags**: `volatility -f <memory_dump> --profile=<profile> driverirp`

76. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Characteristics**: `volatility -f <memory_dump> --profile=<profile> driverirp`

77. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Devices**: `volatility -f <memory_dump> --profile=<profile> driverirp`

78. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Names**: `volatility -f <memory_dump> --profile=<profile> driverirp`

79. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Flags**: `volatility -f <memory_dump> --profile=<profile> driverirp`

80. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Characteristics**: `volatility -f <memory_dump> --profile=<profile> driverirp`

81. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Devices**: `volatility -f <memory_dump> --profile=<profile> driverirp`

82. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Names**: `volatility -f <memory_dump> --profile=<profile> driverirp`

83. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Flags**: `volatility -f <memory_dump> --profile=<profile> driverirp`

84. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Characteristics**: `volatility -f <memory_dump> --profile=<profile> driverirp`

85. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Devices**: `volatility -f <memory_dump> --profile=<profile> driverirp`

86. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Names**: `volatility -f <memory_dump> --profile=<profile> driverirp`

87. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Flags**: `volatility -f <memory_dump> --profile=<profile> driverirp`

88. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Characteristics**: `volatility -f <memory_dump> --profile=<profile> driverirp`

89. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Devices**: `volatility -f <memory_dump> --profile=<profile> driverirp`

90. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Names**: `volatility -f <memory_dump> --profile=<profile> driverirp`

91. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Flags**: `volatility -f <memory_dump> --profile=<profile> driverirp`

92. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Characteristics**: `volatility -f <memory_dump> --profile=<profile> driverirp`

93. **Analyze Driver Device Object Attached Device Attached Device Attached Device Attached Device
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

它还允许使用yarascan模块在进程内搜索字符串：
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Forensic Methodology

1. **Memory Dump Acquisition**
   - **Physical Memory Dump**: `dd if=/dev/mem of=/path/to/image`
   - **Crash Dump**: `copy /y c:\windows\memory.dmp /path/to/image`
   - **Hibernation File**: `copy /y c:\hiberfil.sys /path/to/image`
   - **Virtual Machine Memory**: `vmss2core.exe vmwarevm.vmem /path/to/image`

2. **Memory Dump Analysis**
   - **Identify Profile**: `volatility -f /path/to/image imageinfo`
  json
   - **List Processes**: `volatility -f /path/to/image --profile=Win7SP1x64 pslist`
   - **Process Tree**: `volatility -f /path/to/image --profile=Win7SP1x64 pstree`
   - **Dump Process**: `volatility -f /path/to/image --profile=Win7SP1x64 procdump -p PID -D /path/to/dump`

3. **Network Analysis**
   - **Connections**: `volatility -f /path/to/image --profile=Win7SP1x64 connscan`
   - **Sockets**: `volatility -f /path/to/image --profile=Win7SP1x64 sockets`
   - **HTTP Sessions**: `volatility -f /path/to/image --profile=Win7SP1x64 http_sessions`

4. **File Analysis**
   - **File Listing**: `volatility -f /path/to/image --profile=Win7SPjson1x64 filescan`
   - **Dump File**: `volatility -f /path/to/image --profile=Win7SP1x64 dumpfiles -Q ADDRESS -D /path/to/dump`

5. **Registry Analysis**
   - **Print Registry**: `volatility -f /json/path/to/image --profile=Win7SP1x64 printkey -K "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"`
   - **User Assist**: `voljsonatility -f /path/to/image --profile=Win7SP1x64 userassist`

6. **Malware Analysis**
   - **Malware Detection**: `volatility -f /path/to/image --profile=Win7SP1x64 malfind`
   - **Yara Scan**: `volatility -f /path/to/image --profile=Win7SP1x64 yarascan --yara-file=/path/to/rules.yara`

7. **Timeline Analysis**
   - **Show Timeliner**: `volatility -f /path/to/image --profile=Win7SP1x64 timeliner`
   - **Analyze MFT**: `volatility -f /path/to/image --profile=Win7SP1x64 mftparser`

8. **Plugin Development**
   - **Create New Plugin**: Refer to Volatility documentation for plugin development.

#### Advanced Forensic Methodology

- **Memory Analysis**: In-depth memory analysis using Volatility plugins.
- **Rootkit Detection**: Detecting rootkits using memory forensics.
- **Anti-Forensics Techniques**: Identifying and countering anti-forensics measures.
- **Memory Forensics in Incident Response**: Leveraging memory forensics in incident response investigations.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

**Windows** 在注册表中使用名为 **UserAssist keys** 的功能来跟踪您运行的程序。这些键记录每个程序被执行的次数以及上次运行的时间。
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volvality -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`

- **Extracting DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Drivers**
 json
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Malfind**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Bolt**
  - `volatility -f <memory_dump> --profile=<profile> bolt`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyizing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Malfind**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Bolt**
  - `volatility -f <memory_dump> --profile=<profile> bolt`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Malfind**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Bolt**
  - `volatility -f <memory_dump> --profile=<profile> bolt`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Malfind**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Bolt**
  - `volatility -f <memory_dump> --profile=<profile> bolt`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Malfind**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Bolt**
  - `volatility -f <memory_dump> --profile=<profile> bolt`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Malfind**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Bolt**
  - `volatility -f <memory_dump> --profile=<profile> bolt`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Malfind**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Bolt**
  - `volatility -f <memory_dump> --profile=<profile> bolt`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyizing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Malfind**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Bolt**
  - `volatility -f <memory_dump> --profile=<profile> bolt`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流平台。

{% embed url="https://www.rootedcon.com/" %}

## 服务

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `voljsonity -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key_path>`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> dumpregistry -o <offset> -D <output_directory>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Suspicious Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyifying Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `voljsonity -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
 jsonity -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## 网络

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Network Connections**
  - `voljson -f <memory_dump> --profile=<profile> netscan`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **User Listing**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **Dumping Registry Hive**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Dumping SAM**
  - `volatility -f <memory_dump> --profile=<profile> hashdump -y <hive_offset> -s <system_offset> -o <sam_offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden DLLs**
 json
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `voljson -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Detecting Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Tunneling**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Key Last Write Times**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K`

- **Detecting UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
## 注册表文件

### 打印可用的注册表文件

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `voljsonity -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Dumping a DLL**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **User Accounts**
 json  - `volatility -f <memory_dump> --profile=<profile> useraccounts`

- **Dumping Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **File Extraction**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Yara Scanning**
  - `volatility -f <memory_dump> --profile=<profile> yarascan --yara-file=<rules_file>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden Drivers**
 json  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP Hooks**
  - `volvolatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callback Hooks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Inlined**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
### 获取数值

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `voljsonity -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing DLLs**
  - `voljsonity -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Drivers**
  - `voljsonity -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <outputjson_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyjsoning Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Analyzing Process Call Stacks**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Process Handles**
  - `voljsonity -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
### 转储
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## 文件系统

### 挂载

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheatsheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volvolatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Extracting Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan --dump-dir=<output_directory>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Process DLLs**
     - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Identifying Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Analyzing Shellbags**
  - `volatility -f <memory_dump> --profile=<profile> shellbags`

- **Analyzing ShimCache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Analyzing Hashdump**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Analyzing LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsass`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Analyzing Shellbags**
  - `volatility -f <memory_dump> --profile=<profile> shellbags`

- **Analyzing ShimCache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Analyzing Hashdump**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Analyzing LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsass`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Analyzing Shellbags**
  - `volatility -f <memory_dump> --profile=<profile> shellbags`

- **Analyzing ShimCache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Analyzing Hashdump**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Analyzing LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsass`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Analyzing Shellbags**
  - `volatility -f <memory_dump> --profile=<profile> shellbags`

- **Analyzing ShimCache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Analyzing Hashdump**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Analyzing LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsass`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Analyzing Shellbags**
  - `volatility -f <memory_dump> --profile=<profile> shellbags`

- **Analyzing ShimCache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Analyzing Hashdump**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Analyzing LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsass`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Analyzing Shellbags**
  - `volatility -f <memory_dump> --profile=<profile> shellbags`

- **Analyzing ShimCache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Analyzing Hashdump**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Analyzing LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsass` 

{% endtab %}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
### 扫描/转储

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Forensic Methodology

1. **Memory Dump Acquisition**
   - **Physical Memory Dump**: `dd` or `fmem` tool
   - **Virtual Memory Dump**: `hivex`, `memparser`, or `winpmem` tool

2. **Memory Dump Analysis**
   - **Identify Profile**: `imageinfo` plugin
   - **Process Listing**: `pslist` plugin
   - **Network Connections**: `netscan` plugin
   - **Registry Analysis**: `hivelist`, `hivedump`, `printkey`, `hashdump` plugins
   - **File Analysis**: `filescan`, `dumpfiles`, `malfind` plugins
   - **DLL Analysis**: `dlllist` plugin
   - **Driver Analysis**: `driverirp` plugin
   - **Kernel Analysis**: `kpcrscan`, `callbacks`, `ssdt` plugins

3. **Memory Forensics**
   - **Identify Rogue Processes**: Look for hidden or unlinked processes
   - **Detect Rootkits**: Check for hidden processes, files, registry keys
   - **Analyze Malware**: Memory analysis for malware artifacts
   - **Investigate Security Incidents**: Memory forensics for incident response

4. **Memory Analysis Tools**
   - **Volatility**: Advanced memory forensics framework
   - **Rekall**: Memory analysis framework
   - **WinDbg**: Windows debugger for memory analysis
   - **Redline**: Memory analysis tool by FireEye
   - **Mandiant Memoryze**: Memory analysis tool by FireEye

#### Advanced Memory Analysis

- **Process Analysis**
  - **pstree**: Process tree view
  - **psscan**: Process scan
  - **psxview**: Hidden process detection
  - **cmdline**: Command line arguments
  - **getsids**: Process Security Identifiers (SIDs)

- **Network Analysis**
  - **connections**: Network connections
  - **sockets**: Network sockets
  - **connscan**: Connection scan
  - **sockscan**: Socket scan

- **Registry Analysis**
  - **printkey**: Print registry key contents
  - **hivelist**: List registry hives
  - **hivedump**: Dump registry hives
  - **hashdump**: Dump password hashes

- **File Analysis**
  - **filescan**: File scan
  - **dumpfiles**: Dump files
  - **malfind**: Find injected code and unpacker stubs

- **DLL Analysis**
  - **dlllist**: List loaded DLLs
  - **dlldump**: Dump DLL contents

- **Driver Analysis**
  - **driverirp**: List drivers and IRP handlers
  - **ssdt**: System Service Descriptor Table analysis

- **Kernel Analysis**
  - **kpcrscan**: Scan for KPCR values
  - **callbacks**: Callback functions analysis
  - **ssdt**: System Service Descriptor Table analysis

- **Malware Analysis**
  - **malfind**: Find injected code and unpacker stubs
  - **apihooks**: Detect API hooks
  - **ldrmodules**: Detect loaded modules

- **Rootkit Analysis**
  - **hidden**: Detect hidden processes and objects
  - **unloadedmodules**: List unloaded kernel modules
  - **timeliner**: Timeline analysis

- **Security Incident Analysis**
  - **svcscan**: Service scan
  - **mutantscan**: Mutant scan
  - **getsids**: Process Security Identifiers (SIDs)

- **Memory Dumping**
  - **procdump**: Dump specific processes
  - **vaddump**: Dump virtual address space
  - **vadinfo**: Virtual address space information

- **Memory Acquisition**
  - **imagecopy**: Copy physical memory to an image file
  - **memdump**: Dump physical memory
  - **memdd**: Dump physical memory to a file

- **Memory Integrity**
  - **malfind**: Find injected code and unpacker stubs
  - **apihooks**: Detect API hooks
  - **ldrmodules**: Detect loaded modules

- **Memory Analysis Frameworks**
  - **Volatility**: Advanced memory forensics framework
  - **Rekall**: Memory analysis framework
  - **WinDbg**: Windows debugger for memory analysis
  - **Redline**: Memory analysis tool by FireEye
  - **Mandiant Memoryze**: Memory analysis tool by FireEye

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
### 主文件表

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %} 

## Volatility Cheat Sheet

### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Dumping a DLL**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Listing Sockets**
  - `voljson -f <memory_dump> --profile=<profile> sockets`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Hive**
 json
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **File Extraction**
  - `volatility -f <memory_dump> --profile=<profile> filescan | grep -i <file_extension>`

- **Dumping a File**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

### Advanced Commands

- **Process Memory Analysis**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Detecting Hidden Processes**
 json
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Rootkit Detection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting File System Drivers**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Registry Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting API Calls**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Detecting Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Detecting TrueCrypt Keys**
  - `volatility -f <memory_dump> --profile=<profile> truecryptmaster`

- **Detecting Bitlocker Keys**
  - `volatility -f <memory_dump> --profile=<profile> bitlockermemory`

- **Detecting LUKS Keys**
  - `volatility -f <memory_dump> --profile=<profile> luksmeta`

- **Detecting Process Herpaderping**
  - `volatility -f <memory_dump> --profile=<profile> herpaderping`

- **Detecting Process Hollowing**
  - `volatility -f <memory_dump> --profile=<profile> hollowfind`

- **Detecting Process Doppelganging**
  - `volatility -f <memory_dump> --profile=<profile> doppelganging`

- **Detecting Process Ghostwriting**
  - `volatility -f <memory_dump> --profile=<profile> ghost`

- **Detecting Process Injection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Masquerading**
  - `volvolatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Process Migration**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Privilege Escalation**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Signature Validation**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Thread Execution Hijacking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Hooking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Overwriting**
 json
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Shadowing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Unhooking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Unwinding**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Logging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Blocking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Logging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Blocking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Logging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Blocking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Logging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Blocking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Logging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Blocking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Logging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Blocking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Logging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Blocking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Logging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Blocking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Logging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Blocking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Logging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Blocking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Logging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Blocking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Wrapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Zeroing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Redirection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Patching**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Filtering**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Userland API Monitoring**
  - `volatility -f <memory_dump
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

**NTFS文件系统**使用一个关键组件，称为_主文件表_（MFT）。该表至少包含卷上每个文件的一个条目，也包括MFT本身。关于每个文件的重要细节，如**大小、时间戳、权限和实际数据**，都封装在MFT条目中或在MFT外部但由这些条目引用的区域中。更多详细信息可以在[官方文档](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)中找到。

### SSL密钥/证书

{% tabs %}
{% tab title="vol3" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="vol2" %} 

## Volatility Cheat Sheet

### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `voljson -f <memory_dump> --profile=<profile> dlllist`

- **Dumping a DLL**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **User Listing**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **Dumping SAM**
  - `volvolatility -f <memory_dump> --profile=<profile> dumpfiles -Q 0x<address> -D <output_directory>`

### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden DLLs**
     - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Sockets**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irpfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> portscan`

- **Detecting Hidden Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Hidden Notified Routines**
  - `volatility -f <memory_dump> --profile=<profile> nots`

- **Detecting Hidden Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Hidden SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Hidden IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting Hidden GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Detecting Hidden EAT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> eat`

- **Detecting Hidden Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Hidden IAT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> iat`

- **Detecting Hidden IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden TCP/IP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> tcpip`

- **Detecting Hidden UDP/IP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> udpip`

- **Detecting Hidden SSDT Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt_inline`

- **Detecting Hidden IDT Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt_inline`

- **Detecting Hidden GDT Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt_inline`

- **Detecting Hidden EAT Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> eat_inline`

- **Detecting Hidden TCP/IP Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> tcpip_inline`

- **Detecting Hidden UDP/IP Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> udpip_inline`

- **Detecting Hidden IRP Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp_inline`

- **Detecting Hidden IAT Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> iat_inline`

- **Detecting Hidden Notified Routines Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> nots_inline`

- **Detecting Hidden Callbacks Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks_inline`

- **Detecting Hidden Mutants Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> mutants_inline`

- **Detecting Hidden Timers Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> timers_inline`

- **Detecting Hidden Files Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> filescan_inline`

- **Detecting Hidden Objects Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> handles_inline`

- **Detecting Hidden Registry Keys Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules_inline`

- **Detecting Hidden Drivers Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules_inline`

- **Detecting Hidden Sockets Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules_inline`

- **Detecting Hidden Processes Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules_inline`

{% endtab %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## 恶意软件

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endtab %}

{% tab title="vol2" %} 

## Volatility Cheat Sheet

### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing DLLs of a Process**
  - `voljson -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Listing Handles of a Process**
 json
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Listing Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Hive**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Dumping a File**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <file_path> -D <output_directory>`

### Advanced Commands

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key_path>`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> mpparser`

- **Analyzing TrueCrypt Keys**
  - `volatility -f <memory_dump> --profile=<profile> truecryptmaster`

- **Analyzing User Assist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Analyzing Shellbags**
  - `volatility -f <memory_dump> --profile=<profile> shellbags`

- **Analyzing LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyizing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volability -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volability -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volability -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volability -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volability -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volability -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
### 使用yara进行扫描

使用此脚本从github下载并合并所有yara恶意软件规则：[https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
创建名为_**rules**_的目录并执行该脚本。这将创建一个名为_**malware\_rules.yar**_的文件，其中包含所有恶意软件的yara规则。
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping Registry Hives**
  - `voljson -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Extracting DLLs**
     - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

#### Plugin Options

- **Using Specific Plugin**
  - `volatility -f <memory_dump> --profile=<profile> <plugin_name>`

- **Plugin Help**
  - `volatility --info | grep <plugin_name>`

- **Plugin Usage**
  - `volatility --info | grep -A 2 <plugin_name>`

{% endtab %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
## 其他

### 外部插件

如果要使用外部插件，请确保与插件相关的文件夹是第一个使用的参数。
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Forensic Methodology

1. **Memory Dump Acquisition**
   - **Physical Memory Dump**: `dd if=/dev/mem of=/path/to/image`
   - **Crash Dump**: `copy /y c:\windows\memory.dmp c:\path\to\image`
   - **Hibernation File**: `copy /y c:\hiberfil.sys c:\path\to\image`

2. **Memory Dump Analysis**
   - **Identify Profile**: `volatility -f <dumpfile> imageinfo`
   - **List Processes**: `volatility -f <dumpfile> --profile=<profile> pslist`
   - **Dump Process**: `volatility -f <dumpfile> --profile=<profile> procdump -p <pid> -D <output_directory>`

3. **Network Analysis**
   - **Connections**: `volatility -f <dumpfile> --profile=<profile> connscan`
   - **Sockets**: `volatility -f <dumpfile> --profile=<profile> sockscan`

4. **File Analysis**
   - **File Extraction**: `volatility -f <dumpfile> --profile=<profile> filescan -D <output_directory>`
   - **Dump File**: `volatility -f <dumpfile> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

5. **Registry Analysis**
   - **Registry Hive**: `volatility -f <dumpfile> --profile=<profile> hivelist`
  json
   - **Dump Registry**: `volatility -f <dumpfile> --profile=<profile> printkey -o <offset>`

6. **Malware Analysis**
   - **Malware Detection**: `volatility -f <dumpfile> --profile=<profile> malfind`
   - **YARA Scan**: `volatility -f <dumpfile> --profile=<profile> yarascan --yara-file=<rules_file>`

7. **Timeline Analysis**
   - **Process Timeline**: `volatility -f <dumpfile> --profile=<profile> pstree`
   - **Network Timeline**: `volatility -f <dumpfile> --profile=<profile> connscan`
   - **File Timeline**: `volatility -f <dumpfile> --profile=<profile> filescan`

8. **Plugin Development**
   - **Create New Plugin**: Extend existing plugins or create new ones using Python.

{% endtab %}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

从[https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)下载。
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### 互斥体

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Forensic Methodology

1. **Memory Dump Acquisition**
   - **Physical Memory Dump**: `dd if=/dev/mem of=/path/to/image`
   - **Crash Dump**: `copy /y c:\windows\memory.dmp /path/to/image`
   - **Hibernation File**: `copy /y c:\hiberfil.sys /path/to/image`

2. **Memory Analysis with Volatility**
   - **Identify Profile**: `volatility -f memory.img imageinfo`
   - **List Processes**: `volatility -f memory.img --profile=Win7SP1x64 pslist`
   - **Dump Process**: `volatility -f memory.img --profile=Win7SP1x64 memdump -p PID -D /path/to/dump`

3. **Network Analysis with Volatility**
   - **List Sockets**: `volatility -f memory.img --profile=Win7SP1x64 sockscan`
   - **Connections**: `volatility -f memory.img --profile=Win7SP1x64 connections`

4. **Registry Analysis with Volatility**
   - **User Listing**: `volatility -f memory.img --profile=Win7SPjson1x64 hivelist`
   - **Dump Registry Hive**: `volatility -f memory.img --profile=Win7SP1x64 printkey -o OFFSET`

5. **File Analysis with Volatility**
   - **File Listing**: `volatility -f memory.img --profile=Win7SP1x64 filescan`
   - **Dump File**: `volatility -f memory.img --profile=Win7SP1x64 dumpfiles -Q ADDRESS -D /path/to/dump`

6. **Plugin Usage**
   - **Plugin Syntax**: `volatility -f memory.img --profile=Win7SP1x64 <plugin_name>`

7. **Automating Analysis**
   - **Automated Scripting**: Use Python scripts to automate Volatility commands.

#### Advanced Forensic Methodology

1. **Timeline Analysis**
   - **Identify Last Boot**: `volatility -f memory.img --profile=Win7SP1x64 windows`
   - **Analyze Prefetch Files**: `volatility -f memory.img --profile=Win7SP1x64 prefetchparser`

2. **Malware Analysis**
   - **Detect Hidden Processes**: `volatility -f memory.img --profile=Win7SP1x64 psxview`
   - **Rootkit Detection**: `volatility -f memory.img --profile=Win7SP1x64 malfind`

3. **Memory Forensics Challenges**
   - **Detecting Fileless Malware**: Use Volatility plugins to detect fileless malware.
   - **Analyzing Encrypted Data**: Use memory analysis techniques to analyze encrypted data in memory.

4. **Memory Forensics Best Practices**
   - **Document Findings**: Keep detailed notes of findings during memory analysis.
   - **Validate Results**: Cross-verify findings with multiple memory analysis tools.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
### 符号链接

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping Registry Hives**
  - `voljson -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Extracting DLLs**
     - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

#### Plugin Development

- **Creating a New Plugin**
  - Create a new Python file in the `volatility/plugins` directory
  - Inherit from `volatility.plugins.interface`
  - Implement the `calculate()` method

- **Using the Plugin**
  - `volatility --plugins=<path_to_plugin> -f <memory_dump> <plugin_name>`

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

可以**从内存中读取bash历史记录**。您也可以转储.bash_history文件，但如果它被禁用，您会很高兴可以使用这个volatility模块
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volmemory -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping Registry Hjson**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Dumping Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Process Memory**
  - `voljson -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Extracting DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
### 时间线

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `voljson -f <memory_dump> --profile=<profile> netscan`

- **Dumping a File**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

#### Advanced Commands

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`
  - `volatility -f <memory_dump> --profile=<profile> moddump -o <offset> -D <output_directory>`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> drvscan`

- **Analyizing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volvolatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timers**
  - `volatility -f <memory_dump>
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
### 驱动程序

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volvatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Rootkit Detection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> --output-file <output_file>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handle`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyizing PEB**
  - `volatility -f <memory_dump> --profile=<profile> peb`

- **Analyzing Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Handles**
  - `volvolatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Devices**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Files**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Sections**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Alpc Ports**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden WMI**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden LPC Ports**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Raw Sockets**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Etw Handles**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Desktops**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Tokens**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Jobs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Windows**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Handles**
  - `volvolatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Devices**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Files**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Sections**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Alpc Ports**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden WMI**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden LPC Ports**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Raw Sockets**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Etw Handles**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Desktops**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Tokens**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Jobs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Windows**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Handles**
  - `volvolatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Devices**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Files**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Sections**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Alpc Ports**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden WMI**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden LPC Ports**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Raw Sockets**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Etw Handles**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Desktops**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Tokens**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Jobs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Windows**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
### 获取剪贴板
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### 获取IE浏览历史
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### 获取记事本文本
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### 屏幕截图
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### 主引导记录（MBR）
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**主引导记录（MBR）** 在管理存储介质的逻辑分区方面发挥着至关重要的作用，这些分区使用不同的[文件系统](https://en.wikipedia.org/wiki/File_system)进行结构化。它不仅保存分区布局信息，还包含充当引导加载程序的可执行代码。这个引导加载程序要么直接启动操作系统的第二阶段加载过程（参见[第二阶段引导加载程序](https://en.wikipedia.org/wiki/Second-stage_boot_loader)），要么与每个分区的[卷引导记录](https://en.wikipedia.org/wiki/Volume_boot_record)（VBR）协同工作。欲了解更多信息，请参阅[MBR 维基百科页面](https://en.wikipedia.org/wiki/Master_boot_record)。

# 参考资料
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点会议。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live) 上关注我们。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
