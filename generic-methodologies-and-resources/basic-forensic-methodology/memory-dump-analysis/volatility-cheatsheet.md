# Volatility - CheatSheet

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

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

访问[Volatility命令参考](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)中的官方文档

### “list”与“scan”插件的说明

Volatility有两种主要的插件方法，有时可以从它们的名称中反映出来。“list”插件将尝试浏览Windows内核结构，以检索诸如进程（在内存中定位和遍历`_EPROCESS`结构的链接列表）、操作系统句柄（定位和列出句柄表，取消引用找到的任何指针等）等信息。它们的行为几乎与请求Windows API列出进程时的行为相同。

这使得“list”插件非常快速，但与Windows API一样容易受到恶意软件的操纵。例如，如果恶意软件使用DKOM从`_EPROCESS`链接列表中取消链接一个进程，它将不会显示在任务管理器中，pslist中也不会显示。

另一方面，“scan”插件将采用类似于在内存中雕刻可能在解除引用为特定结构时有意义的内容的方法。例如，`psscan`将读取内存并尝试从中创建`_EPROCESS`对象（它使用池标签扫描，搜索指示感兴趣结构存在的4字节字符串）。优点是它可以找到已退出的进程，即使恶意软件篡改了`_EPROCESS`链接列表，插件仍将在内存中找到该结构（因为该结构仍然需要存在以使进程运行）。缺点是“scan”插件比“list”插件慢一些，有时可能产生误报（进程已退出太久，其结构的部分被其他操作覆盖）。

来源：[http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## 操作系统配置文件

### Volatility3

如readme中所述，您需要将要支持的操作系统的**符号表**放入\_volatility3/volatility/symbols\_中。\
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

如果要使用**您已下载的新配置文件**（例如 Linux 配置文件），您需要在某个地方创建以下文件夹结构：_plugins/overlays/linux_，并将包含配置文件的 zip 文件放入此文件夹中。然后，使用以下命令获取配置文件的编号：

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

在前面的片段中，您可以看到配置文件被称为`LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`，您可以使用它来执行类似以下操作：

```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```

#### 发现配置文件

```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```

#### **imageinfo 与 kdbgscan 之间的区别**

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

**内核调试器块**，由Volatility称为**KDBG**，对于Volatility和各种调试器执行的取证任务至关重要。被标识为`KdDebuggerDataBlock`，类型为`_KDDEBUGGER_DATA64`，其中包含诸如`PsActiveProcessHead`之类的关键引用。这个特定引用指向进程列表的头部，使得能够列出所有进程，这对于彻底的内存分析至关重要。

## 操作系统信息

```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```

插件`banners.Banners`可在**vol3中用于尝试在转储文件中查找Linux横幅**。

## Hashes/密码

提取SAM哈希值，[域缓存凭据](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials)和[lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/#lsa-secrets)。

```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping a File**
  * `volvality -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

**Advanced Commands**

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Analyzing Registry**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Extracting DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`
* **Analyzing Drivers** json
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Identifying Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Analyzing Timelime**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Analyzing Packed Binaries**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handle`
* **Analyzing Process Memory**
  * `volatility -f <memory_dump> --profile=<profile> memmap`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo -p <pid>`

```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```

### 内存转储

进程的内存转储将提取进程当前状态的所有内容。**procdump** 模块将仅提取**代码**。

```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的之一。以**促进技术知识**为使命，这个大会是技术和网络安全专业人士在各个领域的热点交流会。

{% embed url="https://www.rootedcon.com/" %}

### 进程

#### 列出进程

尝试查找**可疑**进程（按名称）或**意外**的子**进程**（例如，cmd.exe 作为 iexplorer.exe 的子进程）。\
比较 pslist 的结果和 psscan 的结果以识别隐藏进程可能会很有趣。

```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `voljsonity -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`
* **Dumping a DLL**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Listing Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Registry Analysis**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Dumping Registry Hive**
  * `volatility -f <memory_dump> --profile=<profile> dumpregistry -o <offset> -D <output_directory>`
* **File Analysis**
  * `voljsonity -f <memory_dump> --profile=<profile> filescan`
* **Dumping a File** json - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`
* **Kernel Modules**
  * `volatility -f <memory_dump> --profile=<profile> modscan`
* **Driver Modules**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Crash Dump Analysis**
  * `volatility -f <memory_dump> --profile=<profile> memmap`
* **Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Command History**
  * `volatility -f <memory_dump> --profile=<profile> cmdscan`
* **User Accounts** json - `volatility -f <memory_dump> --profile=<profile> userassist`
* **Screenshots**
  * `volatility -f <memory_dump> --profile=<profile> screenshot -D <output_directory>`
* **Yara Scanning**
  * `volatility -f <memory_dump> --profile=<profile> yarascan --yara-file=<rules_file>`
* **API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Detecting Hidden Objects**
  * `volvoljsonity -f <memory_dump> --profile=<profile> hiddenevents`
* **Detecting Rootkits**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Injection**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting API-Hooking**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Inline Hooks**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Hollow Processes**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked Processes**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked DLLs**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked File Objects**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked Mutant Objects**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked Registry Objects**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked Desktop Objects**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked Keyed Event Objects**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked Io Completion Objects**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked Timer Objects**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked ALPC Ports**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Consumers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Unlinked WMI Filters**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* \*\*Detecting

```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```

#### 转储进程

```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping a File**
  * `voljsonity -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

**Advanced Commands**

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Extracting Registry Hjson**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Kernel Modules**
  * `volatility -f <memory_dump> --profile=<profile> modscan`
* **Identifying Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Checking for Rootkits**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyating Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```

#### 命令行

是否执行了任何可疑操作？

```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `voljsonity -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`
* **Dumping a DLL**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Listing Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Registry Analysis**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping Registry Hive** json - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **File Extraction**
  * `volatility -f <memory_dump> --profile=<profile> filescan | grep -i <file_extension>`
* **Dumping a File**
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`
* **Kernel Driver Modules**
  * `volatility -f <memory_dump> --profile=<profile> modscan`
* **Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Command History**
  * `volatility -f <memory_dump> --profile=<profile> cmdscan`
* **User Accounts**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Screenshots**
  * `volatility -f <memory_dump> --profile=<profile> screenshot -D <output_directory>`
* **Yara Scanning**
  * `voljsonity -f <memory_dump> --profile=<profile> yarascan --yara-rules=<rules_file>`

**Advanced Commands**

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Detecting Hidden Modules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Detecting Hidden Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Detecting Hidden TCP/UDP Ports**
  * `volatility -f <memory_dump> --profile=<profile> portscan`
* **Detecting Hidden Driver Modules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Detecting Hidden Notified Routines**
  * `volatility -f <memory_dump> --profile=<profile> notsuss`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden Driver Objects**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Detecting Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivescan`
* **Detecting Hidden Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Detecting Hidden TCP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Notified Routines**
  * `volatility -f <memory_dump> --profile=<profile> notsuss`
* **Detecting Hidden Mutants**
  * `volvoljsonity -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden Driver Objects**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Detecting Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivescan`
* **Detecting Hidden Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Detecting Hidden TCP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Detecting Hidden IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Detecting Hidden GDT Hooks** json - `volatility -f <memory_dump> --profile=<profile> gdt`
* **Detecting Hidden EAT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> eat`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Notified Routines**
  * `volatility -f <memory_dump> --profile=<profile> notsuss`
* **Detecting Hidden Mutants**
  * `volvoljsonity -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden Driver Objects**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Detecting Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivescan`
* **Detecting Hidden Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Detecting Hidden TCP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Detecting Hidden IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Detecting Hidden GDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Detecting Hidden EAT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> eat`

```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```

在`cmd.exe`中执行的命令由\*\*`conhost.exe`**（或在Windows 7之前的系统上为`csrss.exe`）管理。这意味着，如果在获取内存转储之前攻击者终止了**`cmd.exe`**，仍然可以从**`conhost.exe`**的内存中恢复会话的命令历史记录。要做到这一点，如果检测到控制台模块中的异常活动，应该转储相关**`conhost.exe`**进程的内存。然后，通过在此转储中搜索**字符串\*\*，可以潜在地提取会话中使用的命令行。

### 环境

获取每个运行进程的环境变量。可能会有一些有趣的值。

```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```

### Volatility Cheat Sheet

#### Basic Commands

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping a File**
  * `voljsonity -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

#### Advanced Commands

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Analyzing Registry**
  * `volatility -f <memory_dump> --profile=<profile> printkey -K <key_path>`
* **Extracting DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Analyzing Drivers** json - `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Identifying Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockets`
* **Analyzing Timelime**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Dumping Registry Hives**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Analyzing PSScan**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Shellbags**
  * `volatility -f <memory_dump> --profile=<profile> shellbags`
* **Analyzing MFT**
  * `volatility -f <memory_dump> --profile=<profile> mftparser`
* **Analyzing LDRModules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Analyating API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing CSRSS**
  * `volatility -f <memory_dump> --profile=<profile> csrss`
* **Analyzing Print Spooler**
  * `volatility -f <memory_dump> --profile=<profile> printkey`
* **Analyzing Desktops**
  * `volatility -f <memory_dump> --profile=<profile> desktops`
* **Analyzing Privileges**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Analyzing Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vaddump`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadwalk`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadlist`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Vad Trees**
  * \`volatility -f \<memory\_dump> --profile=

```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```

#### 令牌权限

检查意外服务中的特权令牌。\
列出使用某些特权令牌的进程可能很有趣。

```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `voljsonity -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`
* **Dumping a DLL**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Listing Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Registry Analysis**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping Registry Hive** json - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **File Extraction**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Dumping a File**
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`
* **Kernel Modules**
  * `volatility -f <memory_dump> --profile=<profile> modscan`
* **Driver Modules**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **UserAssist**
  * `voljsonity -f <memory_dump> --profile=<profile> userassist`
* **Privileges**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Crash Dumps**
  * `volatility -f <memory_dump> --profile=<profile> crashinfo`
* **Yara Scanning**
  * `volatility -f <memory_dump> --profile=<profile> yarascan --yara-file=<rules_file>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Dumping a Process**
  * \`volatility -f \<memory\_dump> --profile= memdump -p -D <

```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```

#### SIDs

检查每个进程拥有的SSID。\
列出使用特权SID的进程（以及使用某些服务SID的进程）可能会很有趣。

```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping Registry Hives**
  * `voljson -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

**Advanced Commands**

* **Analyzing a Process**
  * `volatility -f <memory_dump> --profile=<profile> pstree -p <pid>`
* **Extracting DLLs** json
  * `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`
* **Dumping a File**
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`
* **Analyzing Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Identifying Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Analyzing Timelime**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`

**Plugin Development**

* **Creating a New Plugin**
  * Create a new Python file in the `volatility/plugins` directory
  * Implement the plugin using the Volatility API
  * Use the `vol.py` command with the `--plugins` option to load the custom plugin

```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```

### 句柄

有助于了解进程打开了哪些其他文件、密钥、线程、进程...

```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```

### Volatility Cheat Sheet

#### Basic Commands

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping a File**
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

#### Advanced Commands

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Analyzing Registry**
  * `voljson -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Extracting DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Analyzing Timelime**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`

#### Plugin Development

* **Creating a New Plugin**
  * Refer to the official [Volatility Plugin Development Guide](https://github.com/volatilityfoundation/volatility3/blob/master/README.md#developing-plugins)
* **Compiling Plugins**
  * `python vol.py --plugins=<plugin_directory>`
* **Using Custom Plugins**
  * `volatility --plugins=<custom_plugin_directory> -f <memory_dump> <custom_plugin_name>`

```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```

### DLLs

```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```

#### Volatility Cheat Sheet

**Basic Forensic Methodology**

1. **Memory Dump Analysis**
   * **Identify Profile**: `vol.py -f memory_dump.raw imageinfo`
   * **Analyze Processes**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist`
   * **Analyze DLLs**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 dlllist`
   * **Analyze Handles**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 handles`
   * **Analyze Registry**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 printkey -K "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"`
   * **Analyze Network Connections**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 netscan`
   * **Analyze Drivers**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 driverscan`
   * **Analyze Mutants**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mutantscan`
   * **Analyze Sockets**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 sockets`
   * **Analyze Autostart Locations**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 autoruns`
2. **File Analysis**
   * **Analyze MFT**: `vol.py -f memory_dump.raw --profile=Win7SPjson1 mftparser`
   * **Analyze File Metadata**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 filescan`
3. **Timeline Analysis**
   * **Create Timeline**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mactime`
4. **Malware Analysis**
   * **Analyze Malware**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 malfind`
5. **Rootkit Detection**
   * **Detect Rootkits**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 rootkit`
6. **Memory Analysis**
   * **Analyze Memory**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 memmap`
7. **User Analysis**
   * **AnAnalyze Users**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 userassist`
8. **Registry Analysis**
   * **Analyze Registry**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 printkey -K "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"`
9. **Network Analysis**
   * **Analyze Network**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 netscan`
10. **Process Analysis**
    * **Analyze Processes**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist`
11. **DLL Analysis**
    * **Analyze DLLs**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 dlllist`
12. **Handle Analysis**
    * **Analyze Handles**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 handles`
13. **Driver Analysis**
    * **Analyze Drivers**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 driverscan`
14. **Mutant Analysis**
    * **Analyze Mutants**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mutantscan`
15. **Socket Analysis**
    * **Analyze Sockets**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 sockets`
16. **Autostart Analysis**
    * **Analyze Autostart Locations**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 autoruns`
17. **MFT Analysis**
    * **Analyze MFT**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mftparser`
18. **File Metadata Analysis**
    * **Analyze File Metadata**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 filescan`
19. **Timeline Creation**
    * **Create Timeline**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mactime`
20. **Malware Analysis**
    * **Analyze Malware**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 malfind`
21. **Rootkit Detection**
    * **Detect Rootkits**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 rootkit`
22. **Memory Analysis**
    * **Analyze Memory**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 memmap`
23. **User Analysis**
    * **Analyze Users**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 userassist`
24. **Registry Analysis**
    * **Analyze Registry**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 printkey -K "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"`
25. **Network Analysis**
    * **Analyze Network**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 netscan`
26. **Process Analysis**
    * **Analyze Processes**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist`
27. **DLL Analysis**
    * **Analyze DLLs**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 dlllist`
28. **Handle Analysis**
    * **Analyze Handles**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 handles`
29. **Driver Analysis**
    * **Analyze Drivers**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 driverscan`
30. **Mutant Analysis**
    * **Analyze Mutants**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mutantscan`
31. **Socket Analysis**
    * **Analyze Sockets**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 sockets`
32. **Autostart Analysis**
    * **Analyze Autostart Locations**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 autoruns`
33. **MFT Analysis**
    * **Analyze MFT**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mftparser`
34. **File Metadata Analysis**
    * **Analyze File Metadata**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 filescan`
35. **Timeline Creation**
    * **Create Timeline**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mactime`
36. **Malware Analysis**
    * **Analyze Malware**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 malfind`
37. **Rootkit Detection**
    * **Detect Rootkits**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 rootkit`
38. **Memory Analysis**
    * **Analyze Memory**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 memmap`
39. **User Analysis**
    * **Analyze Users**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 userassist`
40. **Registry Analysis**
    * **Analyze Registry**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 printkey -K "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"`
41. **Network Analysis**
    * **Analyze Network**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 netscan`
42. **Process Analysis**
    * **Analyze Processes**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist`
43. **DLL Analysis**
    * **Analyze DLLs**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 dlllist`
44. **Handle Analysis**
    * **Analyze Handles**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 handles`
45. **Driver Analysis**
    * **Analyze Drivers**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 driverscan`
46. **Mutant Analysis**
    * **Analyze Mutants**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mutantscan`
47. **Socket Analysis**
    * **Analyze Sockets**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 sockets`
48. **Autostart Analysis**
    * **Analyze Autostart Locations**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 autoruns`
49. **MFT Analysis**
    * **Analyze MFT**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mftparser`
50. **File Metadata Analysis**
    * **Analyze File Metadata**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 filescan`
51. **Timeline Creation**
    * **Create Timeline**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mactime`
52. **Malware Analysis**
    * **Analyze Malware**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 malfind`
53. **Rootkit Detection**
    * **Detect Rootkits**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 rootkit`
54. **Memory Analysis**
    * **Analyze Memory**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 memmap`
55. **User Analysis**
    * **Analyze Users**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 userassist`
56. **Registry Analysis**
    * **Analyze Registry**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 printkey -K "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"`
57. **Network Analysis**
    * **Analyze Network**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 netscan`
58. **Process Analysis**
    * **Analyze Processes**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist`
59. **DLL Analysis**
    * **Analyze DLLs**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 dlllist`
60. **Handle Analysis**
    * **Analyze Handles**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 handles`
61. **Driver Analysis**
    * **Analyze Drivers**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 driverscan`
62. **Mutant Analysis**
    * **Analyze Mutants**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 mutantscan`
63. **Socket Analysis**
    * **Analyze Sockets**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 sockets`
64. **Autostart Analysis**
    * **Analyze Autostart Locations**: `vol.py -f memory_dump.raw --profile=Win7SP1x64 autoruns`

```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```

### 每个进程的字符串

Volatility允许我们检查一个字符串属于哪个进程。

```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```

### Volatility Cheat Sheet

#### Basic Commands

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `voljson -f <memory_dump> --profile=<profile> netscan`
* **Dumping a File**
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> --dump-dir=<output_directory>`

#### Advanced Commands

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Analyzing Registry** json
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Extracting DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Analyzing Drivers**
  * `voljson -f <memory_dump> --profile=<profile> driverscan`
* **Identifying Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Analyzing Timelime**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Analyzing PSScan**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Mutantscan**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Yarascan**
  * `volatility -f <memory_dump> --profile=<profile> yarascan`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing LDR Modules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vaddump`
* **Analyzing User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Privileges**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Analyzing Privilege Rights**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Analyzing Kernel Hooks**
  * `volatility -f <memory_dump> --profile=<profile> kdbgscan`
* **Analyzing Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Analyzing GDI Tables**
  * `volatility -f <memory_dump> --profile=<profile> gditimers`
* **Analyzing GDI Shared Handles**
  * `volatility -f <memory_dump> --profile=<profile> gdiview`
* **Analyzing GDI Objects**
  * `volatility -f <memory_dump> --profile=<profile> gdiobjects`
* **Analyzing Atom Tables**
  * `volatility -f <memory_dump> --profile=<profile> atomscan`
* **Analyzing Desktops**
  * `volatility -f <memory_dump> --profile=<profile> desktops`
* **Analyzing Windows Stations**
  * `volatility -f <memory_dump> --profile=<profile> windows`
* **Analyzing Sessions**
  * `volatility -f <memory_dump> --profile=<profile> sessions`
* **Analyzing Printers**
  * `volatility -f <memory_dump> --profile=<profile> printers`
* **Analyzing Shimcache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Shellbags**
  * `volatility -f <memory_dump> --profile=<profile> shellbags`
* **Analyzing MFT**
  * `volatility -f <memory_dump> --profile=<profile> mftparser`
* **Analyzing TrueCrypt Keys**
  * `volatility -f <memory_dump> --profile=<profile> truecryptmaster`
* **Analyzing Bitlocker Keys**
  * `volatility -f <memory_dump> --profile=<profile> bitlockermemory`
* **Analyzing LUKS Keys**
  * `volatility -f <memory_dump> --profile=<profile> luksmeta`
* **Analyzing Chrome Extensions**
  * `volatility -f <memory_dump> --profile=<profile> chromehistory`
* **Analyzing Firefox Extensions**
  * `volatility -f <memory_dump> --profile=<profile> firefoxhistory`
* **Analyzing IE History**
  * `volatility -f <memory_dump> --profile=<profile> iehistory`
* **Analyzing LSA Secrets**
  * `volatility -f <memory_dump> --profile=<profile> lsadump`
* **Analyizing Hashdump**
  * `volatility -f <memory_dump> --profile=<profile> hashdump`
* **Analyzing User Assist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Shellbags**
  * `volatility -f <memory_dump> --profile=<profile> shellbags`
* **Analyzing MBR**
  * `volatility -f <memory_dump> --profile=<profile> mbrparser`
* **Analyzing VBR**
  * `volatility -f <memory_dump> --profile=<profile> vbrparser`
* **Analyzing Registry Hives**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping Registry Hive**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing User Profiles**
  * `volatility -f <memory_dump> --profile=<profile> userprofiles`
* **Analyzing PEB**
  * `volatility -f <memory_dump> --profile=<profile> peb`
* **Analyzing Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vaddump`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Yara Rules**
  * `volatility -f <memory_dump> --profile=<profile> yarascan`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing LDR Modules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vaddump`
* **Analyzing User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Privileges**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Analyizing Privilege Rights**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Analyzing Kernel Hooks**
  * `volatility -f <memory_dump> --profile=<profile> kdbgscan`
* **Analyzing Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Analyzing GDI Tables**
  * `volatility -f <memory_dump> --profile=<profile> gditimers`
* **Analyzing GDI Shared Handles**
  * `volatility -f <memory_dump> --profile=<profile> gdiview`
* **Analyzing GDI Objects**
  * `volatility -f <memory_dump> --profile=<profile> gdiobjects`
* **Analyzing Atom Tables**
  * `volatility -f <memory_dump> --profile=<profile> atomscan`
* **Analyzing Desktops**
  * `volatility -f <memory_dump> --profile=<profile> desktops`
* **Analyzing Windows Stations**
  * `volatility -f <memory_dump> --profile=<profile> windows`
* **Analyzing Sessions**
  * `volatility -f <memory_dump> --profile=<profile> sessions`
* **Analyzing Printers**
  * `volatility -f <memory_dump> --profile=<profile> printers`
* **Analyzing Shimcache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Shellbags**
  * `volatility -f <memory_dump> --profile=<profile> shellbags`
* **Analyzing MFT**
  * `volatility -f <memory_dump> --profile=<profile> mftparser`
* **Analyzing TrueCrypt Keys**
  * `volatility -f <memory_dump> --profile=<profile> truecryptmaster`
* **Analyzing Bitlocker Keys**
  * `volatility -f <memory_dump> --profile=<profile> bitlockermemory`
* **Analyzing LUKS Keys**
  * `volatility -f <memory_dump> --profile=<profile> luksmeta`
* **Analyzing Chrome Extensions**
  * `volatility -f <memory_dump> --profile=<profile> chromehistory`
* **Analyzing Firefox Extensions**
  * `volatility -f <memory_dump> --profile=<profile> firefoxhistory`
* **Analyzing IE History**
  * `volatility -f <memory_dump> --profile=<profile> iehistory`
* **Analyzing LSA Secrets**
  * `volatility -f <memory_dump> --profile=<profile> lsadump`
* **Analyzing Hashdump**
  * `volatility -f <memory_dump> --profile=<profile> hashdump`
* **Analyzing User Assist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Shellbags**
  * `volatility -f <memory_dump> --profile=<profile> shellbags`
* **Analyzing MBR**
  * `volatility -f <memory_dump> --profile=<profile> mbrparser`
* **Analyzing VBR**
  * `volatility -f <memory_dump> --profile=<profile> vbrparser`
* **Analyzing Registry Hives**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping Registry Hive**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing User Profiles**
  * `volatility -f <memory_dump> --profile=<profile> userprofiles`
* **Analyzing PEB**
  * `volatility -f <memory_dump> --profile=<profile> peb`
* **Analyzing Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vaddump`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Yara Rules**
  * `volatility -f <memory_dump> --profile=<profile> yarascan`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing LDR Modules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vaddump`
* **Analyzing User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyizing Privileges**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Analyzing Privilege Rights**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Analyzing Kernel Hooks**
  * `volatility -f <memory_dump> --profile=<profile> kdbgscan`
* **Analyzing Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Analyzing GDI Tables**
  * `volatility -f <memory_dump> --profile=<profile> gditimers`
* **Analyzing GDI Shared Handles**
  * `volatility -f <memory_dump> --profile=<profile> gdiview`
* **Analyzing GDI Objects**
  * `volatility -f <memory_dump> --profile=<profile> gdiobjects`
* **Analyzing Atom Tables**
  * `volatility -f <memory_dump> --profile=<profile> atomscan`
* **Analyzing Desktops**
  * `volatility -f <memory_dump> --profile=<profile> desktops`
* **Analyzing Windows Stations**
  * `volatility -f <memory_dump> --profile=<profile> windows`
* **Analyzing Sessions**
  * `volatility -f <memory_dump> --profile=<profile> sessions`
* **Analyizing Printers**
  * `volatility -f <memory_dump> --profile=<profile> printers`
* **Analyzing Shimcache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Shellbags**
  * `volatility -f <memory_dump> --profile=<profile> shellbags`
* **Analyzing MFT**
  * `volatility -f <memory_dump> --profile=<profile> mftparser`
* **Analyzing TrueCrypt Keys**
  * `volatility -f <memory_dump> --profile=<profile> truecryptmaster`
* **Analyzing Bitlocker Keys**
  * `volatility -f <memory_dump> --profile=<profile> bitlockermemory`
* **Analyzing LUKS Keys**
  * `volatility -f <memory_dump> --profile=<profile> luksmeta`
* **Analyzing Chrome Extensions**
  * `volatility -f <memory_dump> --profile=<profile> chromehistory`
* **Analyzing Firefox Extensions**
  * `volatility -f <memory_dump> --profile=<profile> firefoxhistory`
* **Analyzing IE History**
  * `volatility -f <memory_dump> --profile=<profile> iehistory`
* **Analyzing LSA Secrets**
  * `volatility -f <memory_dump> --profile=<profile> lsadump`
* **Analyzing Hashdump**
  * `volatility -f <memory_dump> --profile=<profile> hashdump`
* **Analyzing User Assist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Shellbags**
  * `volatility -f <memory_dump> --profile=<profile> shellbags`
* **Analyzing MBR**
  * `volatility -f <memory_dump> --profile=<profile> mbrparser`
* **Analyzing VBR**
  * `volatility -f <memory_dump> --profile=<profile> vbrparser`
* **Analyzing Registry Hives**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping Registry Hive**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing User Profiles**
  * `volatility -f <memory_dump> --profile=<profile> userprofiles`
* **Analyzing PEB**
  * `volatility -f <memory_dump> --profile=<profile> peb`
* **Analyzing Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vaddump`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Yara Rules**
  * `volatility -f <memory_dump> --profile=<profile> yarascan`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyizing LDR Modules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Analyzing Handles**
  * \`volatility -f \<memory\_dump> --profile=\<profile

```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```

它还允许使用yarascan模块在进程内搜索字符串：

```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```

### Volatility Cheat Sheet

#### Basic Commands

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping a File**
  * `voljsonity -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

#### Advanced Commands

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Analyzing Registry**
  * `volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`
* **Extracting DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Analyzing Drivers** json - `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Identifying Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Analyzing Timelime**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Analyzing PSScan**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Yara Rules**
  * `volatility -f <memory_dump> --profile=<profile> yarascan`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Privileges**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Analyzing Crashes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Analyzing Kernel Modules**
  * `volatility -f <memory_dump> --profile=<profile> modscan`
* **Analyizing ImpHash**
  * `volatility -f <memory_dump> --profile=<profile> impscan`
* **Analyzing API Audit**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Trace**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Monitor**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
*

```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```

#### UserAssist

**Windows** 在注册表中使用名为 **UserAssist keys** 的功能来跟踪您运行的程序。这些键记录每个程序被执行的次数以及上次运行的时间。

```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping Registry Hives**
  * `voljson -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

**Advanced Commands**

* **Analyzing Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Extracting DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Analyzing Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Identifying Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockets`
* **Analyzing Timelining**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`

**Plugin Options**

* **Using Specific Plugin**
  * `volatility -f <memory_dump> --profile=<profile> <plugin_name>`
* **Plugin Help**
  * `volatility --info | grep <plugin_name>`
* **Plugin Options**
  * `volatility --info | grep <plugin_name> -A <number_of_lines>`

```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流会。

{% embed url="https://www.rootedcon.com/" %}

## 服务

```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```

在进行内存转储分析时，以下是一些常用的Volatility命令和技巧：

* **查看进程列表**：`volatility -f <memory_dump> --profile=<profile> pslist`
* **查看网络连接**：`volatility -f <memory_dump> --profile=<profile> netscan`
* **查看注册表信息**：`volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`
* **查看文件信息**：`volatility -f <memory_dump> --profile=<profile> filescan`

记住，使用适当的插件和配置文件来确保分析的准确性和完整性。

```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```

## 网络

```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```

### Volatility Cheat Sheet

#### Basic Commands

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`
* **Listing Sockets**
  * `voljson -f <memory_dump> --profile=<profile> sockscan`
* **Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Registry Analysis**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping Registry Hive** json- `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **File Extraction**
  * `volatility -f <memory_dump> --profile=<profile> filescan | grep -i <file_extension>`
* **Dumping a File**
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`
* **Rootkit Detection**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Process Tree**
  * `volatility -f <memory_dump> --profile=<profile> pstree`
* **Command History**
  * `volatility -f <memory_dump> --profile=<profile> cmdscan`
* **User Account Information**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Screen Capture**
  * `volatility -f <memory_dump> --profile=<profile> screenshot -D <output_directory>`
* **Kernel Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Crash Dump Analysis**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Detecting Hidden Modules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irp`
* **Detecting Hidden IDT Hooks**
  * `voljson -f <memory_dump> --profile=<profile> idt`
* **Detecting Hidden TCP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Detecting Hidden Notified Routines**
  * `volatility -f <memory_dump> --profile=<profile> notifys`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Detecting Hidden Objects**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Detecting Hidden Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Detecting Hidden TCP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Detecting Hidden IRPs**
  * `volatility -f <memory_dump> --profile=<profile> irp`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Detecting Hidden TCP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Detecting Hidden Notified Routines**
  * `volatility -f <memory_dump> --profile=<profile> notifys`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Detecting Hidden Objects**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Detecting Hidden Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Detecting Hidden TCP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Detecting Hidden IRPs**
  * `volatility -f <memory_dump> --profile=<profile> irp`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Detecting Hidden TCP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Detecting Hidden Notified Routines**
  * `volatility -f <memory_dump> --profile=<profile> notifys`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Detecting Hidden Objects**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Detecting Hidden Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Detecting Hidden TCP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Detecting Hidden IRPs**
  * `volatility -f <memory_dump> --profile=<profile> irp`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Detecting Hidden TCP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Detecting Hidden Notified Routines**
  * `volatility -f <memory_dump> --profile=<profile> notifys`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Detecting Hidden Objects**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Detecting Hidden Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Detecting Hidden TCP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Detecting Hidden IRPs**
  * `volatility -f <memory_dump> --profile=<profile> irp`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Detecting Hidden TCP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Detecting Hidden Notified Routines**
  * `volatility -f <memory_dump> --profile=<profile> notifys`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Detecting Hidden Objects**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Detecting Hidden Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Detecting Hidden TCP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Detecting Hidden IRPs**
  * `volatility -f <memory_dump> --profile=<profile> irp`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Detecting Hidden TCP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Detecting Hidden Notified Routines**
  * `volatility -f <memory_dump> --profile=<profile> notifys`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Detecting Hidden Objects**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Detecting Hidden Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Detecting Hidden TCP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Detecting Hidden IRPs**
  * `volatility -f <memory_dump> --profile=<profile> irp`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Detecting Hidden TCP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Detecting Hidden Notified Routines**
  * `volatility -f <memory_dump> --profile=<profile> notifys`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Detecting Hidden Objects**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Detecting Hidden Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Detecting Hidden TCP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Detecting Hidden IRPs**
  * `volatility -f <memory_dump> --profile=<profile> irp`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Detecting Hidden TCP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden UDP Ports**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Detecting Hidden Notified Routines**
  * `volatility -f <memory_dump> --profile=<profile> notifys`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden Services**
  * \`volatility -f \<memory\_dump> --profile=\<profile

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

```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```

### Volatility Cheat Sheet

#### Basic Commands

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping Registry Hives**
  * `voljson -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Extracting Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

#### Advanced Commands

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Analyzing Process Memory**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
* **Identifying Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Analyzing Kernel Modules**
  * `volatility -f <memory_dump> --profile=<profile> modscan`
* **Identifying Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Analyzing Timelining**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Analyzing Packed Binaries**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Registry Transactions**
  * `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`
* **Analyzing User Assist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Shellbags**
  * `volatility -f <memory_dump> --profile=<profile> shellbags`
* **Analyzing TrueCrypt Keys**
  * `volatility -f <memory_dump> --profile=<profile> truecryptmaster`
* **Analyzing LUKS Keys**
  * `volatility -f <memory_dump> --profile=<profile> luksmeta`
* **Analyzing Bitlocker Keys**
  * `volatility -f <memory_dump> --profile=<profile> bitlocker`
* **Analyzing Chrome Extensions**
  * `volatility -f <memory_dump> --profile=<profile> chromehistory`
* **Analyzing Firefox Extensions**
  * `volatility -f <memory_dump> --profile=<profile> firefoxhistory`
* **Analyzing Internet Explorer History**
  * `volatility -f <memory_dump> --profile=<profile> iehistory`
* **Analyzing Outlook Memory**
  * `volatility -f <memory_dump> --profile=<profile> outlook`
* **Analyzing Thunderbird Memory**
  * `volatility -f <memory_dump> --profile=<profile> thunderbird`
* **Analyzing Skype Memory**
  * `volatility -f <memory_dump> --profile=<profile> skype`
* **Analyzing Telegram Memory**
  * `volatility -f <memory_dump> --profile=<profile> telegram`
* **Analyzing Slack Memory**
  * `volatility -f <memory_dump> --profile=<profile> slack`
* **Analyzing Discord Memory**
  * `volatility -f <memory_dump> --profile=<profile> discord`
* **Analyzing Signal Memory**
  * `volatility -f <memory_dump> --profile=<profile> signal`
* **Analyzing WhatsApp Memory**
  * `volatility -f <memory_dump> --profile=<profile> whatsapp`
* **Analyzing Viber Memory**
  * `volatility -f <memory_dump> --profile=<profile> viber`
* **Analyzing Facebook Messenger Memory**
  * `volatility -f <memory_dump> --profile=<profile> facebookmessenger`
* **Analyzing Instagram Memory**
  * `volatility -f <memory_dump> --profile=<profile> instagram`
* **Analyzing Snapchat Memory**
  * `volatility -f <memory_dump> --profile=<profile> snapchat`
* **Analyzing TikTok Memory**
  * `volatility -f <memory_dump> --profile=<profile> tiktok`
* **Analyzing WeChat Memory**
  * `volatility -f <memory_dump> --profile=<profile> wechat`
* **Analyzing Line Memory**
  * `volatility -f <memory_dump> --profile=<profile> line`
* **Analyzing Kik Memory**
  * `volatility -f <memory_dump> --profile=<profile> kik`
* **Analyzing Telegram Memory**
  * `volatility -f <memory_dump> --profile=<profile> telegram`
* **Analyzing Slack Memory**
  * `volatility -f <memory_dump> --profile=<profile> slack`
* **Analyzing Discord Memory**
  * `volatility -f <memory_dump> --profile=<profile> discord`
* **Analyzing Signal Memory**
  * `volatility -f <memory_dump> --profile=<profile> signal`
* **Analyzing WhatsApp Memory**
  * `volatility -f <memory_dump> --profile=<profile> whatsapp`
* **Analyzing Viber Memory**
  * `volatility -f <memory_dump> --profile=<profile> viber`
* **Analyzing Facebook Messenger Memory**
  * `volatility -f <memory_dump> --profile=<profile> facebookmessenger`
* **Analyzing Instagram Memory**
  * `volatility -f <memory_dump> --profile=<profile> instagram`
* **Analyzing Snapchat Memory**
  * `volatility -f <memory_dump> --profile=<profile> snapchat`
* **Analyzing TikTok Memory**
  * `volatility -f <memory_dump> --profile=<profile> tiktok`
* **Analyzing WeChat Memory**
  * `volatility -f <memory_dump> --profile=<profile> wechat`
* **Analyzing Line Memory**
  * `volatility -f <memory_dump> --profile=<profile> line`
* **Analyzing Kik Memory**
  * `volatility -f <memory_dump> --profile=<profile> kik`
* **Analyzing Telegram Memory**
  * `volatility -f <memory_dump> --profile=<profile> telegram`
* **Analyzing Slack Memory**
  * `volatility -f <memory_dump> --profile=<profile> slack`
* **Analyzing Discord Memory**
  * `volatility -f <memory_dump> --profile=<profile> discord`
* **Analyzing Signal Memory**
  * `volatility -f <memory_dump> --profile=<profile> signal`
* **Analyzing WhatsApp Memory**
  * `volatility -f <memory_dump> --profile=<profile> whatsapp`
* **Analyzing Viber Memory**
  * `volatility -f <memory_dump> --profile=<profile> viber`
* **Analyzing Facebook Messenger Memory**
  * `volatility -f <memory_dump> --profile=<profile> facebookmessenger`
* **Analyzing Instagram Memory**
  * `volatility -f <memory_dump> --profile=<profile> instagram`
* **Analyzing Snapchat Memory**
  * `volatility -f <memory_dump> --profile=<profile> snapchat`
* **Analyzing TikTok Memory**
  * `volatility -f <memory_dump> --profile=<profile> tiktok`
* **Analyzing WeChat Memory**
  * `volatility -f <memory_dump> --profile=<profile> wechat`
* **Analyzing Line Memory**
  * `volatility -f <memory_dump> --profile=<profile> line`
* **Analyzing Kik Memory**
  * `volatility -f <memory_dump> --profile=<profile> kik`
* **Analyzing Telegram Memory**
  * `volatility -f <memory_dump> --profile=<profile> telegram`
* **Analyzing Slack Memory**
  * `volatility -f <memory_dump> --profile=<profile> slack`
* **Analyzing Discord Memory**
  * `volatility -f <memory_dump> --profile=<profile> discord`
* **Analyzing Signal Memory**
  * `volatility -f <memory_dump> --profile=<profile> signal`
* **Analyzing WhatsApp Memory**
  * `volatility -f <memory_dump> --profile=<profile> whatsapp`
* **Analyzing Viber Memory**
  * `volatility -f <memory_dump> --profile=<profile> viber`
* **Analyzing Facebook Messenger Memory**
  * `volatility -f <memory_dump> --profile=<profile> facebookmessenger`
* **Analyzing Instagram Memory**
  * `volatility -f <memory_dump> --profile=<profile> instagram`
* **Analyzing Snapchat Memory**
  * `volatility -f <memory_dump> --profile=<profile> snapchat`
* **Analyzing TikTok Memory**
  * `volatility -f <memory_dump> --profile=<profile> tiktok`
* **Analyzing WeChat Memory**
  * `volatility -f <memory_dump> --profile=<profile> wechat`
* **Analyzing Line Memory**
  * `volatility -f <memory_dump> --profile=<profile> line`
* **Analyzing Kik Memory**
  * `volatility -f <memory_dump> --profile=<profile> kik`
* **Analyzing Telegram Memory**
  * `volatility -f <memory_dump> --profile=<profile> telegram`
* **Analyzing Slack Memory**
  * `volatility -f <memory_dump> --profile=<profile> slack`
* **Analyzing Discord Memory**
  * `volatility -f <memory_dump> --profile=<profile> discord`
* **Analyzing Signal Memory**
  * `volatility -f <memory_dump> --profile=<profile> signal`
* **Analyzing WhatsApp Memory**
  * `volatility -f <memory_dump> --profile=<profile> whatsapp`
* **Analyzing Viber Memory**
  * `volatility -f <memory_dump> --profile=<profile> viber`
* **Analyzing Facebook Messenger Memory**
  * `volatility -f <memory_dump> --profile=<profile> facebookmessenger`
* **Analyzing Instagram Memory**
  * `volatility -f <memory_dump> --profile=<profile> instagram`
* **Analyzing Snapchat Memory**
  * `volatility -f <memory_dump> --profile=<profile> snapchat`
* **Analyzing TikTok Memory**
  * `volatility -f <memory_dump> --profile=<profile> tiktok`
* **Analyzing WeChat Memory**
  * `volatility -f <memory_dump> --profile=<profile> wechat`
* **Analyzing Line Memory**
  * `volatility -f <memory_dump> --profile=<profile> line`
* **Analyzing Kik Memory**
  * `volatility -f <memory_dump> --profile=<profile> kik`

```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```

### 获取数值

```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```

### Volatility Cheatsheet

#### Basic Commands

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing DLLs**
  * `voljson -f <memory_dump> --profile=<profile> dlllist`
* **Dumping a DLL**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Listing Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Registry Analysis**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping Registry Hive**
  * `volvolatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **File Extraction**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Dumping a File** json -f \<memory\_dump> --profile= dumpfiles -Q \<physical\_offset> -D \<output\_directory>\`
* **Kernel Driver Analysis**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Dumping Kernel Driver**
  * `volatility -f <memory_dump> --profile=<profile> moddump -o <offset> -D <output_directory>`
* **Process Tree**
  * `volatility -f <memory_dump> --profile=<profile> pstree`
* **Command History**
  * `volatility -f <memory_dump> --profile=<profile> cmdscan`
* **User Accounts**
  * `volatility -f <memory_dump> --profile=<profile> useraccounts`
* **Dumping SAM**
  * `volatility -f <memory_dump> --profile=<profile> hashdump -y <offset>`
* **Crash Dump Analysis**
  * `volatility -f <memory_dump> --profile=<profile> memmap`

#### Advanced Commands

* **Rootkit Detection**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Detecting Hidden DLLs**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Detecting Hidden Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockets`
* **Detecting Hidden Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Detecting Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivescan`
* **Detecting Hidden Drivers**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Detecting Hidden Objects**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Detecting Hidden IRPs**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Detecting Hidden TCP/IP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> tcpip`
* **Detecting Hidden Token Objects**
  * `volatility -f <memory_dump> --profile=<profile> tokens`
* **Detecting Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Detecting Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Detecting Hidden SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Detecting Hidden IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irpfind`
* **Detecting Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* \*\*Detecting

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

```bash
#See vol2
```

## Volatility Cheat Sheet

### Basic Commands

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing DLLs**
  * `voljson -f <memory_dump> --profile=<profile> dlllist`
* **Dumping a DLL**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Listing Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Registry Analysis**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Command History**
  * `volatility -f <memory_dump> --profile=<profile> cmdscan`
* **User Accounts**
  * `voljson -f <memory_dump> --profile=<profile> useraccounts`
* **Dumping a File** json
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

### Advanced Commands

* **Process Tree**
  * `volatility -f <memory_dump> --profile=<profile> pstree`
* **Kernel Drivers** json
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Detecting Hidden Modules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Detecting Rootkits**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Timelime**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Extracting Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`
* **Dumping Registry Hives**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Network Packets**
  * `volatility -f <memory_dump> --profile=<profile> netscan`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Registry Handles**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Analyzing TCP Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Analyzing User Sessions**
  * `volatility -f <memory_dump> --profile=<profile> sessions`
* **Analyzing Windows**
  * `volatility -f <memory_dump> --profile=<profile> windows`
* **Analyzing WMI**
  * `volatility -f <memory_dump> --profile=<profile> wmiscan`
* **Analyzing Yara Rules**
  * `volatility -f <memory_dump> --profile=<profile> yarascan`
* **Analyzing Zipped Files**
  * `volatility -f <memory_dump> --profile=<profile> zipscan`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volvolatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`
* **Analyzing Suspicious Files**
  * `volatility -f <memory_dump> --profile=<profile> malfile`
* **Analyzing Suspicious Processes**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Suspicious Drivers**
  * `volatility -f <memory_dump> --profile=<profile> malsysdrivers`
* **Analyzing Suspicious Modules**
  * `volatility -f <memory_dump> --profile=<profile> malsysmodules`
* **Analyzing Suspicious Services**
  * `volatility -f <memory_dump> --profile=<profile> malsvcs`
* **Analyzing Suspicious Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> malreg`
* **Analyzing Suspicious Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> malnet`

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
#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `voljson -f <memory_dump> --profile=<profile> netscan`
* **Dumping a File**
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

**Advanced Commands**

* **Analyzing Registry**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Kernel Modules**
  * `volatility -f <memory_dump> --profile=<profile> modscan`
  * `volatility -f <memory_dump> --profile=<profile> moddump -o <offset> -D <output_directory>`
* **Analyzing Drivers**
  * `volatility -f <memory_dump> --profile=<profile> drvscan`
* **Analyating Packed Binaries**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Analyzing Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Timelining**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handle`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Analyzing Process Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Pools**
  * `voljson -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process Dump**
  * `volatility -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`

```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```

#### 主文件表

```bash
# I couldn't find any plugin to extract this information in volatility3
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `voljson -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping Registry Hives**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping a Registry Hive**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Extracting Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan --dump-dir=<output_directory>`
* **Analyzing DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Drivers**
  * `voljson -f <memory_dump> --profile=<profile> drvmap`
* **Analyzing Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Analyzing PSScan**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing LDRModules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing CSRSS**
  * `volatility -f <memory_dump> --profile=<profile> csrss`
* **Analyzing Print Spooler**
  * `volatility -f <memory_dump> --profile=<profile> printkey`
* **Analyzing User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyizing User Sessions**
  * `volatility -f <memory_dump> --profile=<profile> users`
* **Analyzing Privileges**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Analyzing Driver Modules**
  * `volatility -f <memory_dump> --profile=<profile> modules`
* **Analyzing SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing IDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irp`
* **Analyzing Hidden Modules**
  * `volatility -f <memory_dump> --profile=<profile> modscan`
* **Analyzing Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Analyzing Hidden Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads`
* **Analyzing Hidden Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Hidden Ports**
  * `volatility -f <memory_dump> --profile=<profile> port`
* **Analyzing Hidden Devices**
  * `volatility -f <memory_dump> --profile=<profile> devicetree`
* **Analyzing Hidden Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Analyzing Hidden Timers**
  * `volatility -f <memory_dump> --profile=<profile> timers`
* **Analyzing Hidden Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Hidden Notepad**
  * `volatility -f <memory_dump> --profile=<profile> notepad`
* **Analyzing Hidden Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Analyzing Hidden Registry Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey`
* **Analyzing Hidden Registry Data**
  * `volatility -f <memory_dump> --profile=<profile> hivedump`
* **Analyzing Hidden Registry Handles**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Hidden Registry RecentFileCache**
  * `volatility -f <memory_dump> --profile=<profile> recentfilecache`
* **Analyzing Hidden Registry AppCompatCache**
  * `volatility -f <memory_dump> --profile=<profile> appcompatcache`
* **Analyzing Hidden Registry Amcache**
  * `volatility -f <memory_dump> --profile=<profile> amcache`
* **Analyzing Hidden Registry BAM**
  * `volatility -f <memory_dump> --profile=<profile> bam`
* **Analyzing Hidden Registry UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing Hidden Registry ShimCache**
  * \`volatility -

```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```

**NTFS文件系统**使用一个关键组件，称为\_主文件表\_（MFT）。该表至少包含卷上每个文件的一个条目，也包括MFT本身。关于每个文件的重要细节，如**大小、时间戳、权限和实际数据**，都封装在MFT条目中或在MFT外部但由这些条目引用的区域中。更多详细信息可以在[官方文档](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)中找到。

#### SSL密钥/证书

```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `voljson -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping Registry Hives**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping a Registry Hive** json
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Extracting Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
  * `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

**Advanced Commands**

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Identifying Kernel Modules**
  * `voljson -f <memory_dump> --profile=<profile> modscan`
* **Analyzing Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Analyzing SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Timelining**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Analyzing PSScan**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing LDRModules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vadtree`
* **Analyzing DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockets`
* **Analyzing Privileges**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Analyzing Crashes**
  * `volatility -f <memory_dump> --profile=<profile> crashinfo`
* **Analyzing Yara Rules**
  * `volatility -f <memory_dump> --profile=<profile> yarascan`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing User Sessions**
  * `volatility -f <memory_dump> --profile=<profile> users`
* **Analyzing Registry Handles**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Analyzing Registry Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyjsoning Registry Keys**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Binaries**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Values**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Data**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Lists**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Timelining**
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Analyzing Registry Key Usage**
  * \`volatility -

```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```

### 恶意软件

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

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing DLLs**
  * `voljson -f <memory_dump> --profile=<profile> dlllist`
* **Dumping a DLL**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Listing Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Registry Analysis**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping Registry Hive**
  * `voljson -f <memory_dump> --profile=<profile> printkey -o <output_directory>`
* **File Analysis**
  * `volatility -f <memory_dump> --profile=<profile> filescan`
* **Dumping a File** json -f \<memory\_dump> --profile= dumpfiles -Q \<address\_range> -D \<output\_directory>\`
* **Kernel Modules**
  * `volatility -f <memory_dump> --profile=<profile> modscan`
* **Dumping a Kernel Module**
  * `volatility -f <memory_dump> --profile=<profile> moddump -p <pid> -D <output_directory>`
* **Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Command History**
  * `volatility -f <memory_dump> --profile=<profile> cmdscan`
* **User Accounts**
  * `volatility -f <memory_dump> --profile=<profile> useraccounts`
* **Screenshots**
  * `volatility -f <memory_dump> --profile=<profile> screenshot -D <output_directory>`
* **Yara Scanning**
  * `volatility -f <memory_dump> --profile=<profile> yarascan --yara-file=<rules_file>`
* **API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Detecting Hidden Drivers** json -f \<memory\_dump> --profile= ldrmodules\`
* **Detecting Hidden DLLs**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Detecting Hidden TCP/UDP Ports**
  * `volatility -f <memory_dump> --profile=<profile> portscan`
* **Detecting Rootkits**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Injection**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Modules**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Strings**
  * `volatility -f <memory_dump> --profile=<profile> strings`
* **Detecting In-Memory Code**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Rootkits**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Hooks**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Mutexes**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Processes**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Services**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Timers**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Windows**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Handles**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory IRPs**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Imports**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Unload**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Start**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Sections**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Registry**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver IRPs**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Handles**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Functions**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Objects**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Stacks**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Names**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Extensions**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Characteristics**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Flags**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Security**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Policy**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Capabilities**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power State**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Type**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Level**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags2**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags3**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags4**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags5**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags6**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags7**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags8**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags9**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags10**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags11**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags12**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags13**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags14**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags15**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags16**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags17**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags18**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags19**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags20**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags21**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags22**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags23**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags24**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags25**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags26**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags27**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags28**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags29**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags30**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags31**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags32**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags33**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags34**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags35**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags36**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags37**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags38**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags39**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags40**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags41**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags42**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags43**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags44**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags45**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags46**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags47**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags48**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags49**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags50**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags51**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags52**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags53**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags54**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags55**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags56**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags57**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags58**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags59**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags60**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags61**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags62**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags63**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags64**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags65**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags66**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Detecting In-Memory Driver Device Power Shutdown Flags67**
  * \`volatility -f \<memory\_dump> --profile= m

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

#### 使用yara进行扫描

使用此脚本从github下载并合并所有yara恶意软件规则：[https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
创建名为\_**rules**_的目录并执行该脚本。这将创建一个名为_**malware\_rules.yar**\_的文件，其中包含所有恶意软件的yara规则。

```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```

#### Volatility Cheat Sheet

**Basic Forensic Methodology**

1. **Memory Dump Acquisition**
   * **Physical Memory Dump**: `dd if=/dev/mem of=/path/to/image`
   * **Crash Dump**: `copy /y c:\windows\memory.dmp c:\path\to\image`
   * **Hibernation File**: `copy /y c:\hiberfil.sys c:\path\to\image`
2. **Memory Dump Analysis**
   * **Identify Profile**: `volatility -f <dump> imageinfo`
   * **List Processes**: `volatility -f <dump> --profile=<profile> pslist`
   * **Dump Process**: `volatility -f <dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
3. **Network Analysis**
   * **Connections**: `volatility -f <dump> --profile=<profile> connscan`
   * **Sockets**: `volatility -f <dump> --profile=<profile> sockets`
   * **HTTP Sessions**: `volatility -f <dump> --profile=<profile> volatilitfy -f <dump> --profile=<profile> netscan`
4. **File Analysis**
   * **File Listing**: `volatility -f <dump> --profile=<profile> filescan`
   * **Dump File**: `volatility -f <dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`
5. **Registry Analysis**
   * **User Listing**: `volatility -f <dump> --profile=<profile> hivelist`
   * **Dump Registry Hive**: `voljson -f <dump> --profile=<profile> printkey -o <output_directory> -K <registry_key>`
6. **Malware Analysis**
   * **Detect Hidden Processes**: `volatility -f <dump> --profile=<profile> psxview` json
   * **Detect Hidden Modules**: `volatility -f <dump> --profile=<profile> ldrmodules`
7. **Timeline Analysis**
   * **Show Timelines**: `volatility -f <dump> --profile=<profile> timeliner`
   * **Analyze Timelines**: `volatility -f <dump> --profile=<profile> mactime`
8. **Other Useful Commands**
   * **API Hooks**: `volatility -f <dump> --profile=<profile> apihooks`
   * **Driver Modules**: `volatility -f <dump> --profile=<profile> modules`
   * **SSDT Hooks**: `volatility -f <dump> --profile=<profile> ssdt`

```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```

### 其他

#### 外部插件

如果要使用外部插件，请确保与插件相关的文件夹是第一个参数使用的内容。

```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```

#### Volatility Cheat Sheet

**Basic Memory Analysis**

* **List processes:** `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dump a process:** `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **List loaded drivers:** `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **List open network connections:** `volatility -f <memory_dump> --profile=<profile> connections`
* **Recover deleted files:** `volatility -f <memory_dump> --profile=<profile> filescan`

**Malware Analysis**

* **Detect rootkits:** `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Identify injected code:** `voljson -f <memory_dump> --profile=<profile> malfind`

**User Analysis**

* **List user accounts:** `volatility -f <memory_dump> --profile=<profile> useraccounts`
* **Retrieve user passwords:** `volatility -f <memory_dump> --profile=<profile> hashdump`

**Network Analysis**

* **Analyze network packets:** `volatility -f <memory_dump> --profile=<profile> netscan`

**Timeline Analysis**

* **Create a timeline of events:** `volatility -f <memory_dump> --profile=<profile> timeliner`

**Plugin Development**

* **Develop custom plugins:** [Volatility Plugin Development](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage#developing-plugins)

**Memory Forensics Resources**

* **Official Volatility Documentation:** [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
* **Memory Forensics Cheat Sheet:** [Memory Forensics Cheat Sheet](https://github.com/sans-dfir/sift-cheatsheet/blob/master/cheatsheets/Volatility\_Cheat\_Sheet.pdf)

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

```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping a File**
  * `volmemory_dump> --profile=<profile> file -S <start_address> -E <end_address> -D <output_directory>`
* **Registry Analysis**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

**Advanced Commands**

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Identifying Hidden Modules**
  * `voljson --output=json`
* **Analyzing Kernel Modules**
  * `volatility -f <memory_dump> --profile=<profile> modscan`
* **Extracting Kernel Drivers**
  * `volatility -f <memory_dump> --profile=<profile> moddump -D <output_directory>`
* **Analyzing Timelining Information**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Analyzing Suspicious Binaries**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyizing Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Process Environment Variables**
  * `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
* **Analyzing Process Memory Map**
  * `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```

### 符号链接

```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `voljson -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping Registry Hives**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
* **Dumping a Registry Hive** json
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Extracting Files**
  * `volatility -f <memory_dump> --profile=<profile> filescan | grep -i <file_extension>`
* **Dumping LSA Secrets**
  * `volatility -f <memory_dump> --profile=<profile> lsadump`
* **Dumping SAM**
  * `volatility -f <memory_dump> --profile=<profile> hashdump`
* **Dumping Cached Credentials**
  * `volatility -f <memory_dump> --profile=<profile> cachedump`
* **Analyzing ShimCache**
  * `volatility -f <memory_dump> --profile=<profile> shimcache`
* **Analyzing Shellbags**
  * `volatility -f <memory_dump> --profile=<profile> shellbags`
* **Analyzing UserAssist**
  * `volatility -f <memory_dump> --profile=<profile> userassist`
* **Analyzing MFT**
  * `volatility -f <memory_dump> --profile=<profile> mftparser`
* **Analyzing PSScan**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Malware**
  * `volatility -f <memory_dump> --profile=<profile> malsysproc`
* **Analyzing Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Analyzing Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockets`
* **Analyzing Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Analyzing Timeliner**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyizing SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing CSRSS**
  * `volatility -f <memory_dump> --profile=<profile> csrss`
* **Analyzing Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Yara Rules**
  * `volatility -f <memory_dump> --profile=<profile> yarascan`
* **Analyzing API Audit**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> callbacks`
* **Analyzing SSDT Hooks**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing IRP Hooks**
  * `volatility -f <memory_dump> --profile=<profile> irp`
* **Analyizing Scanning Modules**
  * `volatility -f <memory_dump> --profile=<profile> modscan`
* **Analyzing Kernel Modules**
  * `volvolatility -f <memory_dump> --profile=<profile> moddump -D <output_directory>`
* **Analyzing Kernel Drivers**
  * `volatility -f <memory_dump> --profile=<profile> kdbgscan`
* **Analyizing Kernel Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Callbacks**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Handles**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Objects**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver Modules**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver Sections**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver Imports**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver Exports**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver Pools**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver Allocations**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyizing Kernel Driver Unloads**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver Timers**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Handlers**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Callers**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Devices**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Queues**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Pending**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Completed**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Canceled**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Read**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Write**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Device Control**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyizing Kernel Driver IRP Close**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Cleanup**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Create**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Information**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Set Information**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query EA**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyizing Kernel Driver IRP Set EA**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Flush**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Volume Information**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Set Volume Information**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Directory Control**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP File System Control**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Device Control**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Internal Device Control**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Shutdown**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Lock Control**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Cleanup**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Create Mailslot**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Security**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Set Security**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Power**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP System Control**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Device Change**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Quota**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Set Quota**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Device Relations**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Interface**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query PNP Device State**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Bus Information**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Device Text**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query ID**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Device Relations**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Resources**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Resource Requirements**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Legacy Bus Information**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Device Usage Notification**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Surprise Removal**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Query Power**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Set Power**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Others**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Unknown**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyizing Kernel Driver IRP Min**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max Unknown**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min Unknown**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max Others**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min Others**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max Power**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min Power**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max Set Power**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min Set Power**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max Query Power**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min Query Power**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Min WMI**
  * `volatility -f <memory_dump> --profile=<profile> poolscanner`
* **Analyzing Kernel Driver IRP Max WMI**
  * \`

```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```

#### Bash

可以**从内存中读取bash历史记录**。您也可以转储.bash\_history文件，但如果它被禁用，您会很高兴能够使用这个volatility模块

```
./vol.py -f file.dmp linux.bash.Bash
```

#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping Registry Hives**
  * `voljson -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

**Advanced Commands**

* **Analyzing Malware**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Extracting DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`
* **Analyzing Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Identifying Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockets`
* **Analyzing Timelining**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`

**Plugin Resources**

* **Official Volatility Plugins**
  * [https://github.com/volatilityfoundation/volatility/wiki/Plugins](https://github.com/volatilityfoundation/volatility/wiki/Plugins)
* **Volatility Plugin List**
  * [https://github.com/superponible/volatility\_plugins](https://github.com/superponible/volatility\_plugins)
* **Volatility Plugin Development**
  * [https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage)

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
#### Volatility Cheat Sheet

**Basic Commands**

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping a File**
  * `volvality -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

**Advanced Commands**

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Analyzing Registry**
  * `volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`
* **Extracting Registry Hives**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Identifying Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockets`
* **Analyzing Drivers**
  * `voljson -f <memory_dump> --profile=<profile>`
* **Analyzing Packed Binaries**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analylining Malicious DLL Injections**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Timelining**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Analyzing Process Memory**
  * `volatility -f <memory_dump> --profile=<profile> memmap`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyzing Process PEB**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Process Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads`
* **Analyzing Process Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Process Vad**
  * `volatility -f <memory_dump> --profile=<profile> vadinfo`
* **Analyzing Process GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Process LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing Process IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDI Table**
  * `volatility -f <memory_dump> --profile=<profile> gdit`
* **Analyzing Process User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Process Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Process Driverirp**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Analyzing Process Devicetree**
  * `volatility -f <memory_dump> --profile=<profile> devicetree`
* **Analyzing Process Drivermodule**
  * `volatility -f <memory_dump> --profile=<profile> drivermodule`
* **Analyzing Process Driverobject**
  * `volatility -f <memory_dump> --profile=<profile> driverobject`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Process LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing Process IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDI Table**
  * `volatility -f <memory_dump> --profile=<profile> gdit`
* **Analyizing Process User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Process Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Process Driverirp**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Analyzing Process Devicetree**
  * `volatility -f <memory_dump> --profile=<profile> devicetree`
* **Analyzing Process Drivermodule**
  * `volatility -f <memory_dump> --profile=<profile> drivermodule`
* **Analyzing Process Driverobject**
  * `volatility -f <memory_dump> --profile=<profile> driverobject`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Process LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing Process IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDI Table**
  * `volatility -f <memory_dump> --profile=<profile> gdit`
* **Analyzing Process User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Process Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Process Driverirp**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Analyzing Process Devicetree**
  * `volatility -f <memory_dump> --profile=<profile> devicetree`
* **Analyzing Process Drivermodule**
  * `volatility -f <memory_dump> --profile=<profile> drivermodule`
* **Analyzing Process Driverobject**
  * `volatility -f <memory_dump> --profile=<profile> driverobject`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Process LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing Process IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDI Table**
  * `volatility -f <memory_dump> --profile=<profile> gdit`
* **Analyzing Process User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Process Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Process Driverirp**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Analyzing Process Devicetree**
  * `volatility -f <memory_dump> --profile=<profile> devicetree`
* **Analyzing Process Drivermodule**
  * `volatility -f <memory_dump> --profile=<profile> drivermodule`
* **Analyzing Process Driverobject**
  * `volatility -f <memory_dump> --profile=<profile> driverobject`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Process LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing Process IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDI Table**
  * `volatility -f <memory_dump> --profile=<profile> gdit`
* **Analyzing Process User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Process Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Process Driverirp**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Analyzing Process Devicetree**
  * `volatility -f <memory_dump> --profile=<profile> devicetree`
* **Analyzing Process Drivermodule**
  * `volatility -f <memory_dump> --profile=<profile> drivermodule`
* **Analyzing Process Driverobject**
  * `volatility -f <memory_dump> --profile=<profile> driverobject`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Process LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing Process IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDI Table**
  * `volatility -f <memory_dump> --profile=<profile> gdit`
* **Analyzing Process User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Process Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Process Driverirp**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Analyzing Process Devicetree**
  * `volatility -f <memory_dump> --profile=<profile> devicetree`
* **Analyzing Process Drivermodule**
  * `volatility -f <memory_dump> --profile=<profile> drivermodule`
* **Analyzing Process Driverobject**
  * `volatility -f <memory_dump> --profile=<profile> driverobject`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Process LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing Process IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDI Table**
  * `volatility -f <memory_dump> --profile=<profile> gdit`
* **Analyzing Process User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Process Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Process Driverirp**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Analyzing Process Devicetree**
  * `volatility -f <memory_dump> --profile=<profile> devicetree`
* **Analyzing Process Drivermodule**
  * `volatility -f <memory_dump> --profile=<profile> drivermodule`
* **Analyzing Process Driverobject**
  * `volatility -f <memory_dump> --profile=<profile> driverobject`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Process LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing Process IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDI Table**
  * `volatility -f <memory_dump> --profile=<profile> gdit`
* **Analyzing Process User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Process Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Process Driverirp**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Analyzing Process Devicetree**
  * `volatility -f <memory_dump> --profile=<profile> devicetree`
* **Analyzing Process Drivermodule**
  * `volatility -f <memory_dump> --profile=<profile> drivermodule`
* **Analyzing Process Driverobject**
  * `volatility -f <memory_dump> --profile=<profile> driverobject`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Process LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing Process IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDI Table**
  * `volatility -f <memory_dump> --profile=<profile> gdit`
* **Analyzing Process User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Process Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Process Driverirp**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Analyzing Process Devicetree**
  * `volatility -f <memory_dump> --profile=<profile> devicetree`
* **Analyzing Process Drivermodule**
  * `volatility -f <memory_dump> --profile=<profile> drivermodule`
* **Analyzing Process Driverobject**
  * `volatility -f <memory_dump> --profile=<profile> driverobject`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Process LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing Process IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDI Table**
  * `volatility -f <memory_dump> --profile=<profile> gdit`
* **Analyzing Process User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Process Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Process Driverirp**
  * `volatility -f <memory_dump> --profile=<profile> driverirp`
* **Analyzing Process Devicetree**
  * `volatility -f <memory_dump> --profile=<profile> devicetree`
* **Analyzing Process Drivermodule**
  * `volatility -f <memory_dump> --profile=<profile> drivermodule`
* **Analyzing Process Driverobject**
  * `volatility -f <memory_dump> --profile=<profile> driverobject`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing Process LDT**
  * `volatility -f <memory_dump> --profile=<profile> ldt`
* **Analyzing Process IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing Process SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Process GDI Table**
  * `volatility -f <memory_dump> --profile=<profile> gdit`
* **Analyzing Process User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Process Mutants**
  * \`volatility -f \<memory\_dump> --profile=

```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### 驱动程序

```
./vol.py -f file.dmp windows.driverscan.DriverScan
```

### Volatility Cheat Sheet

#### Basic Commands

* **Image Identification**
  * `volatility -f <memory_dump> imageinfo`
* **Listing Processes**
  * `volatility -f <memory_dump> --profile=<profile> pslist`
* **Dumping a Process**
  * `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
* **Listing Network Connections**
  * `volatility -f <memory_dump> --profile=<profile> connections`
* **Dumping a File**
  * `volvality -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

#### Advanced Commands

* **Detecting Hidden Processes**
  * `volatility -f <memory_dump> --profile=<profile> psxview`
* **Analyzing Registry**
  * `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`
* **Extracting Registry Hives**
  * `volatility -f <memory_dump> --profile=<profile> hivelist`
  * `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`
* **Identifying Sockets**
  * `volatility -f <memory_dump> --profile=<profile> sockscan`
* **Analyzing Kernel Modules**
  * `voljsonity -f <memory_dump> --profile=<profile> modscan`
* **Analyzing Drivers**
  * `volatility -f <memory_dump> --profile=<profile> driverscan`
* **Analyzing SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing Mutants**
  * `volatility -f <memory_dump> --profile=<profile> mutantscan`
* **Analyzing Timeliner**
  * `volatility -f <memory_dump> --profile=<profile> timeliner`
* **Analyzing PSScan**
  * `volatility -f <memory_dump> --profile=<profile> psscan`
* **Analyzing Yara Rules**
  * `volatility -f <memory_dump> --profile=<profile> yarascan`
* **Analyzing API Hooks**
  * `volatility -f <memory_dump> --profile=<profile> apihooks`
* **Analyzing GDT**
  * `volatility -f <memory_dump> --profile=<profile> gdt`
* **Analyzing IDT**
  * `volatility -f <memory_dump> --profile=<profile> idt`
* **Analyzing SSDT**
  * `volatility -f <memory_dump> --profile=<profile> ssdt`
* **Analyzing CSRSS**
  * `volatility -f <memory_dump> --profile=<profile> csrss`
* **Analyzing LDR Modules**
  * `volatility -f <memory_dump> --profile=<profile> ldrmodules`
* **Analyzing Handles**
  * `volatility -f <memory_dump> --profile=<profile> handles`
* **Analyzing Vad Trees**
  * `volatility -f <memory_dump> --profile=<profile> vaddump`
* **Analyzing User Handles**
  * `volatility -f <memory_dump> --profile=<profile> userhandles`
* **Analyzing Privileges**
  * `volatility -f <memory_dump> --profile=<profile> privs`
* **Analyzing DLLs**
  * `volatility -f <memory_dump> --profile=<profile> dlllist`
* **Analyizing Threads**
  * `volatility -f <memory_dump> --profile=<profile> threads`
* **Analyzing GDI Tables**
  * `volatility -f <memory_dump> --profile=<profile> gditimers`
* **Analyzing GDI Objects**
  * `volatility -f <memory_dump> --profile=<profile> gdiobjects`
* **Analyzing Atom Tables**
  * `volatility -f <memory_dump> --profile=<profile> atomscan`
* **Analyzing Desktops**
  * `volatility -f <memory_dump> --profile=<profile> desktops`
* **Analyzing Windows Stations**
  * `volatility -f <memory_dump> --profile=<profile> windows`
* **Analyzing Services**
  * `volatility -f <memory_dump> --profile=<profile> svcscan`
* **Analyzing Netscan**
  * `volatility -f <memory_dump> --profile=<profile> netscan`
* **Analyzing Connections**
  * `volatility -f <memory_dump> --profile=<profile> connscan`
* **Analyzing Malfind**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware**
  * `volatility -f <memory_dump> --profile=<profile> malprocfind`
* **Analyzing Malware Config**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware Yara**
  * `volatility -f <memory_dump> --profile=<profile> yarascan`
* **Analyzing Malware Strings**
  * `volatility -f <memory_dump> --profile=<profile> strings`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * `volatility -f <memory_dump> --profile=<profile> malfind`
* **Analyzing Malware MZ**
  * \`volatility -

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

**主引导记录（MBR）** 在管理存储介质的逻辑分区方面发挥着至关重要的作用，这些分区使用不同的[文件系统](https://en.wikipedia.org/wiki/File\_system)进行结构化。它不仅保存分区布局信息，还包含作为引导加载程序的可执行代码。这个引导加载程序要么直接启动操作系统的第二阶段加载过程（参见[第二阶段引导加载程序](https://en.wikipedia.org/wiki/Second-stage\_boot\_loader)），要么与每个分区的[卷引导记录](https://en.wikipedia.org/wiki/Volume\_boot\_record)（VBR）协同工作。欲了解更多信息，请参阅[MBR 维基百科页面](https://en.wikipedia.org/wiki/Master\_boot\_record)。

## 参考资料

* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流之地。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)\*\* 上关注我们。\*\*
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
