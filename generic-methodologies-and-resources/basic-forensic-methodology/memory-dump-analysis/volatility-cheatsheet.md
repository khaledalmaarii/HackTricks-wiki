# Volatility - 速查表

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
- 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点会议。

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

Volatility有两种主要的插件方法，有时可以从它们的名称中反映出来。“list”插件将尝试浏览Windows内核结构，以检索诸如进程（在内存中定位和遍历`_EPROCESS`结构的链接列表）、操作系统句柄（定位和列出句柄表，取消引用找到的任何指针等）等信息。它们的行为几乎与请求时Windows API的行为相同，例如，列出进程。

这使得“list”插件非常快速，但与Windows API一样容易受到恶意软件的操纵。例如，如果恶意软件使用DKOM从`_EPROCESS`链接列表中取消链接进程，则该进程不会显示在任务管理器中，pslist中也不会显示。

另一方面，“scan”插件将采用类似于在内存中雕刻可能在解除引用为特定结构时有意义的内容的方法。例如，`psscan`将读取内存并尝试从中创建`_EPROCESS`对象（它使用池标签扫描，搜索指示感兴趣结构存在的4字节字符串）。优点是它可以挖掘已退出的进程，即使恶意软件篡改了`_EPROCESS`链接列表，插件仍将在内存中找到该结构（因为该结构仍然需要存在以使进程运行）。缺点是，“scan”插件比“list”插件慢一些，有时可能产生误报（进程已退出太久，其结构的部分被其他操作覆盖）。

来源：[http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## 操作系统配置文件

### Volatility3

如readme中所述，您需要将要支持的**操作系统的符号表**放入_volatility3/volatility/symbols_中。\
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
如果要使用**您已下载的新配置文件**（例如 Linux 配置文件），您需要在某处创建以下文件夹结构：_plugins/overlays/linux_，并将包含配置文件的 zip 文件放入此文件夹中。然后，使用以下命令获取配置文件的编号：
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
#### **imageinfo 与 kdbgscan 的区别**

与仅提供配置文件建议的 imageinfo 不同，**kdbgscan** 旨在积极识别正确的配置文件和正确的 KDBG 地址（如果存在多个）。该插件扫描与 Volatility 配置文件相关联的 KDBGHeader 签名，并应用健全性检查以减少误报。输出的详细程度和可以执行的健全性检查数量取决于 Volatility 是否能够找到 DTB，因此，如果您已经知道正确的配置文件（或者从 imageinfo 获得了配置文件建议），请确保使用它（来自[这里](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)）。

始终查看 **kdbgscan 找到的进程数量**。有时，imageinfo 和 kdbgscan 可能会找到 **多个**适合的 **配置文件**，但只有 **有效的配置文件** 会有一些与进程相关的内容（这是因为提取进程需要正确的 KDBG 地址）。
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

**内核调试器块**（称为\_KDDEBUGGER\_DATA64类型的KdDebuggerDataBlock，或者**KDBG**由Volatility命名）对于Volatility和调试器执行的许多操作非常重要。例如，它具有对PsActiveProcessHead的引用，PsActiveProcessHead是进程列表所需的所有进程的列表头。 

## 操作系统信息
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
插件`banners.Banners`可用于在转储文件中尝试查找Linux横幅。

## Hashes/密码

提取SAM哈希值，[域缓存凭据](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials)和[lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets)。
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
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
  - `voljsonity -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Hive**
 json  - `volatility -f <memory_dump> --profile=<profile> hivedump -o <offset> -D <output_directory>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyifying Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing VADs**
  - `volatility -f <memory_dump> --profile=<profile> vaddump -D <output_directory>`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Trace**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Monitor**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Filter**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Syscalls**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Notifiers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Filter Drivers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Inline IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Type Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Notifiers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Filter Drivers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object IRP Hooks**
  - `volvolatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Inline IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Type Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Notifiers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Filter Drivers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Inline IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Type Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Notifiers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Filter Drivers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Inline IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Type Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Notifiers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Filter Drivers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Inline IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object Type Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object Notifiers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object Filter Drivers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object Inline IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object Object Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object Object Type Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object Object Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object Object Notifiers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object Object Object Filter Drivers**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Object Object Object Object
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

[**RootedCON**](https://www.rootedcon.com/)是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的之一。以**促进技术知识**为使命，这个大会是技术和网络安全专业人士在各个领域的热点聚会。

{% embed url="https://www.rootedcon.com/" %}

## 过程

### 列出进程

尝试查找**可疑**进程（按名称）或**意外**的子**进程**（例如，cmd.exe作为iexplorer.exe的子进程）。\
比较pslist的结果和psscan的结果以识别隐藏进程可能会很有趣。

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
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
  - `volvolatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Hive**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **File Extraction**
  - `volatility -f <memory_dump> --profile=<profile> file -S <start> -E <end> --output=<output_directory>`

- **Process Tree**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **User Listing**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **User Information**
 json
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Screen Shots**
  - `volatility -f <memory_dump> --profile=<profile> screenshot --D <output_directory>`

- **Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **SSDT Hooks**
 json
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Crash Dumps**
  - `volatility -f <memory_dump> --profile=<profile> crashinfo`

- **Yara Scanning**
  - `volatility -f <memory_dump> --profile=<profile> yarascan --yara-rules=<rules_file>`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Detecting Hidden SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Hidden IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> portscan`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddenevents`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Injections**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Suspicious Drivers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Services**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Processes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Threads**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Files**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Timers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Desktops**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Windows Stations**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Services**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Drivers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue IRP Hooks**
  - `volvolatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Threads**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Files**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Timers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Desktops**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Windows Stations**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Services**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Threads**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Files**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Timers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Desktops**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Windows Stations**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Services**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Threads**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Files**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Timers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Desktops**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Windows Stations**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Services**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Threads**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Files**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Timers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Desktops**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Windows Stations**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Services**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Threads**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Files**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Timers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Desktops**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Windows Stations**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Services**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Threads**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Files**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Timers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Desktops**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Windows Stations**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Services**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Threads**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Files**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rogue Kernel Registry Keys
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
 json
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> dumpregistry -o <offset> -D <output_directory>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyizing Malware Artifacts**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volvolatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyizing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Process Mitigations**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process PEB**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Process Tokens**
  - `volatility -f <memory_dump>
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
  - `volmemory -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Kernel Modules**
  - `voljson -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> dumpregistry -o <offset> -D <output_directory>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Suspicious Processes**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing User Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> usermodehooks`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyizing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> crashinfo`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing TCP Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing UDP Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan --scan_type=udp`

- **Analyzing Malware Artifacts**
  - `volatility -f <memory_dump> --profile=<profile> malprocfind`

- **Analyzing Malware Processes**
  - `volatility -f <memory_dump> --profile=<profile> malprocfind`

- **Analyzing Malware Threads**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malware Handles**
  - `volatility -f <memory_dump> --profile=<profile> malhandle`

- **Analyzing Malware Modules**
  - `volatility -f <memory_dump> --profile=<profile> malmod`

- **Analyzing Malware Drivers**
  - `volatility -f <memory_dump> --profile=<profile> malsysmods`

- **Analyzing Malware Services**
  - `volatility -f <memory_dump> --profile=<profile> malsrv`

- **Analyzing Malware Registry**
  - `volatility -f <memory_dump> --profile=<profile> malreg`

- **Analyzing Malware Files**
  - `volatility -f <memory_dump> --profile=<profile> malfile`

- **Analyzing Malware Network**
  - `volatility -f <memory_dump> --profile=<profile> malnet`

- **Analyzing Malware Config**
  - `volatility -f <memory_dump> --profile=<profile> malconf`

- **Analyzing Malware Persistence**
  - `volatility -f <memory_dump> --profile=<profile> malpersistence`

- **Analyzing Malware Injection**
  - `volatility -f <memory_dump> --profile=<profile> malinject`

- **Analyzing Malware Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malrootkit`

- **Analyzing Malware Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malhooks`

- **Analyzing Malware Heaps**
  - `volatility -f <memory_dump> --profile=<profile> malheap`

- **Analyzing Malware Handles**
  - `volatility -f <memory_dump> --profile=<profile> malhandle`

- **Analyzing Malware Timers**
  - `volatility -f <memory_dump> --profile=<profile> maltimer`

- **Analyzing Malware Desktops**
  - `volatility -f <memory_dump> --profile=<profile> maldesktop`

- **Analyzing Malware Windows**
  - `volatility -f <memory_dump> --profile=<profile> malwindows`

- **Analyzing Malware Services**
  - `volatility -f <memory_dump> --profile=<profile> malsrv`

- **Analyzing Malware Registry**
  - `volatility -f <memory_dump> --profile=<profile> malreg`

- **Analyizing Malware Crashes**
  - `volatility -f <memory_dump> --profile=<profile> malcrash`

- **Analyzing Malware DLLs**
  - `volatility -f <memory_dump> --profile=<profile> maldlllist`

- **Analyzing Malware Sockets**
  - `volatility -f <memory_dump> --profile=<profile> malsockets`

- **Analyzing Malware TCP Connections**
  - `volatility -f <memory_dump> --profile=<profile> malconnscan`

- **Analyzing Malware UDP Connections**
  - `volatility -f <memory_dump> --profile=<profile> malconnscan --scan_type=udp`

- **Analyzing Malware Plugins**
  - `volatility -f <memory_dump> --profile=<profile> malplugins`

- **Analyzing Malware Config**
  - `volatility -f <memory_dump> --profile=<profile> malconf`

- **Analyzing Malware Persistence**
  - `volatility -f <memory_dump> --profile=<profile> malpersistence`

- **Analyzing Malware Injection**
  - `volatility -f <memory_dump> --profile=<profile> malinject`

- **Analyzing Malware Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malrootkit`

- **Analyzing Malware Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malhooks`

- **Analyzing Malware Heaps**
  - `volatility -f <memory_dump> --profile=<profile> malheap`

- **Analyzing Malware Handles**
  - `volatility -f <memory_dump> --profile=<profile> malhandle`

- **Analyzing Malware Timers**
  - `volatility -f <memory_dump> --profile=<profile> maltimer`

- **Analyzing Malware Desktops**
  - `volatility -f <memory_dump> --profile=<profile> maldesktop`

- **Analyzing Malware Windows**
  - `volatility -f <memory_dump> --profile=<profile> malwindows`

- **Analyzing Malware Services**
  - `volatility -f <memory_dump> --profile=<profile> malsrv`

- **Analyzing Malware Registry**
  - `volatility -f <memory_dump> --profile=<profile> malreg`

- **Analyzing Malware Crashes**
  - `volatility -f <memory_dump> --profile=<profile> malcrash`

- **Analyzing Malware DLLs**
  - `volatility -f <memory_dump> --profile=<profile> maldlllist`

- **Analyzing Malware Sockets**
  - `volatility -f <memory_dump> --profile=<profile> malsockets`

- **Analyzing Malware TCP Connections**
  - `volatility -f <memory_dump> --profile=<profile> malconnscan`

- **Analyzing Malware UDP Connections**
  - `volatility -f <memory_dump> --profile=<profile> malconnscan --scan_type=udp` 

{% endtab %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

在cmd.exe中输入的命令由**conhost.exe**处理（在Windows 7之前为csrss.exe）。因此，即使攻击者设法在我们获取内存**转储**之前**终止cmd.exe**，仍有很大机会从**conhost.exe的内存**中**恢复**命令行会话的历史记录。如果发现**异常情况**（使用控制台的模块），请尝试**转储**与**conhost.exe相关**的进程的**内存**，并在其中搜索**字符串**以提取命令行。

### 环境

获取每个运行进程的环境变量。可能会有一些有趣的值。
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
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
   - **List Processes**: `volatility -f /path/to/image --profile=ProfileName pslist`
   - **Dump Process**: `volatility -f /path/to/image --profile=ProfileName memdump -p PID -D /path/to/dump`

3. **Network Analysis**
   - **Connections**: `volatility -f /path/to/image --profile=ProfileName connections`
  json
   - **Sockets**: `volatility -f /path/to/image --profile=ProfileName sockets`

4. **File Analysis**
   - **File Extraction**: `volatility -f /path/to/image --profile=ProfileName file -S StartAddress -E EndAddress --output-dir=/path/to/dumpdir`

5. **Registry Analysis**
   - **User Listing**: `voljson -f /path/to/image --profile=ProfileName userassist`
   - **Hash Dump**: `volatility -f /path/to/image --profile=ProfileName hashdump`

6. **Malware Analysis**
   - **Malware Detection**: `volatility -f /path/to/image --profile=ProfileName malfind`
   - **Yara Scan**: `volatility -f /path/to/image --profile=ProfileName yarascan --yara-file=/path/to/rules.yara`

7. **Timeline Analysis**
   - **Timeliner Plugin**: `volatility -f /path/to/image --profile=ProfileName timeliner`

8. **Other Plugins**
   - **Plugin Listing**: `volatility --info | grep -i plugin`

#### Advanced Forensic Methodology

1. **Rootkit Detection**
   - **Hidden Processes**: `volatility -f /path/to/image --profile=ProfileName psxview`
   - **Hidden Modules**: `volatility -f /path/to/image --profile=ProfileName ldrmodules`

2. **Anti-Forensics Detection**
   - **Detecting Anti-Forensics**: `volatility -f /path/to/image --profile=ProfileName checkaf`

3. **Memory Integrity Checking**
   - **Checking Memory Integrity**: `volatility -f /path/to/image --profile=ProfileName memmap`

4. **Automated Analysis**
   - **Automated Malware Analysis**: `volatility -f /path/to/image --profile=ProfileName malsysproc`

5. **Memory Forensics Challenges**
   - **Practice Challenges**: [Memory Forensics Challenges](https://github.com/volatilityfoundation/volatility/wiki/Memory-Forensics-Challenges)

{% endtab %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### 令牌权限

检查意外服务中的权限令牌。\
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
  - `voljson -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Dumping a DLL**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Dumping Registry Hive**
 json
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **File Extraction**
  - `volatility -f <memory_dump> --profile=<profile> filescan`
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

- **Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Driver Modules**
 json
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **User Accounts**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Process Environment**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **Crash Dump Analysis**
 json
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Yara Scanning**
  - `volatility -f <memory_dump> --profile=<profile> yarascan --yara-file=<rules_file>`

- **API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Objects**
  - `voljson -f <memory_dump> --profile=<profile> hiddenevents`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Executables**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Injection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Modules**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Strings**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory PE Files**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Processes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory TCP Connections**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory UDP Connections**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory HTTP Connections**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory HTTPS Connections**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory DNS Connections**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Named Pipes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Windows**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Services**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Drivers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Shadow SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Code Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Object Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver MiniFilter Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Filter Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Desktop Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Keyboard Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Mouse Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Timer Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Winlogon Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Service Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Image Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Registry Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver File Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Network Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Process Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Thread Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Desktop Switch Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver File System Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Kernel Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver User Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver Kernel Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Call Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Service Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Object Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Registry Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System File Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Network Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Process Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Thread Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Desktop Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Keyboard Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Mouse Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Timer Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Winlogon Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Service Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Image Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Registry Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System File Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Network Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Process Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Thread Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Desktop Switch Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System File System Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Kernel Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System User Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System Kernel Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Call Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Service Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Object Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Registry Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System File Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Network Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Process Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Thread Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Desktop Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Keyboard Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Mouse Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Timer Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Winlogon Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Service Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Image Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Registry Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System File Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Network Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Process Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Thread Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Desktop Switch Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System File System Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Kernel Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System User Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System Kernel Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System System Call Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System System Service Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System System Object Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System System Registry Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System System File Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System System Network Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System System Process Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System System Thread Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System System Desktop Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Driver System System System Keyboard Hooks**
  - `volatility -f <memory_dump>
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

- **Dumping Registry Hives**
  - `voljson -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Identifying Hidden Processes**
 json
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Extracting DLLs from a Process**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying IRP Hooks**
  - `voljson -f <memory_dump> --profile=<profile> irp`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Identifying API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Analyzing Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Identifying API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyizing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Analyzing Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyifying GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Analyzing Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Analyzing Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Analyzing Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Analyzing Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Analyzing Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Analyzing Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Analyzing Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Analyzing Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile
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
  - `voljson -f <memory_dump> --profile=<profile> netscan`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Identifying Hidden Processes**
  - `voljson -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
     - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Extracting Cached Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Network Packets**
  - `volatility -f <memory_dump> --profile=<profile> tcpconn`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing File Handles**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Extracting Files**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

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

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyating Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyizing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing Connections**
  - `volatility -f <memory_dump> --profile=<profile> connscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Sessions**
  - `volvolatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Objects**
  - `volatility -f <memory_dump> --profile=<profile> userobjects`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Yara**
  - `volatility -
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
### DLLs

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

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Mutantscan**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing MBR**
  - `volatility -f <memory_dump> --profile=<profile> mbrparser`

- **Analyzing MFT**
  - `volatility -f <memory_dump> --profile=<profile> mftparser`

- **Analyzing Shellbags**
  - `volatility -f <memory_dump> --profile=<profile> shellbags`

- **Analyzing TrueCrypt**
  - `volatility -f <memory_dump> --profile=<profile> truecryptmaster`

- **Analyzing Bitlocker**
  - `volatility -f <memory_dump> --profile=<profile> bitlockermount`

- **Analyzing Printers**
  - `volatility -f <memory_dump> --profile=<profile> printers`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyizing User Sessions**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Profiles**
  - `volatility -f <memory_dump> --profile=<profile> userprofiles`

- **Analyzing User Registry**
  - `voljson -f <memory_dump> --profile=<profile> userregistry`

- **Analyzing User Files**
  - `volatility -f <memory_dump> --profile=<profile> userfiles`

- **Analyzing User Activity**
  - `volatility -f <memory_dump> --profile=<profile> useractivity`

- **Analyzing Consoles**
  - `volatility -f <memory_dump> --profile=<profile> consoles`

- **Analyzing Desktops**
  - `volatility -f <memory_dump> --profile=<profile> desktops`

- **Analyzing Windows**
  - `volatility -f <memory_dump> --profile=<profile> windows`

- **Analyzing IE History**
  - `volatility -f <memory_dump> --profile=<profile> iehistory`

- **Analyzing IE Cache**
  - `volatility -f <memory_dump> --profile=<profile> iecache`

- **Analyzing IE Cookies**
  - `volatility -f <memory_dump> --profile=<profile> iecookies`

- **Analyzing IE Tabs**
  - `volatility -f <memory_dump> --profile=<profile> ietabs`

- **Analyzing IE Downloads**
  - `volatility -f <memory_dump> --profile=<profile> iedownloads`

- **Analyzing IE Form Data**
  - `volatility -f <memory_dump> --profile=<profile> ieforms`

- **Analyzing IE Full URL**
  - `volatility -f <memory_dump> --profile=<profile> iefullurl`

- **Analyzing IE Typed URLs**
  - `volatility -f <memory_dump> --profile=<profile> ietypedurls`

- **Analyzing IE Zones**
  - `volatility -f <memory_dump> --profile=<profile> iezones`

- **Analyzing IE WebCache**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache`

- **Analyzing IE WebCache2**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache2`

- **Analyzing IE WebCache3**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache3`

- **Analyzing IE WebCache4**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache4`

- **Analyzing IE WebCache5**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache5`

- **Analyzing IE WebCache6**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache6`

- **Analyzing IE WebCache7**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache7`

- **Analyzing IE WebCache8**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache8`

- **Analyzing IE WebCache9**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache9`

- **Analyzing IE WebCache10**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache10`

- **Analyzing IE WebCache11**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache11`

- **Analyzing IE WebCache12**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache12`

- **Analyzing IE WebCache13**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache13`

- **Analyzing IE WebCache14**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache14`

- **Analyzing IE WebCache15**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache15`

- **Analyzing IE WebCache16**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache16`

- **Analyzing IE WebCache17**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache17`

- **Analyzing IE WebCache18**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache18`

- **Analyzing IE WebCache19**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache19`

- **Analyzing IE WebCache20**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache20`

- **Analyzing IE WebCache21**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache21`

- **Analyzing IE WebCache22**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache22`

- **Analyzing IE WebCache23**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache23`

- **Analyzing IE WebCache24**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache24`

- **Analyzing IE WebCache25**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache25`

- **Analyzing IE WebCache26**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache26`

- **Analyzing IE WebCache27**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache27`

- **Analyzing IE WebCache28**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache28`

- **Analyzing IE WebCache29**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache29`

- **Analyzing IE WebCache30**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache30`

- **Analyzing IE WebCache31**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache31`

- **Analyzing IE WebCache32**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache32`

- **Analyzing IE WebCache33**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache33`

- **Analyzing IE WebCache34**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache34`

- **Analyzing IE WebCache35**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache35`

- **Analyzing IE WebCache36**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache36`

- **Analyzing IE WebCache37**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache37`

- **Analyzing IE WebCache38**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache38`

- **Analyzing IE WebCache39**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache39`

- **Analyzing IE WebCache40**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache40`

- **Analyzing IE WebCache41**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache41`

- **Analyzing IE WebCache42**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache42`

- **Analyzing IE WebCache43**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache43`

- **Analyzing IE WebCache44**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache44`

- **Analyzing IE WebCache45**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache45`

- **Analyzing IE WebCache46**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache46`

- **Analyzing IE WebCache47**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache47`

- **Analyzing IE WebCache48**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache48`

- **Analyzing IE WebCache49**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache49`

- **Analyzing IE WebCache50**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache50`

- **Analyzing IE WebCache51**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache51`

- **Analyzing IE WebCache52**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache52`

- **Analyzing IE WebCache53**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache53`

- **Analyzing IE WebCache54**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache54`

- **Analyzing IE WebCache55**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache55`

- **Analyzing IE WebCache56**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache56`

- **Analyzing IE WebCache57**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache57`

- **Analyzing IE WebCache58**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache58`

- **Analyzing IE WebCache59**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache59`

- **Analyzing IE WebCache60**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache60`

- **Analyzing IE WebCache61**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache61`

- **Analyzing IE WebCache62**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache62`

- **Analyzing IE WebCache63**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache63`

- **Analyzing IE WebCache64**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache64`

- **Analyzing IE WebCache65**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache65`

- **Analyzing IE WebCache66**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache66`

- **Analyzing IE WebCache67**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache67`

- **Analyzing IE WebCache68**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache68`

- **Analyzing IE WebCache69**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache69`

- **Analyzing IE WebCache70**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache70`

- **Analyzing IE WebCache71**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache71`

- **Analyzing IE WebCache72**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache72`

- **Analyzing IE WebCache73**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache73`

- **Analyzing IE WebCache74**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache74`

- **Analyzing IE WebCache75**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache75`

- **Analyzing IE WebCache76**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache76`

- **Analyzing IE WebCache77**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache77`

- **Analyzing IE WebCache78**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache78`

- **Analyzing IE WebCache79**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache79`

- **Analyzing IE WebCache80**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache80`

- **Analyzing IE WebCache81**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache81`

- **Analyzing IE WebCache82**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache82`

- **Analyzing IE WebCache83**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache83`

- **Analyzing IE WebCache84**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache84`

- **Analyzing IE WebCache85**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache85`

- **Analyzing IE WebCache86**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache86`

- **Analyzing IE WebCache87**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache87`

- **Analyzing IE WebCache88**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache88`

- **Analyzing IE WebCache89**
  - `volatility -f <memory_dump> --profile=<profile> iewebcache89`
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
  - `volvolatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

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

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyanalyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Handles**
  - `volvolatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
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
 json
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> socklist`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Hive**
  - `voljson -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **File Extraction**
  - `volatility -f <memory_dump> --profile=<profile> filescan`
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

- **Detecting User Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> usermode`

- **Detecting IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting IRP Hooks**
  - `volvolatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Detecting IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Driver IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Detecting Driver Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> driverinline`

- **Detecting Driver Ports**
  - `volatility -f <memory_dump> --profile=<profile> driverports`

- **Detecting Driver SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> driverssdt`

- **Detecting Driver Timers**
  - `volatility -f <memory_dump> --profile=<profile> drivertimers`

- **Detecting Driver Work Items**
  - `volatility -f <memory_dump> --profile=<profile> driverworkitems`

- **Detecting Driver Object Headers**
  - `volvolatility -f <memory_dump> --profile=<profile> driverobjectheaders`

- **Detecting Driver Object Types**
 json
  - `volatility -f <memory_dump> --profile=<profile> driverobjecttypes`

- **Detecting Driver Device Objects**
 json
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceobjects`

- **Detecting Driver Device Object Names**
  - `volatility -f <memory_dump> --profile=<profile> driverdevicenames`

- **Detecting Driver Device Object Types**
  - `volatility -f <memory_dump> --profile=<profile> driverdevicetypes`

- **Detecting Driver Device Object Characteristics**
  - `volatility -f <memory_dump> --profile=<profile> driverdevicecharacteristics`

- **Detecting Driver Device Object Extensions**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceextensions`

- **Detecting Driver Device Object Attached Devices**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddevices`

- **Detecting Driver Device Object Attached Device Names**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddevicenames`

- **Detecting Driver Device Object Attached Device Types**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddevicetypes`

- **Detecting Driver Device Object Attached Device Characteristics**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddevicecharacteristics`

- **Detecting Driver Device Object Attached Device Extensions**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceextensions`

- **Detecting Driver Device Object Attached Device Attached Devices**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddevices`

- **Detecting Driver Device Object Attached Device Attached Device Names**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddevicenames`

- **Detecting Driver Device Object Attached Device Attached Device Types**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddevicetypes`

- **Detecting Driver Device Object Attached Device Attached Device Characteristics**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddevicecharacteristics`

- **Detecting Driver Device Object Attached Device Attached Device Extensions**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceextensions`

- **Detecting Driver Device Object Attached Device Attached Device Attached Devices**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddevices`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Names**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddevicenames`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Types**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddevicetypes`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Characteristics**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddevicecharacteristics`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Extensions**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceextensions`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Devices**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceattacheddevices`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Device Names**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceattacheddevicenames`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Device Types**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceattacheddevicetypes`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Device Characteristics**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceattacheddevicecharacteristics`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Device Extensions**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceattacheddeviceextensions`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Devices**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceattacheddeviceattacheddevices`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Names**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceattacheddeviceattacheddevicenames`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Types**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceattacheddeviceattacheddevicetypes`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Characteristics**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceattacheddeviceattacheddevicecharacteristics`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Extensions**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceattacheddeviceattacheddeviceextensions`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Devices**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddeviceattacheddeviceattacheddeviceattacheddevices`

- **Detecting Driver Device Object Attached Device Attached Device Attached Device Attached Device Attached Device Attached Device Names**
  - `volatility -f <memory_dump> --profile=<profile> driverdeviceattacheddeviceattacheddeviceattacheddevice
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

**Windows**系统在注册表数据库中维护一组**键**（**UserAssist keys**）来跟踪执行的程序。这些**键**中包含有关程序执行次数、最后执行日期和时间的信息。
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
  - `volvolatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Hive**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Dumping SAM**
  - `volatility -f <memory_dump> --profile=<profile> hashdump -y <offset>`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump -o <offset>`

- **Dumping User Credentials**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **File Analysis**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Yara Scanning**
  - `volatility -f <memory_dump> --profile=<profile> yarascan --yara-file=<rules_file>`

- **Dumping Files**
 json
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <file_path> -D <output_directory>`

- **Process Tree**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **SSDT Hooks**
 json
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Crash Dumps**
  - `volatility -f <memory_dump> --profile=<profile> crashinfo`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> portscan`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Injection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting API-Hooking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Windows**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden File Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

-
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

- **Extracting DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Drivers**
 jsonity -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad**
  - `volatility -f <memory_dump> --profile=<profile> vad`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> services`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing PEB**
  - `volatility -f <memory_dump> --profile=<profile> peb`

- **Analyizing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing GDI Objects**
  - `volatility -f <memory_dump> --profile=<profile> gdiobjects`

- **Analyzing GDI Shared Handles**
  - `volatility -f <memory_dump> --profile=<profile> gdi-sharedhandles`

- **Analyzing GDI DCs**
  - `voljsonity -f <memory_dump> --profile=<profile> gdi-dcs`

- **Analyzing GDI Palettes**
  - `volatility -f <memory_dump> --profile=<profile> gdi-palettes`

- **Analyzing GDI Brushes**
  - `volatility -f <memory_dump> --profile=<profile> gdi-brushes`

- **Analyzing GDI Bitmaps**
  - `volatility -f <memory_dump> --profile=<profile> gdi-bitmaps`

- **Analyzing GDI Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-fonts`

- **Analyzing GDI Texts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-texts`

- **Analyzing GDI Paths**
  - `volatility -f <memory_dump> --profile=<profile> gdi-paths`

- **Analyzing GDI Regions**
  - `volatility -f <memory_dump> --profile=<profile> gdi-regions`

- **Analyzing GDI Pen**
  - `volatility -f <memory_dump> --profile=<profile> gdi-pen`

- **Analyzing GDI Metafiles**
  - `volatility -f <memory_dump> --profile=<profile> gdi-metafiles`

- **Analyzing GDI Colors**
  - `volatility -f <memory_dump> --profile=<profile> gdi-colors`

- **Analyzing GDI Log Pens**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logpens`

- **Analyzing GDI Log Brushes**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logbrushes`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Brushes**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logbrushes`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdi-logfonts`

- **Analyzing GDI Log Fonts
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

- **Analyzing Mutantscan**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yarascan**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`
  - `volatility -f <memory_dump> --profile=<profile> psscan`
  - `volatility -f <memory_dump> --profile=<profile> threads`
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Malfind**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`
  - `volatility -f <memory_dump> --profile=<profile> malprocfind`

- **Analyzing Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`
  - `voljsonatility -f <memory_dump> --profile=<profile> modules`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Netscan**
  - `volatility -f <memory_dump> --profile=<profile> netscan`

- **Analyzing Consoles**
  - `volatility -f <memory_dump> --profile=<profile> consoles`

- **Analyzing Desktops**
  - `volatility -f <memory_dump> --profile=<profile> desktops`

- **Analyzing Shims**
  - `volatility -f <memory_dump> --profile=<profile> shims`

- **Analyzing Vadinfo**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo`

- **Analyzing IAT**
  - `volatility -f <memory_dump> --profile=<profile> iat`

- **Analyizing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing GDI Objects**
  - `volatility -f <memory_dump> --profile=<profile> gdi`

- **Analyzing GDI Shared Handles**
  - `volatility -f <memory_dump> --profile=<profile> gdi`

- **Analyzing GDI User Handles**
  - `volatility -f <memory_dump> --profile=<profile> gdi`

- **Analyzing Atom Tables**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Entries**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Usage**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table References**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Dereferences**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Allocations**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Analyzing Atom Table Deallocation**
  - `volatility -f <memory_dump> --profile=<profile> atomscan
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
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **User Accounts**
  - `voljson -f <memory_dump> --profile=<profile> useraccounts`

- **Dumping a File**
 json
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

### Advanced Commands

- **Process Tree**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Kernel Drivers**
 json
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <registry_key> -D <output_directory>`

- **Dumping a Registry Hive**
 json
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> dumpregistry -o <offset> -D <output_directory>`

- **Dumping a Registry Key**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <registry_key>`

- **Extracting Files from Unallocated Space**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Extracting Cached Files**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Extracting LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Extracting SAM Database**
  - `voljson -f <memory_dump> --profile=<profile> sam`

- **Dumping a Service**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Dumping a Driver**
  - `volatility -f <memory_dump> --profile=<profile> drvload -D <output_directory>`

- **Detecting Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting IRP Hooks**
  - `voljson -f <memory_dump> --profile=<profile> irp`

- **Detecting IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting Callback Hooks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Detecting Timer Hooks**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Driver Signature**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Detecting Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting Process Injection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Hollowing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Doppelgänging**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Herpaderping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Ghostwriting**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process AtomBombing**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process APC Injection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Thread Execution Hijacking**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Relocation**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Execution**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Load**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Write**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Mapping**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Copy**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Delete**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Rename**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Replace**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Append**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Encrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Compress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decompress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Pack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unpack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Inject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Eject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Hide**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Show**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Lock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unlock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Encrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Compress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decompress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Pack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unpack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Inject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Eject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Hide**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Show**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Lock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unlock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Encrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Compress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decompress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Pack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unpack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Inject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Eject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Hide**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Show**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Lock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unlock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Encrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Compress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decompress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Pack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unpack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Inject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Eject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Hide**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Show**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Lock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unlock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Encrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Compress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decompress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Pack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unpack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Inject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Eject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Hide**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Show**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Lock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unlock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Encrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Compress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decompress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Pack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unpack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Inject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Eject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Hide**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Show**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Lock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unlock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Encrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Compress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decompress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Pack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unpack**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Inject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Eject**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Hide**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Show**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Lock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Unlock**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Encrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decrypt**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Compress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image Decompress**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Process Image
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

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Analyzing Suspicious Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Process Rekall**
  - `volatility -f <memory_dump> --profile=<profile> rekall pslist`

- **Analyzing Process Vad Tree**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Process Vad Walk**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing Process Vadinfo**
  - `volatility -f <memory_dump> --profile=<profile> vadinfo -o <offset>`

- **Analycode**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volvolatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyizing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Timeliner**
  - `volatility -f
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

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

- **Recovering Deleted Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Analyzing Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Process Memory**
 json
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Extracting Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> moddump -p <pid> -D <output_directory>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Suspicious Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyting Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Threads**
  - `volvolatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Modules**
  - `volatility -f <memory_dump> --profile=<profile> modlist -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Process Registry Handles**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Analyzing Process Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Values**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Data**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Subkeys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Values**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Data**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Security**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Name**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Last Write Time**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Class Name**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyizing Process Registry Key Security Descriptor**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Name**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Type**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Length**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Last Write Time**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data MD5**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data SHA1**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyizing Process Registry Key Value Data SHA256**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data SHA512**
  - `volvolatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data CRC32**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data SSDEEP**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data YARA**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Process Registry Key Value Data Hex Dump Wide Unicode Strings**
  - `
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
  - `voljson -f <memory_dump> --profile=<profile> sockscan`

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

- **Kernel Driver Analysis**
 json
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Rootkit Detection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Extracting Deleted Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan | grep -i <deleted>`

- **Dumping Deleted Files**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

- **Analyzing Network Packets**
  - `volatility -f <memory_dump> --profile=<profile> netscan`

- **Analyzing Registry Transactions**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing User Sessions**
  - `volatility -f <memory_dump> --profile=<profile> consoles`

- **Analyzing User Accounts**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **Analyzing User Privileges**
  - `voljson -f <memory_dump> --profile=<profile> privs`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Entries**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump>
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
 json
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **Dumping Registry Hive**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Dumping SAM**
  - `volatility -f <memory_dump> --profile=<profile> hashdump -y <hive_offset> -s <system_offset> -o <output_directory>`

- **Dumping LSA Secrets**
  - `volvolatility -f <memory_dump> --profile=<profile> lsadump -o <output_directory>`

- **Dumping Password Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Dumping Anti-Forensics**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Dumping Drivers**
  - `volatility -f <memory_dump> --profile=<profile> drvmap`

- **Dumping Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Dumping Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Dumping Registry Handles**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Dumping Yara Scans**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Dumping API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Dumping SSDT**
 json
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Dumping GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Dumping IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Dumping LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Dumping Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Dumping Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> kdbgscan`

- **Dumping SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Dumping IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Dumping Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Dumping Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Dumping Scans**
  - `volatility -f <memory_dump> --profile=<profile> scans`

- **Dumping GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Dumping GDI Objects**
  - `volatility -f <memory_dump> --profile=<profile> gdiobjects`

- **Dumping GDI Shared Handles**
  - `volatility -f <memory_dump> --profile=<profile> gdi_shared_handles`

- **Dumping GDI DCs**
  - `volatility -f <memory_dump> --profile=<profile> gdicells`

- **Dumping GDI Palettes**
  - `volatility -f <memory_dump> --profile=<profile> gdipalettes`

- **Dumping GDI Brushes**
  - `volatility -f <memory_dump> --profile=<profile> gdibrushes`

- **Dumping GDI Bitmaps**
  - `volatility -f <memory_dump> --profile=<profile> gdibitmaps`

- **Dumping GDI Fonts**
  - `volatility -f <memory_dump> --profile=<profile> gdifonts`

- **Dumping GDI Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gditextout`

- **Dumping GDI Text Ext**
  - `volatility -f <memory_dump> --profile=<profile> gditextext`

- **Dumping GDI Text In**
  - `volatility -f <memory_dump> --profile=<profile> gditextin`

- **Dumping GDI Text Ext Out**
  - `volatility -f <memory_dump> --profile=<profile> gditextextout`

- **Dumping GDI Text Ext Ex**
  - `volatility -f <memory_dump> --profile=<profile> gditextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextextex`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextout`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextext`

- **Dumping GDI Poly Text Out**
  - `volatility -f <memory_dump> --profile=<profile> gdiptextin`

- **Dumping GDI Poly Text Out**
  -
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
NTFS文件系统包含一个名为_master file table_或MFT的文件。在NTFS文件系统卷上，MFT中至少有一个条目与每个文件对应，包括MFT本身。**关于文件的所有信息，包括大小、时间戳、权限和数据内容**，都存储在MFT条目中，或者在由MFT条目描述的MFT之外的空间中。来自[这里](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)。

### SSL密钥/证书

{% tabs %}
{% tab title="vol3" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
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
  - `voljsonity -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Dumping a DLL**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Hive**
 json  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **File Extraction**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Dumping a File**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

- **Process Tree**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **User Listing**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **User Information**
  - `voljsonity -f <memory_dump> --profile=<profile> userassist`

- **Screenshots**
  - `volatility -f <memory_dump> --profile=<profile> screenshot -D <output_directory>`

#### Advanced Commands

- **Malware Analysis**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Rootkit Detection**
     - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Detecting Driver IRP Hooks**
  - `volvoljsonity -f <memory_dump> --profile=<profile> irp`

- **Detecting Driver Inline Hooks**
  - `volatility -f <memory_dump> --profile=<profile> inlined`

- **Detecting IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Detecting GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Detecting Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Detecting Hidden Sections**
  - `volatility -f <memory_dump> --profile=<profile> sections`

- **Detecting Hidden Shims**
  - `volatility -f <memory_dump> --profile=<profile> shims`

- **Detecting Hidden SSDT**
  - `volatility -f <memory_dump> --profile=<profile> hiddenssdt`

- **Detecting Hidden IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenirp`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> hiddenproc`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> hiddenthread`

- **Detecting Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> hiddenports`

- **Detecting Hidden Devices**
  - `volatility -f <memory_dump> --profile=<profile> hiddendevices`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hiddenreg`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddenobj`

- **Detecting Hidden Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> hiddencallbacks`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> hiddenservices`

- **Detecting Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> hiddendrivers`

- **Detecting Hidden Files**
  - `volatility -f <memory_dump> --profile=<profile> hiddenfiles`

- **Detecting Hidden Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> hiddenmutex`

- **Detecting Hidden TCP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddentcp`

- **Detecting Hidden UDP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenudp`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> hiddentimers`

- **Detecting Hidden Raw Sockets**
  - `volatility -f <memory_dump> --profile=<profile> hiddenrawsockets`

- **Detecting Hidden Processes with Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocscallbacks`

- **Detecting Hidden Processes with Ports**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsports`

- **Detecting Hidden Processes with Timers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenproctimers`

- **Detecting Hidden Processes with Raw Sraw Sockets**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsrawsockets`

- **Detecting Hidden Processes with Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmutexes`

- **Detecting Hidden Processes with IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsirp`

- **Detecting Hidden Processes with SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsssdts`

- **Detecting Hidden Processes with Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmodules`

- **Detecting Hidden Processes with Handles**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocshandles`

- **Detecting Hidden Processes with Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsobjects`

- **Detecting Hidden Processes with Services**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsservices`

- **Detecting Hidden Processes with Drivers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsdrivers`

- **Detecting Hidden Processes with Files**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsfiles`

- **Detecting Hidden Processes with TCP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocstcp`

- **Detecting Hidden Processes with UDP Connections**
 json  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsudp`

- **Detecting Hidden Processes with Timers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocestimers`

- **Detecting Hidden Processes with Raw Sockets**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsrawsockets`

- **Detecting Hidden Processes with Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmutexes`

- **Detecting Hidden Processes with IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsirp`

- **Detecting Hidden Processes with SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsssdts`

- **Detecting Hidden Processes with Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmodules`

- **Detecting Hidden Processes with Handles**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocshandles`

- **Detecting Hidden Processes with Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsobjects`

- **Detecting Hidden Processes with Services**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsservices`

- **Detecting Hidden Processes with Drivers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsdrivers`

- **Detecting Hidden Processes with Files**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsfiles`

- **Detecting Hidden Processes with TCP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocstcp`

- **Detecting Hidden Processes with UDP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsudp`

- **Detecting Hidden Processes with Timers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocestimers`

- **Detecting Hidden Processes with Raw Sockets**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsrawsockets`

- **Detecting Hidden Processes with Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmutexes`

- **Detecting Hidden Processes with IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsirp`

- **Detecting Hidden Processes with SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsssdts`

- **Detecting Hidden Processes with Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmodules`

- **Detecting Hidden Processes with Handles**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocshandles`

- **Detecting Hidden Processes with Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsobjects`

- **Detecting Hidden Processes with Services**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsservices`

- **Detecting Hidden Processes with Drivers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsdrivers`

- **Detecting Hidden Processes with Files**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsfiles`

- **Detecting Hidden Processes with TCP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocstcp`

- **Detecting Hidden Processes with UDP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsudp`

- **Detecting Hidden Processes with Timers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocestimers`

- **Detecting Hidden Processes with Raw Sockets**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsrawsockets`

- **Detecting Hidden Processes with Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmutexes`

- **Detecting Hidden Processes with IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsirp`

- **Detecting Hidden Processes with SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsssdts`

- **Detecting Hidden Processes with Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmodules`

- **Detecting Hidden Processes with Handles**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocshandles`

- **Detecting Hidden Processes with Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsobjects`

- **Detecting Hidden Processes with Services**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsservices`

- **Detecting Hidden Processes with Drivers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsdrivers`

- **Detecting Hidden Processes with Files**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsfiles`

- **Detecting Hidden Processes with TCP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocstcp`

- **Detecting Hidden Processes with UDP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsudp`

- **Detecting Hidden Processes with Timers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocestimers`

- **Detecting Hidden Processes with Raw Sockets**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsrawsockets`

- **Detecting Hidden Processes with Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmutexes`

- **Detecting Hidden Processes with IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsirp`

- **Detecting Hidden Processes with SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsssdts`

- **Detecting Hidden Processes with Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmodules`

- **Detecting Hidden Processes with Handles**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocshandles`

- **Detecting Hidden Processes with Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsobjects`

- **Detecting Hidden Processes with Services**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsservices`

- **Detecting Hidden Processes with Drivers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsdrivers`

- **Detecting Hidden Processes with Files**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsfiles`

- **Detecting Hidden Processes with TCP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocstcp`

- **Detecting Hidden Processes with UDP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsudp`

- **Detecting Hidden Processes with Timers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocestimers`

- **Detecting Hidden Processes with Raw Sockets**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsrawsockets`

- **Detecting Hidden Processes with Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmutexes`

- **Detecting Hidden Processes with IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsirp`

- **Detecting Hidden Processes with SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsssdts`

- **Detecting Hidden Processes with Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmodules`

- **Detecting Hidden Processes with Handles**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocshandles`

- **Detecting Hidden Processes with Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsobjects`

- **Detecting Hidden Processes with Services**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsservices`

- **Detecting Hidden Processes with Drivers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsdrivers`

- **Detecting Hidden Processes with Files**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsfiles`

- **Detecting Hidden Processes with TCP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocstcp`

- **Detecting Hidden Processes with UDP Connections**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsudp`

- **Detecting Hidden Processes with Timers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocestimers`

- **Detecting Hidden Processes with Raw Sockets**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsrawsockets`

- **Detecting Hidden Processes with Mutexes**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmutexes`

- **Detecting Hidden Processes with IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsirp`

- **Detecting Hidden Processes with SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsssdts`

- **Detecting Hidden Processes with Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsmodules`

- **Detecting Hidden Processes with Handles**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocshandles`

- **Detecting Hidden Processes with Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsobjects`

- **Detecting Hidden Processes with Services**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsservices`

- **Detecting Hidden Processes with Drivers**
  - `volatility -f <memory_dump> --profile=<profile> hiddenprocsdrivers`

- **Detecting Hidden Processes with Files**
  - `volatility -f <memory_dump> --profile
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

### Volatility Cheat Sheet

#### Basic Forensic Methodology

1. **Memory Dump Acquisition**
   - **Physical Memory Dump**: `dd if=/dev/mem of=/path/to/image`
   - **Crash Dump**: `copy /y c:\windows\memory.dmp c:\path\to\image`
   - **Hibernation File**: `copy /y c:\hiberfil.sys c:\path\to\image`

2. **Memory Dump Analysis**
   - **Identify Profile**: `volatility -f memory.img imageinfo`
   - **List Processes**: `volatility -f memory.img --profile=Win7SP1x64 pslist`
   - **Dump Process**: `volatility -f memory.img --profile=Win7SP1x64 memdump -p PID -D /path/to/dump`

3. **Network Analysis**
   - **Connections**: `volatility -f memory.img --profile=Win7SP1x64 connscan`
   - **Sockets**: `volatility -f memory.img --profile=Win7SP1x64 sockets`

4. **Registry Analysis**
   - **User Listing**: `volatility -f memory.img --profile=Win7SP1x64 hivelist`
   - **User Registry**: `volatility -f memory.img --profile=Win7SP1x64 printkey -o OFFSET`

5. **File Analysis**
   - **File Listing**: `volatility -f memory.img --profile=Win7SP1x64 filescan`
   - **Dump File**: `volatility -f memory.img --profile=Win7SP1x64 dumpfiles -Q OFFSET -D /path/to/dump`

6. **Malware Analysis**
   - **Malware Detection**: `volatility -f memory.img --profile=Win7SP1x64 malfind`
   - **YARA Scan**: `volatility -f memory.img --profile=Win7SP1x64 yarascan --yara-file=/path/to/rules`

7. **Timeline Analysis**
   - **Process Timeline**: `volatility -f memory.img --profile=Win7SP1x64 pstree`
   - **Network Timeline**: `volatility -f memory.img --profile=Win7SP1x64 connscan`
   - **Registry Timeline**: `volatility -f memory.img --profile=Win7SP1x64 printkey -K 'ControlSet001\Control\Windows'`

8. **Plugin Development**
   - **Create New Plugin**: Extend `volatility.plugins.interface.interface`
   - **Register Plugin**: Add to `volatility.plugins.__init__.py`

#### Advanced Forensic Methodology

- **Memory Forensics**: Analyzing volatile memory for forensic artifacts.
- **Timeline Analysis**: Reconstructing events based on timestamps.
- **Malware Analysis**: Identifying and analyzing malicious software.
- **Rootkit Detection**: Detecting and analyzing rootkits in memory dumps.

{% endtab %}
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
  - `voljson -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Extracting Registry Hive**
 json
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Dumping a DLL**
  - `voljson -f <memory_dump> --profile=<profile> dlldump -D <output_directory> -b <base_address>`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverlist`

- **Dumping a Driver**
  - `volatility -f <memory_dump> --profile=<profile> moddump -b <base_address> -D <output_directory>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyjsoning a Socket**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing User Accounts**
  - `voljson -f <memory_dump> --profile=<profile> useraccounts`

- **Analyzing User Account Information**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing User Account Tokens**
  - `volatility -f <memory_dump> --profile=<profile> usertok`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> crashinfo`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Pstree**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malware Config**
  - `volatility -f <memory_dump> --profile=<profile> malfind -c`

- **Analyzing Malware Yara**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan -r <yara_rules>`

- **Analyzing Malware API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Malware API Hooks Modules**
  - `volatility -f <memory_dump> --profile=<profile> apihooks -m`

- **Analyzing Malware LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Malware LDR Modules Full**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules -v`

- **Analyzing Malware SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyizing Malware SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt -H`

- **Analyzing Malware IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Malware GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Malware GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt -H`

- **Analyzing Malware IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **AnalyAnalyzing Malware IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp -m`

- **Analyzing Malware API Calls**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Malware API Calls Modules**
  - `volatility -f <memory_dump> --profile=<profile> apihooks -m`

- **Analyzing Malware API Calls Full**
  - `volatility -f <memory_dump> --profile=<profile> apihooks -v`

- **Analyzing Malware API Calls Handles**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -t`

- **Analyzing Malware API Calls Handles Full**
  - `voljson -f <memoryjson_dump> --profile=<profile> apihooks -t -v`

- **Analyzing Malware API Calls DLLs**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -l`

- **Analyzing Malware API Calls DLLs Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -l -v`

- **Analyzing Malware API Calls Sockets**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -s`

- **Analyzing Malware API Calls Sockets Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -s -v`

- **Analyzing Malware API Calls Files**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -f`

- **Analyzing Malware API Calls Files Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -f -v`

- **Analyzing Malware API Calls Registries**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -r`

- **Analyzing Malware API Calls Registries Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -r -v`

- **Analyzing Malware API Calls Mutexes**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -m`

- **Analyzing Malware API Calls Mutexes Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -m -v`

- **Analyzing Malware API Calls Processes**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -p`

- **Analyzing Malware API Calls Processes Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -p -v`

- **Analyzing Malware API Calls Threads**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -T`

- **Analyzing Malware API Calls Threads Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -T -v`

- **Analyzing Malware API Calls Services**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -S`

- **Analyzing Malware API Calls Services Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -S -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls Drivers Full**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d -v`

- **Analyzing Malware API Calls Drivers**
  - `voljson -f <memory_dump> --profile=<profile> apihooks -d`

- **Analyzing Malware API Calls
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
## 其他

### 外部插件

如果要使用外部插件，请确保与插件相关的文件夹是第一个参数使用的内容。
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
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
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Hive**
 json
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **File Extraction**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Dumping a File**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

- **Kernel Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Driver Module Dump**
  - `volatility -f <memory_dump> --profile=<profile> moddump -D <output_directory>`

- **Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **User Accounts**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **User Account Dump**
 json
  - `volatility -f <memory_dump> --profile=<profile> dumpusers -D <output_directory>`

- **Crash Dump**
  - `volatility -f <memory_dump> --profile=<profile> memmap -D <output_directory>`

### Advanced Commands

- **Process Memory Analysis**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Process Memory Dump**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Process Memory Strings**
  - `volatility -f <memory_dump> --profile=<profile> strings -p <pid>`

- **Process Memory Handles**
  - `volvolatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Process Memory Pools**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Process Memory VAD Tree**
  - `volatility -f <memory_dump> --profile=<profile> vad -p <pid>`

- **Process Memory VAD Walk**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk -p <pid>`

- **Process Memory Malware Detection**
  - `volatility -f <memory_dump> --profile=<profile> malfind -p <pid>`

- **Process Memory API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks -p <pid>`

- **Process Memory DLL Injection**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> drivermodule -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump> --profile=<profile> driverirp -p <pid>`

- **Process Memory Driver Module**
  - `volatility -f <memory_dump
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

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Drivers**
  - `volvolatility -f <memory_dump> --profile=<profile> driverscan`

- **Extracting Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> moddump -D <output_directory>`

#### Plugin Usage

- **Using a Specific Plugin**
  - `volatility -f <memory_dump> --profile=<profile> <plugin_name>`

- **Plugin Help**
  - `volatility --info | grep <plugin_name>`

#### Memory Analysis

- **Analyzing Memory Dumps**
  - `volatility -f <memory_dump> --profile=<profile> <plugin_name>`

- **Automating Analysis**
  - `volatility -f <memory_dump> --profile=<profile> --output-file=<output_file> <plugin_name>`

#### Additional Resources

- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)

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

#### Basic Forensic Methodology

1. **Memory Dump Analysis**
   - **Identify Profile**: `vol.py -f memory_dump.raw imageinfo`
   - **Analyze Processes**: `vol.py -f memory_dump.raw --profile=ProfileName pslist`
   - **Analyze Process Memory**: `vol.py -f memory_dump.raw --profile=ProfileName memmap -p PID`
   - **Dump Process Memory**: `vol.py -f memory_dump.raw --profile=ProfileName memdump -p PID -D .`
   - **Analyze DLLs**: `vol.py -f memory_dump.raw --profile=ProfileName dlllist -p PID`
   - **Analyze Handles**: `vol.py -f memory_dump.raw --profile=ProfileName handles -p PID`
   - **Analyze Registry**: `vol.py -f memory_dump.raw --profile=ProfileName printkey -o OFFSET`
   - **Analyze Network Connections**: `vol.py -f memory_dump.raw --profile=ProfileName connscan`
   - **Analyze Drivers**: `vol.py -f memory_dump.raw --profile=ProfileName driverscan`
   - **Analyze Sockets**: `vol.py -f memory_dump.raw --profile=ProfileName sockets`
   - **Analyze Autostart Locations**: `vol.py -f memory_dump.raw --profile=ProfileName autoruns`

2. **File Analysis**
   - **Identify File Type**: `file filename`
   - **Extract Strings**: `strings -n 8 filename`
   - **Check PE Headers**: `readpe filename`
   - **Analyze Metadata**: `exiftool filename`
   - **Analyze PDF**: `pdf-parser filename`

3. **Network Analysis**
   - **Capture Traffic**: `tcpdump -i eth0 -w output.pcap`
   - **Anjsonze PCAP**: `wireshark output.pcap`
   - **Analyze HTTP Traffic**: `tshark -r output.pcap -Y 'http.request.method == "POST"'`

4. **Timeline Analysis**
   - **Collect System Events**: `log2timeline.py timeline.csv /`
   - **Analyze Timeline**: `psort.py -z UTC timeline.csv`

5. **Malware Analysis**
   - **Static Analysis**: `strings malware_sample | grep -i key`
   - **Dynamic Analysis**: `strace -c malware_sample`

6. **Memory Forensics Tools**
   - **Volatility**: Open-source memory forensics framework
   - **Rekall**: Memory analysis framework
   - **LiME**: Linux Memory Extractor
   - **WinDbg**: Windows Debugger

7. **Additional Resources**
   - **SANS DFIR**: Digital Forensics and Incident Response
   - **DFRWS**: Digital Forensics Research Workshop
   - **Open Security Training**: Memory Forensics Course

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

可以**从内存中读取bash历史记录**。您也可以转储.bash_history文件，但如果它被禁用，您会很高兴能够使用这个volatility模块
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %} 

### Volatility Cheat Sheet

#### Basic Forensic Methodology

1. **Memory Dump Acquisition**
   - **Physical Memory Dump**: `dd` or `fmem` tool
   - **Virtual Memory Dump**: `hivex` tool

2. **Memory Dump Analysis**
   - **Identify Profile**: `imageinfo`
   - **List Processes**: `pslist`
   - **Dump Process**: `procdump`
   - **Analyze DLLs**: `dlllist`
   - **Analyze Handles**: `handles`
   - **Analyze Registry**: `printkey`
   - **Analyze Network Connections**: `netscan`
   - **Analyze Drivers**: `ldrmodules`

3. **Timeline Analysis**
   - **Identify Last Boot Time**: `timeliner`
   - **List Running Processes**: `pstree`
   - **Analyze Process Timelines**: `psscan`
   - **Analyze Kernel Modules**: `modscan`
   - **Analyze Registry Modifications**: `printkey`
   - **Analyze Filesystem Metadata**: `mftparser`

4. **Malware Analysis**
   - **Detect Hidden Processes**: `psxview`
   - **Detect Hidden Drivers**: `hidden`
   - **Detect Hidden DLLs**: `ldrmodules`
   - **Detect Rootkits**: `svcscan`

5. **Network Analysis**
   - **Analyze Sockets**: `sockets`
   - **Analyze Connections**: `connections`
   - **Analyze Listening Ports**: `sockets`
   - **Analyze Network Packets**: `pcap`

6. **Miscellaneous Analysis**
   - **Analyze Crashes**: `crashinfo`
   - **Analyze User Accounts**: `userassist`
   - **Analyze Shell Items**: `shellbags`
   - **Analyze Print Jobs**: `printraw`

#### Advanced Forensic Methodology

1. **Memory Forensics**
   - **Identify Processes**: `pslist`
   - **Anjsonalyze DLLs**: `dlllist`
   - **Analyze Handles**: `handles`
   - **Analyze Registry**: `printkey`
   - **Analyze Network Connections**: `netscan`

2. **File System Forensics**
   - **Analyze File Metadata**: `filescan`
   - **Analyze File Content**: `dumpfiles`
   - **Analyze File System Structure**: `mftparser`

3. **Network Forensics**
   - **Analyze Network Packets**: `pcap`
   - **Analyze Network Connections**: `connections`
   - **Analyze DNS Records**: `dns`
   - **Analyze HTTP Traffic**: `volatility`

4. **Malware Analysis**
   - **Detect Hidden Processes**: `psxview`
   - **Detect Hidden Drivers**: `hidden`
   - **Detect Hidden DLLs**: `ldrmodules`
   - **Detect Rootkits**: `svcscan`

5. **Timeline Analysis**
   - **Identify Last Boot Time**: `timeliner`
   - **List Running Processes**: `pstree`
  json- **Analyze Process Timelines**: `psscan`
   - **Analyze Kernel Modules**: `modscan`
   - **Analyze Registry Modifications**: `printkey`

6. **Miscellaneous Analysis**
   - **Analyze Crashes**: `crashinfo`
   - **Analyze User Accounts**: `userassist`
   - **Analyze Shell Items**: `shellbags`
   - **Analyze Print Jobs**: `printraw`

{% endtab %}
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
  - `volvolatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Hive**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Dumping SAM**
  - `volatility -f <memory_dump> --profile=<profile> hashdump -y <offset>`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping User Credentials**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **File Analysis**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Yara Scanning**
  - `volatility -f <memory_dump> --profile=<profile> yarascan --yara-file=<rules_file>`

- **Dumping Files**
 json
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <file_path> -D <output_directory>`

- **Process Tree**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **SSDT Hooks**
 json
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Kernel Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Crash Dumps**
  - `volatility -f <memory_dump> --profile=<profile> crashinfo`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> portscan`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Injection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting API-Hooking**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivescan`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> portscan`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Detecting Hidden Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivescan`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Injection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting API-Hooking**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivescan`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> portscan`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Detecting Hidden Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivescan`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Injection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting API-Hooking**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivescan`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> portscan`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Detecting Hidden Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivescan`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Injection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting API-Hooking**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivescan`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> portscan`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Detecting Hidden Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivescan`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Injection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting API-Hooking**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivescan`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Detecting Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Detecting Hidden TCP/UDP Ports**
  - `volatility -f <memory_dump> --profile=<profile> portscan`

- **Detecting Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Detecting Hidden Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Detecting Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivescan`

- **Detecting Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Detecting Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Detecting Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Detecting Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Detecting Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Detecting Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> hiddeneval`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting In-Memory Injection**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Detecting API-Hooking**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Detecting SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Detecting Driver Modules**
  - `volatility -
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

### Volatility Cheatsheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `voljsonity -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Pools**
  - `voljsonity -f <memory_dump> --profile=<profile> poolscanner`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyizing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> id
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
```
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
MBR保存了关于如何在介质上组织逻辑分区（包含[文件系统](https://en.wikipedia.org/wiki/File_system)）的信息。MBR还包含可执行代码，用作已安装操作系统的加载程序，通常通过将控制权传递给加载程序的[第二阶段](https://en.wikipedia.org/wiki/Second-stage_boot_loader)，或与每个分区的[卷引导记录](https://en.wikipedia.org/wiki/Volume_boot_record)（VBR）结合使用。这个MBR代码通常被称为[引导加载程序](https://en.wikipedia.org/wiki/Boot_loader)。来自[这里](https://en.wikipedia.org/wiki/Master_boot_record)。

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点会议。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF版本的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
