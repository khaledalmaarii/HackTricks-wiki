# Volatility - 速查表

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士的热门交流平台。

{% embed url="https://www.rootedcon.com/" %}

如果你想要一些**快速而疯狂**的东西，可以同时使用多个 Volatility 插件，你可以使用：[https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
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
{% tab title="方法2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Volatility命令

访问官方文档：[Volatility命令参考](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### 关于“list”和“scan”插件的说明

Volatility有两种主要的插件方法，有时可以从它们的名称中反映出来。"list"插件将尝试通过Windows内核结构来获取信息，如进程（在内存中定位和遍历`_EPROCESS`结构的链接列表）、操作系统句柄（定位和列出句柄表，解引用找到的任何指针等）。它们的行为几乎与Windows API的行为相同，例如列出进程。

这使得"list"插件非常快速，但与Windows API一样容易受到恶意软件的操纵。例如，如果恶意软件使用DKOM将进程从`_EPROCESS`链接列表中取消链接，它将不会显示在任务管理器中，pslist中也不会显示。

另一方面，"scan"插件将采用类似于在内存中雕刻可能在解引用为特定结构时有意义的内容的方法。例如，`psscan`将读取内存并尝试从中创建`_EPROCESS`对象（它使用池标签扫描，即搜索指示感兴趣结构存在的4字节字符串）。优点是它可以挖掘已退出的进程，即使恶意软件篡改了`_EPROCESS`链接列表，插件仍然可以在内存中找到该结构（因为该结构仍然需要存在以使进程运行）。缺点是"scan"插件比"list"插件稍慢，并且有时可能产生误报（进程已退出太久，其结构的部分被其他操作覆盖）。

来源：[http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## 操作系统配置文件

### Volatility3

如readme中所述，您需要将要支持的操作系统的**符号表**放在_volatility3/volatility/symbols_目录下。\
各种操作系统的符号表包可以从以下位置**下载**：

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### 外部配置文件

您可以获取支持的配置文件列表，执行以下操作：
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
如果你想使用**你已经下载的新配置文件**（例如Linux配置文件），你需要在某个地方创建以下文件夹结构：_plugins/overlays/linux_，并将包含配置文件的zip文件放入该文件夹中。然后，使用以下命令获取配置文件的数量：
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
您可以从[https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)下载Linux和Mac的配置文件。

在前面的代码块中，您可以看到配置文件被称为`LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`，您可以使用它来执行类似以下的操作：
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### 发现个人资料

```plaintext
volatility -f <memory_dump> imageinfo
```

使用上述命令来获取内存转储文件的基本信息。
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo和kdbgscan之间的区别**

与仅提供配置文件建议的imageinfo不同，**kdbgscan**旨在确定正确的配置文件和正确的KDBG地址（如果存在多个）。该插件扫描与Volatility配置文件相关联的KDBGHeader签名，并应用健全性检查以减少误报。输出的详细程度和可以执行的健全性检查数量取决于Volatility是否能够找到DTB，因此如果您已经知道正确的配置文件（或者如果您从imageinfo获得了配置文件建议），请确保使用它（来自[这里](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)）。

始终查看**kdbgscan找到的进程数量**。有时候，imageinfo和kdbgscan可以找到**多个**合适的**配置文件**，但只有**有效的配置文件会有一些与进程相关的信息**（这是因为提取进程需要正确的KDBG地址）。
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

**内核调试器块**（称为\_KDDEBUGGER\_DATA64类型的KdDebuggerDataBlock，或者在volatility中称为**KDBG**）对于Volatility和调试器执行的许多操作非常重要。例如，它引用了PsActiveProcessHead，这是进程列表所需的所有进程的列表头。

## 操作系统信息
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
插件`banners.Banners`可以在转储中使用**vol3来查找Linux横幅**。

## 哈希/密码

提取SAM哈希，[域缓存凭据](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials)和[lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets)。

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## 内存转储

进程的内存转储将提取出进程当前状态的所有内容。procdump模块只会提取代码。
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流之地。

{% embed url="https://www.rootedcon.com/" %}

## 进程

### 列出进程

尝试查找**可疑**进程（按名称）或**意外**的子进程（例如，cmd.exe作为iexplorer.exe的子进程）。\
比较pslist的结果和psscan的结果可以识别隐藏进程。

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% tab title="vol2" %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% endtab %}
{% endtabs %}

### 转储进程

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### 命令行

是否执行了任何可疑操作？

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% tab title="vol2" %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

在cmd.exe中输入的命令会由conhost.exe处理（在Windows 7之前是csrss.exe）。因此，即使攻击者在我们获取内存转储之前成功终止了cmd.exe，仍然有很大的机会从conhost.exe的内存中恢复命令行会话的历史记录。如果你发现一些奇怪的东西（使用控制台的模块），尝试转储与conhost.exe相关的进程的内存，并在其中搜索字符串以提取命令行。

### 环境

获取每个运行进程的环境变量。可能会有一些有趣的值。

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% tab title="vol2" %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### 令牌权限

检查意外服务中的权限令牌。\
列出使用某些特权令牌的进程可能会很有趣。

{% tabs %}
{% tab title="vol3" %}
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% tab title="vol2" %}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

检查每个进程拥有的SSID。\
列出使用特权SID的进程（以及使用某些服务SID的进程）可能会很有趣。

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### 句柄

有助于了解进程打开的其他文件、键、线程、进程等的句柄。
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% endtabs %}

### DLLs

{% tabs %}
{% tab title="vol3" %}

#### List loaded DLLs

```bash
volatility -f <memory_dump> --profile=<profile> dlllist
```

#### Dump DLL

```bash
volatility -f <memory_dump> --profile=<profile> dlldump -D <output_directory> -b <base_address>
```

#### Find DLL by name

```bash
volatility -f <memory_dump> --profile=<profile> dlllist | grep <dll_name>
```

#### Find DLL by process

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>
```

#### Find DLL by module

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -m <module_name>
```

#### Find DLL by base address

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -b <base_address>
```

#### Find DLL by size

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -s <size>
```

#### Find DLL by path

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -i <path>
```

#### Find DLL by timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -t <timestamp>
```

#### Find DLL by checksum

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -c <checksum>
```

#### Find DLL by description

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -d <description>
```

#### Find DLL by company

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -o <company>
```

#### Find DLL by product

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -r <product>
```

#### Find DLL by version

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -v <version>
```

#### Find DLL by language

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -l <language>
```

#### Find DLL by original filename

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -n <original_filename>
```

#### Find DLL by internal name

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -e <internal_name>
```

#### Find DLL by legal copyright

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -g <legal_copyright>
```

#### Find DLL by legal trademark

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -k <legal_trademark>
```

#### Find DLL by product version

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -x <product_version>
```

#### Find DLL by file description

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -y <file_description>
```

#### Find DLL by file version

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -z <file_version>
```

#### Find DLL by comments

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -a <comments>
```

#### Find DLL by private build

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -w <private_build>
```

#### Find DLL by special build

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -q <special_build>
```

#### Find DLL by product name

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -u <product_name>
```

#### Find DLL by file size

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -j <file_size>
```

#### Find DLL by file path

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -o <file_path>
```

#### Find DLL by file extension

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -p <file_extension>
```

#### Find DLL by file attributes

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -m <file_attributes>
```

#### Find DLL by file creation time

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -n <file_creation_time>
```

#### Find DLL by file modification time

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -e <file_modification_time>
```

#### Find DLL by file access time

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -t <file_access_time>
```

#### Find DLL by file change time

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -y <file_change_time>
```

#### Find DLL by file attributes change time

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -z <file_attributes_change_time>
```

#### Find DLL by file creation timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -a <file_creation_timestamp>
```

#### Find DLL by file modification timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -s <file_modification_timestamp>
```

#### Find DLL by file access timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -d <file_access_timestamp>
```

#### Find DLL by file change timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -f <file_change_timestamp>
```

#### Find DLL by file attributes change timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -g <file_attributes_change_timestamp>
```

#### Find DLL by file creation date

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -h <file_creation_date>
```

#### Find DLL by file modification date

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -j <file_modification_date>
```

#### Find DLL by file access date

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -k <file_access_date>
```

#### Find DLL by file change date

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -l <file_change_date>
```

#### Find DLL by file attributes change date

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -x <file_attributes_change_date>
```

#### Find DLL by file creation datetime

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -c <file_creation_datetime>
```

#### Find DLL by file modification datetime

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -v <file_modification_datetime>
```

#### Find DLL by file access datetime

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -b <file_access_datetime>
```

#### Find DLL by file change datetime

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -n <file_change_datetime>
```

#### Find DLL by file attributes change datetime

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -m <file_attributes_change_datetime>
```

#### Find DLL by file creation year

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -i <file_creation_year>
```

#### Find DLL by file modification year

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -o <file_modification_year>
```

#### Find DLL by file access year

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -p <file_access_year>
```

#### Find DLL by file change year

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -q <file_change_year>
```

#### Find DLL by file attributes change year

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -r <file_attributes_change_year>
```

#### Find DLL by file creation month

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -s <file_creation_month>
```

#### Find DLL by file modification month

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -d <file_modification_month>
```

#### Find DLL by file access month

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -f <file_access_month>
```

#### Find DLL by file change month

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -g <file_change_month>
```

#### Find DLL by file attributes change month

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -h <file_attributes_change_month>
```

#### Find DLL by file creation day

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -j <file_creation_day>
```

#### Find DLL by file modification day

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -k <file_modification_day>
```

#### Find DLL by file access day

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -l <file_access_day>
```

#### Find DLL by file change day

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -x <file_change_day>
```

#### Find DLL by file attributes change day

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -a <file_attributes_change_day>
```

#### Find DLL by file creation hour

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -b <file_creation_hour>
```

#### Find DLL by file modification hour

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -n <file_modification_hour>
```

#### Find DLL by file access hour

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -m <file_access_hour>
```

#### Find DLL by file change hour

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -i <file_change_hour>
```

#### Find DLL by file attributes change hour

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -o <file_attributes_change_hour>
```

#### Find DLL by file creation minute

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -p <file_creation_minute>
```

#### Find DLL by file modification minute

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -q <file_modification_minute>
```

#### Find DLL by file access minute

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -r <file_access_minute>
```

#### Find DLL by file change minute

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -s <file_change_minute>
```

#### Find DLL by file attributes change minute

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -d <file_attributes_change_minute>
```

#### Find DLL by file creation second

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -f <file_creation_second>
```

#### Find DLL by file modification second

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -g <file_modification_second>
```

#### Find DLL by file access second

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -h <file_access_second>
```

#### Find DLL by file change second

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -j <file_change_second>
```

#### Find DLL by file attributes change second

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -k <file_attributes_change_second>
```

#### Find DLL by file creation millisecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -l <file_creation_millisecond>
```

#### Find DLL by file modification millisecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -x <file_modification_millisecond>
```

#### Find DLL by file access millisecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -a <file_access_millisecond>
```

#### Find DLL by file change millisecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -b <file_change_millisecond>
```

#### Find DLL by file attributes change millisecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -n <file_attributes_change_millisecond>
```

#### Find DLL by file creation microsecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -m <file_creation_microsecond>
```

#### Find DLL by file modification microsecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -i <file_modification_microsecond>
```

#### Find DLL by file access microsecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -o <file_access_microsecond>
```

#### Find DLL by file change microsecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -p <file_change_microsecond>
```

#### Find DLL by file attributes change microsecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -q <file_attributes_change_microsecond>
```

#### Find DLL by file creation nanosecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -r <file_creation_nanosecond>
```

#### Find DLL by file modification nanosecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -s <file_modification_nanosecond>
```

#### Find DLL by file access nanosecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -d <file_access_nanosecond>
```

#### Find DLL by file change nanosecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -f <file_change_nanosecond>
```

#### Find DLL by file attributes change nanosecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -g <file_attributes_change_nanosecond>
```

#### Find DLL by file creation timezone

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -h <file_creation_timezone>
```

#### Find DLL by file modification timezone

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -j <file_modification_timezone>
```

#### Find DLL by file access timezone

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -k <file_access_timezone>
```

#### Find DLL by file change timezone

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -l <file_change_timezone>
```

#### Find DLL by file attributes change timezone

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -x <file_attributes_change_timezone>
```

#### Find DLL by file creation offset

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -a <file_creation_offset>
```

#### Find DLL by file modification offset

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -s <file_modification_offset>
```

#### Find DLL by file access offset

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -d <file_access_offset>
```

#### Find DLL by file change offset

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -f <file_change_offset>
```

#### Find DLL by file attributes change offset

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -g <file_attributes_change_offset>
```

#### Find DLL by file creation offset hours

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -h <file_creation_offset_hours>
```

#### Find DLL by file modification offset hours

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -j <file_modification_offset_hours>
```

#### Find DLL by file access offset hours

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -k <file_access_offset_hours>
```

#### Find DLL by file change offset hours

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -l <file_change_offset_hours>
```

#### Find DLL by file attributes change offset hours

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -x <file_attributes_change_offset_hours>
```

#### Find DLL by file creation offset minutes

```bash
vol
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### 进程的字符串

Volatility允许我们检查一个字符串属于哪个进程。

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% tab title="vol2" %}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

它还允许使用yarascan模块在进程中搜索字符串：

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows**系统在注册表数据库中维护一组**键**（**UserAssist键**），用于跟踪执行的程序。这些**键**中包含了程序的执行次数以及最后执行的日期和时间。
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流之地。

{% embed url="https://www.rootedcon.com/" %}

## 服务

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% tab title="vol2" %}
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
{% tab title="vol2" %}
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
{% endtab %}
{% endtabs %}

## 注册表

### 打印可用的注册表

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### 获取一个值

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
### 转储

```bash
volatility -f <dumpfile> imageinfo
```

- 查看转储文件的信息

```bash
volatility -f <dumpfile> --profile=<profile> pslist
```

- 列出转储文件中的进程列表

```bash
volatility -f <dumpfile> --profile=<profile> psscan
```

- 扫描转储文件中的进程

```bash
volatility -f <dumpfile> --profile=<profile> pstree
```

- 显示转储文件中的进程树

```bash
volatility -f <dumpfile> --profile=<profile> dlllist -p <pid>
```

- 列出指定进程的加载的DLL列表

```bash
volatility -f <dumpfile> --profile=<profile> handles -p <pid>
```

- 列出指定进程的句柄列表

```bash
volatility -f <dumpfile> --profile=<profile> filescan
```

- 扫描转储文件中的文件

```bash
volatility -f <dumpfile> --profile=<profile> cmdline -p <pid>
```

- 显示指定进程的命令行参数

```bash
volatility -f <dumpfile> --profile=<profile> getsids
```

- 显示转储文件中的安全标识符（SID）

```bash
volatility -f <dumpfile> --profile=<profile> hivelist
```

- 列出转储文件中的注册表列表

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key>
```

- 打印指定注册表键的内容

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset>
```

- 打印指定注册表键的内容（使用偏移量）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry>
```

- 打印指定注册表键的内容（使用偏移量和注册表文件）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件和Windows目录）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录和自定义命令）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令和系统文件）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件和用户文件）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件和文件）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件和地址）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址和详细信息）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息和十六进制值）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值和数据）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据和字节）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节和名称）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称和列表）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l -i
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称、列表和索引）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l -i -e
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称、列表、索引和扩展信息）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l -i -e -t <type>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称、列表、索引、扩展信息和类型）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l -i -e -t <type> -g
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称、列表、索引、扩展信息、类型和全局标志）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l -i -e -t <type> -g -y
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称、列表、索引、扩展信息、类型、全局标志和键值类型）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l -i -e -t <type> -g -y -k <keytype>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称、列表、索引、扩展信息、类型、全局标志、键值类型和键类型）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l -i -e -t <type> -g -y -k <keytype> -m <machine>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称、列表、索引、扩展信息、类型、全局标志、键值类型、键类型和机器）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l -i -e -t <type> -g -y -k <keytype> -m <machine> -q
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称、列表、索引、扩展信息、类型、全局标志、键值类型、键类型、机器和静默模式）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l -i -e -t <type> -g -y -k <keytype> -m <machine> -q -j
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称、列表、索引、扩展信息、类型、全局标志、键值类型、键类型、机器、静默模式和JSON格式）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l -i -e -t <type> -g -y -k <keytype> -m <machine> -q -j -z <timezone>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称、列表、索引、扩展信息、类型、全局标志、键值类型、键类型、机器、静默模式、JSON格式和时区）

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K <key> -o <offset> -r <registry> -w <windows> -c <cmd> -s <system> -u <user> -f <file> -a <address> -v -x -d -b <byte> -n <name> -l -i -e -t <type> -g -y -k <keytype> -m <machine> -q -j -z <timezone> -H <hive>
```

- 打印指定注册表键的内容（使用偏移量、注册表文件、Windows目录、自定义命令、系统文件、用户文件、文件、地址、详细信息、十六进制值、数据、字节、名称、列表、索引、扩展信息、类型、全局标志、键值类型、键类型、机器、静默模式、JSON格式、时区和Hive
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
{% tab title="vol2" %}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% endtabs %}

### 扫描/转储

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% endtabs %}

### 主文件表

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

NTFS文件系统包含一个称为_master file table_（MFT）的文件。在NTFS文件系统卷上，MFT中至少有一个条目，包括MFT本身。**有关文件的所有信息，包括其大小、时间和日期戳、权限和数据内容**，都存储在MFT条目中，或者在由MFT条目描述的MFT之外的空间中。来自[这里](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)。

### SSL密钥/证书
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% tab title="vol2" %}
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
{% tab title="vol2" %}
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
{% endtab %}
{% endtabs %}

### 使用yara进行扫描

使用此脚本从github下载并合并所有yara恶意软件规则：[https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
创建名为_**rules**_的目录并执行它。这将创建一个名为_**malware\_rules.yar**_的文件，其中包含所有的yara恶意软件规则。
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% tab title="vol2" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}

## MISC

### 外部插件

如果你想使用外部插件，请确保与插件相关的文件夹是第一个参数使用的。
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% tab title="vol2" %}
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
### 互斥锁

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### 符号链接

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

可以**从内存中读取bash历史记录**。您也可以转储_.bash\_history_文件，但如果禁用了该文件，您会很高兴能够使用这个volatility模块

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp linux.bash.Bash
```
{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### 时间线

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### 驱动程序

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### 获取剪贴板内容
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### 获取IE浏览器历史记录

```bash
volatility -f <memory_dump> --profile=<profile> iehistory
```

使用上述命令可以从内存转储文件中提取Internet Explorer浏览器的历史记录。

### 解析IE历史记录

```bash
volatility -f <memory_dump> --profile=<profile> iehistory -i <index>
```

使用上述命令可以解析特定索引的Internet Explorer浏览器历史记录。

### 导出IE历史记录

```bash
volatility -f <memory_dump> --profile=<profile> iehistory -i <index> --dump-dir=<output_directory>
```

使用上述命令可以将特定索引的Internet Explorer浏览器历史记录导出到指定的输出目录。

### 获取IE缓存

```bash
volatility -f <memory_dump> --profile=<profile> iecache
```

使用上述命令可以从内存转储文件中提取Internet Explorer浏览器的缓存。

### 解析IE缓存

```bash
volatility -f <memory_dump> --profile=<profile> iecache -i <index>
```

使用上述命令可以解析特定索引的Internet Explorer浏览器缓存。

### 导出IE缓存

```bash
volatility -f <memory_dump> --profile=<profile> iecache -i <index> --dump-dir=<output_directory>
```

使用上述命令可以将特定索引的Internet Explorer浏览器缓存导出到指定的输出目录。
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### 获取记事本文本

To extract text from a memory dump, you can use the `notepad` plugin in Volatility. This plugin allows you to retrieve the contents of any notepad windows that were open at the time of the memory capture.

To use the `notepad` plugin, follow these steps:

1. Identify the profile of the memory dump using the `imageinfo` plugin.
2. Run the `notepad` plugin with the appropriate profile and memory dump file.
3. The plugin will scan the memory dump for notepad windows and extract the text from them.
4. The extracted text will be displayed in the terminal.

Here is an example command to run the `notepad` plugin:

```
volatility -f memory_dump.raw --profile=Win7SP1x64 notepad
```

Replace `memory_dump.raw` with the path to your memory dump file, and `Win7SP1x64` with the profile of your memory dump.

Once the command is executed, you will see the text from any open notepad windows in the output.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### 截图

```bash
$ volatility -f memory_dump.vmem imageinfo
```

使用`volatility`命令来获取内存转储文件的信息。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 pslist
```

使用`volatility`命令来获取内存转储文件中运行的进程列表。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 psscan
```

使用`volatility`命令来扫描内存转储文件中的进程。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 pstree
```

使用`volatility`命令来生成内存转储文件中进程的树状结构。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 dlllist -p <PID>
```

使用`volatility`命令来获取指定进程的加载的DLL列表。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 handles -p <PID>
```

使用`volatility`命令来获取指定进程的句柄列表。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 cmdline -p <PID>
```

使用`volatility`命令来获取指定进程的命令行参数。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 filescan | grep -i <keyword>
```

使用`volatility`命令来扫描内存转储文件中的文件，并根据关键字进行过滤。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 malfind -p <PID>
```

使用`volatility`命令来查找指定进程中的恶意代码。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 hivelist
```

使用`volatility`命令来获取内存转储文件中的注册表信息。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 printkey -K <registry_key>
```

使用`volatility`命令来打印指定注册表键的内容。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 hashdump -s <system_hive> -y <sam_hive>
```

使用`volatility`命令来获取系统和SAM注册表中的哈希值。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 userassist
```

使用`volatility`命令来获取用户操作历史记录。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 shimcache
```

使用`volatility`命令来获取Shimcache信息。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 hibinfo
```

使用`volatility`命令来获取休眠文件的信息。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 hibdump -o <output_directory>
```

使用`volatility`命令来导出休眠文件。

```bash
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 screenshot -D <output_directory>
```

使用`volatility`命令来获取屏幕截图。
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### 主引导记录 (MBR)

The Master Boot Record (MBR) is the first sector of a storage device, such as a hard disk or solid-state drive. It contains the boot loader, which is responsible for loading the operating system into memory and starting the boot process. The MBR also contains the partition table, which defines the structure of the storage device and the location of each partition.

主引导记录 (MBR) 是存储设备（如硬盘或固态硬盘）的第一个扇区。它包含引导加载程序，负责将操作系统加载到内存中并启动引导过程。MBR 还包含分区表，定义了存储设备的结构和每个分区的位置。
```
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
MBR（主引导记录）保存了关于逻辑分区（包含文件系统）在介质上的组织方式的信息。MBR还包含可执行代码，用作已安装操作系统的加载程序，通常通过将控制权传递给加载程序的第二阶段，或与每个分区的卷引导记录（VBR）结合使用。这个MBR代码通常被称为引导加载程序。来自[这里](https://en.wikipedia.org/wiki/Master_boot_record)。

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)是西班牙最重要的网络安全活动之一，也是欧洲最重要的活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士的热点聚会。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家网络安全公司工作吗？想要在HackTricks中宣传你的公司吗？或者想要获取PEASS的最新版本或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家NFT收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 加入[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上关注我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧。

</details>
