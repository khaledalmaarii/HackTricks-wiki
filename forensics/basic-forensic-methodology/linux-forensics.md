# Linux取证

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## 初始信息收集

### 基本信息

首先，建议准备一些**带有已知良好的二进制文件和库的USB设备**（可以只获取ubuntu并复制文件夹_/bin_，_/sbin_，_/lib_和_/lib64_），然后挂载USB设备，并修改环境变量以使用这些二进制文件：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
一旦您配置了系统以使用良好且已知的二进制文件，您可以开始提取一些基本信息：
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### 可疑信息

在获取基本信息时，您应该检查以下异常情况：

* **Root进程**通常以较低的PID运行，因此如果您发现一个具有较大PID的Root进程，可能存在可疑情况
* 检查`/etc/passwd`中没有shell的用户的**注册登录**
* 检查`/etc/shadow`中没有shell的用户的**密码哈希值**

### 内存转储

为了获取正在运行的系统的内存，建议使用[**LiME**](https://github.com/504ensicsLabs/LiME)。

要进行**编译**，您需要使用与受害机器使用的**相同内核**。

{% hint style="info" %}
请记住，您**不能在受害机器上安装LiME或任何其他东西**，因为这将对其进行多个更改。
{% endhint %}

因此，如果您有一个相同版本的Ubuntu，可以使用`apt-get install lime-forensics-dkms`。

在其他情况下，您需要从GitHub下载[**LiME**](https://github.com/504ensicsLabs/LiME)，并使用正确的内核头文件进行编译。要**获取受害机器的确切内核头文件**，您只需将目录`/lib/modules/<kernel version>`复制到您的机器上，然后使用它们来**编译**LiME：
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME支持3种格式：

* 原始格式（将每个段连接在一起）
* 填充格式（与原始格式相同，但右侧位填充为零）
* Lime格式（推荐的带有元数据的格式）

LiME还可以用于通过网络发送转储，而不是将其存储在系统上，使用类似于：`path=tcp:4444`

### 磁盘镜像

#### 关闭系统

首先，您需要**关闭系统**。这并不总是一个选择，因为有时系统将是一台公司无法承受关闭的生产服务器。\
有两种关闭系统的方式，一种是**正常关闭**，一种是**“拔插头”关闭**。第一种方式将允许**进程按照通常的方式终止**，并且**文件系统**将被**同步**，但也会允许可能的**恶意软件**破坏证据。"拔插头"的方法可能会导致**一些信息丢失**（由于我们已经对内存进行了镜像，所以不会丢失太多信息），而**恶意软件将没有任何机会**对此做任何事情。因此，如果您**怀疑**可能存在**恶意软件**，只需在系统上执行**`sync`**命令，然后拔掉电源。

#### 对磁盘进行镜像

重要的是要注意，在**将您的计算机连接到与案件相关的任何设备之前**，您需要确保它将以**只读方式挂载**，以避免修改任何信息。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### 磁盘镜像预分析

对没有更多数据的磁盘镜像进行镜像制作。
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 搜索已知恶意软件

### 修改的系统文件

一些Linux系统具有验证许多已安装组件完整性的功能，这提供了一种有效的方式来识别异常或不合适的文件。例如，在Linux上，`rpm -Va`旨在验证使用RedHat软件包管理器安装的所有软件包。
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### 恶意软件/Rootkit 检测工具

阅读以下页面，了解可以用于查找恶意软件的工具：

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## 搜索已安装的程序

### 软件包管理器

在基于 Debian 的系统中，_**/var/lib/dpkg/status**_ 文件包含有关已安装软件包的详细信息，而 _**/var/log/dpkg.log**_ 文件记录了软件包安装时的信息。\
在 RedHat 和相关的 Linux 发行版中，**`rpm -qa --root=/mntpath/var/lib/rpm`** 命令将列出系统上 RPM 数据库的内容。
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### 其他

**并非所有已安装的程序都会在上述命令中列出**，因为某些应用程序在某些系统上不可用作为软件包，必须从源代码安装。因此，检查诸如 _**/usr/local**_ 和 _**/opt**_ 等位置可能会发现其他已从源代码编译和安装的应用程序。
```bash
ls /opt /usr/local
```
另一个好主意是**检查**$PATH中的**常见文件夹**，查找与**已安装软件包无关的二进制文件**：
```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```
<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 恢复已删除的运行中的二进制文件

![](<../../.gitbook/assets/image (641).png>)

## 检查自启动位置

### 计划任务
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### 服务

恶意软件通常会作为新的未授权服务嵌入系统。Linux有一些脚本用于在计算机启动时启动服务。初始化启动脚本 _**/etc/inittab**_ 调用其他脚本，如 rc.sysinit 和 _**/etc/rc.d/**_ 目录下的各种启动脚本，或者在一些旧版本中是 _**/etc/rc.boot/**_。在其他版本的Linux中，如Debian，启动脚本存储在 _**/etc/init.d/**_ 目录中。此外，一些常见的服务在 _**/etc/inetd.conf**_ 或 _**/etc/xinetd/**_ 中启用，具体取决于Linux的版本。数字取证人员应检查每个启动脚本中是否存在异常条目。

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### 内核模块

在Linux系统上，内核模块通常用作恶意软件包的rootkit组件。内核模块是根据 `/lib/modules/'uname -r'` 和 `/etc/modprobe.d` 目录中的配置信息以及 `/etc/modprobe` 或 `/etc/modprobe.conf` 文件在系统启动时加载的。应检查这些区域是否存在与恶意软件相关的项目。

### 其他自启动位置

Linux使用几个配置文件在用户登录系统时自动启动可执行文件，这些文件可能包含恶意软件的痕迹。

* _**/etc/profile.d/\***_ , _**/etc/profile**_ , _**/etc/bash.bashrc**_ 在任何用户账户登录时执行。
* _**∼/.bashrc**_ , _**∼/.bash\_profile**_ , _**\~/.profile**_ , _**∼/.config/autostart**_ 在特定用户登录时执行。
* _**/etc/rc.local**_ 传统上在所有正常系统服务启动后执行，即在切换到多用户运行级别的过程结束时。

## 检查日志

在受损系统上查找所有可用的日志文件，以寻找恶意执行和相关活动的痕迹，例如创建新服务。

### 纯日志

记录在系统和安全日志中的**登录**事件，包括通过网络登录，可以揭示**恶意软件**或**入侵者**在特定时间通过给定账户访问受损系统的情况。系统日志中可以捕获与恶意软件感染相关的其他事件，包括在事件发生时创建**新服务**或新账户。\
有趣的系统登录日志：

* **/var/log/syslog** (debian) 或 **/var/log/messages** (Redhat)
* 显示系统的一般消息和信息。这是全局系统活动的数据日志。
* **/var/log/auth.log** (debian) 或 **/var/log/secure** (Redhat)
* 保存成功或失败的登录和认证过程的认证日志。存储位置取决于系统类型。
* `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**：启动消息和引导信息。
* **/var/log/maillog** 或 **var/log/mail.log**：用于邮件服务器日志，方便查看在服务器上运行的 postfix、smtpd 或与电子邮件相关的服务信息。
* **/var/log/kern.log**：保存内核日志和警告信息。内核活动日志（例如 dmesg、kern.log、klog）可以显示特定服务的重复崩溃，可能表明安装了不稳定的木马版本。
* **/var/log/dmesg**：设备驱动程序消息的存储库。使用 **dmesg** 命令查看此文件中的消息。
* **/var/log/faillog**：记录失败的登录信息。因此，用于检查潜在的安全漏洞，如登录凭据被盗和暴力攻击。
* **/var/log/cron**：记录与 Crond 相关的消息（cron 作业）。例如，cron 守护程序启动作业的时间。
* **/var/log/daemon.log**：跟踪运行的后台服务，但不以图形方式表示。
* **/var/log/btmp**：记录所有失败的登录尝试。
* **/var/log/httpd/**：包含 Apache httpd 守护程序的 error\_log 和 access\_log 文件的目录。所有 httpd 遇到的错误都记录在 **error\_log** 文件中。考虑内存问题和其他与系统相关的错误。**access\_log** 记录通过 HTTP 进入的所有请求。
* **/var/log/mysqld.log** 或 **/var/log/mysql.log**：记录每个调试、失败和成功消息的 MySQL 日志文件，包括 MySQL 守护程序 mysqld 的启动、停止和重启。系统根据目录决定。RedHat、CentOS、Fedora 和其他基于 RedHat 的系统使用 /var/log/mariadb/mariadb.log。然而，Debian/Ubuntu 使用 /var/log/mysql/error.log 目录。
* **/var/log/xferlog**：保存 FTP 文件传输会话。包括文件名和用户发起的 FTP 传输等信息。
* **/var/log/\***：始终应检查此目录中的意外日志

{% hint style="info" %}
在入侵或恶意软件事件中，Linux系统的日志和审计子系统可能被禁用或删除。由于Linux系统的日志通常包含有关恶意活动的最有用信息，入侵者经常删除它们。因此，在检查可用的日志文件时，重要的是查找可能表示删除或篡改的间隙或乱序条目。
{% endhint %}

### 命令历史

许多Linux系统配置为为每个用户账户维护命令历史记录：

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### 登录

使用命令 `last -Faiwx` 可以获取已登录用户的列表。\
建议检查这些登录是否合理：

* 有任何未知用户吗？
* 有任何不应该登录的用户吗？

这很重要，因为**攻击者**有时可能将 `/bin/bash` 复制到 `/bin/false` 中，以便像 **lightdm** 这样的用户可以登录。

注意，您也可以通过阅读日志来查看此信息。
### 应用程序痕迹

* **SSH**: 使用SSH连接到受损系统或从受损系统连接到其他系统会在每个用户帐户的文件中留下记录（_**∼/.ssh/authorized\_keys**_ 和 _**∼/.ssh/known\_keys**_）。这些记录可以显示远程主机的主机名或IP地址。
* **Gnome桌面**: 用户帐户可能有一个 _**∼/.recently-used.xbel**_ 文件，其中包含有关在Gnome桌面上运行的应用程序最近访问的文件的信息。
* **VIM**: 用户帐户可能有一个 _**∼/.viminfo**_ 文件，其中包含有关VIM使用情况的详细信息，包括搜索字符串历史和使用vim打开的文件的路径。
* **Open Office**: 最近使用的文件。
* **MySQL**: 用户帐户可能有一个 _**∼/.mysql\_history**_ 文件，其中包含使用MySQL执行的查询。
* **Less**: 用户帐户可能有一个 _**∼/.lesshst**_ 文件，其中包含有关less使用情况的详细信息，包括搜索字符串历史和通过less执行的shell命令。

### USB日志

[**usbrip**](https://github.com/snovvcrash/usbrip) 是一个用纯Python 3编写的小型软件，用于解析Linux日志文件（根据发行版，可能是`/var/log/syslog*`或`/var/log/messages*`）以构建USB事件历史记录表。

了解所有已使用的USB设备是很有趣的，如果您有一个授权的USB设备列表，那么查找"违规事件"（使用不在该列表中的USB设备）将更加有用。

### 安装
```
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 示例

#### Example 1: Collecting Volatile Data

#### 示例 1：收集易失性数据

In this example, we will demonstrate how to collect volatile data from a Linux system using various command-line tools.

在这个示例中，我们将演示如何使用各种命令行工具从Linux系统中收集易失性数据。

1. **Step 1**: Identify the running processes

   **步骤 1**：识别正在运行的进程

   Use the `ps` command to list all the running processes on the system.

   使用 `ps` 命令列出系统上所有正在运行的进程。

   ```bash
   ps aux
   ```

2. **Step 2**: Capture network connections

   **步骤 2**：捕获网络连接

   Use the `netstat` command to capture information about active network connections.

   使用 `netstat` 命令捕获有关活动网络连接的信息。

   ```bash
   netstat -antp
   ```

3. **Step 3**: Check open files

   **步骤 3**：检查打开的文件

   Use the `lsof` command to check which files are currently open by the processes.

   使用 `lsof` 命令检查进程当前打开的文件。

   ```bash
   lsof
   ```

4. **Step 4**: View system logs

   **步骤 4**：查看系统日志

   Use the `dmesg` command to view the kernel ring buffer and system logs.

   使用 `dmesg` 命令查看内核环形缓冲区和系统日志。

   ```bash
   dmesg
   ```

5. **Step 5**: Collect memory dump

   **步骤 5**：收集内存转储

   Use the `dd` command to create a memory dump file.

   使用 `dd` 命令创建一个内存转储文件。

   ```bash
   dd if=/dev/mem of=memory_dump.dd bs=1M count=1024
   ```

6. **Step 6**: Analyze the collected data

   **步骤 6**：分析收集的数据

   Use various tools like `strings`, `grep`, and `hexdump` to analyze the collected data.

   使用 `strings`、`grep` 和 `hexdump` 等各种工具来分析收集的数据。

   ```bash
   strings memory_dump.dd | grep "password"
   hexdump -C memory_dump.dd
   ```

By following these steps, you can collect volatile data from a Linux system and analyze it for potential security issues or evidence of malicious activity.

通过按照这些步骤，您可以从Linux系统中收集易失性数据，并分析其中的潜在安全问题或恶意活动的证据。
```
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
更多示例和信息请参考GitHub：[https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 检查用户账户和登录活动

检查 _**/etc/passwd**_、_**/etc/shadow**_ 和 **安全日志**，查找与已知未经授权事件密切相关的异常名称或账户的创建和使用。还要检查可能的sudo暴力攻击。\
此外，检查 _**/etc/sudoers**_ 和 _**/etc/groups**_ 等文件，查找给用户授予的意外特权。\
最后，查找没有密码或密码容易猜测的账户。

## 检查文件系统

文件系统数据结构可以提供与恶意软件事件相关的大量**信息**，包括事件的**时间**和**恶意软件**的实际**内容**。\
恶意软件越来越多地被设计为**阻碍文件系统分析**。一些恶意软件会更改恶意文件的日期时间戳，以使时间线分析更加困难。其他恶意代码被设计为仅将某些信息存储在内存中，以最小化存储在文件系统中的数据量。\
为了应对这些反取证技术，有必要**仔细关注文件系统日期时间戳的时间线分析**，以及存储在可能发现恶意软件的常见位置的文件。

* 使用 **autopsy** 可以查看可能有助于发现可疑活动的事件时间线。您还可以直接使用 **Sleuth Kit** 的 `mactime` 功能。
* 检查 **$PATH** 内是否有意外的脚本（可能是一些sh或php脚本？）
* `/dev` 中的文件曾经是特殊文件，您可能会在这里找到与恶意软件相关的非特殊文件。
* 查找异常或**隐藏的文件**和**目录**，例如“.. ”（点 点 空格）或“..^G ”（点 点 控制-G）
* 系统上的 /bin/bash 的 Setuid 副本 `find / -user root -perm -04000 –print`
* 检查已删除的**inode的日期时间戳**，如果在同一时间删除了大量文件，则可能表明恶意活动，例如安装了rootkit或木马服务。
* 由于inode是按照下一个可用的方式分配的，因此在大约相同时间放置在系统上的恶意文件可能会被分配连续的inode。因此，在定位到恶意软件的一个组件后，检查相邻的inode可能会很有成效。
* 还要检查像 _/bin_ 或 _/sbin_ 这样的目录，因为新文件或修改文件的**修改时间**可能很有趣。
* 按创建日期对目录中的文件和文件夹进行排序，以查看最近的文件或文件夹（通常是最后一个）。

您可以使用 `ls -laR --sort=time /bin` 检查文件夹中最近的文件。\
您可以使用 `ls -lai /bin |sort -n` 检查文件夹中文件的inode。

{% hint style="info" %}
请注意，**攻击者**可以**修改时间**以使**文件看起来合法**，但他**无法修改inode**。如果您发现一个文件表明它的创建和修改时间与同一文件夹中的其他文件相同，但是**inode**却**意外地更大**，那么该文件的时间戳已被修改。
{% endhint %}

## 比较不同文件系统版本的文件

#### 查找添加的文件
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### 查找修改的内容

When conducting a forensic investigation on a Linux system, it is important to identify any modified content that may be relevant to the case. This can include modified files, directories, or system configurations.

To find modified content, you can use various tools and techniques. One common approach is to compare the current state of the system with a known good state. This can be done by creating a baseline of the system's files and configurations, and then comparing it with the current state.

One tool that can be used for this purpose is the `find` command. By using the `-newer` option, you can search for files that have been modified after a specific date and time. For example, the following command will find all files modified within the last 24 hours:

```
find / -type f -newermt "24 hours ago"
```

You can also use the `stat` command to obtain detailed information about a file, including its modification time. For example, the following command will display the modification time of a file:

```
stat <file_path>
```

Additionally, you can check the system logs for any suspicious activities or modifications. The `/var/log` directory contains various log files that can provide valuable information about system events.

By identifying and analyzing modified content, you can gain insights into the actions taken on the system and potentially uncover evidence relevant to your investigation.
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### 查找已删除的文件

When conducting Linux forensics, it is important to be able to find deleted files. Even though a file may have been deleted, it is often still recoverable from the file system.

在进行Linux取证时，能够找到已删除的文件非常重要。即使文件已被删除，通常仍然可以从文件系统中恢复。

One way to find deleted files is by using the `grep` command to search for specific file signatures within the unallocated space of a disk image. File signatures are unique patterns of bytes that can be used to identify the file type.

一种查找已删除文件的方法是使用`grep`命令在磁盘镜像的未分配空间中搜索特定的文件签名。文件签名是用于识别文件类型的唯一字节模式。

To search for deleted files using `grep`, you can use the following command:

使用`grep`搜索已删除文件，可以使用以下命令：

```bash
grep -a -b -E -o -P '<file_signature>' <disk_image>
```

- The `-a` option treats the disk image as a text file.
- The `-b` option prints the byte offset of the matching pattern.
- The `-E` option enables extended regular expressions.
- The `-o` option prints only the matching part of the line.
- The `-P` option enables Perl-compatible regular expressions.

- `-a`选项将磁盘镜像视为文本文件。
- `-b`选项打印匹配模式的字节偏移量。
- `-E`选项启用扩展正则表达式。
- `-o`选项仅打印行的匹配部分。
- `-P`选项启用Perl兼容的正则表达式。

Replace `<file_signature>` with the specific file signature you want to search for, and `<disk_image>` with the path to the disk image file.

将`<file_signature>`替换为要搜索的特定文件签名，将`<disk_image>`替换为磁盘镜像文件的路径。

By searching for file signatures within the unallocated space, you may be able to find deleted files that can provide valuable evidence during a forensic investigation.

通过在未分配空间中搜索文件签名，您可能能够找到已删除的文件，这些文件可以在取证调查中提供有价值的证据。
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### 其他过滤器

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

仅选择已添加（`A`）、已复制（`C`）、已删除（`D`）、已修改（`M`）、已重命名（`R`）的文件，并且其类型（即常规文件、符号链接、子模块等）已更改（`T`）、未合并（`U`）、未知（`X`）或已破坏配对（`B`）。可以使用任意组合的过滤字符（包括无）。当将`*`（全部或无）添加到组合中时，如果比较中存在与其他条件匹配的文件，则选择所有路径；如果没有与其他条件匹配的文件，则不选择任何内容。

此外，这些大写字母可以转换为小写字母以进行排除。例如，`--diff-filter=ad`排除已添加和已删除的路径。

请注意，并非所有的差异都可以包含所有类型。例如，从索引到工作树的差异永远不会有已添加的条目（因为差异中包含的路径集受限于索引中的内容）。类似地，如果禁用了对复制和重命名类型的检测，那么复制和重命名条目将不会出现。

## 参考资料

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

* 发现我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

**通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
