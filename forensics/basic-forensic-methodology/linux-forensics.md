# Linux取证

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，利用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 初始信息收集

### 基本信息

首先，建议准备一些带有**已知良好二进制文件和库的USB**（您可以使用Ubuntu并复制文件夹_/bin_，_/sbin_，_/lib_和_/lib64_），然后挂载USB，修改环境变量以使用这些二进制文件：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
一旦您已配置系统以使用良好且已知的二进制文件，您可以开始**提取一些基本信息**：
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

在获取基本信息时，应检查以下异常情况：

- **Root进程**通常以较低的PID运行，因此如果发现一个具有较大PID的Root进程，可能存在可疑情况
- 检查`/etc/passwd`中没有shell的用户的**注册登录**
- 检查`/etc/shadow`中没有shell的用户的**密码哈希值**

### 内存转储

要获取运行系统的内存，建议使用[**LiME**](https://github.com/504ensicsLabs/LiME)。\
要**编译**它，需要使用与受害者机器相同的**内核**。

{% hint style="info" %}
请记住，**不能在受害者机器上安装LiME或任何其他东西**，因为这将对其进行多处更改
{% endhint %}

因此，如果您有一个相同版本的Ubuntu，可以使用`apt-get install lime-forensics-dkms`\
在其他情况下，您需要从github下载[**LiME**](https://github.com/504ensicsLabs/LiME)，并使用正确的内核头文件编译它。要**获取受害者机器的确切内核头文件**，您只需将目录`/lib/modules/<kernel version>`复制到您的机器上，然后使用它们**编译** LiME：
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME支持3种**格式**：

- 原始（每个段连接在一起）
- 填充（与原始相同，但右位填充为零）
- Lime（推荐的带有元数据的格式）

LiME还可以用于通过网络发送转储，而不是将其存储在系统上，使用类似以下的内容：`path=tcp:4444`

### 磁盘成像

#### 关机

首先，您需要**关闭系统**。这并不总是一个选项，因为有时系统将是公司无法关闭的生产服务器。\
有**2种**关闭系统的方式，**正常关闭**和**"拔插头"关闭**。第一种方式将允许**进程像往常一样终止**，**文件系统**也将被**同步**，但也会允许可能的**恶意软件**来**销毁证据**。"拔插头"方法可能会带来**一些信息丢失**（不会丢失太多信息，因为我们已经对内存进行了镜像），而**恶意软件将无法对此做任何事情**。因此，如果您**怀疑**可能存在**恶意软件**，只需在系统上执行**`sync`** **命令**然后拔掉电源插头。

#### 对磁盘进行成像

重要的是要注意，在**将计算机连接到与案件相关的任何内容之前**，您需要确保它将以**只读**方式挂载，以避免修改任何信息。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### 磁盘映像预分析

使用没有更多数据的磁盘映像。
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)轻松构建和**自动化工作流**，利用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 搜索已知恶意软件

### 修改过的系统文件

一些Linux系统具有**验证许多已安装组件完整性**的功能，提供了一种有效的识别异常或位置不对的文件的方式。例如，在Linux上，`rpm -Va`旨在验证所有使用RedHat软件包管理器安装的软件包。
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### 恶意软件/Rootkit 检测器

阅读以下页面以了解可用于查找恶意软件的工具：

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## 搜索已安装的程序

### 软件包管理器

在基于 Debian 的系统中，_**/var/ lib/dpkg/status**_ 文件包含有关已安装软件包的详细信息，而 _**/var/log/dpkg.log**_ 文件记录了软件包安装时的信息。\
在 RedHat 及相关的 Linux 发行版中，**`rpm -qa --root=/ mntpath/var/lib/rpm`** 命令将列出系统上 RPM 数据库的内容。
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### 其他

**并非所有已安装的程序都会在上述命令中列出**，因为某些应用程序在某些系统上不作为软件包提供，必须从源代码安装。因此，检查诸如 _**/usr/local**_ 和 _**/opt**_ 等位置可能会发现其他已从源代码编译并安装的应用程序。
```bash
ls /opt /usr/local
```
另一个好主意是**检查**`$PATH`中的**常见文件夹**，查找与**已安装软件包无关**的**可执行文件**：
```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)轻松构建并**自动化**由全球**最先进**的社区工具驱动的工作流。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 恢复已删除的运行二进制文件

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

恶意软件经常会将自己深入嵌入为一个新的未经授权的服务。Linux有许多脚本用于在计算机启动时启动服务。初始化启动脚本 _**/etc/inittab**_ 调用其他脚本，如 rc.sysinit 和 _**/etc/rc.d/**_ 目录下的各种启动脚本，或者在一些旧版本中是 _**/etc/rc.boot/**_。在其他版本的Linux中，如Debian，启动脚本存储在 _**/etc/init.d/**_ 目录中。此外，一些常见服务在 _**/etc/inetd.conf**_ 或 _**/etc/xinetd/**_ 中启用，具体取决于Linux的版本。数字取证人员应检查每个启动脚本中是否存在异常条目。

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### 内核模块

在Linux系统中，内核模块通常被用作恶意软件包的rootkit组件。内核模块是根据 `/lib/modules/'uname -r'` 和 `/etc/modprobe.d` 目录中的配置信息以及 `/etc/modprobe` 或 `/etc/modprobe.conf` 文件在系统启动时加载的。应检查这些区域是否存在与恶意软件相关的条目。

### 其他自启动位置

Linux有几个配置文件用于在用户登录系统时自动启动可执行文件，这些文件可能包含恶意软件的痕迹。

* _**/etc/profile.d/\***_ , _**/etc/profile**_ , _**/etc/bash.bashrc**_ 在任何用户帐户登录时执行。
* _**∼/.bashrc**_ , _**∼/.bash\_profile**_ , _**\~/.profile**_ , _**∼/.config/autostart**_ 在特定用户登录时执行。
* _**/etc/rc.local**_ 传统上在所有正常系统服务启动后执行，在切换到多用户运行级别的过程结束时执行。

## 检查日志

在受损系统上查看所有可用的日志文件，以查找恶意执行和相关活动的痕迹，如创建新服务。

### 纯日志

系统和安全日志中记录的**登录**事件，包括通过网络登录，可以显示**恶意软件**或**入侵者**在特定时间通过给定帐户访问受损系统的情况。系统日志中还可以捕获与恶意软件感染时间相关的其他事件，包括在事件发生时创建**新**的**服务**或新帐户。\
有趣的系统登录：

* **/var/log/syslog** (debian) 或 **/var/log/messages** (Redhat)
* 显示有关系统的一般消息和信息。这是全局系统活动的数据日志。
* **/var/log/auth.log** (debian) 或 **/var/log/secure** (Redhat)
* 保留成功或失败登录以及认证过程的认证日志。存储位置取决于系统类型。
* `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**：启动消息和引导信息。
* **/var/log/maillog** 或 **var/log/mail.log**：用于邮件服务器日志，适用于在服务器上运行的postfix、smtpd或与电子邮件相关的服务信息。
* **/var/log/kern.log**：保留内核日志和警告信息。内核活动日志（例如，dmesg、kern.log、klog）可以显示特定服务重复崩溃，可能表明安装了不稳定的木马版本。
* **/var/log/dmesg**：设备驱动程序消息的存储库。使用 **dmesg** 查看此文件中的消息。
* **/var/log/faillog**：记录失败登录的信息。因此，适用于检查潜在的安全漏洞，如登录凭据被盗和暴力攻击。
* **/var/log/cron**：记录与Crond相关的消息（cron作业）。例如，cron守护程序启动作业时。
* **/var/log/daemon.log**：跟踪运行的后台服务，但不以图形方式表示。
* **/var/log/btmp**：记录所有失败的登录尝试。
* **/var/log/httpd/**：包含Apache httpd守护程序的error\_log和access\_log文件的目录。httpd遇到的每个错误都记录在 **error\_log** 文件中。考虑内存问题和其他系统相关错误。**access\_log** 记录通过HTTP进入的所有请求。
* **/var/log/mysqld.log** 或 **/var/log/mysql.log**：记录使用MySQL执行的每个调试、失败和成功消息，包括启动、停止和重新启动MySQL守护程序mysqld。系统决定目录。RedHat、CentOS、Fedora和其他基于RedHat的系统使用 /var/log/mariadb/mariadb.log。但是，Debian/Ubuntu使用 /var/log/mysql/error.log 目录。
* **/var/log/xferlog**：保留FTP文件传输会话。包括文件名和用户发起的FTP传输等信息。
* **/var/log/\***：您应始终检查此目录中的意外日志

{% hint style="info" %}
Linux系统日志和审计子系统可能在入侵或恶意软件事件中被禁用或删除。因为Linux系统上的日志通常包含有关恶意活动的最有用信息，入侵者经常删除它们。因此，在检查可用的日志文件时，重要的是查找可能表示删除或篡改的间隙或顺序不当的条目。
{% endhint %}

### 命令历史

许多Linux系统配置为为每个用户帐户保留命令历史记录：

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### 登录

使用命令 `last -Faiwx` 可以获取已登录用户的列表。\
建议检查这些登录是否合理：

* 任何未知用户？
* 任何不应该有shell登录的用户？

这很重要，因为**攻击者**有时可能会将 `/bin/bash` 复制到 `/bin/false` 中，因此像 **lightdm** 这样的用户可能会**能够登录**。

请注意，您也可以通过阅读日志来查看这些信息。

### 应用程序痕迹

* **SSH**：使用SSH连接到受损系统和从受损系统连接到系统会导致为每个用户帐户在文件中创建条目（_**∼/.ssh/authorized\_keys**_ 和 _**∼/.ssh/known\_keys**_）。这些条目可以显示远程主机的主机名或IP地址。
* **Gnome桌面**：用户帐户可能有一个包含有关在Gnome桌面上运行的应用程序最近访问的文件信息的 _**∼/.recently-used.xbel**_ 文件。
* **VIM**：用户帐户可能有一个包含有关VIM使用的详细信息的 _**∼/.viminfo**_ 文件，包括搜索字符串历史和使用vim打开的文件的路径。
* **Open Office**：最近的文件。
* **MySQL**：用户帐户可能有一个包含使用MySQL执行的查询的 _**∼/.mysql\_history**_ 文件。
* **Less**：用户帐户可能有一个包含有关less使用的详细信息的 _**∼/.lesshst**_ 文件，包括搜索字符串历史和通过less执行的shell命令。

### USB日志

[**usbrip**](https://github.com/snovvcrash/usbrip) 是一个纯Python 3编写的小型软件，用于解析Linux日志文件（取决于发行版，可能是 `/var/log/syslog*` 或 `/var/log/messages*`）以构建USB事件历史表。

了解已使用的所有USB设备是很有趣的，如果您有一个USB设备的授权列表，将更有用，以查找“违规事件”（使用未包含在该列表中的USB设备）。

### 安装
```
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 例子
```
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
更多示例和信息请查看github：[https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流**，利用全球**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 查看用户帐户和登录活动

检查 _**/etc/passwd**_、_**/etc/shadow**_ 和**安全日志**，查找是否有异常名称或在已知未经授权事件附近创建或使用的帐户。还要检查可能的sudo暴力攻击。\
此外，检查 _**/etc/sudoers**_ 和 _**/etc/groups**_ 等文件，查看是否给用户授予了意外的特权。\
最后，查找没有密码或**易于猜测**密码的帐户。

## 检查文件系统

文件系统数据结构可以提供大量与**恶意软件**事件相关的**信息**，包括事件的**时间**和**恶意软件**的实际**内容**。\
**恶意软件**越来越多地被设计为**阻碍文件系统分析**。一些恶意软件会更改恶意文件的日期时间戳，使其更难通过时间线分析找到它们。其他恶意代码被设计为仅在内存中存储某些信息，以最小化存储在文件系统中的数据量。\
为了应对这种反取证技术，有必要**仔细关注文件系统日期时间戳的时间线分析**，以及存储恶意软件可能被发现的常见位置中的文件。

* 使用**autopsy**可以查看可能有助于发现可疑活动的事件时间线。您还可以直接使用**Sleuth Kit**的`mactime`功能。
* 检查**$PATH**中的**意外脚本**（也许是一些sh或php脚本？）
* `/dev`中的文件曾经是特殊文件，您可能会在这里找到与恶意软件相关的非特殊文件。
* 查找异常或**隐藏文件**和**目录**，例如“.. ”（点 点 空格）或“..^G ”（点 点 控制-G）
* 系统上的/bin/bash的setuid副本 `find / -user root -perm -04000 –print`
* 查看已删除**inode的日期时间戳，以查看是否在同一时间删除了大量文件**，这可能表明恶意活动，如安装rootkit或木马服务。
* 因为inode是按照下一个可用基础分配的，**在系统上放置的恶意文件可能在大致相同的时间被分配连续的inode**。因此，在定位恶意软件的一个组件后，检查相邻的inode可能是有效的。
* 还要检查类似 _/bin_ 或 _/sbin_ 的目录，因为新文件或修改文件的**修改时间**可能很有趣。
* 查看一个目录的文件和文件夹按创建日期**排序**，而不是按字母顺序，以查看哪些文件或文件夹是最近的（通常是最后的）。

您可以使用 `ls -laR --sort=time /bin` 检查一个文件夹中最近的文件\
您可以使用 `ls -lai /bin |sort -n` 检查文件夹中文件的inode

{% hint style="info" %}
请注意，**攻击者**可以**修改**时间使**文件看起来** **合法**，但他**无法修改**inode。如果发现一个**文件**的创建和修改时间与同一文件夹中其他文件的时间相同，但**inode**意外地更大，则该**文件的时间戳已被修改**。
{% endhint %}

## 比较不同文件系统版本的文件

#### 查找添加的文件
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### 寻找修改过的内容
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### 寻找已删除的文件
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### 其他过滤器

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

仅选择文件类型为已添加 (`A`)、已复制 (`C`)、已删除 (`D`)、已修改 (`M`)、已重命名 (`R`)、类型已更改 (`T`)、未合并 (`U`)、未知 (`X`) 或已配对破损 (`B`) 的文件。可以使用过滤字符的任意组合（包括无）。当在组合中添加 `*`（全部或无）时，如果有任何文件符合比较中的其他条件，则选择所有路径；如果没有文件符合其他条件，则不选择任何内容。

此外，**这些大写字母可以转换为小写以排除**。例如，`--diff-filter=ad` 排除了已添加和已删除的路径。

请注意，并非所有差异都可以包含所有类型。例如，从索引到工作树的差异永远不会包含已添加条目（因为差异中包含的路径集受限于索引中的内容）。同样，如果禁用了这些类型的检测，则无法出现已复制和已重命名的条目。

## 参考资料

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

您在**网络安全公司**工作吗？您想在 HackTricks 中看到您的**公司广告**吗？或者您想访问**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

* 发现我们的独家[NFTs 集合](https://opensea.io/collection/the-peass-family)，[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md) **@carlospolopm**](https://twitter.com/hacktricks\_live)**。**

**通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享您的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 可轻松构建和**自动化工作流程**，使用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
