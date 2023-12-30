# Linux 取证

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

其他支持 HackTricks 的方式：

* 如果你想在 HackTricks 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享你的黑客技巧。

</details>

## 初始信息收集

### 基本信息

首先，建议携带一个**USB**，里面有**已知良好的二进制文件和库**（你可以直接获取 ubuntu 并复制 _/bin_、_/sbin_、_/lib_ 和 _/lib64_ 文件夹），然后挂载 USB，并修改环境变量以使用这些二进制文件：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
一旦您配置系统使用良好且已知的二进制文件，您可以开始**提取一些基本信息**：
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

在获取基本信息时，你应该检查一些异常情况，比如：

* **Root 进程** 通常具有较低的 PIDS，因此如果你发现一个具有较大 PID 的 root 进程，你可能会怀疑
* 检查 `/etc/passwd` 中没有 shell 的用户的**注册登录**
* 检查 `/etc/shadow` 中没有 shell 的用户的**密码哈希**

### 内存转储

要获取正在运行的系统的内存，建议使用 [**LiME**](https://github.com/504ensicsLabs/LiME)。\
要**编译**它，你需要使用受害机器正在使用的**相同内核**。

{% hint style="info" %}
记住，你**不能在受害机器上安装 LiME 或任何其他东西**，因为这会对其进行多次更改
{% endhint %}

因此，如果你有一个相同版本的 Ubuntu，你可以使用 `apt-get install lime-forensics-dkms`\
在其他情况下，你需要从 github 下载 [**LiME**](https://github.com/504ensicsLabs/LiME)，并使用正确的内核头文件进行编译。要**获取受害机器的确切内核头文件**，你可以简单地**复制目录** `/lib/modules/<kernel version>` 到你的机器，然后使用它们**编译** LiME：
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME支持3种**格式**：

* Raw（每个段连续拼接在一起）
* Padded（与raw相同，但右侧位用零填充）
* Lime（带有元数据的推荐格式）

LiME还可以用来**通过网络发送转储**，而不是将其存储在系统上，使用类似：`path=tcp:4444`

### 磁盘成像

#### 关机

首先，你需要**关闭系统**。这并不总是一个选项，因为有时系统会是公司无法承受关闭的生产服务器。\
有**两种**关闭系统的方法，一种是**正常关机**，另一种是**"拔插头"关机**。前者将允许**进程正常终止**和**文件系统**被**同步**，但它也会允许可能的**恶意软件**来**销毁证据**。"拔插头"方法可能会带来**一些信息丢失**（不会丢失太多信息，因为我们已经取得了内存的镜像），并且**恶意软件将没有任何机会**做任何事情。因此，如果你**怀疑**可能有**恶意软件**，只需在系统上执行**`sync`** **命令**然后拔掉电源。

#### 获取磁盘镜像

重要的是要注意，在**连接你的计算机到任何与案件相关的东西之前**，你需要确保它将被**以只读方式挂载**，以避免修改任何信息。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### 磁盘映像预分析

对一个没有更多数据的磁盘映像进行成像。
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 来轻松构建并**自动化工作流程**，这些工作流程由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 搜索已知恶意软件

### 修改过的系统文件

一些 Linux 系统具有**验证许多已安装组件的完整性**的功能，这提供了一种有效的方法来识别不寻常或不合适的文件。例如，Linux 上的 `rpm -Va` 旨在验证使用 RedHat 包管理器安装的所有包。
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### 恶意软件/Rootkit 检测器

阅读以下页面以了解有助于发现恶意软件的工具：

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## 搜索已安装的程序

### 包管理器

在基于Debian的系统中，_**/var/lib/dpkg/status**_ 文件包含已安装包的详细信息，而 _**/var/log/dpkg.log**_ 文件记录了包安装时的信息。\
在RedHat及相关Linux发行版中，**`rpm -qa --root=/mntpath/var/lib/rpm`** 命令将列出系统上RPM数据库的内容。
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### 其他

**并非所有已安装的程序都会通过上述命令列出**，因为某些应用程序对于特定系统来说并不提供包形式，必须从源代码安装。因此，检查像 _**/usr/local**_ 和 _**/opt**_ 这样的位置可能会发现其他已经从源代码编译并安装的应用程序。
```bash
ls /opt /usr/local
```
另一个好主意是**检查**位于**$PATH**中的**常见文件夹**，寻找与**已安装包无关的二进制文件：**
```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```
```markdown
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 来轻松构建并**自动化工作流程**，这些工作流程由世界上**最先进**的社区工具提供支持。
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 恢复已删除的运行中二进制文件

![](<../../.gitbook/assets/image (641).png>)

## 检查自启动位置

### 计划任务
```
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

恶意软件通常会将自己伪装成一个新的、未经授权的服务。Linux有许多脚本用于在计算机启动时启动服务。初始化启动脚本 _**/etc/inittab**_ 会调用其他脚本，如rc.sysinit以及位于 _**/etc/rc.d/**_ 目录下的各种启动脚本，或在某些较旧版本中的 _**/etc/rc.boot/**_。在其他版本的Linux中，如Debian，启动脚本存储在 _**/etc/init.d/**_ 目录中。此外，一些常见服务在 _**/etc/inetd.conf**_ 或 _**/etc/xinetd/**_ 中启用，具体取决于Linux的版本。数字调查员应检查这些启动脚本中的异常条目。

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### 内核模块

在Linux系统上，内核模块通常被用作恶意软件包的rootkit组件。根据 `/lib/modules/'uname -r'` 和 `/etc/modprobe.d` 目录中的配置信息，以及 `/etc/modprobe` 或 `/etc/modprobe.conf` 文件，内核模块在系统启动时加载。应检查这些区域是否有与恶意软件相关的项目。

### 其他自启动位置

Linux使用几个配置文件来在用户登录系统时自动启动可执行文件，这些文件可能包含恶意软件的痕迹。

* _**/etc/profile.d/\***_ ， _**/etc/profile**_ ， _**/etc/bash.bashrc**_ 在任何用户账户登录时执行。
* _**∼/.bashrc**_ ， _**∼/.bash\_profile**_ ， _**\~/.profile**_ ， _**∼/.config/autostart**_ 在特定用户登录时执行。
* _**/etc/rc.local**_ 传统上在所有正常系统服务启动后执行，在切换到多用户运行级别的过程结束时执行。

## 检查日志

检查受损系统上所有可用的日志文件，寻找恶意执行的痕迹和相关活动，如创建新服务。

### 纯日志

**登录** 事件记录在系统和安全日志中，包括通过网络的登录，可以揭示 **恶意软件** 或 **入侵者通过特定账户在特定时间获得了对受损系统的访问**。恶意软件感染时的其他事件也可以在系统日志中捕获，包括在事件发生时创建的 **新** **服务** 或新账户。\
值得关注的系统登录：

* **/var/log/syslog** (debian) 或 **/var/log/messages** (Redhat)
* 显示系统的一般消息和信息。它是全局系统所有活动的数据日志。
* **/var/log/auth.log** (debian) 或 **/var/log/secure** (Redhat)
* 保存成功或失败的登录和认证过程的认证日志。存储取决于系统类型。
* `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**：启动消息和启动信息。
* **/var/log/maillog** 或 **var/log/mail.log**：用于邮件服务器日志，适用于在服务器上运行的postfix、smtpd或与邮件相关的服务信息。
* **/var/log/kern.log**：保存内核日志和警告信息。内核活动日志（例如，dmesg、kern.log、klog）可以显示某个服务反复崩溃，可能表明安装了不稳定的木马化版本。
* **/var/log/dmesg**：设备驱动消息的存储库。使用 **dmesg** 查看此文件中的消息。
* **/var/log/faillog**：记录失败登录的信息。因此，对于检查潜在的安全漏洞，如登录凭证被黑和暴力攻击，非常有用。
* **/var/log/cron**：记录与Crond相关的消息（cron作业）。比如cron守护进程启动作业的时候。
* **/var/log/daemon.log**：跟踪运行中的后台服务，但不以图形方式表示它们。
* **/var/log/btmp**：记录所有失败的登录尝试。
* **/var/log/httpd/**：包含Apache httpd守护进程的error\_log和access\_log文件的目录。httpd遇到的每个错误都保存在 **error\_log** 文件中。考虑内存问题和其他系统相关的错误。**access\_log** 记录通过HTTP收到的所有请求。
* **/var/log/mysqld.log** 或 **/var/log/mysql.log**：MySQL日志文件，记录每个调试、失败和成功消息，包括MySQL守护进程mysqld的启动、停止和重启。系统决定目录。RedHat、CentOS、Fedora和其他基于RedHat的系统使用 /var/log/mariadb/mariadb.log。然而，Debian/Ubuntu使用 /var/log/mysql/error.log 目录。
* **/var/log/xferlog**：保存FTP文件传输会话。包括文件名和用户发起的FTP传输的信息。
* **/var/log/\*** : 您应该始终检查此目录中是否有意外的日志

{% hint style="info" %}
Linux系统日志和审计子系统可能在入侵或恶意软件事件中被禁用或删除。因为Linux系统上的日志通常包含有关恶意活动的最有用信息，入侵者经常删除它们。因此，在检查可用的日志文件时，寻找可能表明删除或篡改的间隙或顺序错误的迹象是很重要的。
{% endhint %}

### 命令历史

许多Linux系统配置为为每个用户账户维护命令历史：

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### 登录

使用命令 `last -Faiwx` 可以获取已登录用户的列表。\
建议检查这些登录是否合理：

* 有未知用户吗？
* 有不应该登录shell的用户吗？

这很重要，因为 **攻击者** 有时可能会将 `/bin/bash` 复制到 `/bin/false` 中，这样像 **lightdm** 这样的用户可能 **能够登录**。

请注意，您也可以通过阅读日志来查看这些信息。

### 应用痕迹

* **SSH**：使用SSH从受损系统到其他系统的连接会在每个用户账户的文件中产生条目（_**∼/.ssh/authorized\_keys**_ 和 _**∼/.ssh/known\_keys**_）。这些条目可以揭示远程主机的主机名或IP地址。
* **Gnome桌面**：用户账户可能有一个 _**∼/.recently-used.xbel**_ 文件，其中包含使用在Gnome桌面上运行的应用程序访问的文件的信息。
* **VIM**：用户账户可能有一个 _**∼/.viminfo**_ 文件，其中包含使用VIM的详细信息，包括搜索字符串历史和使用vim打开的文件路径。
* **Open Office**：最近文件。
* **MySQL**：用户账户可能有一个 _**∼/.mysql\_history**_ 文件，其中包含使用MySQL执行的查询。
* **Less**：用户账户可能有一个 _**∼/.lesshst**_ 文件，其中包含使用less的详细信息，包括搜索字符串历史和通过less执行的shell命令。

### USB日志

[**usbrip**](https://github.com/snovvcrash/usbrip) 是一个用纯Python 3编写的小软件，它解析Linux日志文件（`/var/log/syslog*` 或 `/var/log/messages*`，取决于发行版）以构建USB事件历史表。

了解所有已使用的USB非常有趣，如果您有一个授权的USB列表，找到“违规事件”（未在该列表中的USB的使用）将更有用。

### 安装
```
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 示例
```
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
更多示例和信息请访问GitHub：[https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建并**自动化工作流程**，这些工作流程由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 审查用户账户和登录活动

检查 _**/etc/passwd**_、_**/etc/shadow**_ 和**安全日志**，寻找不寻常的名称或账户，特别是那些在已知未授权事件发生前后创建或使用的账户。同时，检查可能发生的sudo暴力破解攻击。\
此外，检查 _**/etc/sudoers**_ 和 _**/etc/groups**_ 文件，查看是否有给用户意外授权的情况。\
最后，寻找**没有密码**或**容易被猜到密码**的账户。

## 检查文件系统

文件系统的数据结构可以提供大量与**恶意软件**事件相关的**信息**，包括事件的**时间**和恶意软件的实际**内容**。\
**恶意软件**越来越多地被设计来**阻碍文件系统分析**。一些恶意软件会更改恶意文件的日期时间戳，使其更难通过时间线分析被找到。其他恶意代码被设计为仅将某些信息存储在内存中，以最小化文件系统中存储的数据量。\
为了应对这些反取证技术，需要**仔细关注文件系统日期时间戳的时间线分析**，以及恶意软件可能被发现的常见位置中存储的文件。

* 使用 **autopsy** 可以查看可能有助于发现可疑活动的事件时间线。您也可以直接使用 **Sleuth Kit** 的 `mactime` 功能。
* 检查 **$PATH** 中的**意外脚本**（可能是一些sh或php脚本？）
* `/dev` 中的文件过去是特殊文件，您可能会在这里找到与恶意软件相关的非特殊文件。
* 寻找不寻常或**隐藏的文件**和**目录**，例如“.. ”（点点空格）或“..^G ”（点点控制-G）
* 系统上的/bin/bash的Setuid副本 `find / -user root -perm -04000 –print`
* 审查已删除**inodes的日期时间戳，查看是否有大量文件在同一时间被删除**，这可能表明恶意活动，如安装rootkit或木马化服务。
* 由于inodes是按下一个可用基础分配的，**大约在同一时间放置在系统上的恶意文件可能会被分配连续的inodes**。因此，在定位到恶意软件的一个组件后，检查相邻的inodes可能会很有成效。
* 还要检查像 _/bin_ 或 _/sbin_ 这样的目录，因为新文件或修改过的文件的**修改时间或更改时间**可能很有趣。
* 查看按创建日期而非字母顺序排序的目录中的文件和文件夹是很有趣的，以便查看哪些文件或文件夹是最新的（通常是最后的文件夹）。

您可以使用 `ls -laR --sort=time /bin` 检查文件夹中最新的文件\
您可以使用 `ls -lai /bin |sort -n` 检查文件夹内文件的inodes

{% hint style="info" %}
请注意，**攻击者**可以**修改**文件的**时间**以使文件看起来**合法**，但他**不能**修改**inode**。如果您发现一个**文件**显示它是在与同一文件夹中其他文件**同时**创建和修改的，但**inode**却**异常地大**，那么该文件的**时间戳被修改过**。
{% endhint %}

## 比较不同文件系统版本的文件

#### 查找新增文件
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### 查找修改过的内容
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### 查找已删除的文件
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### 其他过滤器

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

仅选择被添加（`A`）、复制（`C`）、删除（`D`）、修改（`M`）、重命名（`R`）的文件，以及那些类型（即常规文件、符号链接、子模块等）发生变化（`T`）、未合并（`U`）、未知（`X`）或配对破裂（`B`）的文件。可以使用过滤字符的任意组合（包括无）。当组合中添加了 `*`（全部或无）时，如果比较中有任何文件符合其他条件，则选择所有路径；如果没有文件符合其他条件，则不选择任何内容。

此外，**这些大写字母可以小写来排除**。例如 `--diff-filter=ad` 排除了添加和删除的路径。

请注意，并非所有差异都能展示所有类型。例如，从索引到工作树的差异永远不会有添加条目（因为差异包含的路径集受到索引中内容的限制）。同样，如果禁用了这些类型的检测，则复制和重命名条目也不会出现。

## 参考资料

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

您在**网络安全公司**工作吗？您想在**HackTricks**中看到您的**公司广告**吗？或者您想要访问**最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* 获取[**官方的 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f)或[**telegram 群组**](https://t.me/peass)或在**Twitter**上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**

通过向[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks)和[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来**分享您的黑客技巧**。

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
