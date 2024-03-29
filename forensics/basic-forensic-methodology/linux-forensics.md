# Linux取证

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和**自动化工作流程**，利用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 初始信息收集

### 基本信息

首先，建议准备一些带有**已知良好的二进制文件和库的USB**（您可以只需获取ubuntu并复制文件夹_/bin_，_/sbin_，_/lib_和_/lib64_），然后挂载USB，并修改环境变量以使用这些二进制文件：
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

为了获取运行中系统的内存，建议使用[**LiME**](https://github.com/504ensicsLabs/LiME)。\
要进行**编译**，需要使用受害机器正在使用的**相同内核**。

{% hint style="info" %}
请记住，**不能在受害机器上安装LiME或任何其他内容**，因为这将对其进行多处更改
{% endhint %}

因此，如果你有一个与Ubuntu相同版本的系统，可以使用`apt-get install lime-forensics-dkms`\
在其他情况下，您需要从github下载[**LiME**](https://github.com/504ensicsLabs/LiME)，并使用正确的内核头文件进行编译。要**获取受害机器的确切内核头文件**，只需将目录`/lib/modules/<kernel version>`复制到您的机器上，然后使用它们**编译** LiME：
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
有**2种**关闭系统的方式，**正常关闭**和**"拔插头"关闭**。第一种方式将允许**进程像往常一样终止**，并且**文件系统**将被**同步**，但也会允许可能的**恶意软件**来**销毁证据**。"拔插头"方法可能会带来**一些信息丢失**（不会丢失太多信息，因为我们已经对内存进行了图像拍摄），并且**恶意软件将没有任何机会**对此做任何事情。因此，如果您**怀疑**可能存在**恶意软件**，只需在系统上执行**`sync`** **命令**，然后拔掉插头。

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

使用无更多数据的磁盘映像。
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和**自动化工作流**，利用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 搜索已知恶意软件

### 修改过的系统文件

Linux提供了用于确保系统组件完整性的工具，这对于发现潜在问题文件至关重要。

* **基于RedHat的系统**：使用 `rpm -Va` 进行全面检查。
* **基于Debian的系统**：首先使用 `dpkg --verify` 进行初始验证，然后使用 `debsums | grep -v "OK$"`（在使用 `apt-get install debsums` 安装 `debsums` 后）来识别任何问题。

### 恶意软件/Rootkit检测器

阅读以下页面，了解可用于查找恶意软件的工具：

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## 搜索已安装程序

要有效地搜索Debian和RedHat系统上已安装的程序，考虑在常见目录中手动检查的同时，结合系统日志和数据库。

* 对于Debian，检查 _**`/var/lib/dpkg/status`**_ 和 _**`/var/log/dpkg.log`**_ 以获取有关软件包安装的详细信息，使用 `grep` 过滤特定信息。
* RedHat用户可以使用 `rpm -qa --root=/mntpath/var/lib/rpm` 查询RPM数据库以列出已安装的软件包。

要查找手动安装或超出这些软件包管理器范围的软件，请探索目录如 _**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_ 和 _**`/sbin`**_。将目录列表与特定于系统的命令结合使用，以识别与已知软件包不相关的可执行文件，增强您对所有已安装程序的搜索。
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)轻松构建并由全球**最先进**的社区工具驱动的**自动化工作流程**。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 恢复已删除的运行二进制文件

想象一个从/tmp/exec执行并被删除的进程。可以提取它。
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
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

恶意软件可能安装为服务的路径：

- **/etc/inittab**：调用初始化脚本如rc.sysinit，进一步指向启动脚本。
- **/etc/rc.d/** 和 **/etc/rc.boot/**：包含用于服务启动的脚本，后者在旧版Linux中找到。
- **/etc/init.d/**：在某些Linux版本（如Debian）中用于存储启动脚本。
- 服务也可以通过 **/etc/inetd.conf** 或 **/etc/xinetd/** 激活，取决于Linux变体。
- **/etc/systemd/system**：系统和服务管理器脚本的目录。
- **/etc/systemd/system/multi-user.target.wants/**：包含应在多用户运行级别中启动的服务的链接。
- **/usr/local/etc/rc.d/**：用于自定义或第三方服务。
- **\~/.config/autostart/**：用于特定用户的自动启动应用程序，可能是用户定向恶意软件的隐藏位置。
- **/lib/systemd/system/**：由安装的软件包提供的系统范围默认单元文件。

### 内核模块

Linux内核模块，恶意软件常用作rootkit组件，在系统启动时加载。这些模块的关键目录和文件包括：

- **/lib/modules/$(uname -r)**：保存运行的内核版本的模块。
- **/etc/modprobe.d**：包含控制模块加载的配置文件。
- **/etc/modprobe** 和 **/etc/modprobe.conf**：全局模块设置的文件。

### 其他自动启动位置

Linux使用各种文件在用户登录时自动执行程序，可能隐藏恶意软件：

- **/etc/profile.d/**\*、**/etc/profile** 和 **/etc/bash.bashrc**：任何用户登录时执行。
- **\~/.bashrc**、**\~/.bash\_profile**、**\~/.profile** 和 **\~/.config/autostart**：用户特定文件，在其登录时运行。
- **/etc/rc.local**：在所有系统服务启动后运行，标志着过渡到多用户环境的结束。

## 检查日志

Linux系统通过各种日志文件跟踪用户活动和系统事件。这些日志对于识别未经授权的访问、恶意软件感染和其他安全事件至关重要。关键日志文件包括：

- **/var/log/syslog**（Debian）或 **/var/log/messages**（RedHat）：捕获系统范围的消息和活动。
- **/var/log/auth.log**（Debian）或 **/var/log/secure**（RedHat）：记录认证尝试、成功和失败的登录。
- 使用 `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` 过滤相关认证事件。
- **/var/log/boot.log**：包含系统启动消息。
- **/var/log/maillog** 或 **/var/log/mail.log**：记录电子邮件服务器活动，有助于跟踪与电子邮件相关的服务。
- **/var/log/kern.log**：存储内核消息，包括错误和警告。
- **/var/log/dmesg**：保存设备驱动程序消息。
- **/var/log/faillog**：记录失败的登录尝试，有助于安全事件调查。
- **/var/log/cron**：记录cron作业执行。
- **/var/log/daemon.log**：跟踪后台服务活动。
- **/var/log/btmp**：记录失败的登录尝试。
- **/var/log/httpd/**：包含Apache HTTPD错误和访问日志。
- **/var/log/mysqld.log** 或 **/var/log/mysql.log**：记录MySQL数据库活动。
- **/var/log/xferlog**：记录FTP文件传输。
- **/var/log/**：始终检查意外日志。

{% hint style="info" %}
Linux系统日志和审计子系统可能在入侵或恶意软件事件中被禁用或删除。因为Linux系统上的日志通常包含有关恶意活动的最有用信息，入侵者经常删除它们。因此，在检查可用的日志文件时，重要的是查找可能表示删除或篡改的间隙或顺序不当的条目。
{% endhint %}

**Linux为每个用户维护一个命令历史记录**，存储在：

- \~/.bash\_history
- \~/.zsh\_history
- \~/.zsh\_sessions/\*
- \~/.python\_history
- \~/.\*\_history

此外，`last -Faiwx` 命令提供用户登录列表。检查其中是否有未知或意外的登录。

检查可能授予额外权限的文件：

- 检查 `/etc/sudoers` 是否授予了意外的用户权限。
- 检查 `/etc/sudoers.d/` 是否授予了意外的用户权限。
- 检查 `/etc/groups` 以识别任何异常的组成员或权限。
- 检查 `/etc/passwd` 以识别任何异常的组成员或权限。

一些应用程序还会生成自己的日志：

- **SSH**：检查 _\~/.ssh/authorized\_keys_ 和 _\~/.ssh/known\_hosts_ 是否存在未经授权的远程连接。
- **Gnome桌面**：查看 _\~/.recently-used.xbel_ 以查找通过Gnome应用程序最近访问的文件。
- **Firefox/Chrome**：检查 _\~/.mozilla/firefox_ 或 _\~/.config/google-chrome_ 中的浏览器历史记录和下载，以查找可疑活动。
- **VIM**：查看 _\~/.viminfo_ 以获取使用详细信息，如访问的文件路径和搜索历史。
- **Open Office**：检查最近访问的文档，可能指示文件受到 compromise。
- **FTP/SFTP**：查看 _\~/.ftp\_history_ 或 _\~/.sftp\_history_ 中的日志，以查找可能未经授权的文件传输。
- **MySQL**：调查 _\~/.mysql\_history_ 中执行的MySQL查询，可能揭示未经授权的数据库活动。
- **Less**：分析 _\~/.lesshst_ 以获取使用历史，包括查看的文件和执行的命令。
- **Git**：检查 _\~/.gitconfig_ 和项目 _.git/logs_ 中的更改。

### USB日志

[**usbrip**](https://github.com/snovvcrash/usbrip) 是一款纯Python 3编写的小型软件，用于解析Linux日志文件（取决于发行版，可能是`/var/log/syslog*`或`/var/log/messages*`）以构建USB事件历史表。

了解所有已使用的USB设备是很有趣的，如果您有授权的USB设备列表，将更有用，以查找“违规事件”（使用不在该列表中的USB设备）。 

### 安装
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 例子
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
更多示例和信息请查看github：[https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，利用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 查看用户帐户和登录活动

检查 _**/etc/passwd**_、_**/etc/shadow**_ 和**安全日志**，查找是否有异常名称或在已知未经授权事件附近创建或使用的帐户。还要检查可能的sudo暴力攻击。\
此外，检查 _**/etc/sudoers**_ 和 _**/etc/groups**_ 等文件，查看是否给用户授予了意外的特权。\
最后，查找没有密码或**易于猜测**密码的帐户。

## 检查文件系统

### 在恶意软件调查中分析文件系统结构

在调查恶意软件事件时，文件系统的结构是信息的重要来源，可以揭示事件序列和恶意软件的内容。然而，恶意软件作者正在开发技术来阻碍这种分析，例如修改文件时间戳或避免使用文件系统进行数据存储。

为了对抗这些反取证方法，重要的是：

* 使用工具如**Autopsy**进行彻底的时间线分析，可视化事件时间线，或使用**Sleuth Kit**的`mactime`获取详细的时间线数据。
* 检查系统的$PATH中的意外脚本，这些脚本可能包括攻击者使用的shell或PHP脚本。
* 检查`/dev`中的非典型文件，因为它传统上包含特殊文件，但可能包含与恶意软件相关的文件。
* 搜索具有类似“.. ”（点 点 空格）或“..^G”（点 点 控制-G）名称的隐藏文件或目录，这些文件可能隐藏恶意内容。
* 使用命令`find / -user root -perm -04000 -print`识别setuid root文件，这会找到具有提升权限的文件，可能会被攻击者滥用。
* 检查inode表中的删除时间戳，以发现大量文件删除，可能表明存在rootkit或特洛伊木马。
* 在识别一个恶意文件后，检查相邻的inode，因为它们可能被放在一起。
* 检查常见的二进制目录（_/bin_、_/sbin_）中最近修改的文件，因为这些文件可能被恶意软件更改。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
请注意，**攻击者** 可以**修改**时间以使文件看起来**合法**，但他**无法**修改**inode**。如果您发现一个**文件**表明它是在与同一文件夹中的其他文件**相同时间**创建和修改的，但**inode**却**意外地更大**，那么该文件的**时间戳已被修改**。
{% endhint %}

## 比较不同文件系统版本的文件

### 文件系统版本比较摘要

要比较文件系统版本并准确定位更改，我们使用简化的 `git diff` 命令：

* **查找新文件**，比较两个目录：
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **对于修改后的内容**，列出更改，忽略特定行：
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **检测已删除的文件**：
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **筛选选项** (`--diff-filter`) 有助于缩小范围，如添加 (`A`)、删除 (`D`) 或修改 (`M`) 文件。
* `A`: 添加的文件
* `C`: 复制的文件
* `D`: 删除的文件
* `M`: 修改的文件
* `R`: 重命名的文件
* `T`: 类型更改（例如，文件到符号链接）
* `U`: 未合并的文件
* `X`: 未知的文件
* `B`: 损坏的文件

## 参考资料

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **书籍: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

您在**网络安全公司**工作吗？ 想要在 HackTricks 中看到您的**公司广告**吗？ 或者想要访问**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

* 探索[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们独家的[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord 群组**](https://discord.gg/hRep4RUj7f) 或 **电报群组** 或在 **Twitter** 上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享您的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 可轻松构建和**自动化工作流程**，利用世界上**最先进**的社区工具。\
立即获取访问权限:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
