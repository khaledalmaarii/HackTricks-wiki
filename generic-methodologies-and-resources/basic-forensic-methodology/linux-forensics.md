# Linux Forensics

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
今天就获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

{% hint style="success" %}
学习和实践 AWS 渗透测试：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 渗透测试：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

## 初始信息收集

### 基本信息

首先，建议准备一些 **USB**，上面有 **已知的良好二进制文件和库**（你可以直接获取 ubuntu 并复制文件夹 _/bin_, _/sbin_, _/lib,_ 和 _/lib64_），然后挂载 USB，并修改环境变量以使用这些二进制文件：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
一旦您配置系统以使用良好且已知的二进制文件，您就可以开始**提取一些基本信息**：
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

在获取基本信息时，您应该检查一些奇怪的事情，例如：

* **Root 进程** 通常使用低 PIDS，因此如果您发现一个具有大 PID 的 root 进程，您可能会怀疑
* 检查 `/etc/passwd` 中没有 shell 的用户的 **注册登录**
* 检查 `/etc/shadow` 中没有 shell 的用户的 **密码哈希**

### 内存转储

要获取运行系统的内存，建议使用 [**LiME**](https://github.com/504ensicsLabs/LiME)。\
要 **编译** 它，您需要使用受害者机器正在使用的 **相同内核**。

{% hint style="info" %}
请记住，您 **不能在受害者机器上安装 LiME 或其他任何东西**，因为这会对其进行多次更改
{% endhint %}

因此，如果您有一个相同版本的 Ubuntu，您可以使用 `apt-get install lime-forensics-dkms`\
在其他情况下，您需要从 github 下载 [**LiME**](https://github.com/504ensicsLabs/LiME) 并使用正确的内核头文件进行编译。要 **获取受害者机器的确切内核头文件**，您可以直接 **复制目录** `/lib/modules/<kernel version>` 到您的机器，然后使用它们 **编译** LiME：
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 支持 3 **格式**：

* 原始（每个段落连接在一起）
* 填充（与原始相同，但右侧位用零填充）
* Lime（推荐格式，带有元数据）

LiME 还可以用于 **通过网络发送转储**，而不是使用类似 `path=tcp:4444` 的方式将其存储在系统上。

### 磁盘成像

#### 关机

首先，您需要 **关闭系统**。这并不总是一个选项，因为有时系统可能是公司无法承受关闭的生产服务器。\
有 **2 种方法** 可以关闭系统，**正常关机** 和 **“拔掉插头”关机**。第一种方法将允许 **进程正常终止**，并使 **文件系统** **同步**，但这也可能允许潜在的 **恶意软件** **破坏证据**。“拔掉插头”方法可能会导致 **一些信息丢失**（由于我们已经获取了内存的映像，丢失的信息不会很多），并且 **恶意软件将没有机会** 采取任何行动。因此，如果您 **怀疑** 可能存在 **恶意软件**，请在系统上执行 **`sync`** **命令** 然后拔掉插头。

#### 获取磁盘映像

重要的是要注意，在 **将计算机连接到与案件相关的任何设备之前**，您需要确保它将以 **只读方式挂载**，以避免修改任何信息。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### 磁盘映像预分析

对没有更多数据的磁盘映像进行成像。
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
<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## 搜索已知恶意软件

### 修改过的系统文件

Linux 提供工具以确保系统组件的完整性，这对于发现潜在问题文件至关重要。

* **基于 RedHat 的系统**：使用 `rpm -Va` 进行全面检查。
* **基于 Debian 的系统**：使用 `dpkg --verify` 进行初步验证，然后使用 `debsums | grep -v "OK$"`（在使用 `apt-get install debsums` 安装 `debsums` 后）来识别任何问题。

### 恶意软件/根套件检测器

阅读以下页面以了解可以用于查找恶意软件的工具：

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## 搜索已安装程序

要有效搜索 Debian 和 RedHat 系统上已安装的程序，可以考虑利用系统日志和数据库，同时在常见目录中进行手动检查。

* 对于 Debian，检查 _**`/var/lib/dpkg/status`**_ 和 _**`/var/log/dpkg.log`**_ 以获取有关软件包安装的详细信息，使用 `grep` 过滤特定信息。
* RedHat 用户可以使用 `rpm -qa --root=/mntpath/var/lib/rpm` 查询 RPM 数据库以列出已安装的软件包。

要发现手动安装或在这些软件包管理器之外安装的软件，探索像 _**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_ 和 _**`/sbin`**_ 等目录。将目录列表与特定于系统的命令结合使用，以识别与已知软件包无关的可执行文件，从而增强您对所有已安装程序的搜索。
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
<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## 恢复已删除的运行二进制文件

想象一下一个从 /tmp/exec 执行并随后被删除的进程。可以提取它
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

恶意软件可以作为服务安装的路径：

* **/etc/inittab**: 调用初始化脚本，如 rc.sysinit，进一步指向启动脚本。
* **/etc/rc.d/** 和 **/etc/rc.boot/**: 包含服务启动的脚本，后者在较旧的 Linux 版本中找到。
* **/etc/init.d/**: 在某些 Linux 版本（如 Debian）中用于存储启动脚本。
* 服务也可以通过 **/etc/inetd.conf** 或 **/etc/xinetd/** 激活，具体取决于 Linux 变体。
* **/etc/systemd/system**: 系统和服务管理器脚本的目录。
* **/etc/systemd/system/multi-user.target.wants/**: 包含应在多用户运行级别启动的服务的链接。
* **/usr/local/etc/rc.d/**: 用于自定义或第三方服务。
* **\~/.config/autostart/**: 用户特定的自动启动应用程序，可以是针对用户的恶意软件的隐藏地点。
* **/lib/systemd/system/**: 安装包提供的系统范围默认单元文件。

### 内核模块

Linux 内核模块，通常被恶意软件作为 rootkit 组件使用，在系统启动时加载。与这些模块相关的关键目录和文件包括：

* **/lib/modules/$(uname -r)**: 存放正在运行的内核版本的模块。
* **/etc/modprobe.d**: 包含控制模块加载的配置文件。
* **/etc/modprobe** 和 **/etc/modprobe.conf**: 全局模块设置的文件。

### 其他自动启动位置

Linux 使用各种文件在用户登录时自动执行程序，可能隐藏恶意软件：

* **/etc/profile.d/**\*, **/etc/profile** 和 **/etc/bash.bashrc**: 针对任何用户登录执行。
* **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile** 和 **\~/.config/autostart**: 用户特定的文件，在他们登录时运行。
* **/etc/rc.local**: 在所有系统服务启动后运行，标志着过渡到多用户环境的结束。

## 检查日志

Linux 系统通过各种日志文件跟踪用户活动和系统事件。这些日志对于识别未经授权的访问、恶意软件感染和其他安全事件至关重要。关键日志文件包括：

* **/var/log/syslog** (Debian) 或 **/var/log/messages** (RedHat): 捕获系统范围的消息和活动。
* **/var/log/auth.log** (Debian) 或 **/var/log/secure** (RedHat): 记录身份验证尝试、成功和失败的登录。
* 使用 `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` 过滤相关的身份验证事件。
* **/var/log/boot.log**: 包含系统启动消息。
* **/var/log/maillog** 或 **/var/log/mail.log**: 记录邮件服务器活动，有助于跟踪与邮件相关的服务。
* **/var/log/kern.log**: 存储内核消息，包括错误和警告。
* **/var/log/dmesg**: 保存设备驱动程序消息。
* **/var/log/faillog**: 记录失败的登录尝试，有助于安全漏洞调查。
* **/var/log/cron**: 记录 cron 作业执行。
* **/var/log/daemon.log**: 跟踪后台服务活动。
* **/var/log/btmp**: 记录失败的登录尝试。
* **/var/log/httpd/**: 包含 Apache HTTPD 错误和访问日志。
* **/var/log/mysqld.log** 或 **/var/log/mysql.log**: 记录 MySQL 数据库活动。
* **/var/log/xferlog**: 记录 FTP 文件传输。
* **/var/log/**: 始终检查此处是否有意外日志。

{% hint style="info" %}
Linux 系统日志和审计子系统可能在入侵或恶意软件事件中被禁用或删除。因为 Linux 系统上的日志通常包含有关恶意活动的一些最有用的信息，入侵者通常会删除它们。因此，在检查可用日志文件时，重要的是查找可能表明删除或篡改的间隙或无序条目。
{% endhint %}

**Linux 为每个用户维护命令历史**，存储在：

* \~/.bash\_history
* \~/.zsh\_history
* \~/.zsh\_sessions/\*
* \~/.python\_history
* \~/.\*\_history

此外，`last -Faiwx` 命令提供用户登录的列表。检查是否有未知或意外的登录。

检查可以授予额外权限的文件：

* 检查 `/etc/sudoers` 是否有意外授予的用户权限。
* 检查 `/etc/sudoers.d/` 是否有意外授予的用户权限。
* 检查 `/etc/groups` 以识别任何异常的组成员资格或权限。
* 检查 `/etc/passwd` 以识别任何异常的组成员资格或权限。

一些应用程序还会生成自己的日志：

* **SSH**: 检查 _\~/.ssh/authorized\_keys_ 和 _\~/.ssh/known\_hosts_ 以查找未经授权的远程连接。
* **Gnome 桌面**: 查看 _\~/.recently-used.xbel_ 以获取通过 Gnome 应用程序访问的最近文件。
* **Firefox/Chrome**: 检查 _\~/.mozilla/firefox_ 或 _\~/.config/google-chrome_ 中的浏览器历史和下载，以查找可疑活动。
* **VIM**: 检查 _\~/.viminfo_ 以获取使用详情，如访问的文件路径和搜索历史。
* **Open Office**: 检查最近的文档访问，以指示可能被破坏的文件。
* **FTP/SFTP**: 检查 _\~/.ftp\_history_ 或 _\~/.sftp\_history_ 中的日志，以查找可能未经授权的文件传输。
* **MySQL**: 检查 _\~/.mysql\_history_ 以调查执行的 MySQL 查询，可能揭示未经授权的数据库活动。
* **Less**: 分析 _\~/.lesshst_ 以获取使用历史，包括查看的文件和执行的命令。
* **Git**: 检查 _\~/.gitconfig_ 和项目 _.git/logs_ 以获取对存储库的更改。

### USB 日志

[**usbrip**](https://github.com/snovvcrash/usbrip) 是一个用纯 Python 3 编写的小软件，它解析 Linux 日志文件（`/var/log/syslog*` 或 `/var/log/messages*`，具体取决于发行版），以构建 USB 事件历史表。

了解**所有使用过的 USB** 是很有趣的，如果你有一个授权的 USB 列表来查找“违规事件”（不在该列表中的 USB 使用），将更有用。

### 安装
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 示例
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
更多示例和信息请查看 GitHub: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
今天就获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## 审查用户账户和登录活动

检查 _**/etc/passwd**_、_**/etc/shadow**_ 和 **安全日志**，寻找不寻常的名称或在已知未授权事件附近创建和使用的账户。同时，检查可能的 sudo 暴力攻击。\
此外，检查像 _**/etc/sudoers**_ 和 _**/etc/groups**_ 这样的文件，寻找意外授予用户的权限。\
最后，查找 **没有密码** 或 **容易猜测** 的密码的账户。

## 检查文件系统

### 在恶意软件调查中分析文件系统结构

在调查恶意软件事件时，文件系统的结构是一个重要的信息来源，揭示事件的顺序和恶意软件的内容。然而，恶意软件作者正在开发技术来阻碍这种分析，例如修改文件时间戳或避免使用文件系统进行数据存储。

为了对抗这些反取证方法，至关重要的是：

* 使用 **Autopsy** 进行全面的时间线分析，以可视化事件时间线，或使用 **Sleuth Kit** 的 `mactime` 获取详细的时间线数据。
* 调查系统 $PATH 中的意外脚本，这可能包括攻击者使用的 shell 或 PHP 脚本。
* 检查 `/dev` 中的非典型文件，因为它通常包含特殊文件，但可能存放与恶意软件相关的文件。
* 搜索名称为 ".. "（点点空格）或 "..^G"（点点控制-G）的隐藏文件或目录，这可能隐藏恶意内容。
* 使用命令 `find / -user root -perm -04000 -print` 识别 setuid root 文件。这将找到具有提升权限的文件，可能被攻击者滥用。
* 检查 inode 表中的删除时间戳，以发现大规模文件删除，可能表明存在 rootkit 或木马。
* 在识别一个恶意文件后，检查连续的 inode，以寻找附近的恶意文件，因为它们可能被放在一起。
* 检查常见的二进制目录 (_/bin_、_/sbin_) 中最近修改的文件，因为这些文件可能被恶意软件更改。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
注意，一个**攻击者**可以**修改**时间以使**文件看起来**是**合法的**，但他**无法**修改**inode**。如果你发现一个**文件**显示它的创建和修改时间与同一文件夹中其他文件的**时间相同**，但**inode**却**意外地更大**，那么该**文件的时间戳被修改**了。
{% endhint %}

## 比较不同文件系统版本的文件

### 文件系统版本比较摘要

为了比较文件系统版本并确定更改，我们使用简化的`git diff`命令：

* **查找新文件**，比较两个目录：
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **对于修改过的内容**，列出更改，同时忽略特定行：
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **检测已删除文件**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **过滤选项** (`--diff-filter`) 有助于缩小到特定的更改，如添加的 (`A`)、删除的 (`D`) 或修改的 (`M`) 文件。
* `A`: 添加的文件
* `C`: 复制的文件
* `D`: 删除的文件
* `M`: 修改的文件
* `R`: 重命名的文件
* `T`: 类型更改（例如，从文件到符号链接）
* `U`: 未合并的文件
* `X`: 未知的文件
* `B`: 损坏的文件

## 参考文献

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **书籍：Linux系统的恶意软件取证实用指南：数字取证实用指南**

<details>

<summary><strong>从零到英雄学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

你在一家**网络安全公司**工作吗？你想在HackTricks上看到你的**公司广告**吗？或者你想访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)!

* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* 获取[**官方PEASS和HackTricks周边**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**在** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**上关注我。**

**通过向** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR分享你的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics)轻松构建和**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
今天就获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}
