# Windows 痕迹

## Windows 痕迹

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 通用 Windows 痕迹

### Windows 10 通知

在路径 `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` 中，您可以找到数据库 `appdb.dat`（Windows 周年纪念版之前）或 `wpndatabase.db`（Windows 周年纪念版之后）。

在这个 SQLite 数据库中，您可以找到 `Notification` 表，其中包含所有通知（以 XML 格式），这些通知可能包含有趣的数据。

### 时间线

时间线是 Windows 的一个特性，它提供了访问过的网页、编辑过的文档和执行过的应用程序的**按时间顺序的历史记录**。

数据库位于路径 `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`。这个数据库可以用 SQLite 工具打开，或者使用工具 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **生成两个可以用工具** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **打开的文件**。

### ADS (Alternate Data Streams)

下载的文件可能包含 **ADS Zone.Identifier**，指示文件是如何从内网、互联网等下载的。一些软件（如浏览器）通常会放入**更多**的**信息**，如下载文件的**URL**。

## **文件备份**

### 回收站

在 Vista/Win7/Win8/Win10 中，**回收站**可以在驱动器根目录的文件夹 **`$Recycle.bin`** 中找到（`C:\$Recycle.bin`）。\
当文件在此文件夹中被删除时，会创建两个特定的文件：

* `$I{id}`：文件信息（删除日期）
* `$R{id}`：文件内容

![](<../../../.gitbook/assets/image (486).png>)

拥有这些文件，您可以使用工具 [**Rifiuti**](https://github.com/abelcheung/rifiuti2) 来获取被删除文件的原始地址和删除日期（对于 Vista – Win10 使用 `rifiuti-vista.exe`）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
### 卷影副本

卷影副本是Microsoft Windows中包含的一项技术，它可以创建计算机文件或卷的**备份副本**或快照，即使它们正在使用中。

这些备份通常位于文件系统根目录下的`\System Volume Information`中，名称由以下图像中显示的**UIDs**组成：

![](<../../../.gitbook/assets/image (520).png>)

使用**ArsenalImageMounter**挂载取证映像后，可以使用工具[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html)来检查卷影副本，甚至**提取**来自卷影副本备份的文件。

![](<../../../.gitbook/assets/image (521).png>)

注册表项`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`包含**不备份**的文件和键：

![](<../../../.gitbook/assets/image (522).png>)

注册表`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`还包含有关`卷影副本`的配置信息。

### Office自动保存文件

你可以在以下位置找到Office自动保存的文件：`C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell项目

Shell项目是包含如何访问另一个文件的信息的项目。

### 最近文档（LNK）

Windows在用户**打开、使用或创建文件**时**自动**创建这些**快捷方式**：

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

当创建一个文件夹时，也会创建到该文件夹、父文件夹和祖父文件夹的链接。

这些自动创建的链接文件**包含有关来源的信息**，比如它是**文件**还是**文件夹**，该文件的**MAC** **时间**，存储文件的**卷信息**和**目标文件的文件夹**。这些信息对于恢复那些被删除的文件很有用。

此外，链接文件的**创建日期**是原始文件**第一次**被**使用**的时间，链接文件的**修改日期**是原始文件最后一次被使用的时间。

要检查这些文件，你可以使用[**LinkParser**](http://4discovery.com/our-tools/)。

在这个工具中，你会发现**两组**时间戳：

* **第一组：**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **第二组：**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

第一组时间戳引用的是**文件本身的时间戳**。第二组引用的是**链接文件的时间戳**。

你可以通过运行Windows CLI工具：[**LECmd.exe**](https://github.com/EricZimmerman/LECmd)来获取相同的信息。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
在这种情况下，信息将被保存在CSV文件中。

### Jumplists

这些是每个应用程序指示的最近文件。这是您可以在每个应用程序中访问的**应用程序最近使用的文件列表**。它们可以是**自动创建或自定义**的。

自动创建的**jumplists**存储在`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`。Jumplists按照格式`{id}.autmaticDestinations-ms`命名，初始ID是应用程序的ID。

自定义jumplists存储在`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`，通常由应用程序创建，因为文件发生了一些**重要**的事情（可能被标记为收藏）

任何jumplist的**创建时间**指示**第一次访问文件的时间**，**修改时间是最后一次**。

您可以使用[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md)检查jumplists。

![](<../../../.gitbook/assets/image (474).png>)

（_请注意，JumplistExplorer提供的时间戳与jumplist文件本身有关_）

### Shellbags

[**点击此链接了解什么是shellbags。**](interesting-windows-registry-keys.md#shellbags)

## 使用Windows USB

可以通过创建以下内容来识别使用了USB设备：

* Windows最近文件夹
* Microsoft Office最近文件夹
* Jumplists

请注意，某些LNK文件不是指向原始路径，而是指向WPDNSE文件夹：

![](<../../../.gitbook/assets/image (476).png>)

WPDNSE文件夹中的文件是原始文件的副本，因此在PC重启后不会保留，GUID取自shellbag。

### 注册表信息

[查看此页面了解](interesting-windows-registry-keys.md#usb-information)哪些注册表键包含有关USB连接设备的有趣信息。

### setupapi

检查文件`C:\Windows\inf\setupapi.dev.log`以获取USB连接产生的时间戳（搜索`Section start`）。

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

可以使用[**USBDetective**](https://usbdetective.com)获取有关连接到映像的USB设备的信息。

![](<../../../.gitbook/assets/image (483).png>)

### 插放清理

“插放清理”计划任务负责**清除**旧版驱动程序。根据在线报告，尽管其描述指出“将保留每个驱动程序包的最新版本”，但它似乎也会清除**30天内未使用的驱动程序**。因此，**30天内未连接的可移动设备可能会被移除其驱动程序**。

计划任务本身位于`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`，其内容如下所示：

![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

任务引用了“pnpclean.dll”，它负责执行清理活动，我们还看到“UseUnifiedSchedulingEngine”字段设置为“TRUE”，这指定使用通用任务调度引擎来管理任务。“MaintenanceSettings”中的“Period”和“Deadline”值“P1M”和“P2M”指示任务调度程序在常规自动维护期间每月执行一次任务，如果连续2个月失败，则在紧急自动维护期间开始尝试任务。**此部分内容复制自**[**这里**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)**。**

## 电子邮件

电子邮件包含**2个有趣的部分：头部和内容**。在**头部**中，您可以找到信息，如：

* **谁**发送了电子邮件（电子邮件地址、IP、已转发电子邮件的邮件服务器）
* **何时**发送了电子邮件

此外，在`References`和`In-Reply-To`头部中，您可以找到消息的ID：

![](<../../../.gitbook/assets/image (484).png>)

### Windows邮件应用

此应用程序以HTML或文本形式保存电子邮件。您可以在`\Users\<username>\AppData\Local\Comms\Unistore\data\3\`内的子文件夹中找到电子邮件。电子邮件以`.dat`扩展名保存。

电子邮件的**元数据**和**联系人**可以在**EDB数据库**中找到：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**更改文件扩展名**从`.vol`到`.edb`，您可以使用工具[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)打开它。在`Message`表中，您可以看到电子邮件。

### Microsoft Outlook

当使用Exchange服务器或Outlook客户端时，会有一些MAPI头部：

* `Mapi-Client-Submit-Time`：发送电子邮件时系统的时间
* `Mapi-Conversation-Index`：线程的子消息数量和线程每条消息的时间戳
* `Mapi-Entry-ID`：消息标识符。
* `Mappi-Message-Flags`和`Pr_last_Verb-Executed`：关于MAPI客户端的信息（消息已读？未读？已回复？已转发？不在办公室？）

在Microsoft Outlook客户端中，所有发送/接收的消息、联系人数据和日历数据都存储在PST文件中：

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook`（WinXP）
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

注册表路径`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`指示正在使用的文件。

您可以使用工具[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)打开PST文件。

![](<../../../.gitbook/assets/image (485).png>)

### Outlook OST

当Microsoft Outlook配置**使用** **IMAP**或使用**Exchange**服务器时，它会生成一个**OST**文件，存储与PST文件几乎相同的信息。它保持文件与服务器同步，**最近12个月**，**最大文件大小为50GB**，并保存在**与PST**文件相同的文件夹中。您可以使用[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)检查此文件。

### 恢复附件

您可能会在文件夹中找到它们：

* `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook` -> IE10
* `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook` -> IE11+

### Thunderbird MBOX

**Thunderbird**在文件夹`\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`中的**MBOX** **文件**中存储信息

## 缩略图

当用户访问文件夹并使用缩略图进行组织时，会创建一个`thumbs.db`文件。即使被删除，这个数据库**存储文件夹中图像的缩略图**。在WinXP和Win 8-8.1中，此文件会自动创建。在Win7/Win10中，如果通过UNC路径（\IP\folder...）访问，则会自动创建。

可以使用工具[**Thumbsviewer**](https://thumbsviewer.github.io)读取此文件。

### Thumbcache

从Windows Vista开始，**缩略图预览存储在系统的集中位置**。这为系统提供了独立于它们位置的图像访问，并解决了Thumbs.db文件的局部性问题。缓存存储在**`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`**中，作为多个文件，标签为**thumbcache\_xxx.db**（按大小编号）；以及用于在每个大小的数据库中查找缩略图的索引。

* Thumbcache\_32.db -> 小
* Thumbcache\_96.db -> 中
* Thumbcache\_256.db -> 大
* Thumbcache\_1024.db -> 特大

您可以使用[**ThumbCache Viewer**](https://thumbcacheviewer.github.io)读取此文件。

## Windows注册表

Windows注册表包含大量关于**系统和用户行为**的**信息**。

包含注册表的文件位于：

* %windir%\System32\Config\*_SAM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SECURITY\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SYSTEM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SOFTWARE\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_DEFAULT\*_: `HKEY_LOCAL_MACHINE`
* %UserProfile%{User}\*_NTUSER.DAT\*_: `HKEY_CURRENT_USER`

从Windows Vista和Windows 2008 Server开始，`HKEY_LOCAL_MACHINE`注册表文件的一些备份位于**`%Windir%\System32\Config\RegBack\`**。

从这些版本开始，注册表文件**`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`**被创建，保存有关程序执行的信息。

### 工具

一些工具对分析注册表文件很有用：

* **注册表编辑器**：它安装在Windows中。它是一个GUI，用于浏览当前会话的Windows注册表。
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：它允许您加载注册表文件，并通过GUI浏览它们。它还包含突出显示有趣信息的键的书签。
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：同样，它有一个GUI，允许浏览加载的注册表，并且还包含突出显示加载的注册表中有趣信息的插件。
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html)：另一个GUI应用程序，能够从加载的注册表中提取重要信息。

### 恢复已删除元素

当一个键被删除时，它会被标记为这样，但直到它占用的空间需要时才会被移除。因此，使用像**Registry Explorer**这样的工具可以恢复这些已删除的键。

### 最后写入时间

每个键值都包含一个**时间戳**，指示上次修改的时间。

### SAM

文件/配置单元**SAM**包含系统的**用户、组和用户密码**哈希。

在`SAM\Domains\Account\Users`中，您可以获得用户名、RID、最后登录、最后失败登录、登录计数器、密码策略以及账户创建时间。要获取**哈希**，您还**需要**文件/配置单元**SYSTEM**。

### Windows注册表中的有趣条目

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## 执行的程序

### 基本Windows进程

在以下页面上，您可以了解基本的Windows进程以检测可疑行为：

{% content-ref url="windows-processes.md" %}
[windows-processes.md](windows-processes.md)
{% endcontent-ref %}

### Windows最近应用

在注册表`NTUSER.DAT`的路径`Software\Microsoft\Current Version\Search\RecentApps`中，您可以找到子键，其中包含有关**执行的应用程序**、**最后执行时间**和**启动次数**的信息。

### BAM（后台活动调节器）

您可以使用注册表编辑器打开`SYSTEM`文件，在路径`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`中找到有关**每个用户执行的应用程序**的信息（注意路径中的`{SID}`），以及**执行时间**（时间在注册表的Data值中）。

### Windows预取

预取是一种技术，允许计算机静默地**获取用户**可能在不久的将来访问的内容所需的资源，以便可以更快地访问资源。

Windows预取包括创建**执行程序的缓存**，以便能够更快地加载它们。这些缓存作为`.pf`文件创建在路径：`C:\Windows\Prefetch`中。在XP/VISTA/WIN7中有128个文件的限制，在Win8/Win10中有1024个文件的限制。

文件名创建为`{program_name}-{hash}.pf`（哈希基于可执行文件的路径和参数）。在W10中，这些文件被压缩。请注意，文件的单独存在表明**程序在某个时候被执行**过。

文件`C:\Windows\Prefetch\Layout.ini`包含**预取文件的文件夹名称**。此文件包含**执行次数**、**执行日期**和**程序打开的文件**的**信息**。

要检查这些文件，您可以使用工具[**PEcmd.exe**](https://github.com/EricZimmerman/PECmd)：
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** 的目标与 prefetch 相同，即通过预测下一步将要加载的内容来**更快地加载程序**。然而，它并不替代 prefetch 服务。\
该服务会在 `C:\Windows\Prefetch\Ag*.db` 生成数据库文件。

在这些数据库中，你可以找到**程序**的**名称**、**执行**的**次数**、**打开**的**文件**、**访问**的**卷**、**完整**的**路径**、**时间范围**和**时间戳**。

你可以使用工具 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) 来访问这些信息。

### SRUM

**系统资源使用监视器**（SRUM）**监控**由**进程** **消耗**的**资源**。它在 W8 中出现，并将数据存储在位于 `C:\Windows\System32\sru\SRUDB.dat` 的 ESE 数据库中。

它提供以下信息：

* 应用程序 ID 和路径
* 执行进程的用户
* 发送的字节数
* 接收的字节数
* 网络接口
* 连接持续时间
* 进程持续时间

这些信息每 60 分钟更新一次。

你可以使用工具 [**srum\_dump**](https://github.com/MarkBaggett/srum-dump) 从这个文件中获取数据。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**Shimcache**，也称为**AppCompatCache**，是**Microsoft**创建的**应用程序兼容性数据库**的组成部分，操作系统使用它来识别应用程序兼容性问题。

缓存根据操作系统存储各种文件元数据，例如：

* 文件完整路径
* 文件大小
* **$Standard\_Information** (SI) 最后修改时间
* ShimCache 最后更新时间
* 进程执行标志

此信息可以在注册表中找到：

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
* XP (96 条目)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
* Server 2003 (512 条目)
* 2008/2012/2016 Win7/Win8/Win10 (1024 条目)

您可以使用工具 [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) 来解析此信息。

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

**Amcache.hve** 文件是一个注册表文件，存储已执行应用程序的信息。它位于 `C:\Windows\AppCompat\Programas\Amcache.hve`

**Amcache.hve** 记录了最近运行的进程，并列出了被执行的文件的路径，然后可以用来找到执行的程序。它还记录了程序的 SHA1。

您可以使用工具 [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser) 来解析此信息。
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
```markdown
最有趣的 CVS 文件是 `Amcache_Unassociated file entries`。

### RecentFileCache

此工件仅在 W7 的 `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` 中找到，它包含了一些二进制文件最近执行的信息。

您可以使用工具 [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) 来解析该文件。

### 计划任务

您可以从 `C:\Windows\Tasks` 或 `C:\Windows\System32\Tasks` 提取它们，并将它们作为 XML 阅读。

### 服务

您可以在注册表的 `SYSTEM\ControlSet001\Services` 下找到它们。您可以看到将要执行什么以及何时执行。

### **Windows 商店**

已安装的应用程序可以在 `\ProgramData\Microsoft\Windows\AppRepository\` 中找到\
这个存储库有一个 **日志**，其中包含系统内数据库 **`StateRepository-Machine.srd`** 中的 **每个已安装应用程序**。

在此数据库的应用程序表中，可以找到 "Application ID"、"PackageNumber" 和 "Display Name" 列。这些列包含了预安装和已安装应用程序的信息，如果某些应用程序已卸载也可以找到，因为已安装应用程序的 ID 应该是连续的。

也可以在注册表路径 `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` 中**找到已安装的应用程序**\
以及在 `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\` 中找到**已卸载的** **应用程序**。

## Windows 事件

Windows 事件中出现的信息包括：

* 发生了什么
* 时间戳（UTC + 0）
* 涉及的用户
* 涉及的主机（主机名，IP）
* 访问的资产（文件，文件夹，打印机，服务）

日志位于 Windows Vista 之前的 `C:\Windows\System32\config` 和 Windows Vista 之后的 `C:\Windows\System32\winevt\Logs`。在 Windows Vista 之前，事件日志是二进制格式，之后，它们是 **XML 格式** 并使用 **.evtx** 扩展名。

事件文件的位置可以在 SYSTEM 注册表中找到 **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

它们可以通过 Windows 事件查看器（**`eventvwr.msc`**）或其他工具如 [**Event Log Explorer**](https://eventlogxp.com) **或** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** 查看。**

### 安全

此记录访问事件并提供有关安全配置的信息，可以在 `C:\Windows\System32\winevt\Security.evtx` 中找到。

事件文件的 **最大大小** 是可配置的，当达到最大大小时，它将开始覆盖旧事件。

注册为的事件包括：

* 登录/注销
* 用户的行为
* 访问文件、文件夹和共享资产
* 修改安全配置

与用户认证相关的事件：

| EventID   | 描述                        |
| --------- | ---------------------------- |
| 4624      | 认证成功                    |
| 4625      | 认证错误                     |
| 4634/4647 | 注销                        |
| 4672      | 具有管理员权限的登录         |

在 EventID 4634/4647 中有一些有趣的子类型：

* **2 (交互式)**：登录是交互式的，使用键盘或像 VNC 或 `PSexec -U-` 这样的软件
* **3 (网络)**：连接到共享文件夹
* **4 (批处理)**：执行的进程
* **5 (服务)**：由服务控制管理器启动的服务
* **6 (代理):** 代理登录
* **7 (解锁)**：使用密码解锁屏幕
* **8 (网络明文)**：用户通过发送明文密码进行认证。这个事件通常来自 IIS
* **9 (新凭证)**：使用 `RunAs` 命令或用户使用不同的凭证访问网络服务时生成
* **10 (远程交互式)**：通过终端服务或 RDP 进行认证
* **11 (缓存交互式)**：使用最后缓存的凭证访问，因为无法联系到域控制器
* **12 (缓存远程交互式)**：远程使用缓存凭证登录（10 和 11 的结合）。
* **13 (缓存解锁)**：使用缓存凭证解锁锁定的机器。

在这篇文章中，您可以找到如何模仿所有这些类型的登录，在哪些登录中您将能够从内存中转储凭证：[https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

事件的状态和子状态信息可以指示事件原因的更多细节。例如，看看以下 Event ID 4625 的状态和子状态代码：

![](<../../../.gitbook/assets/image (455).png>)

### 恢复 Windows 事件

强烈建议通过**拔掉电源**关闭可疑的 PC，以最大化恢复 Windows 事件的可能性。如果它们被删除了，一个可能有用的工具是 [**Bulk\_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor)，指定 **evtx** 扩展名。

## 使用 Windows 事件识别常见攻击

* [https://redteamrecipe.com/event-codes/](https://redteamrecipe.com/event-codes/)

### 暴力破解攻击

暴力破解攻击很容易识别，因为会出现**多个 EventIDs 4625**。如果攻击**成功**，在 EventIDs 4625 之后，**会出现一个 EventID 4624**。

### 时间更改

这对取证团队来说是可怕的，因为所有的时间戳都会被修改。这个事件由安全事件日志中的 EventID 4616 记录。

### USB 设备

以下系统 EventIDs 很有用：

* 20001 / 20003 / 10000：第一次使用
* 10100：驱动更新

EventID 112 来自 DeviceSetupManager 包含每个 USB 设备插入的时间戳。

### 关机 / 开机

"事件日志" 服务的 ID 6005 表示 PC 已开机。ID 6006 表示它已关机。

### 日志删除

安全事件 ID 1102 表示日志已被删除。

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
```
