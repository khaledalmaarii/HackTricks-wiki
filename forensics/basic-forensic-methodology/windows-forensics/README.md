# Windows取证

## Windows取证

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 通用Windows取证

### Windows 10通知

在路径`\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`中，您可以找到数据库`appdb.dat`（Windows周年更新前）或`wpndatabase.db`（Windows周年更新后）。

在这个SQLite数据库中，您可以找到包含所有通知（以XML格式）的`Notification`表，其中可能包含有趣的数据。

### 时间轴

时间轴是Windows的一个特性，提供了访问的网页、编辑的文档和执行的应用程序的**时间顺序历史记录**。

数据库位于路径`\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`。可以使用SQLite工具或工具[**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)打开此数据库，**该工具生成2个文件，可以使用工具**[**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **打开**。

### ADS（备用数据流）

下载的文件可能包含**ADS Zone.Identifier**，指示它是如何从内部网络、互联网等**下载**的。一些软件（如浏览器）通常会放入**更多**的**信息**，如文件下载的**URL**。

## **文件备份**

### 回收站

在Vista/Win7/Win8/Win10中，**回收站**可以在驱动器根目录（`C:\$Recycle.bin`）中找到。\
当在此文件夹中删除文件时，会创建2个特定文件：

* `$I{id}`：文件信息（删除时间的日期）
* `$R{id}`：文件内容

![](<../../../.gitbook/assets/image (486).png>)

有了这些文件，您可以使用工具[**Rifiuti**](https://github.com/abelcheung/rifiuti2)获取已删除文件的原始地址和删除日期（对于Vista – Win10，请使用`rifiuti-vista.exe`）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### 阴影副本

阴影副本是包含在 Microsoft Windows 中的技术，可以在计算机文件或卷正在使用时创建**备份副本**或快照。

这些备份通常位于文件系统根目录下的 `\System Volume Information` 中，名称由以下图像中显示的**UIDs**组成：

![](<../../../.gitbook/assets/image (520).png>)

使用 **ArsenalImageMounter** 挂载取证镜像，可以使用工具 [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) 来检查阴影副本，甚至从阴影副本备份中**提取文件**。

![](<../../../.gitbook/assets/image (521).png>)

注册表项 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` 包含**不备份**的文件和键：

![](<../../../.gitbook/assets/image (522).png>)

注册表 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` 还包含有关`Volume Shadow Copies`的配置信息。

### Office 自动保存文件

您可以在以下位置找到 office 自动保存文件：`C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell 项目

Shell 项目是包含有关如何访问另一个文件的信息的项目。

### 最近文档 (LNK)

当用户在以下位置**打开、使用或创建文件**时，Windows会**自动创建**这些**快捷方式**：

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

创建文件夹时，还会创建指向文件夹、父文件夹和祖父文件夹的链接。

这些自动创建的链接文件**包含有关源文件的信息**，例如它是一个**文件**还是一个**文件夹**，该文件的**MAC时间**，文件存储位置的**卷信息**和**目标文件夹**的信息。这些信息可用于在文件被删除时恢复这些文件。

此外，链接文件的**创建日期**是原始文件**首次使用的时间**，链接文件的**修改日期**是原始文件**最后使用的时间**。

您可以使用 [**LinkParser**](http://4discovery.com/our-tools/) 来检查这些文件。

在此工具中，您将找到**2组**时间戳：

* **第一组：**
1. 文件修改日期
2. 文件访问日期
3. 文件创建日期
* **第二组：**
1. 链接修改日期
2. 链接访问日期
3. 链接创建日期。

第一组时间戳引用**文件本身的时间戳**。第二组引用**链接文件的时间戳**。

您可以使用 Windows CLI 工具 [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) 获取相同的信息。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
### 跳转列表

这些是每个应用程序指示的最近文件。这是您可以在每个应用程序中访问的**最近使用的文件列表**。它们可以**自动创建或自定义**。

自动创建的**跳转列表**存储在`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`中。跳转列表的命名遵循格式`{id}.autmaticDestinations-ms`，其中初始ID是应用程序的ID。

自定义跳转列表存储在`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`中，通常是因为应用程序发生了**重要**事件（可能标记为收藏）而创建。

任何跳转列表的**创建时间**表示**文件被访问的第一次时间**，**修改时间表示最后一次时间**。

您可以使用[JumplistExplorer](https://ericzimmerman.github.io/#!index.md)检查跳转列表。

![](<../../../.gitbook/assets/image (474).png>)

（_请注意，JumplistExplorer提供的时间戳与跳转列表文件本身相关_）

### Shellbags

[**点击此链接了解什么是shellbags。**](interesting-windows-registry-keys.md#shellbags)

## Windows USB使用

通过以下内容可以确定已使用USB设备：

- Windows最近文件夹
- Microsoft Office最近文件夹
- 跳转列表

请注意，有些LNK文件指向WPDNSE文件夹而不是原始路径：

![](<../../../.gitbook/assets/image (476).png>)

WPDNSE文件夹中的文件是原始文件的副本，因此在PC重新启动后不会保留，并且GUID是从shellbag中获取的。

### 注册表信息

[查看此页面以了解](interesting-windows-registry-keys.md#usb-information)哪些注册表键包含有关连接的USB设备的有趣信息。

### setupapi

检查文件`C:\Windows\inf\setupapi.dev.log`以获取有关USB连接产生的时间戳（搜索`Section start`）。

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)可用于获取连接到图像的USB设备的信息。

![](<../../../.gitbook/assets/image (483).png>)

### 插拔清理

名为“插拔清理”的计划任务主要用于删除过时的驱动程序版本。与其指定的保留最新驱动程序包版本的目的相反，在线资源表明它还会针对在过去30天内未连接的驱动程序进行操作。因此，未连接在过去30天内的可移动设备的驱动程序可能会被删除。

该任务位于以下路径：
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

提供了描述任务内容的截图：
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**任务的关键组件和设置：**
- **pnpclean.dll**：此DLL负责实际的清理过程。
- **UseUnifiedSchedulingEngine**：设置为`TRUE`，表示使用通用任务调度引擎。
- **MaintenanceSettings**：
- **Period（'P1M'）**：指示任务计划程序在常规自动维护期间每月启动清理任务。
- **Deadline（'P2M'）**：如果任务连续两个月失败，则指示任务计划程序在紧急自动维护期间执行任务。

此配置确保定期维护和清理驱动程序，并提供在连续失败的情况下重新尝试任务的规定。

**更多信息，请查看：**[**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## 电子邮件

电子邮件包含**2个有趣部分：邮件头和邮件内容**。在**邮件头**中，您可以找到以下信息：

- **谁**发送了电子邮件（电子邮件地址、IP、重定向电子邮件的邮件服务器）
- 电子邮件发送的**时间**

此外，在`References`和`In-Reply-To`头中，您可以找到消息的ID：

![](<../../../.gitbook/assets/image (484).png>)

### Windows邮件应用

此应用程序以HTML或文本格式保存电子邮件。您可以在`\Users\<username>\AppData\Local\Comms\Unistore\data\3\`文件夹中的子文件夹中找到以`.dat`扩展名保存的电子邮件。

电子邮件的**元数据**和**联系人**可以在**EDB数据库**中找到：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

将文件的扩展名从`.vol`更改为`.edb`，然后您可以使用工具[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)打开它。在`Message`表中，您可以查看电子邮件。

### Microsoft Outlook

当使用Exchange服务器或Outlook客户端时，将会有一些MAPI头：

- `Mapi-Client-Submit-Time`：发送电子邮件时的系统时间
- `Mapi-Conversation-Index`：线程的子消息数量和每个线程消息的时间戳
- `Mapi-Entry-ID`：消息标识符。
- `Mappi-Message-Flags`和`Pr_last_Verb-Executed`：有关MAPI客户端的信息（消息已读？未读？已回复？已重定向？是否离开办公室？）

在Microsoft Outlook客户端中，所有已发送/接收的消息、联系人数据和日历数据都存储在以下PST文件中：

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook`（WinXP）
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

注册表路径`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`指示正在使用的文件。

您可以使用工具[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)打开PST文件。

![](<../../../.gitbook/assets/image (485).png>)

### Outlook OST

当使用IMAP或Exchange服务器配置Microsoft Outlook时，它会生成一个OST文件，其中存储了与PST文件几乎相同的信息。它将文件与服务器同步，保留**最近12个月**的文件，最大文件大小为**50GB**，并保存在与PST文件相同的文件夹中。您可以使用[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)检查此文件。

### 恢复附件

您可能会在以下文件夹中找到它们：

- `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook` -> IE10
- `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook` -> IE11+

### Thunderbird MBOX

**Thunderbird**将信息存储在文件夹`\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`中的**MBOX文件**中。

## 缩略图

当用户访问文件夹并使用缩略图进行组织时，将创建一个`thumbs.db`文件。这个数据库**存储文件夹中图像的缩略图**，即使它们被删除也是如此。在WinXP和Win 8-8.1中，此文件会自动创建。在Win7/Win10中，如果通过UNC路径（\IP\folder...）访问，它会自动创建。

您可以使用工具[**Thumbsviewer**](https://thumbsviewer.github.io)读取此文件。

### Thumbcache

从Windows Vista开始，**缩略图预览存储在系统的集中位置**。这使系统可以访问图像，而不受其位置的限制，并解决了Thumbs.db文件的局部性问题。缓存存储在**`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`**中，标有**thumbcache\_xxx.db**（按大小编号的文件）以及用于在每个大小数据库中查找缩略图的索引。

- Thumbcache\_32.db -> 小
- Thumbcache\_96.db -> 中
- Thumbcache\_256.db -> 大
- Thumbcache\_1024.db -> 特大

您可以使用[**ThumbCache Viewer**](https://thumbcacheviewer.github.io)读取此文件。

## Windows注册表

Windows注册表包含有关**系统和用户操作**的大量**信息**。

包含注册表的文件位于：

- %windir%\System32\Config\*_SAM\*_: `HKEY_LOCAL_MACHINE`
- %windir%\System32\Config\*_SECURITY\*_: `HKEY_LOCAL_MACHINE`
- %windir%\System32\Config\*_SYSTEM\*_: `HKEY_LOCAL_MACHINE`
- %windir%\System32\Config\*_SOFTWARE\*_: `HKEY_LOCAL_MACHINE`
- %windir%\System32\Config\*_DEFAULT\*_: `HKEY_LOCAL_MACHINE`
- %UserProfile%{User}\*_NTUSER.DAT\*_: `HKEY_CURRENT_USER`

从Windows Vista和Windows 2008 Server开始，`HKEY_LOCAL_MACHINE`注册表文件有一些备份，位于**`%Windir%\System32\Config\RegBack\`**中。

此外，从这些版本开始，注册表文件**`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`**会保存有关程序执行的信息。

### 工具

一些工具对于分析注册表文件很有用：

- **注册表编辑器**：它已安装在Windows中。这是一个GUI，可用于浏览当前会话的Windows注册表。
- [**注册表浏览器**](https://ericzimmerman.github.io/#!index.md)：它允许您加载注册表文件并通过GUI浏览它们。它还包含突出显示具有有趣信息的键的书签。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：同样，它具有GUI，可让您浏览加载的注册表，并包含突出显示已加载注册表中有趣信息的插件。
- [**Windows注册表恢复**](https://www.mitec.cz/wrr.html)：另一个能够提取注册表中重要信息的GUI应用程序。

### 恢复已删除元素

当键被删除时，它会被标记为已删除，但直到需要其占用的空间时才会被删除。因此，使用诸如**注册表浏览器**之类的工具，可以恢复这些已删除的键。

### 最后写入时间

每个键-值包含一个指示上次修改时间的**时间戳**。

### SAM

文件/注册表**SAM**包含系统的**用户、组和用户密码**哈希。

在`SAM\Domains\Account\Users`中，您可以获取用户名、RID、上次登录、上次登录失败、登录计数器、密码策略以及帐户创建时间。要获取**哈希值**，您还需要文件/注册表**SYSTEM**。

### Windows注册表中的有趣条目

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## 已执行的程序

### 基本Windows进程

您可以在以下页面了解有关检测可疑行为的基本Windows进程：

{% content-ref url="windows-processes.md" %}
[windows-processes.md](windows-processes.md)
{% endcontent-ref %}

### Windows最近应用程序

在注册表`NTUSER.DAT`的路径`Software\Microsoft\Current Version\Search\RecentApps`中，您可以找到有关**已执行的应用程序**、**上次执行时间**以及**启动次数**的信息。

### BAM（后台活动调节器）

您可以使用注册表编辑器打开`SYSTEM`文件，在路径`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`中，您可以找到有关**每个用户执行的应用程序**的信息（请注意路径中的`{SID}`），以及它们执行的**时间**（时间在注册表的数据值中）。

### Windows预取

预取是一种技术，允许计算机**静默获取显示内容所需的资源**，用户**可能在不久的将来访问**，以便更快地访问资源。

Windows预取包括创建**已执行程序的缓存**，以便能够更快地加载它们。这些缓存作为`.pf`文件创建在路径：`C:\Windows\Prefetch`中。在XP/VISTA/WIN7中，限制为128个文件，在Win8/Win10中为1024个文件。

文件名创建为`{program_name}-{hash}.pf`（哈希基于可执行文件的路径和参数）。在W10中，这些文件是压缩的。请注意，文件的存在仅表示**该程序曾被执行**。

文件`C:\Windows\Prefetch\Layout.ini`包含**预取文件夹的名称**。此文件包含有关**执行次数**、**执行日期**和程序打开的**文件**的信息。

要检查这些文件，您可以使用工具[**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch**的目标与prefetch相同，通过预测下一个加载的内容来**加快程序加载速度**。但是，它并不取代prefetch服务。\
该服务会在`C:\Windows\Prefetch\Ag*.db`中生成数据库文件。

在这些数据库中，您可以找到**程序的名称**、**执行次数**、**打开的文件**、**访问的卷**、**完整路径**、**时间范围**和**时间戳**。

您可以使用工具[**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/)访问这些信息。

### SRUM

**系统资源使用监视器**（SRUM）**监视**进程**消耗的资源**。它出现在W8中，并将数据存储在位于`C:\Windows\System32\sru\SRUDB.dat`的ESE数据库中。

它提供以下信息：

* AppID和路径
* 执行进程的用户
* 发送字节数
* 接收字节数
* 网络接口
* 连接持续时间
* 进程持续时间

此信息每60分钟更新一次。

您可以使用工具[**srum\_dump**](https://github.com/MarkBaggett/srum-dump)从此文件中获取日期。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**Shimcache**, 也被称为 **AppCompatCache**, 是 **应用程序兼容性数据库** 的一个组件，由 **Microsoft** 创建并被操作系统用来识别应用程序兼容性问题。

该缓存根据操作系统存储各种文件元数据，例如：

* 文件完整路径
* 文件大小
* **$Standard\_Information** (SI) 最后修改时间
* ShimCache 最后更新时间
* 进程执行标志

这些信息可以在注册表中找到：

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
* XP (96 个条目)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
* Server 2003 (512 个条目)
* 2008/2012/2016 Win7/Win8/Win10 (1024 个条目)

您可以使用工具 [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) 来解析这些信息。

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

**Amcache.hve** 文件是一个存储执行应用程序信息的注册表文件。它位于 `C:\Windows\AppCompat\Programas\Amcache.hve`

**Amcache.hve** 记录了最近运行的进程，并列出了执行的文件路径，可以用来查找执行的程序。它还记录了程序的 SHA1。

您可以使用工具 [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser) 来解析这些信息。
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
最有趣的CSV文件生成是`Amcache_Unassociated file entries`。

### RecentFileCache

此工件仅可在W7中找到，位于`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`，其中包含有关某些二进制文件最近执行的信息。

您可以使用工具[**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser)来解析文件。

### 计划任务

您可以从`C:\Windows\Tasks`或`C:\Windows\System32\Tasks`中提取它们，并将其读取为XML。

### 服务

您可以在注册表中的`SYSTEM\ControlSet001\Services`下找到它们。您可以查看将要执行的内容以及执行时间。

### **Windows商店**

安装的应用程序可以在`\ProgramData\Microsoft\Windows\AppRepository\`中找到\
此存储库具有一个**日志**，其中包含系统中安装的**每个应用程序**的信息，存储在数据库**`StateRepository-Machine.srd`**中。

在此数据库的Application表中，可以找到列："Application ID"、"PackageNumber"和"Display Name"。这些列包含有关预安装和已安装应用程序的信息，并且可以查找是否已卸载某些应用程序，因为已安装应用程序的ID应该是连续的。

还可以在注册表路径`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`中**找到已安装的应用程序**\
以及在`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`中**找到已卸载的应用程序**。

## Windows事件

Windows事件中显示的信息有：

* 发生了什么
* 时间戳（UTC + 0）
* 涉及的用户
* 涉及的主机（主机名、IP）
* 访问的资产（文件、文件夹、打印机、服务）

日志位于Windows Vista之前的`C:\Windows\System32\config`中，在Windows Vista之后位于`C:\Windows\System32\winevt\Logs`中。在Windows Vista之前，事件日志以二进制格式存储，在Windows Vista之后，它们以**XML格式**存储，并使用**.evtx**扩展名。

事件文件的位置可以在SYSTEM注册表中的**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**中找到。

可以使用Windows事件查看器（**`eventvwr.msc`**）或其他工具如[**Event Log Explorer**](https://eventlogxp.com) **或** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**来可视化这些事件。**

### 安全

这会记录访问事件，并提供有关安全配置的信息，可以在`C:\Windows\System32\winevt\Security.evtx`中找到。

事件文件的**最大大小**是可配置的，当达到最大大小时，它将开始覆盖旧事件。

注册的事件包括：

* 登录/注销
* 用户操作
* 访问文件、文件夹和共享资产
* 修改安全配置

与用户身份验证相关的事件：

| EventID   | 描述                        |
| --------- | ---------------------------- |
| 4624      | 成功身份验证                 |
| 4625      | 身份验证错误                 |
| 4634/4647 | 注销                         |
| 4672      | 具有管理员权限的登录           |

在EventID 4634/4647中有有趣的子类型：

* **2（交互式）**：使用键盘或软件（如VNC或`PSexec -U-`）进行交互式登录
* **3（网络）**：连接到共享文件夹
* **4（批处理）**：执行的进程
* **5（服务）**：由服务控制管理器启动的服务
* **6（代理）**：代理登录
* **7（解锁）**：使用密码解锁屏幕
* **8（网络明文）**：用户发送明文密码进行身份验证。此事件通常来自IIS
* **9（新凭据）**：当使用命令`RunAs`或用户使用不同凭据访问网络服务时生成
* **10（远程交互式）**：通过终端服务或RDP进行身份验证
* **11（缓存交互式）**：使用最后缓存的凭据访问，因为无法联系域控制器
* **12（缓存远程交互式）**：使用缓存凭据远程登录（10和11的组合）
* **13（缓存解锁）**：使用缓存凭据解锁已锁定的计算机

在此文章中，您可以找到如何模拟所有这些类型的登录以及在其中哪些类型中可以从内存中转储凭据的信息：[https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

事件的状态和子状态信息可以指示有关事件原因的更多详细信息。例如，查看以下Event ID 4625的状态和子状态代码：

![](<../../../.gitbook/assets/image (455).png>)

### 恢复Windows事件

强烈建议关闭可疑的计算机，**拔掉电源**以最大化恢复Windows事件的可能性。如果它们被删除，可以尝试使用工具[**Bulk\_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor)来恢复它们，指示**evtx**扩展名。

## 通过Windows事件识别常见攻击

* [https://redteamrecipe.com/event-codes/](https://redteamrecipe.com/event-codes/)

### 暴力破解攻击

暴力破解攻击很容易识别，因为会出现**多个EventID 4625**。如果攻击**成功**，在EventID 4625之后，将会出现**一个EventID 4624**。

### 时间更改

这对取证团队来说是非常糟糕的，因为所有时间戳都将被修改。此事件由安全事件日志中的EventID 4616记录。

### USB设备

以下System EventIDs很有用：

* 20001 / 20003 / 10000：第一次使用
* 10100：驱动程序更新

DeviceSetupManager中的EventID 112包含每个插入的USB设备的时间戳。

### 关机/开机

“事件日志”服务的ID 6005表示计算机已开机。ID 6006表示计算机已关机。

### 日志删除

安全EventID 1102表示日志已被删除。
