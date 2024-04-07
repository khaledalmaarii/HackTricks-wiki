# Windows取证物

## Windows取证物

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 通用Windows取证物

### Windows 10通知

在路径`\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`中，您可以找到数据库`appdb.dat`（Windows周年更新之前）或`wpndatabase.db`（Windows周年更新之后）。

在这个SQLite数据库中，您可以找到包含所有通知（以XML格式）的`Notification`表，其中可能包含有趣的数据。

### 时间轴

时间轴是Windows的一个特性，提供了访问的网页、编辑的文档和执行的应用程序的**时间顺序历史记录**。

数据库位于路径`\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`。可以使用SQLite工具或工具[**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)打开此数据库，**该工具生成2个文件，可以使用工具**[**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **打开**。

### ADS（备用数据流）

下载的文件可能包含**ADS Zone.Identifier**，指示它是如何从内部网络、互联网等**下载**的。一些软件（如浏览器）通常会放置**更多**的**信息**，如文件下载的**URL**。

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

使用 **ArsenalImageMounter** 挂载取证镜像，可以使用工具 [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) 来检查阴影副本，甚至可以从阴影副本备份中**提取文件**。

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
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **第二组：**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate。

第一组时间戳引用**文件本身的时间戳**。第二组引用**链接文件的时间戳**。

您可以通过运行 Windows CLI 工具 [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) 获取相同的信息。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
### 跳转列表

这些是每个应用程序指示的最近文件。这是您可以在每个应用程序上访问的**最近使用的文件列表**。它们可以**自动创建或自定义**。

自动创建的**跳转列表**存储在`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`中。跳转列表的命名遵循格式`{id}.autmaticDestinations-ms`，其中初始ID是应用程序的ID。

自定义跳转列表存储在`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`中，它们通常由应用程序创建，通常是因为文件发生了**重要**事件（可能标记为收藏夹）。

任何跳转列表的**创建时间**表示**文件被访问的第一次时间**，**修改时间表示最后一次时间**。

您可以使用[JumplistExplorer](https://ericzimmerman.github.io/#!index.md)检查跳转列表。

![](<../../../.gitbook/assets/image (474).png>)

（_请注意，JumplistExplorer提供的时间戳与跳转列表文件本身相关_）

### Shellbags

[**点击此链接了解什么是shellbags。**](interesting-windows-registry-keys.md#shellbags)

## Windows USB使用

通过以下内容的创建，可以确定已使用USB设备：

* Windows最近文件夹
* Microsoft Office最近文件夹
* 跳转列表

请注意，有些LNK文件指向WPDNSE文件夹而不是原始路径：

![](<../../../.gitbook/assets/image (476).png>)

文件夹WPDNSE中的文件是原始文件的副本，因此不会在PC重新启动后保留，并且GUID是从shellbag中获取的。

### 注册表信息

[查看此页面以了解](interesting-windows-registry-keys.md#usb-information)哪些注册表键包含有关连接的USB设备的有趣信息。

### setupapi

检查文件`C:\Windows\inf\setupapi.dev.log`，以获取有关USB连接产生的时间戳（搜索`Section start`）。

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)可用于获取连接到图像的USB设备的信息。

![](<../../../.gitbook/assets/image (483).png>)

### 插拔清理

名为“插拔清理”的计划任务主要用于删除过时的驱动程序版本。与保留最新驱动程序包版本的指定目的相反，在线资源表明它还针对在过去30天内未活动的驱动程序。因此，未连接在过去30天内的可移动设备的驱动程序可能会被删除。

该任务位于以下路径：
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

提供了描述任务内容的屏幕截图：
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

电子邮件包含**2个有趣部分：邮件的标题和内容**。在**标题**中，您可以找到以下信息：

* **谁**发送了电子邮件（电子邮件地址、IP、重定向电子邮件的邮件服务器）
* 电子邮件发送的**时间**

此外，在`References`和`In-Reply-To`标题中，您可以找到消息的ID：

![](<../../../.gitbook/assets/image (484).png>)

### Windows邮件应用

此应用程序以HTML或文本格式保存电子邮件。您可以在`\Users\<username>\AppData\Local\Comms\Unistore\data\3\`的子文件夹中找到电子邮件。电子邮件以`.dat`扩展名保存。

电子邮件的**元数据**和**联系人**可以在**EDB数据库**中找到：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

将文件的扩展名从`.vol`更改为`.edb`，然后您可以使用工具[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)打开它。在`Message`表中，您可以查看电子邮件。

### Microsoft Outlook

当使用Exchange服务器或Outlook客户端时，将会有一些MAPI标题：

* `Mapi-Client-Submit-Time`：发送电子邮件时的系统时间
* `Mapi-Conversation-Index`：线程的子消息数量和线程每条消息的时间戳
* `Mapi-Entry-ID`：消息标识符。
* `Mappi-Message-Flags`和`Pr_last_Verb-Executed`：有关MAPI客户端的信息（消息已读？未读？已回复？重定向？离开办公室？）

在Microsoft Outlook客户端中，所有已发送/接收的消息、联系人数据和日历数据都存储在以下PST文件中：

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook`（WinXP）
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

注册表路径`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`指示正在使用的文件。

您可以使用工具[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)打开PST文件。

![](<../../../.gitbook/assets/image (485).png>)
### Microsoft Outlook OST Files

**OST文件**是Microsoft Outlook在配置了**IMAP**或**Exchange**服务器时生成的，存储类似于PST文件的信息。该文件与服务器同步，保留**最近12个月**的数据，最大大小为**50GB**，位于与PST文件相同的目录中。要查看OST文件，可以使用[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)。

### 检索附件

丢失的附件可能可以从以下位置恢复：

- 对于**IE10**：`%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- 对于**IE11及以上**：`%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX文件

**Thunderbird**使用**MBOX文件**存储数据，位于`\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`。

### 图像缩略图

- **Windows XP和8-8.1**：访问带有缩略图的文件夹会生成一个`thumbs.db`文件，即使在删除后仍会存储图像预览。
- **Windows 7/10**：通过UNC路径访问时会创建`thumbs.db`。
- **Windows Vista及更新版本**：缩略图预览集中存储在`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`中，文件名为**thumbcache\_xxx.db**。[**Thumbsviewer**](https://thumbsviewer.github.io)和[**ThumbCache Viewer**](https://thumbcacheviewer.github.io)是查看这些文件的工具。

### Windows注册表信息

Windows注册表存储广泛的系统和用户活动数据，包含在以下文件中：

- 对于各种`HKEY_LOCAL_MACHINE`子键，位于`%windir%\System32\Config`。
- 对于`HKEY_CURRENT_USER`，位于`%UserProfile%{User}\NTUSER.DAT`。
- Windows Vista及更高版本会在`%Windir%\System32\Config\RegBack\`中备份`HKEY_LOCAL_MACHINE`注册表文件。
- 此外，程序执行信息存储在从Windows Vista和Windows 2008 Server开始的`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`中。

### 工具

一些工具可用于分析注册表文件：

* **注册表编辑器**：已安装在Windows中。它是一个GUI，可用于浏览当前会话的Windows注册表。
* [**注册表浏览器**](https://ericzimmerman.github.io/#!index.md)：允许您加载注册表文件并通过GUI浏览它们。还包含突出显示具有有趣信息的键的书签。
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：同样具有GUI，可用于浏览加载的注册表，并包含突出显示加载的注册表中有趣信息的插件。
* [**Windows注册表恢复**](https://www.mitec.cz/wrr.html)：另一个能够提取注册表中重要信息的GUI应用程序。

### 恢复已删除元素

删除键后会标记为已删除，但在需要占用其空间之前不会被删除。因此，使用诸如**注册表浏览器**之类的工具可以恢复这些已删除的键。

### 最后写入时间

每个键-值包含一个指示其上次修改时间的**时间戳**。

### SAM

文件/注册表**SAM**包含系统的**用户、组和用户密码**哈希。

在`SAM\Domains\Account\Users`中，您可以获取用户名、RID、上次登录、上次登录失败、登录计数器、密码策略以及帐户创建时间。要获取**哈希值**，还需要文件/注册表**SYSTEM**。

### Windows注册表中的有趣条目

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## 执行的程序

### 基本Windows进程

在[此文章](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)中，您可以了解常见的Windows进程，以便检测可疑行为。

### Windows最近的应用程序

在注册表`NTUSER.DAT`的路径`Software\Microsoft\Current Version\Search\RecentApps`中，您可以找到有关**执行的应用程序**、**上次执行时间**以及**启动次数**的信息。

### BAM（后台活动调节器）

您可以使用注册表编辑器打开`SYSTEM`文件，在路径`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`中，您可以找到有关每个用户执行的**应用程序**的信息（注意路径中的`{SID}`），以及它们执行的**时间**（时间在注册表的数据值中）。

### Windows预取

预取是一种技术，允许计算机默默地**获取显示内容所需的资源**，用户**可能在不久的将来访问**，以便更快地访问资源。

Windows预取包括创建**已执行程序的缓存**，以便更快地加载它们。这些缓存以`.pf`文件的形式创建在路径：`C:\Windows\Prefetch`。在XP/VISTA/WIN7中限制为128个文件，在Win8/Win10中为1024个文件。

文件名创建为`{program_name}-{hash}.pf`（哈希基于可执行文件的路径和参数）。在W10中，这些文件是压缩的。请注意，文件的存在仅表示**该程序曾被执行**。

文件`C:\Windows\Prefetch\Layout.ini`包含**预取文件夹的名称**。该文件包含有关**执行次数**、**执行日期**和程序打开的**文件**的信息。

要检查这些文件，可以使用工具[**PEcmd.exe**](https://github.com/EricZimmerman/PECmd)。
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

**AppCompatCache**（也称为**ShimCache**）是**Microsoft**开发的**应用程序兼容性数据库**的一部分，用于解决应用程序兼容性问题。该系统组件记录了各种文件元数据，包括：

- 文件的完整路径
- 文件大小
- **$Standard\_Information**（SI）下的最后修改时间
- ShimCache的最后更新时间
- 进程执行标志

这些数据存储在注册表中的特定位置，具体取决于操作系统的版本：

- 对于XP，数据存储在`SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`下，容量为96个条目。
- 对于Server 2003以及Windows版本2008、2012、2016、7、8和10，存储路径为`SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`，分别容纳512和1024个条目。

要解析存储的信息，建议使用[**AppCompatCacheParser**工具](https://github.com/EricZimmerman/AppCompatCacheParser)。

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

**Amcache.hve**文件本质上是一个记录在系统上执行的应用程序详细信息的注册表文件。通常位于`C:\Windows\AppCompat\Programas\Amcache.hve`。

该文件存储了最近执行的进程的记录，包括可执行文件的路径和它们的SHA1哈希值。这些信息对于跟踪系统上应用程序的活动非常宝贵。

要提取和分析**Amcache.hve**中的数据，可以使用[**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser)工具。以下命令是使用AmcacheParser解析**Amcache.hve**文件内容并以CSV格式输出结果的示例命令：
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
在生成的CSV文件中，`Amcache_Unassociated file entries`特别值得注意，因为它提供了关于未关联文件条目的丰富信息。

最有趣的CSV文件是`Amcache_Unassociated file entries`。

### RecentFileCache

此工件仅可在W7中找到，位于`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`，其中包含有关某些二进制文件最近执行的信息。

您可以使用工具[**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser)来解析该文件。

### 计划任务

您可以从`C:\Windows\Tasks`或`C:\Windows\System32\Tasks`中提取它们，并将其读取为XML。

### 服务

您可以在注册表中的`SYSTEM\ControlSet001\Services`下找到它们。您可以查看将要执行的内容以及执行时间。

### **Windows商店**

安装的应用程序可以在`\ProgramData\Microsoft\Windows\AppRepository\`中找到。\
此存储库中有一个**日志**，其中包含系统中安装的**每个应用程序**的信息，存储在名为**`StateRepository-Machine.srd`**的数据库中。

在此数据库的Application表中，可以找到列："Application ID"、"PackageNumber"和"Display Name"。这些列包含有关预安装和已安装应用程序的信息，并且可以查找是否已卸载某些应用程序，因为已安装应用程序的ID应该是连续的。

还可以在注册表路径`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`中**找到已安装的应用程序**\
以及在`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`中**找到已卸载的应用程序**。

## Windows事件

Windows事件中显示的信息包括：

* 发生了什么
* 时间戳（UTC + 0）
* 涉及的用户
* 涉及的主机（主机名，IP）
* 访问的资产（文件，文件夹，打印机，服务）

日志位于Windows Vista之前的`C:\Windows\System32\config`中，在Windows Vista之后位于`C:\Windows\System32\winevt\Logs`中。在Windows Vista之前，事件日志以二进制格式存储，在Windows Vista之后，它们以**XML格式**存储，并使用**.evtx**扩展名。

事件文件的位置可以在SYSTEM注册表中的**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**中找到。

可以使用Windows事件查看器（**`eventvwr.msc`**）或其他工具如[**Event Log Explorer**](https://eventlogxp.com) **或** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**来查看这些事件**。

## 理解Windows安全事件日志记录

安全配置文件中记录了访问事件，位于`C:\Windows\System32\winevt\Security.evtx`。此文件的大小可调整，当容量达到时，旧事件将被覆盖。记录的事件包括用户登录和注销、用户操作、安全设置更改，以及文件、文件夹和共享资产的访问。

### 用户身份验证的关键事件ID：

- **EventID 4624**：表示用户成功验证。
- **EventID 4625**：表示验证失败。
- **EventIDs 4634/4647**：代表用户注销事件。
- **EventID 4672**：表示具有管理权限的登录。

#### EventID 4634/4647中的子类型：

- **Interactive (2)**：直接用户登录。
- **Network (3)**：访问共享文件夹。
- **Batch (4)**：执行批处理过程。
- **Service (5)**：服务启动。
- **Proxy (6)**：代理身份验证。
- **Unlock (7)**：使用密码解锁屏幕。
- **Network Cleartext (8)**：明文密码传输，通常来自IIS。
- **New Credentials (9)**：使用不同凭据进行访问。
- **Remote Interactive (10)**：远程桌面或终端服务登录。
- **Cache Interactive (11)**：使用缓存凭据登录，无需与域控制器联系。
- **Cache Remote Interactive (12)**：使用缓存凭据远程登录。
- **Cached Unlock (13)**：使用缓存凭据解锁。

#### EventID 4625的状态和子状态代码：

- **0xC0000064**：用户名不存在 - 可能指示用户名枚举攻击。
- **0xC000006A**：正确的用户名但密码错误 - 可能是密码猜测或暴力破解尝试。
- **0xC0000234**：用户帐户被锁定 - 可能是多次登录失败导致的暴力破解攻击。
- **0xC0000072**：帐户已禁用 - 未经授权的尝试访问已禁用的帐户。
- **0xC000006F**：在允许的时间外登录 - 表示尝试在设置的登录时间之外访问，可能是未经授权访问的迹象。
- **0xC0000070**：违反工作站限制 - 可能是尝试从未经授权的位置登录。
- **0xC0000193**：帐户过期 - 使用已过期用户帐户的访问尝试。
- **0xC0000071**：密码已过期 - 使用过时密码的登录尝试。
- **0xC0000133**：时间同步问题 - 客户端和服务器之间存在较大的时间差异，可能表明更复杂的攻击，如票据传递攻击。
- **0xC0000224**：需要强制更改密码 - 频繁的强制更改可能表明试图破坏帐户安全性。
- **0xC0000225**：表示系统错误而不是安全问题。
- **0xC000015b**：拒绝的登录类型 - 使用未经授权的登录类型进行访问尝试，例如用户尝试执行服务登录。

#### EventID 4616：
- **时间更改**：修改系统时间，可能会混淆事件时间轴。

#### EventID 6005和6006：
- **系统启动和关闭**：EventID 6005表示系统启动，而EventID 6006表示系统关闭。

#### EventID 1102：
- **日志删除**：安全日志被清除，通常是掩盖非法活动的红旗。

#### 用于USB设备跟踪的EventID：
- **20001 / 20003 / 10000**：USB设备首次连接。
- **10100**：USB驱动程序更新。
- **EventID 112**：USB设备插入时间。

要了解有关模拟这些登录类型和凭据转储机会的实际示例，请参阅[Altered Security的详细指南](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)。

事件详细信息，包括状态和子状态代码，可进一步了解事件原因，特别是在Event ID 4625中。

### 恢复Windows事件

为增加恢复已删除Windows事件的机会，建议直接拔掉嫌疑计算机的电源以关闭它。推荐使用指定`.evtx`扩展名的恢复工具**Bulk_extractor**来尝试恢复此类事件。

### 通过Windows事件识别常见攻击

要全面了解如何使用Windows事件ID识别常见网络攻击，请访问[Red Team Recipe](https://redteamrecipe.com/event-codes/)。

#### 暴力破解攻击

通过多个EventID 4625记录识别，如果攻击成功，则会跟随EventID 4624。

#### 时间更改

通过EventID 4616记录，系统时间的更改可能会使取证分析复杂化。

#### USB设备跟踪

用于USB设备跟踪的有用的系统EventID包括用于初始使用的20001/20003/10000，用于驱动程序更新的10100，以及来自DeviceSetupManager的插入时间戳的EventID 112。
#### 系统电源事件

EventID 6005表示系统启动，而EventID 6006表示关机。

#### 日志删除

安全事件ID 1102表示日志删除，这是进行取证分析的关键事件。

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
