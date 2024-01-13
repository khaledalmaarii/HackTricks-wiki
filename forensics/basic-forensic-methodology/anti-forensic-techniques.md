<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 时间戳

攻击者可能对**更改文件的时间戳**感兴趣，以避免被检测到。\
可以在MFT的`$STANDARD_INFORMATION`和`$FILE_NAME`属性中找到时间戳。

这两个属性都有4个时间戳：**修改**、**访问**、**创建**和**MFT注册表修改**（MACE或MACB）。

**Windows资源管理器**和其他工具显示来自**`$STANDARD_INFORMATION`**的信息。

## TimeStomp - 反取证工具

此工具**修改**`$STANDARD_INFORMATION`中的时间戳信息，**但不**修改`$FILE_NAME`中的信息。因此，可以**识别**可疑**活动**。

## Usnjrnl

**USN日志**（更新序列号日志）或更改日志，是Windows NT文件系统（NTFS）的一个特性，**记录对卷所做的更改**。\
可以使用工具[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)来搜索此记录的修改。

![](<../../.gitbook/assets/image (449).png>)

上图是**工具**显示的**输出**，可以看到对文件进行了一些**更改**。

## $LogFile

为了确保系统崩溃后能够一致地恢复关键文件系统结构，对文件系统的所有元数据更改都会被记录下来。这称为[预写日志](https://en.wikipedia.org/wiki/Write-ahead_logging)。\
记录的元数据存储在一个名为“**$LogFile**”的文件中，该文件位于NTFS文件系统的根目录中。\
可以使用像[LogFileParser](https://github.com/jschicht/LogFileParser)这样的工具来解析这个文件并找到更改。

![](<../../.gitbook/assets/image (450).png>)

同样，在工具的输出中可以看到进行了**一些更改**。

使用同一工具还可以识别时间戳被修改的**具体时间**：

![](<../../.gitbook/assets/image (451).png>)

* CTIME: 文件的创建时间
* ATIME: 文件的修改时间
* MTIME: 文件的MFT注册表修改时间
* RTIME: 文件的访问时间

## `$STANDARD_INFORMATION`和`$FILE_NAME`比较

另一种识别可疑修改文件的方法是比较两个属性的时间，寻找**不匹配**。

## 纳秒

**NTFS**时间戳的**精度**为**100纳秒**。因此，发现时间戳如2010-10-10 10:10:**00.000:0000的文件非常可疑**。

## SetMace - 反取证工具

此工具可以修改`$STARNDAR_INFORMATION`和`$FILE_NAME`两个属性。然而，从Windows Vista开始，需要一个活动的操作系统来修改这些信息。

# 数据隐藏

NFTS使用簇和最小信息大小。这意味着，如果一个文件占用了一个簇和半个簇，那么**剩下的半个簇永远不会被使用**，直到文件被删除。因此，可以**在这个松散空间中隐藏数据**。

有像slacker这样的工具允许在这个“隐藏”的空间中隐藏数据。然而，对`$logfile`和`$usnjrnl`的分析可以显示添加了一些数据：

![](<../../.gitbook/assets/image (452).png>)

然后，可以使用像FTK Imager这样的工具来检索松散空间。注意，这类工具可以保存内容，使其模糊或甚至加密。

# UsbKill

这是一个工具，如果检测到USB端口有任何变化，它将**关闭计算机**。\
发现这一点的方法是检查正在运行的进程并**审查每个正在运行的python脚本**。

# Live Linux发行版

这些发行版是**在RAM内存中执行**的。唯一能检测到它们的方式是**如果NTFS文件系统以写权限挂载**。如果它只是以读权限挂载，将无法检测到入侵。

# 安全删除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows配置

可以禁用几种Windows日志记录方法，使取证调查变得更加困难。

## 禁用时间戳 - UserAssist

这是一个注册表键，维护了用户每次运行可执行文件的日期和时间。

禁用UserAssist需要两个步骤：

1. 设置两个注册表键，`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`和`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`，都设置为零，以表示我们希望禁用UserAssist。
2. 清除看起来像`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`的注册表子树。

## 禁用时间戳 - 预取

这将保存有关执行的应用程序的信息，目的是提高Windows系统的性能。然而，这也可以用于取证实践。

* 执行`regedit`
* 选择文件路径`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* 右键单击`EnablePrefetcher`和`EnableSuperfetch`
* 选择修改每个这些，将值从1（或3）更改为0
* 重启

## 禁用时间戳 - 最后访问时间

每当从Windows NT服务器上的NTFS卷打开文件夹时，系统都会花时间**更新每个列出文件夹上的时间戳字段**，称为最后访问时间。在频繁使用的NTFS卷上，这可能会影响性能。

1. 打开注册表编辑器（Regedit.exe）。
2. 浏览到`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`。
3. 查找`NtfsDisableLastAccessUpdate`。如果它不存在，添加这个DWORD并将其值设置为1，这将禁用该过程。
4. 关闭注册表编辑器，并重启服务器。

## 删除USB历史

所有**USB设备条目**都存储在Windows注册表的**USBSTOR**注册表键下，每当您将USB设备插入PC或笔记本电脑时，都会创建子键。您可以在这里找到这个键`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**删除这个**你将删除USB历史。\
您还可以使用工具[**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html)来确保您已经删除它们（并删除它们）。

另一个保存USB信息的文件是`C:\Windows\INF`内的`setupapi.dev.log`。这也应该被删除。

## 禁用影子副本

**列出**影子副本，使用`vssadmin list shadowstorage`\
**删除**它们，运行`vssadmin delete shadow`

您也可以按照[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)中提出的步骤通过GUI删除它们

禁用影子副本：

1. 转到Windows开始按钮，输入"services"到文本搜索框；打开服务程序。
2. 从列表中找到"Volume Shadow Copy"，突出显示它，然后右键>属性。
3. 从"启动类型"下拉菜单中，选择禁用，然后点击应用和确定。

![](<../../.gitbook/assets/image (453).png>)

也可以在注册表`HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`中修改哪些文件将被复制到影子副本的配置。

## 覆盖已删除的文件

* 您可以使用**Windows工具**：`cipher /w:C` 这将指示cipher从C驱动器中的可用未使用磁盘空间中删除任何数据。
* 您还可以使用像[**Eraser**](https://eraser.heidi.ie)这样的工具

## 删除Windows事件日志

* Windows + R --> eventvwr.msc --> 展开"Windows日志" --> 右键单击每个类别并选择"清除日志"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## 禁用Windows事件日志

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* 在服务部分禁用"Windows事件日志"服务
* `WEvtUtil.exec clear-log` 或 `WEvtUtil.exe cl`

## 禁用$UsnJrnl

* `fsutil usn deletejournal /d c:`


<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
