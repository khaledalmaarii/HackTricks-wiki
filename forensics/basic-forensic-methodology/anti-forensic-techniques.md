<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 时间戳

攻击者可能有兴趣**更改文件的时间戳**以避免被检测。\
可以在MFT中的属性`$STANDARD_INFORMATION`和`$FILE_NAME`中找到时间戳。

这两个属性都有4个时间戳：**修改**、**访问**、**创建**和**MFT注册修改**（MACE或MACB）。

**Windows资源管理器**和其他工具显示来自**`$STANDARD_INFORMATION`**的信息。

## TimeStomp - 反取证工具

该工具**修改**了**`$STANDARD_INFORMATION`**中的时间戳信息，**但不会**修改**`$FILE_NAME`**中的信息。因此，可以**识别**出**可疑活动**。

## Usnjrnl

**USN日志**（更新序列号日志）是Windows NT文件系统（NTFS）的一个功能，**记录对卷所做更改的记录**。\
可以使用工具[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)来搜索对此记录的修改。

![](<../../.gitbook/assets/image (449).png>)

上图是该**工具显示的输出**，可以看到对文件进行了一些**更改**。

## $LogFile

文件系统的所有元数据更改都会被记录下来，以确保系统崩溃后可以一致地恢复关键文件系统结构。这称为[预写式日志记录](https://en.wikipedia.org/wiki/Write-ahead_logging)。\
记录的元数据存储在名为“**$LogFile**”的文件中，该文件位于NTFS文件系统的根目录中。\
可以使用诸如[LogFileParser](https://github.com/jschicht/LogFileParser)之类的工具来解析此文件并查找更改。

![](<../../.gitbook/assets/image (450).png>)

再次，在工具的输出中，可以看到**进行了一些更改**。

使用相同的工具，可以确定**时间戳何时被修改**：

![](<../../.gitbook/assets/image (451).png>)

* CTIME：文件的创建时间
* ATIME：文件的修改时间
* MTIME：文件的MFT注册修改时间
* RTIME：文件的访问时间

## `$STANDARD_INFORMATION`和`$FILE_NAME`比较

另一种识别可疑修改文件的方法是比较两个属性上的时间，寻找**不匹配**。

## 纳秒

**NTFS**时间戳的**精度**为**100纳秒**。因此，找到时间戳为2010-10-10 10:10:**00.000:0000的文件非常可疑**。

## SetMace - 反取证工具

该工具可以修改`$STARNDAR_INFORMATION`和`$FILE_NAME`两个属性。但是，从Windows Vista开始，需要一个实时操作系统来修改此信息。

# 数据隐藏

NFTS使用一个簇和最小信息大小。这意味着如果一个文件占用一个半簇，**剩余的一半将永远不会被使用**，直到文件被删除。因此，可以**在这个空闲空间中隐藏数据**。

有一些工具，如slacker，允许在这个“隐藏”空间中隐藏数据。但是，对`$logfile`和`$usnjrnl`的分析可能会显示添加了一些数据：

![](<../../.gitbook/assets/image (452).png>)

因此，可以使用FTK Imager等工具检索空闲空间。请注意，这种工具可能会保存内容模糊化或甚至加密。

# UsbKill

这是一个工具，如果检测到USB端口发生任何更改，将**关闭计算机**。\
发现这一点的方法是检查运行中的进程并**查看每个运行的Python脚本**。

# 实时Linux发行版

这些发行版是**在RAM内存中执行**的。唯一的检测方法是**如果NTFS文件系统以写权限挂载**。如果只以读权限挂载，将无法检测入侵。

# 安全删除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows配置

可以禁用几种Windows日志记录方法，使取证调查变得更加困难。

## 禁用时间戳 - UserAssist

这是一个维护用户运行每个可执行文件的日期和时间的注册表键。

禁用UserAssist需要两个步骤：

1. 设置两个注册表键，`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`和`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`，都设置为零，以表示我们要禁用UserAssist。
2. 清除类似`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`的注册表子树。

## 禁用时间戳 - Prefetch

这将保存有关执行的应用程序的信息，目的是提高Windows系统的性能。但是，这也对取证实践有用。

* 执行`regedit`
* 选择文件路径`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* 右键单击`EnablePrefetch`和`EnableSuperfetch`
* 对每个进行修改，将值从1（或3）更改为0
* 重新启动

## 禁用时间戳 - 最后访问时间

每当从Windows NT服务器的NTFS卷中打开文件夹时，系统会花费时间**更新列出的每个文件夹上的时间戳字段**，称为最后访问时间。在使用频繁的NTFS卷上，这可能会影响性能。

1. 打开注册表编辑器（Regedit.exe）。
2. 浏览到`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`。
3. 查找`NtfsDisableLastAccessUpdate`。如果不存在，请添加此DWORD并将其值设置为1，以禁用该过程。
4. 关闭注册表编辑器，并重新启动服务器。

## 删除USB历史记录

所有**USB设备条目**都存储在Windows注册表的**USBSTOR**注册表键下，该键包含每次将USB设备插入PC或笔记本电脑时创建的子键。您可以在此处找到此键 H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**删除此**将删除USB历史记录。\
您还可以使用工具[**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html)确保已删除它们（并删除它们）。

保存有关USB的信息的另一个文件是`C:\Windows\INF`中的文件`setupapi.dev.log`。这也应该被删除。

## 禁用阴影副本

使用`vssadmin list shadowstorage`**列出**阴影副本\
运行`vssadmin delete shadow`**删除**它们

也可以通过GUI删除它们，按照[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)中提出的步骤进行操作。

要禁用阴影副本：

1. 转到Windows开始按钮，输入“services”到文本搜索框中；打开服务程序。
2. 从列表中找到“Volume Shadow Copy”，突出显示它，然后右键单击 > 属性。
3. 从“启动类型”下拉菜单中选择“禁用”，然后单击应用和确定。

![](<../../.gitbook/assets/image (453).png>)

还可以在注册表`HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`中修改要复制到阴影副本中的文件的配置。

## 覆盖已删除的文件

* 您可以使用一个**Windows工具**：`cipher /w:C` 这将指示cipher从C驱动器中的可用未使用磁盘空间中删除任何数据。
* 您还可以使用诸如[**Eraser**](https://eraser.heidi.ie)之类的工具

## 删除Windows事件日志

* Windows + R --> eventvwr.msc --> 展开“Windows日志” --> 右键单击每个类别，选择“清除日志”
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## 禁用Windows事件日志

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* 在服务部分内部禁用服务“Windows事件日志”
* `WEvtUtil.exec clear-log` 或 `WEvtUtil.exe cl`

## 禁用$UsnJrnl

* `fsutil usn deletejournal /d c:`

</details>
