<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# 时间戳

攻击者可能有兴趣**更改文件的时间戳**以避免被检测到。\
可以在MFT的属性`$STANDARD_INFORMATION`和`$FILE_NAME`中找到时间戳。

这两个属性都有4个时间戳：**修改时间**，**访问时间**，**创建时间**和**MFT注册修改时间**（MACE或MACB）。

**Windows资源管理器**和其他工具显示来自**`$STANDARD_INFORMATION`**的信息。

## TimeStomp - 反取证工具

该工具**修改**了**`$STANDARD_INFORMATION`**中的时间戳信息，但**不修改**`$FILE_NAME`中的信息。因此，可以**识别**出**可疑活动**。

## Usnjrnl

**USN日志**（Update Sequence Number Journal）或更改日志是Windows NT文件系统（NTFS）的一个功能，用于**记录对卷所做的更改**。\
可以使用工具[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)来搜索对此记录的修改。

![](<../../.gitbook/assets/image (449).png>)

上图是该工具显示的**输出**，可以观察到对文件进行了一些**更改**。

## $LogFile

文件系统的所有元数据更改都会被记录下来，以确保在系统崩溃后能够恢复关键的文件系统结构。这称为[预写式日志](https://en.wikipedia.org/wiki/Write-ahead\_logging)。\
记录的元数据存储在名为“**$LogFile**”的文件中，该文件位于NTFS文件系统的根目录中。\
可以使用诸如[LogFileParser](https://github.com/jschicht/LogFileParser)之类的工具解析此文件并查找更改。

![](<../../.gitbook/assets/image (450).png>)

同样，在工具的输出中可以看到**进行了一些更改**。

使用相同的工具，可以确定**时间戳被修改的时间**：

![](<../../.gitbook/assets/image (451).png>)

* CTIME：文件的创建时间
* ATIME：文件的修改时间
* MTIME：文件的MFT注册修改时间
* RTIME：文件的访问时间

## `$STANDARD_INFORMATION`和`$FILE_NAME`的比较

另一种识别可疑修改文件的方法是比较两个属性上的时间，寻找**不匹配**。

## 纳秒

**NTFS**时间戳的**精度**为**100纳秒**。因此，找到时间戳为2010-10-10 10:10:**00.000:0000**的文件非常可疑。

## SetMace - 反取证工具

该工具可以修改`$STARNDAR_INFORMATION`和`$FILE_NAME`两个属性。但是，从Windows Vista开始，需要使用活动操作系统来修改此信息。

# 数据隐藏

NTFS使用簇和最小信息大小。这意味着如果一个文件占用了一个半簇，**剩余的一半将永远不会被使用**，直到文件被删除。因此，可以在这个"隐藏"空间中**隐藏数据**。

有一些工具（如slacker）允许在这个"隐藏"空间中隐藏数据。但是，对`$logfile`和`$usnjrnl`进行分析可以显示出添加了一些数据：

![](<../../.gitbook/assets/image (452).png>)

然后，可以使用FTK Imager等工具检索这个空闲空间。请注意，这种工具可以保存内容模糊或甚至加密。

# UsbKill

这是一个工具，如果检测到USB端口发生任何更改，将**关闭计算机**。\
发现这一点的方法是检查运行中的进程并**查看每个正在运行的Python脚本**。

# 实时Linux发行版

这些发行版是在**RAM内存中执行**的。唯一能够检测到它们的方法是**如果NTFS文件系统以写权限挂载**。如果只以读权限挂载，将无法检测到入侵。
# 安全删除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows配置

可以禁用多种Windows日志记录方法，使取证调查更加困难。

## 禁用时间戳 - UserAssist

这是一个维护用户运行每个可执行文件的日期和时间的注册表键。

禁用UserAssist需要两个步骤：

1. 设置两个注册表键，`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`和`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`，都设置为零，以表示我们要禁用UserAssist。
2. 清除类似于`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`的注册表子树。

## 禁用时间戳 - Prefetch

这将保存有关执行的应用程序的信息，以改善Windows系统的性能。然而，这也对取证实践有用。

* 执行`regedit`
* 选择文件路径`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* 右键单击`EnablePrefetcher`和`EnableSuperfetch`
* 对每个进行修改，将值从1（或3）更改为0
* 重新启动

## 禁用时间戳 - 最后访问时间

当从Windows NT服务器上的NTFS卷打开文件夹时，系统会花费时间在每个列出的文件夹上更新一个称为最后访问时间的时间戳字段。在使用频繁的NTFS卷上，这可能会影响性能。

1. 打开注册表编辑器（Regedit.exe）。
2. 浏览到`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`。
3. 查找`NtfsDisableLastAccessUpdate`。如果不存在，请添加此DWORD并将其值设置为1，以禁用该过程。
4. 关闭注册表编辑器，并重新启动服务器。

## 删除USB历史记录

所有**USB设备条目**都存储在Windows注册表的**USBSTOR**注册表键下，该键包含在您将USB设备插入PC或笔记本电脑时创建的子键。您可以在此处找到此键：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**删除**它将删除USB历史记录。\
您还可以使用工具[**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html)来确保您已删除它们（并删除它们）。

保存有关USB设备的另一个文件是`C:\Windows\INF`目录中的`setupapi.dev.log`文件。这也应该被删除。

## 禁用阴影副本

使用`vssadmin list shadowstorage`**列出**阴影副本\
运行`vssadmin delete shadow`**删除**它们

您还可以按照[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)中提出的步骤通过GUI删除它们。

要禁用阴影副本：

1. 转到Windows开始按钮，然后在文本搜索框中键入"services"；打开Services程序。
2. 从列表中找到"Volume Shadow Copy"，将其突出显示，然后右键单击 > 属性。
3. 从"启动类型"下拉菜单中选择禁用，然后单击应用和确定。

![](<../../.gitbook/assets/image (453).png>)

还可以在注册表`HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`中修改要复制到阴影副本中的文件的配置。

## 覆盖已删除的文件

* 您可以使用**Windows工具**：`cipher /w:C`。这将指示cipher从C驱动器中的可用未使用磁盘空间中删除任何数据。
* 您还可以使用诸如[**Eraser**](https://eraser.heidi.ie)之类的工具

## 删除Windows事件日志

* Windows + R --> eventvwr.msc --> 展开"Windows Logs" --> 右键单击每个类别，选择"Clear Log"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## 禁用Windows事件日志

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* 在服务部分禁用"Windows Event Log"服务
* `WEvtUtil.exec clear-log`或`WEvtUtil.exe cl`

## 禁用$UsnJrnl

* `fsutil usn deletejournal /d c:`


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
