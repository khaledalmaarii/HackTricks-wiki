{% hint style="success" %}
学习和实践AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

# 时间戳

攻击者可能有兴趣**更改文件的时间戳**以避免被检测。\
可以在 MFT 中的属性 `$STANDARD_INFORMATION` 和 `$FILE_NAME` 中找到时间戳。

这两个属性都有 4 个时间戳：**修改**、**访问**、**创建** 和 **MFT 注册修改**（MACE 或 MACB）。

**Windows 资源管理器**和其他工具显示来自 **`$STANDARD_INFORMATION`** 的信息。

## TimeStomp - 反取证工具

该工具**修改**了 **`$STANDARD_INFORMATION`** 中的时间戳信息，**但不会**修改 **`$FILE_NAME`** 中的信息。因此，可以**识别**出**可疑活动**。

## Usnjrnl

**USN 日志**（Update Sequence Number Journal）是 NTFS（Windows NT 文件系统）的一个功能，用于跟踪卷的更改。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) 工具允许检查这些更改。

![](<../../.gitbook/assets/image (449).png>)

上图是该工具显示的**输出**，可以观察到对文件进行了一些**更改**。

## $LogFile

**文件系统中的所有元数据更改都会被记录**，这个过程称为[预写式日志记录](https://en.wikipedia.org/wiki/Write-ahead_logging)。记录的元数据保存在名为 `**$LogFile**` 的文件中，位于 NTFS 文件系统的根目录中。可以使用诸如 [LogFileParser](https://github.com/jschicht/LogFileParser) 的工具来解析此文件并识别更改。

![](<../../.gitbook/assets/image (450).png>)

再次，在工具的输出中可以看到**进行了一些更改**。

使用相同的工具，可以确定**时间戳何时被修改**：

![](<../../.gitbook/assets/image (451).png>)

* CTIME：文件的创建时间
* ATIME：文件的修改时间
* MTIME：文件的 MFT 注册修改
* RTIME：文件的访问时间

## `$STANDARD_INFORMATION` 和 `$FILE_NAME` 比较

另一种识别可疑修改文件的方法是比较两个属性上的时间，寻找**不匹配**。

## 纳秒

**NTFS** 时间戳的**精度**为**100 纳秒**。因此，找到时间戳为 2010-10-10 10:10:**00.000:0000 的文件非常可疑。

## SetMace - 反取证工具

该工具可以修改 `$STARNDAR_INFORMATION` 和 `$FILE_NAME` 两个属性。但是，从 Windows Vista 开始，需要一个实时操作系统来修改这些信息。

# 数据隐藏

NFTS 使用一个簇和最小信息大小。这意味着如果一个文件占用一个半簇，**剩余的一半将永远不会被使用**，直到文件被删除。因此，可以**在这个空闲空间中隐藏数据**。

有一些工具如 slacker 允许在这个“隐藏”空间中隐藏数据。然而，对 `$logfile` 和 `$usnjrnl` 的分析可以显示添加了一些数据：

![](<../../.gitbook/assets/image (452).png>)

因此，可以使用 FTK Imager 等工具检索空闲空间。请注意，这种工具可以保存内容混淆或甚至加密。

# UsbKill

这是一个工具，如果检测到 USB 端口发生任何更改，将**关闭计算机**。\
发现这一点的方法是检查运行中的进程并**审查每个运行的 Python 脚本**。

# 实时 Linux 发行版

这些发行版是**在 RAM 内存中执行**的。唯一能够检测到它们的方法是**如果 NTFS 文件系统以写权限挂载**。如果只以读权限挂载，将无法检测到入侵。

# 安全删除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows 配置

可以禁用多种 Windows 日志记录方法，使取证调查变得更加困难。

## 禁用时间戳 - UserAssist

这是一个维护用户运行每个可执行文件的日期和时间的注册表键。

禁用 UserAssist 需要两个步骤：

1. 设置两个注册表键，`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` 和 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`，都设置为零，以表示我们要禁用 UserAssist。
2. 清除类似 `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` 的注册表子树。

## 禁用时间戳 - Prefetch

这将保存有关执行的应用程序的信息，目的是改善 Windows 系统的性能。但是，这也对取证实践有用。

* 执行 `regedit`
* 选择文件路径 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* 右键单击 `EnablePrefetcher` 和 `EnableSuperfetch`
* 对每个都选择修改，将值从 1（或 3）更改为 0
* 重新启动

## 禁用时间戳 - 最后访问时间

每当从 Windows NT 服务器上的 NTFS 卷打开文件夹时，系统会花时间**更新列出的每个文件夹的时间戳字段**，称为最后访问时间。在使用频繁的 NTFS 卷上，这可能会影响性能。

1. 打开注册表编辑器（Regedit.exe）。
2. 浏览到 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`。
3. 查找 `NtfsDisableLastAccessUpdate`。如果不存在，请添加此 DWORD 并将其值设置为 1，以禁用该过程。
4. 关闭注册表编辑器，并重新启动服务器。
## 删除 USB 历史记录

所有的 **USB 设备条目** 都存储在 Windows 注册表中的 **USBSTOR** 注册表键下，其中包含子键，每当您将 USB 设备插入 PC 或笔记本电脑时就会创建。您可以在此处找到此键 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**删除此** 将删除 USB 历史记录。\
您也可以使用工具 [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) 来确保已删除它们（并删除它们）。

另一个保存有关 USB 的信息的文件是位于 `C:\Windows\INF` 内的文件 `setupapi.dev.log`。这也应该被删除。

## 禁用阴影副本

使用 `vssadmin list shadowstorage` **列出**阴影副本\
运行 `vssadmin delete shadow` **删除**它们

您还可以通过 GUI 删除它们，按照 [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) 中提出的步骤进行操作。

要禁用阴影副本，请按照[此处的步骤](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)：

1. 通过在单击 Windows 启动按钮后的文本搜索框中键入 "services" 来打开服务程序。
2. 从列表中找到 "Volume Shadow Copy"，选择它，然后通过右键单击访问属性。
3. 从 "启动类型" 下拉菜单中选择禁用，然后通过单击应用和确定来确认更改。

还可以在注册表 `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` 中修改要复制到阴影副本中的文件的配置。

## 覆盖已删除的文件

* 您可以使用一个 **Windows 工具**：`cipher /w:C` 这将指示 cipher 从 C 驱动器内的可用未使用磁盘空间中删除任何数据。
* 您还可以使用类似 [**Eraser**](https://eraser.heidi.ie) 的工具

## 删除 Windows 事件日志

* Windows + R --> eventvwr.msc --> 展开 "Windows 日志" --> 右键单击每个类别，然后选择 "清除日志"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## 禁用 Windows 事件日志

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* 在服务部分内禁用服务 "Windows 事件日志"
* `WEvtUtil.exec clear-log` 或 `WEvtUtil.exe cl`

## 禁用 $UsnJrnl

* `fsutil usn deletejournal /d c:`

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


{% hint style="success" %}
学习并练习 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
