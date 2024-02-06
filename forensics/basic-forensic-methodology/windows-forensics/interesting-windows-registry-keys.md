# 有趣的Windows注册表键

## 有趣的Windows注册表键

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上**关注**我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## **Windows系统信息**

### 版本

* **`Software\Microsoft\Windows NT\CurrentVersion`**：Windows版本、服务包、安装时间和注册所有者

### 主机名

* **`System\ControlSet001\Control\ComputerName\ComputerName`**：主机名

### 时区

* **`System\ControlSet001\Control\TimeZoneInformation`**：时区

### 最后访问时间

* **`System\ControlSet001\Control\Filesystem`**：最后访问时间（默认情况下使用`NtfsDisableLastAccessUpdate=1`禁用，如果为`0`，则已启用）。
* 要启用它：`fsutil behavior set disablelastaccess 0`

### 关机时间

* `System\ControlSet001\Control\Windows`：关机时间
* `System\ControlSet001\Control\Watchdog\Display`：关机计数（仅限XP）

### 网络信息

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**：网络接口
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**：执行网络连接的第一次和最后一次时间以及通过VPN的连接
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}`**（适用于XP）& `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`：网络类型（0x47-无线，0x06-有线，0x17-3G）和类别（0-公共，1-私人/家庭，2-域/工作）以及最后连接

### 共享文件夹

* **`System\ControlSet001\Services\lanmanserver\Shares\`**：共享文件夹及其配置。如果启用了**客户端端缓存**（CSCFLAGS），则共享文件的副本将保存在客户端和服务器的`C:\Windows\CSC`中
* CSCFlag=0 -> 默认情况下，用户需要指定要缓存的文件
* CSCFlag=16 -> 自动缓存文档。“用户从共享文件夹打开的所有文件和程序将自动脱机可用”，未选中“优化性能”。
* CSCFlag=32 -> 类似于前面的选项，但选中了“优化性能”
* CSCFlag=48 -> 缓存已禁用。
* CSCFlag=2048：此设置仅适用于Win 7和8，并且是默认设置，直到禁用“简单文件共享”或使用“高级”共享选项。它似乎也是“家庭组”的默认设置
* CSCFlag=768 -> 此设置仅在共享打印设备上看到。

### 自启动程序

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `Software\Microsoft\Windows\CurrentVersion\Runonce`
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `Software\Microsoft\Windows\CurrentVersion\Run`

### 资源管理器搜索

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery`：用户使用资源管理器/助手搜索的内容。具有`MRU=0`的项目是最后一个。

### 输入路径

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`：资源管理器中键入的路径（仅适用于W10）

### 最近文档

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`：用户打开的最近文档
* `NTUSER.DAT\Software\Microsoft\Office{版本}{Excel|Word}\FileMRU`：最近的Office文档。版本：
* 14.0 Office 2010
* 12.0 Office 2007
* 11.0 Office 2003
* 10.0 Office X
* `NTUSER.DAT\Software\Microsoft\Office{版本}{Excel|Word} UserMRU\LiveID_###\FileMRU`：最近的Office文档。版本：
* 15.0 Office 2013
* 16.0 Office 2016

### 最近使用的项目

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LasVisitedPidlMRU`

指示执行文件的路径

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSaveMRU`（XP）
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSavePidlMRU`

指示在打开的窗口内打开的文件

### 最后运行的命令

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Policies\RunMR`

### 用户辅助键

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

GUID是应用程序的ID。保存的数据：

* 最后运行时间
* 运行次数
* GUI应用程序名称（包含绝对路径和更多信息）
* 焦点时间和焦点名称

## Shellbags

当您打开一个目录时，Windows会在注册表中保存有关如何可视化该目录的数据。这些条目称为Shellbags。

资源管理器访问：

* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

桌面访问：

* `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

要分析Shellbags，您可以使用[**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md)，您将能够找到文件夹的**MAC时间**以及与文件夹的**首次访问和最后访问**相关的**创建日期和修改日期**。

从以下图片中注意两件事：

1. 我们知道插入在**E：**中的**USB文件夹的名称**
2. 我们知道**shellbag的创建和修改时间**以及文件夹的创建和访问时间

![](<../../../.gitbook/assets/image (475).png>)

## USB信息

### 设备信息

注册表`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`监视连接到PC的每个USB设备。\
在此注册表中，可以找到：

* 制造商名称
* 产品名称和版本
* 设备类别ID
* 卷名称（在以下图片中，卷名称是突出显示的子键）

![](<../../../.gitbook/assets/image (477).png>)

![](<../../../.gitbook/assets/image (479) (1).png>)

此外，通过检查注册表`HKLM\SYSTEM\ControlSet001\Enum\USB`并比较子键的值，可以找到VID值。

![](<../../../.gitbook/assets/image (478).png>)

有了上述信息，可以使用注册表`SOFTWARE\Microsoft\Windows Portable Devices\Devices`来获取**`{GUID}`**：

![](<../../../.gitbook/assets/image (480).png>)

### 使用设备的用户

现在有了设备的**{GUID}**，可以**检查所有用户的NTUDER.DAT蜂房**，搜索GUID，直到在其中一个蜂房中找到它（`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2`）。

![](<../../../.gitbook/assets/image (481).png>)

### 最后挂载

通过检查注册表`System\MoutedDevices`，可以找出**最后挂载的设备**是哪个。在下图中，检查最后挂载在`E：`上的设备是东芝的（使用Registry Explorer工具）。

![](<../../../.gitbook/assets/image (483) (1) (1).png>)

### 卷序列号

在`Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`中，您可以找到卷序列号。**知道卷名称和卷序列号，您可以将使用该信息的LNK文件的信息进行关联**。

请注意，当格式化USB设备时：

* 创建新的卷名称
* 创建新的卷序列号
* 保留物理序列号

### 时间戳

在`System\ControlSet001\Enum\USBSTOR{VEN_PROD_VERSION}{USB serial}\Properties{83da6326-97a6-4088-9453-a1923f573b29}\`中，您可以找到设备连接的第一次和最后一次时间：

* 0064 -- 第一次连接
* 0066 -- 最后一次连接
* 0067 -- 断开连接

![](<../../../.gitbook/assets/image (482).png>)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上**关注**我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
