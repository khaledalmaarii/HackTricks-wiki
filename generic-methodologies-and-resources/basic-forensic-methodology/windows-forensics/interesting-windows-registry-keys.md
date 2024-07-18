# 有趣的Windows注册表键

### 有趣的Windows注册表键

{% hint style="success" %}
学习和实践AWS黑客：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享黑客技巧。

</details>
{% endhint %}

### **Windows版本和所有者信息**
- 位于**`Software\Microsoft\Windows NT\CurrentVersion`**，您将找到Windows版本、服务包、安装时间以及注册所有者的名称。

### **计算机名称**
- 主机名位于**`System\ControlSet001\Control\ComputerName\ComputerName`**。

### **时区设置**
- 系统的时区存储在**`System\ControlSet001\Control\TimeZoneInformation`**中。

### **访问时间跟踪**
- 默认情况下，最后访问时间跟踪被关闭（**`NtfsDisableLastAccessUpdate=1`**）。要启用它，请使用：
`fsutil behavior set disablelastaccess 0`

### Windows版本和服务包
- **Windows版本**指示版本（例如，家庭版、专业版）及其发布（例如，Windows 10、Windows 11），而**服务包**是包含修复程序和有时新功能的更新。

### 启用最后访问时间
- 启用最后访问时间跟踪允许您查看文件上次打开的时间，这对于取证分析或系统监控至关重要。

### 网络信息详细信息
- 注册表中保存了大量关于网络配置的数据，包括**网络类型（无线、有线、3G）**和**网络类别（公共、私人/家庭、域/工作）**，这对于了解网络安全设置和权限至关重要。

### 客户端端缓存（CSC）
- **CSC**通过缓存共享文件的副本来增强离线文件访问。不同的**CSCFlags**设置控制如何以及哪些文件被缓存，影响性能和用户体验，特别是在网络连接不稳定的环境中。

### 自启动程序
- 在各种`Run`和`RunOnce`注册表键中列出的程序会在启动时自动运行，影响系统启动时间，并有可能成为识别恶意软件或不需要的软件的关注点。

### Shellbags
- **Shellbags**不仅存储文件夹视图的偏好设置，还提供了对文件夹访问的取证证据，即使文件夹已经不存在。它们对于调查非常宝贵，揭示了通过其他方式不明显的用户活动。

### USB信息和取证
- 注册表中存储的有关USB设备的详细信息可以帮助跟踪连接到计算机的设备，可能将设备与敏感文件传输或未经授权访问事件联系起来。

### 卷序列号
- **卷序列号**对于跟踪文件系统的特定实例至关重要，在需要在不同设备之间建立文件来源的取证场景中非常有用。

### **关机详细信息**
- 关机时间和计数（仅适用于XP）保存在**`System\ControlSet001\Control\Windows`**和**`System\ControlSet001\Control\Watchdog\Display`**中。

### **网络配置**
- 有关详细网络接口信息，请参阅**`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**。
- 首次和最后一次网络连接时间，包括VPN连接，在**`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**的各个路径下记录。

### **共享文件夹**
- 共享文件夹和设置位于**`System\ControlSet001\Services\lanmanserver\Shares`**。客户端端缓存（CSC）设置决定离线文件的可用性。

### **自动启动的程序**
- 类似**`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`**和`Software\Microsoft\Windows\CurrentVersion`下的条目详细说明了设置为在启动时运行的程序。

### **搜索和输入路径**
- 在注册表中跟踪的资源管理器搜索和输入路径分别位于**`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`**下的WordwheelQuery和TypedPaths中。

### **最近文档和Office文件**
- 访问的最近文档和Office文件记录在`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`和特定Office版本路径中。

### **最近使用的（MRU）项目**
- MRU列表，指示最近的文件路径和命令，存储在`NTUSER.DAT`的各个`ComDlg32`和`Explorer`子键中。

### **用户活动跟踪**
- 用户助手功能记录了详细的应用程序使用统计信息，包括运行次数和上次运行时间，位于**`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**。

### **Shellbags分析**
- 存储着文件夹访问详细信息的Shellbags位于`USRCLASS.DAT`和`NTUSER.DAT`的`Software\Microsoft\Windows\Shell`下。使用**[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)**进行分析。

### **USB设备历史**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`**和**`HKLM\SYSTEM\ControlSet001\Enum\USB`**包含有关连接的USB设备的丰富详细信息，包括制造商、产品名称和连接时间戳。
- 可通过搜索`NTUSER.DAT`中的设备的**{GUID}**来确定与特定USB设备关联的用户。
- 可通过`System\MountedDevices`和`Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`分别追踪最后安装的设备及其卷序列号。

本指南总结了访问Windows系统上详细系统、网络和用户活动信息的关键路径和方法，旨在清晰易懂。


{% hint style="success" %}
学习和实践AWS黑客：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享黑客技巧。

</details>
{% endhint %}
