# macOS .Net应用程序注入

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

**这是文章[https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)的摘要。请查看获取更多详细信息！**

## .NET Core调试 <a href="#net-core-debugging" id="net-core-debugging"></a>

### **建立调试会话** <a href="#net-core-debugging" id="net-core-debugging"></a>

在.NET中，调试器和被调试程序之间的通信由[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp)管理。该组件为每个.NET进程设置两个命名管道，如[dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127)中所示，这些管道通过[twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27)启动。这些管道的后缀分别为**`-in`**和**`-out`**。

通过访问用户的**`$TMPDIR`**，可以找到用于调试.Net应用程序的调试FIFO。

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259)负责管理来自调试器的通信。要启动新的调试会话，调试器必须通过以`MessageHeader`结构开头的`out`管道发送消息，详细信息请参阅.NET源代码：
```c
struct MessageHeader {
MessageType   m_eType;        // Message type
DWORD         m_cbDataBlock;  // Size of following data block (can be zero)
DWORD         m_dwId;         // Message ID from sender
DWORD         m_dwReplyId;    // Reply-to Message ID
DWORD         m_dwLastSeenId; // Last seen Message ID by sender
DWORD         m_dwReserved;   // Reserved for future (initialize to zero)
union {
struct {
DWORD         m_dwMajorVersion;   // Requested/accepted protocol version
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;
BYTE          m_sMustBeZero[8];
}
```
要请求一个新会话，需要按照以下方式填充这个结构，将消息类型设置为 `MT_SessionRequest`，将协议版本设置为当前版本：
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
这个标头随后使用`write`系统调用发送到目标，接着是包含会话GUID的`sessionRequestData`结构体：
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
读取`out`管道上的操作确认了调试会话建立的成功或失败:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## 读取内存
一旦建立了调试会话，就可以使用[`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896)消息类型来读取内存。readMemory函数进行了详细说明，执行了发送读取请求和检索响应的必要步骤：
```c
bool readMemory(void *addr, int len, unsigned char **output) {
// Allocation and initialization
...
// Write header and read response
...
// Read the memory from the debuggee
...
return true;
}
```
完整的概念验证（POC）可以在[这里](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)找到。

## 写入内存

同样，可以使用`writeMemory`函数来写入内存。该过程涉及将消息类型设置为`MT_WriteMemory`，指定数据的地址和长度，然后发送数据：
```c
bool writeMemory(void *addr, int len, unsigned char *input) {
// Increment IDs, set message type, and specify memory location
...
// Write header and data, then read the response
...
// Confirm memory write was successful
...
return true;
}
```
关联的POC在[这里](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)。

## .NET Core代码执行 <a href="#net-core-code-execution" id="net-core-code-execution"></a>

要执行代码，需要识别具有rwx权限的内存区域，可以使用vmmap -pages来完成：
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
在.NET Core中，定位要覆盖的函数指针位置是必要的，这可以通过针对**动态函数表（DFT）**来实现。这个表在[`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h)中有详细说明，被运行时用于JIT编译辅助函数。

对于x64系统，可以使用签名搜索来找到`libcorclr.dll`中对符号`_hlpDynamicFuncTable`的引用。

`MT_GetDCB`调试器函数提供了有用的信息，包括一个辅助函数`m_helperRemoteStartAddr`的地址，指示了`libcorclr.dll`在进程内存中的位置。然后使用这个地址来开始搜索DFT，并用shellcode的地址覆盖一个函数指针。

可以在[这里](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)找到用于注入到PowerShell的完整POC代码。

## 参考资料

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
