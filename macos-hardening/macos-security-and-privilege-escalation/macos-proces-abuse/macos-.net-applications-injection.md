# macOS .Net Applications Injection

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**이것은 [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) 게시물의 요약입니다. 추가 세부정보는 해당 링크를 확인하세요!**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **디버깅 세션 설정** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET에서 디버거와 디버그 대상 간의 통신 처리는 [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp)에서 관리됩니다. 이 구성 요소는 [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127)에서 볼 수 있듯이 각 .NET 프로세스에 대해 두 개의 명명된 파이프를 설정하며, 이는 [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27)를 통해 시작됩니다. 이러한 파이프는 **`-in`** 및 **`-out`**으로 접미사가 붙습니다.

사용자의 **`$TMPDIR`**를 방문하면 .Net 애플리케이션을 디버깅하기 위한 디버깅 FIFO를 찾을 수 있습니다.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259)는 디버거로부터의 통신 관리를 담당합니다. 새로운 디버깅 세션을 시작하려면 디버거는 `MessageHeader` 구조체로 시작하는 메시지를 `out` 파이프를 통해 전송해야 하며, 이는 .NET 소스 코드에 자세히 설명되어 있습니다:
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
새 세션을 요청하기 위해, 이 구조체는 다음과 같이 채워지며, 메시지 유형을 `MT_SessionRequest`로 설정하고 프로토콜 버전을 현재 버전으로 설정합니다:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
이 헤더는 `write` 시스템 호출을 사용하여 대상에 전송되며, 그 뒤에 세션을 위한 GUID를 포함하는 `sessionRequestData` 구조체가 옵니다:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` 파이프에서의 읽기 작업은 디버깅 세션 설정의 성공 또는 실패를 확인합니다:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## 메모리 읽기
디버깅 세션이 설정되면 [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) 메시지 유형을 사용하여 메모리를 읽을 수 있습니다. 함수 readMemory는 읽기 요청을 보내고 응답을 검색하는 데 필요한 단계를 수행하는 자세한 내용입니다:
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
The complete proof of concept (POC) is available [here](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Writing Memory

유사하게, 메모리는 `writeMemory` 함수를 사용하여 쓸 수 있습니다. 이 과정은 메시지 유형을 `MT_WriteMemory`로 설정하고, 데이터의 주소와 길이를 지정한 다음, 데이터를 전송하는 것을 포함합니다:
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
연관된 POC는 [여기](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)에서 확인할 수 있습니다.

## .NET Core 코드 실행 <a href="#net-core-code-execution" id="net-core-code-execution"></a>

코드를 실행하려면 rwx 권한이 있는 메모리 영역을 식별해야 하며, 이는 vmmap -pages를 사용하여 수행할 수 있습니다.
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
함수 포인터를 덮어쓸 위치를 찾는 것은 필요하며, .NET Core에서는 **Dynamic Function Table (DFT)**를 타겟팅하여 이를 수행할 수 있습니다. 이 테이블은 [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h)에서 자세히 설명되어 있으며, 런타임에서 JIT 컴파일 헬퍼 함수에 사용됩니다.

x64 시스템의 경우, 서명 검색을 사용하여 `libcorclr.dll`에서 심볼 `_hlpDynamicFuncTable`에 대한 참조를 찾을 수 있습니다.

`MT_GetDCB` 디버거 함수는 헬퍼 함수의 주소인 `m_helperRemoteStartAddr`를 포함하여 유용한 정보를 제공합니다. 이는 프로세스 메모리에서 `libcorclr.dll`의 위치를 나타냅니다. 이 주소는 DFT 검색을 시작하고 함수 포인터를 셸코드의 주소로 덮어쓰는 데 사용됩니다.

PowerShell에 대한 주입을 위한 전체 POC 코드는 [여기](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)에서 접근할 수 있습니다.

## References

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
