# macOS .Net 애플리케이션 인젝션

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 해킹 기법을 공유하세요.

</details>

**이것은 [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)의 글 요약입니다. 자세한 내용은 해당 글을 확인하세요!**

## .NET Core 디버깅 <a href="#net-core-debugging" id="net-core-debugging"></a>

### **디버깅 세션 설정** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET에서 디버거와 디버깅 대상 간의 통신은 [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp)에서 관리됩니다. 이 구성 요소는 [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127)에서 확인할 수 있듯이 .NET 프로세스당 두 개의 이름이 지정된 파이프를 설정합니다. 이 파이프는 [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27)를 통해 시작됩니다. 이 파이프는 **`-in`**과 **`-out`**로 접미사가 붙습니다.

사용자의 **`$TMPDIR`**을 방문하면 .Net 애플리케이션을 디버깅하기 위한 디버깅 FIFO를 찾을 수 있습니다.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259)는 디버거로부터의 통신을 관리합니다. 새로운 디버깅 세션을 시작하려면 디버거는 `out` 파이프를 통해 `MessageHeader` 구조체로 시작하는 메시지를 보내야 합니다. 이 구조체는 .NET 소스 코드에서 자세히 설명되어 있습니다:
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
새 세션을 요청하기 위해 다음과 같이 이 구조체를 채웁니다. 메시지 유형을 `MT_SessionRequest`로 설정하고 프로토콜 버전을 현재 버전으로 설정합니다.
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
이 헤더는 `write` 시스콜을 사용하여 대상에게 전송되며, 세션에 대한 GUID를 포함하는 `sessionRequestData` 구조체가 뒤따릅니다:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` 파이프에 대한 읽기 작업은 디버깅 세션 설정의 성공 또는 실패를 확인합니다.
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## 메모리 읽기
디버깅 세션이 설정되면 [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) 메시지 유형을 사용하여 메모리를 읽을 수 있습니다. readMemory 함수는 자세히 설명되어 있으며, 읽기 요청을 보내고 응답을 검색하기 위해 필요한 단계를 수행합니다:
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
완전한 개념 증명 (POC)은 [여기](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)에서 사용할 수 있습니다.

## 메모리 쓰기

마찬가지로, `writeMemory` 함수를 사용하여 메모리를 쓸 수 있습니다. 이 과정은 메시지 유형을 `MT_WriteMemory`로 설정하고 데이터의 주소와 길이를 지정한 다음 데이터를 전송하는 것을 포함합니다:
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

코드를 실행하기 위해서는 rwx 권한을 가진 메모리 영역을 식별해야 합니다. 이는 vmmap -pages를 사용하여 수행할 수 있습니다:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
함수 포인터를 덮어쓸 위치를 찾는 것이 필요하며, .NET Core에서는 **Dynamic Function Table (DFT)**를 대상으로 할 수 있습니다. 이 테이블은 JIT 컴파일 헬퍼 함수를 위해 런타임에서 사용됩니다. 

x64 시스템의 경우, `libcorclr.dll`에서 `_hlpDynamicFuncTable` 심볼에 대한 참조를 찾기 위해 시그니처 헌팅을 사용할 수 있습니다.

`MT_GetDCB` 디버거 함수는 `m_helperRemoteStartAddr`라는 헬퍼 함수의 주소를 포함한 유용한 정보를 제공합니다. 이 주소는 프로세스 메모리에서 `libcorclr.dll`의 위치를 나타냅니다. 이 주소를 사용하여 DFT를 검색하고 함수 포인터를 쉘코드의 주소로 덮어씁니다.

PowerShell로의 인젝션을 위한 전체 POC 코드는 [여기](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)에서 확인할 수 있습니다.

## 참고 자료

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
