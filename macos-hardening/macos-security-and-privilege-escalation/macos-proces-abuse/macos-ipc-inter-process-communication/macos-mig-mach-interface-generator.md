# macOS MIG - Mach接口生成器

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

MIG被创建用于**简化Mach IPC**代码创建的过程。它基本上**生成了所需的代码**，用于服务器和客户端根据给定的定义进行通信。即使生成的代码看起来很丑陋，开发人员只需导入它，他的代码将比以前简单得多。

### 示例

创建一个定义文件，这里是一个非常简单的函数：

{% code title="myipc.defs" %}
```cpp
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
{% endcode %}

现在使用 mig 生成服务器和客户端代码，这些代码将能够相互通信以调用 Subtract 函数：
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
在当前目录中将创建几个新文件。

在文件**`myipcServer.c`**和**`myipcServer.h`**中，您可以找到结构**`SERVERPREFmyipc_subsystem`**的声明和定义，该结构基本上定义了根据接收到的消息ID调用的函数（我们指定了起始编号为500）：
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{% endtab %}

{% tab title="myipcServer.h" %} 

### macOS MIG (Mach Interface Generator)

macOS MIG (Mach Interface Generator) is a tool used to define inter-process communication (IPC) for macOS. It generates client and server-side code for message-based IPC. MIG is commonly used in macOS kernel programming for defining system calls and handling IPC between user-space and kernel-space.

#### Example of a MIG definition file:

```c
routine myipc_server_routine {
    mach_msg_header_t Head;
    mach_msg_type_t Type;
    int data;
} -> {
    mach_msg_header_t Head;
    mach_msg_type_t Type;
    int result;
};
```

In the example above, `myipc_server_routine` is defined with input parameters and output parameters. This definition specifies the structure of the message exchanged between client and server processes using MIG.

MIG simplifies the process of defining and handling IPC in macOS, making it easier for developers to implement secure and efficient communication between processes.
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
根据前面的结构，函数**`myipc_server_routine`**将获取**消息ID**并返回要调用的适当函数：
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
在这个示例中，我们只在定义中定义了一个函数，但如果我们定义了更多函数，它们将位于**`SERVERPREFmyipc_subsystem`**数组内，第一个函数将被分配给ID **500**，第二个函数将被分配给ID **501**...

实际上可以在**`myipcServer.h`**中的**`subsystem_to_name_map_myipc`**结构中识别这种关系：
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
最后，使服务器工作的另一个重要函数将是**`myipc_server`**，这个函数实际上会**调用**与接收到的id相关联的函数：

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* 最小大小：如果不同，routine()将更新它 */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id &#x3C; 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

检查前面突出显示的行，访问要通过ID调用的函数。

以下是创建一个简单**服务器**和**客户端**的代码，其中客户端可以从服务器调用Subtract函数：

{% tabs %}
{% tab title="myipc_server.c" %}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{% endtab %}

{% tab title="myipc_client.c" %} 

### macOS IPC - Inter-Process Communication

#### macOS MIG - Mach Interface Generator

Mach Interface Generator (MIG) is a tool used to define inter-process communication (IPC) for macOS. It generates client-side and server-side code for message-based communication between processes. MIG is commonly used in macOS for system services and kernel extensions.

To use MIG, you need to define an interface definition file (.defs) that specifies the messages and data structures exchanged between processes. This file is then processed by MIG to generate the necessary C code for IPC.

MIG simplifies the development of IPC mechanisms in macOS by handling the low-level details of message passing and data serialization. It allows developers to focus on defining the message formats and handling the communication logic.

By leveraging MIG for IPC, developers can ensure a standardized and efficient way of communication between processes in macOS, enhancing the overall security and reliability of the system. 

#### Example:

```c
#include <mach/mach.h>
#include <stdio.h>

#include "myipc.h"

int main() {
    mach_port_t server_port;
    kern_return_t kr;

    kr = bootstrap_look_up(bootstrap_port, "com.example.myipc", &server_port);
    if (kr != KERN_SUCCESS) {
        printf("Error looking up server port: %s\n", mach_error_string(kr));
        return 1;
    }

    myipc_hello(server_port);

    return 0;
}
```

In this example, the client application looks up the server port using `bootstrap_look_up` and then calls the `myipc_hello` function to communicate with the server process.

{% endtab %}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
### 二进制分析

由于许多二进制文件现在使用 MIG 来公开 mach 端口，了解如何**识别使用了 MIG**以及**MIG 执行的功能**与每个消息 ID 是很有趣的。

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) 可以解析 Mach-O 二进制文件中的 MIG 信息，指示消息 ID 并识别要执行的函数：
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
在之前提到的函数`myipc_server`将负责**根据接收的消息ID调用正确的函数**。然而，通常情况下你不会有二进制文件的符号（没有函数名称），因此有趣的是**查看反编译后的样子**，因为它总是非常相似的（此函数的代码与暴露的函数无关）：

{% tabs %}
{% tab title="myipc_server反编译 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// 初始指令以找到正确的函数指针
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// 调用sign_extend_64以帮助识别此函数
// 这将在rax中存储需要调用的调用指针
// 检查地址0x100004040的使用（函数地址数组）
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// 如果-否，if返回false，而else调用正确的函数并返回true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// 计算地址以使用2个参数调用正确的函数
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>
{% endtab %}

{% tab title="myipc_server反编译 2" %}
这是在不同版本的Hopper free中反编译的相同函数：

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// 初始指令以找到正确的函数指针
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS & G) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 < 0x0) {
if (CPU_FLAGS & L) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500（起始ID）
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS & NE) {
r8 = 0x1;
}
}
// 与前一个版本中相同的if else
// 检查地址0x100004040（函数地址数组）的使用
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// 调用计算出的地址，其中应该包含函数
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>
{% endtab %}
{% endtabs %}

实际上，如果你转到函数**`0x100004000`**，你会找到**`routine_descriptor`**结构体的数组。结构体的第一个元素是**函数实现的地址**，**结构体占用0x28字节**，因此每0x28字节（从字节0开始）你可以得到8字节，这将是将要调用的**函数的地址**：

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

这些数据可以通过[**使用此Hopper脚本**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py)提取。
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) **和** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github仓库提交PR来分享您的黑客技巧。**

</details>
