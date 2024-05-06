# macOS MIG - Mach接口生成器

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

MIG被创建用于**简化Mach IPC**代码的生成过程。它基本上**生成了所需的代码**，以便服务器和客户端可以根据给定的定义进行通信。即使生成的代码看起来很丑陋，开发人员只需导入它，他的代码将比以前简单得多。

定义是使用接口定义语言（IDL）使用`.defs`扩展名指定的。

这些定义有5个部分：

- **子系统声明**：关键字子系统用于指示**名称**和**ID**。还可以将其标记为**`KernelServer`**，如果服务器应在内核中运行。
- **包含和导入**：MIG使用C预处理器，因此可以使用导入。此外，可以使用`uimport`和`simport`用于用户或服务器生成的代码。
- **类型声明**：可以定义数据类型，尽管通常会导入`mach_types.defs`和`std_types.defs`。对于自定义类型，可以使用一些语法：
  - \[i`n/out]tran：需要从传入消息翻译或传出消息翻译的函数
  - `c[user/server]type`：映射到另一个C类型。
  - `destructor`：在释放类型时调用此函数。
- **操作**：这些是RPC方法的定义。有5种不同类型：
  - `routine`：期望回复
  - `simpleroutine`：不期望回复
  - `procedure`：期望回复
  - `simpleprocedure`：不期望回复
  - `function`：期望回复

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

请注意，第一个**参数是要绑定的端口**，MIG将**自动处理回复端口**（除非在客户端代码中调用`mig_get_reply_port()`）。此外，**操作的ID**将是**连续的**，从指定的子系统ID开始（因此，如果一个操作已被弃用，则会被删除，并且使用`skip`来仍然使用其ID）。

现在使用MIG生成服务器和客户端代码，这些代码将能够相互通信以调用Subtract函数：
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
在当前目录中将创建几个新文件。

{% hint style="success" %}
您可以在系统中找到一个更复杂的示例：`mdfind mach_port.defs`\
您可以从与文件相同的文件夹中编译它：`mig -DLIBSYSCALL_INTERFACE mach_ports.defs`
{% endhint %}

在文件**`myipcServer.c`**和**`myipcServer.h`**中，您可以找到结构体**`SERVERPREFmyipc_subsystem`**的声明和定义，该结构体基本上定义了根据接收的消息ID调用的函数（我们指定了起始编号为500）：

{% tabs %}
{% tab title="myipcServer.c" %}
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

macOS MIG (Mach Interface Generator) is a tool used to define inter-process communication (IPC) for macOS. It generates client and server-side code for message-based IPC. MIG is commonly used in macOS kernel programming for handling system calls and managing kernel resources.

#### Example of MIG Interface Definition

```c
routine myipc_server_routine_1(
    In int in_val,
    Out int *out_val
);
```

In the example above, `myipc_server_routine_1` is a MIG routine that takes an integer input `in_val` and returns an integer output `out_val`.

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
在这个例子中，我们只在定义中定义了一个函数，但如果我们定义了更多函数，它们将位于**`SERVERPREFmyipc_subsystem`**数组内，第一个函数将被分配给ID **500**，第二个函数将被分配给ID **501**...

如果预期函数将发送一个**回复**，那么函数`mig_internal kern_return_t __MIG_check__Reply__<name>`也会存在。

实际上可以在**`myipcServer.h`**中的结构体**`subsystem_to_name_map_myipc`**（在其他文件中为**`subsystem_to_name_map_***`**）中识别这种关系：
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
最后，使服务器工作的另一个重要函数将是**`myipc_server`**，它实际上将**调用**与接收的id相关联的函数：

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

检查先前突出显示的行，访问要按ID调用的函数。

以下是创建一个简单**服务器**和**客户端**的代码，其中客户端可以从服务器调用减法函数：

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

{% tab title="myipc_client.c" %}在macOS中，MIG（Mach接口生成器）是一种用于处理进程间通信（IPC）的强大工具。通过MIG，可以生成用于在Mach消息传递系统中进行IPC的客户端和服务器代码。这种方法可以被恶意软件利用来实现特权升级和其他攻击。因此，在进行macOS硬化时，需要注意限制MIG接口的使用，以防止进程滥用。{% endtab %}
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
{% endtab %}
{% endtabs %}

### NDR\_record

NDR\_record由`libsystem_kernel.dylib`导出，它是一个结构体，允许MIG**转换数据，使其对系统不可知**，因为MIG被设计用于在不同系统之间使用（而不仅仅是在同一台机器上）。

这很有趣，因为如果在二进制文件中发现`_NDR_record`作为一个依赖项（`jtool2 -S <binary> | grep NDR`或`nm`），这意味着该二进制文件是一个MIG客户端或服务器。

此外，**MIG服务器**在`__DATA.__const`（或macOS内核中的`__CONST.__constdata`和其他\*OS内核中的`__DATA_CONST.__const`）中具有调度表。这可以通过**`jtool2`**来转储。

而**MIG客户端**将使用`__NDR_record`通过`__mach_msg`发送到服务器。

## 二进制分析

### jtool

由于许多二进制文件现在使用MIG来公开mach端口，了解如何**识别MIG的使用**以及MIG在每个消息ID上执行的**函数**是很有趣的。

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2)可以从Mach-O二进制文件中解析MIG信息，指示消息ID并识别要执行的函数：
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
此外，MIG 函数只是被调用的实际函数的包装器，这意味着通过获取其反汇编并使用 BL 进行过滤，您可能会找到被调用的实际函数：
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### 汇编

先前提到负责**根据接收到的消息ID调用正确函数**的函数是`myipc_server`。然而，通常不会有二进制文件的符号（没有函数名称），因此有兴趣**查看反编译后的样子**，因为它总是非常相似的（此函数的代码与暴露的函数无关）：

{% tabs %}
{% tab title="反编译后的 myipc_server 1" %}
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
// 调用 sign_extend_64 可以帮助识别此函数
// 这将在 rax 中存储需要调用的指针
// 检查地址 0x100004040 的使用（函数地址数组）
// 0x1f4 = 500（起始ID）
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// 如果 - else，如果 if 返回 false，而 else 调用正确的函数并返回 true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// 计算地址，使用 2 个参数调用正确的函数
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

{% tab title="反编译后的 myipc_server 2" %}
这是在不同版本的 Hopper free 中反编译的相同函数：

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
// 与前一个版本相同的 if else
// 检查地址 0x100004040（函数地址数组）的使用
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// 调用计算出的地址，应该在其中的函数
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

实际上，如果转到函数**`0x100004000`**，您将找到**`routine_descriptor`**结构体的数组。结构体的第一个元素是**函数实现的地址**，**结构体占用 0x28 字节**，因此每 0x28 字节（从字节 0 开始）您可以获得 8 字节，那将是将要调用的**函数的地址**：

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

此数据可以使用[**此 Hopper 脚本**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py)提取。
### 调试

MIG 生成的代码还调用 `kernel_debug` 来生成关于进入和退出操作的日志。可以使用 **`trace`** 或 **`kdv`** 来检查它们：`kdv all | grep MIG`

## 参考资料

* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的 **公司在 HackTricks 中被广告** 或 **下载 PDF 格式的 HackTricks**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
