# macOS 通过任务端口的线程注入

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

此帖子复制自 [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)（其中包含更多信息）

### 代码

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

### 1. 线程劫持

我们首先调用 **`task_threads()`** 在任务端口上获取远程任务中的线程列表，然后选择其中一个进行劫持。与传统的代码注入框架不同，我们**不能创建新的远程线程**，因为 `thread_create_running()` 将被新的缓解措施阻止。

然后，我们可以调用 **`thread_suspend()`** 停止线程运行。

此时，我们对远程线程唯一有用的控制是**停止**它，**启动**它，**获取**其**寄存器**值，并**设置**其寄存器**值**。因此，我们可以通过设置远程线程中的**寄存器** `x0` 到 `x7` 为**参数**，**设置** **`pc`** 为我们想要执行的函数，并启动线程来**启动远程函数**调用。此时，我们需要检测返回并确保线程不会崩溃。

有几种方法可以做到这一点。一种方法是为远程线程使用 `thread_set_exception_ports()` **注册异常处理程序**，并在调用函数之前将返回地址寄存器 `lr` 设置为无效地址；这样，函数运行后会生成异常，并向我们的异常端口发送消息，此时我们可以检查线程状态以检索返回值。然而，为了简单起见，我复制了 Ian Beer 的 triple\_fetch 漏洞中使用的策略，即**将 `lr` 设置为会无限循环的指令的地址**，然后反复轮询线程的寄存器，直到 **`pc` 指向那个指令**。

### 2. 用于通信的 Mach 端口

下一步是**创建 Mach 端口，我们可以通过它与远程线程通信**。这些 Mach 端口稍后在帮助任务之间传输任意发送和接收权限时会很有用。

为了建立双向通信，我们需要在**本地任务和远程任务中**创建两个 Mach 接收权限。然后，我们需要**将发送权限传输**给每个端口**到另一个任务**。这将为每个任务提供一种发送消息的方式，该消息可以被另一个任务接收。

让我们首先关注设置本地端口，即本地任务持有接收权限的端口。我们可以像创建任何其他 Mach 端口一样，通过调用 `mach_port_allocate()` 来创建 Mach 端口。诀窍是将发送权限从当前任务复制到远程任务。

我们可以使用的一个方便的技巧是使用 `thread_set_special_port()` 将我们本地端口的**发送权限存放在远程线程的 `THREAD_KERNEL_PORT` 特殊端口中**；然后，我们可以让远程线程调用 `mach_thread_self()` 来检索发送权限。

接下来我们将设置远程端口，这与我们刚才做的几乎相反。我们可以让**远程线程通过调用 `mach_reply_port()` 分配一个 Mach 端口**；我们不能使用 `mach_port_allocate()`，因为后者在内存中返回分配的端口名称，而我们还没有读取原语。一旦我们有了一个端口，我们可以通过在远程线程中调用 `mach_port_insert_right()` 来创建发送权限。然后，我们可以通过调用 `thread_set_special_port()` 将端口存放在内核中。最后，在本地任务中，我们可以通过在远程线程上调用 `thread_get_special_port()` 来检索端口，**给我们一个发送权限到刚在远程任务中分配的 Mach 端口**。

此时，我们已经创建了将用于双向通信的 Mach 端口。

### 3. 基本内存读/写 <a href="#step-3-basic-memory-readwrite" id="step-3-basic-memory-readwrite"></a>

现在我们将使用执行原语来创建基本的内存读写原语。这些原语不会用于太多（我们很快会升级到更强大的原语），但它们是帮助我们扩展对远程进程控制的关键步骤。

为了使用我们的执行原语读写内存，我们将寻找像这样的函数：
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
它们可能对应以下汇编代码：
```
_read_func:
ldr     x0, [x0]
ret
_write_func:
str     x1, [x0]
ret
```
快速扫描一些常见库揭示了一些好的候选项。要读取内存，我们可以使用 [Objective-C 运行时库](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) 中的 `property_getName()` 函数：
```c
const char *property_getName(objc_property_t prop)
{
return prop->name;
}
```
```markdown
正如事实证明，`prop` 是 `objc_property_t` 的第一个字段，因此这直接对应于上面假设的 `read_func`。我们只需要执行一个远程函数调用，第一个参数是我们想要读取的地址，返回值将是该地址的数据。

找到一个现成的函数来写内存稍微困难一些，但是仍然有很好的选项，而且没有不希望的副作用。在 libxpc 中，`_xpc_int64_set_value()` 函数具有以下反汇编：
```
```
__xpc_int64_set_value:
str     x1, [x0, #0x18]
ret
```
因此，要在地址 `address` 处执行64位写入，我们可以执行远程调用：
```c
_xpc_int64_set_value(address - 0x18, value)
```
### 4. 共享内存

我们下一步是在远程和本地任务之间创建共享内存。这将使我们能够更容易地在进程之间传输数据：有了共享内存区域，任意内存读写就像远程调用`memcpy()`一样简单。此外，拥有共享内存区域将使我们能够轻松地设置堆栈，以便我们可以调用具有超过8个参数的函数。

为了简化操作，我们可以重用libxpc的共享内存功能。Libxpc提供了一种XPC对象类型`OS_xpc_shmem`，它允许通过XPC建立共享内存区域。通过逆向libxpc，我们确定`OS_xpc_shmem`基于Mach内存条目，这些是代表虚拟内存区域的Mach端口。由于我们已经展示了如何向远程任务发送Mach端口，我们可以使用这一点来轻松地设置我们自己的共享内存。

首先，我们需要使用`mach_vm_allocate()`分配我们将要共享的内存。我们需要使用`mach_vm_allocate()`，这样我们就可以使用`xpc_shmem_create()`为该区域创建一个`OS_xpc_shmem`对象。`xpc_shmem_create()`将为我们创建Mach内存条目，并将Mach发送权限存储在不透明的`OS_xpc_shmem`对象的偏移`0x18`处。

一旦我们拥有了内存条目端口，我们将在远程进程中创建一个代表相同内存区域的`OS_xpc_shmem`对象，使我们能够调用`xpc_shmem_map()`来建立共享内存映射。首先，我们执行远程调用`malloc()`来为`OS_xpc_shmem`分配内存，并使用我们的基本写原语将本地`OS_xpc_shmem`对象的内容复制进去。不幸的是，结果对象并不完全正确：其Mach内存条目字段在偏移`0x18`处包含本地任务对内存条目的名称，而不是远程任务的名称。为了解决这个问题，我们使用`thread_set_special_port()`技巧将Mach内存条目的发送权限插入远程任务，然后用远程内存条目的名称覆盖字段`0x18`。此时，远程`OS_xpc_shmem`对象有效，内存映射可以通过远程调用`xpc_shmem_remote()`来建立。

### 5. 完全控制 <a href="#step-5-full-control" id="step-5-full-control"></a>

有了已知地址的共享内存和任意执行原语，我们基本上完成了。任意内存读写是通过分别调用`memcpy()`到共享区域和从共享区域实现的。通过根据调用约定在堆栈上布局第8个参数之外的额外参数，可以执行具有超过8个参数的函数调用。通过之前建立的端口发送Mach消息，可以在任务之间传输任意Mach端口。我们甚至可以通过使用fileports（特别感谢Ian Beer在triple_fetch中展示了这种技术！）在进程之间传输文件描述符。

简而言之，我们现在对受害进程有了完全且容易的控制。您可以在[threadexec](https://github.com/bazad/threadexec)库中看到完整的实现和公开的API。

<details>

<summary><strong>从零开始学习AWS黑客攻击成为英雄，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
