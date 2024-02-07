# macOS通过任务端口进行线程注入

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs收藏品](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 代码

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. 线程劫持

首先，在任务端口上调用**`task_threads()`**函数以从远程任务获取线程列表。选择一个线程进行劫持。这种方法与传统的代码注入方法不同，因为由于新的防护措施阻止了`thread_create_running()`，创建新的远程线程是被禁止的。

为了控制线程，调用**`thread_suspend()`**来暂停其执行。

对远程线程允许的唯一操作涉及**停止**和**启动**它，**检索**和**修改**其寄存器值。通过将寄存器`x0`到`x7`设置为**参数**，配置**`pc`**以指向所需的函数，并激活线程来启动远程函数调用。确保线程在返回后不崩溃需要检测返回值。

一种策略涉及为远程线程**注册异常处理程序**，使用`thread_set_exception_ports()`，在函数调用之前将`lr`寄存器设置为无效地址。这会在函数执行后触发异常，向异常端口发送消息，从而使得可以检查线程状态以恢复返回值。另一种方法是从Ian Beer的triple\_fetch漏洞利用中采用，将`lr`设置为无限循环。然后持续监视线程的寄存器，直到**`pc`指向该指令**。

## 2. 用于通信的Mach端口

接下来的阶段涉及建立Mach端口以便与远程线程进行通信。这些端口在在任务之间传输任意发送和接收权限方面起着关键作用。

为了实现双向通信，需要在本地和远程任务中创建两个Mach接收权限。随后，将每个端口的发送权限传输到对应的任务，实现消息交换。

关注本地端口，本地任务持有接收权限。使用`mach_port_allocate()`创建端口。挑战在于将发送权限传输到远程任务中的此端口。

一种策略涉及利用`thread_set_special_port()`将本地端口的发送权限放置在远程线程的`THREAD_KERNEL_PORT`中。然后，指示远程线程调用`mach_thread_self()`以检索发送权限。

对于远程端口，过程基本上是相反的。指示远程线程通过`mach_reply_port()`生成一个Mach端口（由于其返回机制，`mach_port_allocate()`不适用）。在端口创建后，远程线程调用`mach_port_insert_right()`来建立发送权限。然后使用`thread_set_special_port()`将此权限存储在内核中。回到本地任务，对远程线程使用`thread_get_special_port()`以获取远程任务中新分配的Mach端口的发送权限。

完成这些步骤将建立Mach端口，为双向通信奠定基础。

## 3. 基本内存读写原语

在本节中，重点是利用执行原语建立基本的内存读写原语。尽管在此阶段，这些原语不会有太多用途，但这些初始步骤对于更多地控制远程进程至关重要。很快，它们将升级为更高级的版本。

### 使用执行原语进行内存读写

目标是使用特定函数执行内存读取和写入。用于读取内存的函数具有以下结构：
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
对于写入内存，使用类似于这种结构的函数：
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
这些函数对应于给定的汇编指令：
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### 识别适当的函数

对常见库的扫描显示了适合这些操作的候选函数：

1. **读取内存：**
从[Objective-C运行时库](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html)中的`property_getName()`函数被确定为适合读取内存的函数。以下是该函数的概述：
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
这个函数实际上像`read_func`一样运作，通过返回`objc_property_t`的第一个字段。

2. **写入内存：**
查找用于写入内存的预构建函数更具挑战性。然而，来自libxpc的`_xpc_int64_set_value()`函数是一个合适的候选项，具有以下反汇编内容：
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
要在特定地址执行64位写操作，远程调用的结构如下：
```c
_xpc_int64_set_value(address - 0x18, value)
```
## 4. 共享内存设置

建立了这些基本原语后，就为创建共享内存奠定了基础，这标志着控制远程进程的重要进展。

### 进程概述：

1. **内存分配**：
- 使用 `mach_vm_allocate()` 分配共享内存。
- 使用 `xpc_shmem_create()` 为分配的内存区域创建一个 `OS_xpc_shmem` 对象。此函数将管理 Mach 内存条目的创建，并将 Mach 发送权限存储在 `OS_xpc_shmem` 对象的偏移量 `0x18` 处。

2. **在远程进程中创建共享内存**：
- 使用远程调用 `malloc()` 为远程进程中的 `OS_xpc_shmem` 对象分配内存。
- 将本地 `OS_xpc_shmem` 对象的内容复制到远程进程。但是，此初始复制将在偏移量 `0x18` 处具有不正确的 Mach 内存条目名称。

3. **纠正 Mach 内存条目**：
- 利用 `thread_set_special_port()` 方法将 Mach 内存条目的发送权限插入到远程任务中。
- 通过用远程内存条目的名称覆盖它来纠正偏移量 `0x18` 处的 Mach 内存条目字段。

4. **完成共享内存设置**：
- 验证远程 `OS_xpc_shmem` 对象。
- 通过远程调用 `xpc_shmem_remote()` 建立共享内存映射。

通过遵循这些步骤，本地和远程任务之间的共享内存将被高效地设置，从而实现简单的数据传输和执行需要多个参数的函数。

## 附加代码片段

用于内存分配和共享内存对象创建：
```c
mach_vm_allocate();
xpc_shmem_create();
```
用于在远程进程中创建和校正共享内存对象：
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
## 5. 实现完全控制

成功建立共享内存并获得任意执行能力后，我们基本上已经获得了对目标进程的完全控制。实现这种控制的关键功能包括：

1. **任意内存操作**：
- 通过调用 `memcpy()` 从共享区域复制数据来执行任意内存读取。
- 使用 `memcpy()` 将数据传输到共享区域以执行任意内存写入。

2. **处理具有多个参数的函数调用**：
- 对于需要超过 8 个参数的函数，在栈上按照调用约定安排额外的参数。

3. **Mach 端口传输**：
- 通过先前建立的端口，通过 Mach 消息在任务之间传输 Mach 端口。

4. **文件描述符传输**：
- 使用文件端口在进程之间传输文件描述符，这是 Ian Beer 在 `triple_fetch` 中强调的一种技术。

这种全面的控制被封装在[threadexec](https://github.com/bazad/threadexec)库中，提供了详细的实现和用户友好的 API，用于与受害进程进行交互。

## 重要考虑事项：

- 确保正确使用 `memcpy()` 进行内存读/写操作，以保持系统稳定性和数据完整性。
- 在传输 Mach 端口或文件描述符时，遵循适当的协议并负责处理资源，以防止泄漏或意外访问。

通过遵循这些准则并利用 `threadexec` 库，可以高效地管理和与进程进行精细级别的交互，实现对目标进程的完全控制。

# 参考资料
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
