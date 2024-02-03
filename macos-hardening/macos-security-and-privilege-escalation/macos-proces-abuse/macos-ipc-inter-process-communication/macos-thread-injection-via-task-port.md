# macOS 通过任务端口的线程注入

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 代码

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. 线程劫持

最初，调用**`task_threads()`**函数在任务端口上获取远程任务的线程列表。选择一个线程进行劫持。这种方法与传统的代码注入方法不同，因为由于新的缓解措施阻止了`thread_create_running()`，创建新的远程线程是被禁止的。

为了控制线程，调用**`thread_suspend()`**，暂停其执行。

允许在远程线程上进行的唯一操作包括**停止**和**启动**它，**检索**和**修改**其寄存器值。通过将寄存器`x0`到`x7`设置为**参数**，将**`pc`**配置为目标函数，并激活线程，启动远程函数调用。确保线程在返回后不会崩溃，需要检测返回。

一种策略包括为远程线程使用`thread_set_exception_ports()`**注册异常处理程序**，在函数调用之前将`lr`寄存器设置为无效地址。这在函数执行后触发异常，向异常端口发送消息，使线程状态可检查以恢复返回值。或者，如Ian Beer的triple\_fetch漏洞利用所采用的，将`lr`设置为无限循环。然后不断监视线程的寄存器，直到**`pc`指向那条指令**。

## 2. 用于通信的Mach端口

随后的阶段涉及建立Mach端口以便与远程线程通信。这些端口在任务之间传输任意发送和接收权限方面起着关键作用。

为了实现双向通信，创建了两个Mach接收权限：一个在本地任务中，另一个在远程任务中。随后，将每个端口的发送权限传输到对方任务，实现消息交换。

关注本地端口，接收权限由本地任务持有。使用`mach_port_allocate()`创建端口。挑战在于将发送权限传输到远程任务中的这个端口。

一种策略涉及利用`thread_set_special_port()`将发送权限放置在远程线程的`THREAD_KERNEL_PORT`中。然后，指示远程线程调用`mach_thread_self()`来检索发送权限。

对于远程端口，过程基本上是相反的。指示远程线程通过`mach_reply_port()`生成一个Mach端口（因为`mach_port_allocate()`由于其返回机制不适用）。在创建端口后，远程线程中调用`mach_port_insert_right()`来建立发送权限。然后使用`thread_set_special_port()`将该权限存储在内核中。回到本地任务，使用`thread_get_special_port()`在远程线程上获取发送权限，以获取远程任务中新分配的Mach端口的发送权限。

完成这些步骤后，就建立了Mach端口，为双向通信奠定了基础。

## 3. 基本内存读/写原语

在本节中，重点是利用执行原语建立基本的内存读写原语。这些初始步骤对于获得对远程进程的更多控制至关重要，尽管在这个阶段，原语不会有太多用途。不久，它们将被升级到更高级的版本。

### 使用执行原语进行内存读写

目标是使用特定函数执行内存读写。对于读取内存，使用类似以下结构的函数：
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
对于写入内存，使用的函数与此结构类似：
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
### 识别合适的函数

扫描常见库揭示了适合这些操作的候选函数：

1. **读取内存：**
从 [Objective-C 运行时库](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) 中识别出 `property_getName()` 函数作为读取内存的合适函数。该函数如下所示：

```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```

这个函数有效地像 `read_func` 一样，通过返回 `objc_property_t` 的第一个字段来工作。

2. **写入内存：**
找到一个预建的写入内存的函数更具挑战性。然而，来自 libxpc 的 `_xpc_int64_set_value()` 函数是一个合适的候选，以下是其反汇编：
```
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
要在特定地址执行64位写入，远程调用的结构如下：
```c
_xpc_int64_set_value(address - 0x18, value)
```
在这些原语建立之后，为创建共享内存奠定了基础，这在控制远程进程方面标志着显著的进步。

## 4. 共享内存设置

目标是在本地和远程任务之间建立共享内存，简化数据传输并便于调用具有多个参数的函数。该方法涉及利用 `libxpc` 及其基于 Mach 内存条目构建的 `OS_xpc_shmem` 对象类型。

### 过程概述：

1. **内存分配**：
- 使用 `mach_vm_allocate()` 分配用于共享的内存。
- 使用 `xpc_shmem_create()` 创建分配内存区域的 `OS_xpc_shmem` 对象。此函数将管理 Mach 内存条目的创建，并在 `OS_xpc_shmem` 对象的偏移 `0x18` 处存储 Mach 发送权限。

2. **在远程进程中创建共享内存**：
- 通过远程调用 `malloc()` 在远程进程中为 `OS_xpc_shmem` 对象分配内存。
- 将本地 `OS_xpc_shmem` 对象的内容复制到远程进程。然而，这个初始副本在偏移 `0x18` 处的 Mach 内存条目名称将是不正确的。

3. **纠正 Mach 内存条目**：
- 利用 `thread_set_special_port()` 方法将 Mach 内存条目的发送权限插入远程任务。
- 通过覆盖其远程内存条目的名称，纠正偏移 `0x18` 处的 Mach 内存条目字段。

4. **完成共享内存设置**：
- 验证远程 `OS_xpc_shmem` 对象。
- 通过远程调用 `xpc_shmem_remote()` 建立共享内存映射。

按照这些步骤操作，可以高效地设置本地和远程任务之间的共享内存，从而实现简单的数据传输和执行需要多个参数的函数。

## 额外的代码片段

用于内存分配和共享内存对象创建：
```c
mach_vm_allocate();
xpc_shmem_create();
```
为了在远程进程中创建和校正共享内存对象：
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
确保正确处理Mach端口和内存条目名称的细节，以确保共享内存设置正常工作。

## 5. 实现完全控制

成功建立共享内存并获得任意执行能力后，我们实际上已经完全控制了目标进程。实现这种控制的关键功能包括：

1. **任意内存操作**：
- 通过调用`memcpy()`从共享区域复制数据来执行任意内存读取。
- 使用`memcpy()`将数据传输到共享区域来执行任意内存写入。

2. **处理多参数函数调用**：
- 对于需要超过8个参数的函数，按照调用约定在栈上排列额外的参数。

3. **Mach端口传输**：
- 通过之前建立的端口，通过Mach消息在任务之间传输Mach端口。

4. **文件描述符传输**：
- 使用fileports在进程之间传输文件描述符，这是Ian Beer在`triple_fetch`中强调的技术。

这种全面的控制被封装在[threadexec](https://github.com/bazad/threadexec)库中，提供了详细的实现和一个用户友好的API，用于与受害进程交互。

## 重要考虑因素：

- 确保正确使用`memcpy()`进行内存读/写操作，以保持系统稳定性和数据完整性。
- 在传输Mach端口或文件描述符时，遵循适当的协议并负责任地处理资源，以防止泄露或意外访问。

遵循这些指导原则并使用`threadexec`库，可以有效地管理和与进程进行精细级别的交互，实现对目标进程的完全控制。

# 参考资料
* https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks**中看到您的**公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
