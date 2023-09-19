# macOS通过任务端口进行线程注入

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

本文摘自[https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)（其中包含更多信息）

### 代码

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

### 1. 线程劫持

首先，我们调用任务端口上的**`task_threads()`**来获取远程任务中的线程列表，然后选择其中一个线程进行劫持。与传统的代码注入框架不同，我们**无法创建一个新的远程线程**，因为`thread_create_running()`将被新的防护机制阻塞。

然后，我们可以调用**`thread_suspend()`**来停止线程的运行。

此时，我们对远程线程的唯一有用的控制是**停止**它，**启动**它，**获取**它的**寄存器**值，并**设置**它的寄存器**值**。因此，我们可以通过将远程线程中的寄存器`x0`到`x7`设置为**参数**，将**`pc`**设置为要执行的函数，并启动线程来**发起远程函数**调用。此时，我们需要检测返回值并确保线程不会崩溃。

有几种方法可以实现这一点。一种方法是使用`thread_set_exception_ports()`为远程线程注册异常处理程序，并在调用函数之前将返回地址寄存器`lr`设置为无效地址；这样，在函数运行后，将生成一个异常并向我们的异常端口发送消息，此时我们可以检查线程的状态以获取返回值。然而，为了简单起见，我复制了Ian Beer的triple\_fetch漏洞利用中使用的策略，即将`lr`设置为一个会无限循环的指令的地址，然后反复轮询线程的寄存器，直到**`pc`指向该指令**。

### 2. 用于通信的Mach端口

下一步是**创建Mach端口，以便我们可以与远程线程进行通信**。这些Mach端口在稍后帮助在任务之间传输任意的发送和接收权限时非常有用。

为了建立双向通信，我们需要创建两个Mach接收权限：一个在**本地任务中**，一个在**远程任务中**。然后，我们需要将一个发送权限**传输到另一个任务的每个端口**。这样，每个任务都有一种可以发送消息并被另一个任务接收的方法。

首先，让我们专注于设置本地端口，即本地任务持有接收权限的端口。我们可以像创建其他Mach端口一样，调用`mach_port_allocate()`来创建Mach端口。关键是将发送权限传递到远程任务中。

我们可以使用一种方便的技巧，只使用基本的执行原语将发送权限从当前任务复制到远程任务中，即使用`thread_set_special_port()`将发送权限存储在远程线程的`THREAD_KERNEL_PORT`特殊端口中；然后，我们可以使远程线程调用`mach_thread_self()`来检索发送权限。

接下来，我们将设置远程端口，这与我们刚刚所做的相反。我们可以通过调用`mach_reply_port()`使远程线程分配一个Mach端口；我们不能使用`mach_port_allocate()`，因为后者将在内存中返回分配的端口名称，而我们还没有读取原语。一旦我们有了一个端口，我们可以通过在远程线程中调用`mach_port_insert_right()`来创建一个发送权限。然后，我们可以使用`thread_set_special_port()`将端口存储在内核中。最后，在本地任务中，我们可以通过在远程线程上调用`thread_get_special_port()`来检索端口，**从而获得刚刚在远程任务中分配的Mach端口的发送权限**。

此时，我们已经创建了用于双向通信的Mach端口。
### 3. 基本内存读写 <a href="#step-3-basic-memory-readwrite" id="step-3-basic-memory-readwrite"></a>

现在我们将使用执行原语来创建基本的内存读写原语。这些原语并不会用于太多的事情（我们很快将升级到更强大的原语），但它们是帮助我们扩展对远程进程控制的关键步骤。

为了使用我们的执行原语读写内存，我们将寻找这样的函数：
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
快速扫描一些常见的库，发现了一些很好的候选项。要读取内存，我们可以使用[Objective-C运行时库](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html)中的`property_getName()`函数：
```c
const char *property_getName(objc_property_t prop)
{
return prop->name;
}
```
事实证明，`prop`是`objc_property_t`的第一个字段，因此与上面的假设的`read_func`直接对应。我们只需要进行远程函数调用，第一个参数是我们想要读取的地址，返回值将是该地址处的数据。

找到一个现成的用于写入内存的函数稍微困难一些，但仍然有很好的选择，而且没有不希望的副作用。在libxpc中，`_xpc_int64_set_value()`函数的反汇编代码如下：
```
__xpc_int64_set_value:
str     x1, [x0, #0x18]
ret
```
因此，要在地址`address`执行64位写入操作，我们可以执行远程调用：
```c
_xpc_int64_set_value(address - 0x18, value)
```
有了这些基本操作，我们就可以创建共享内存了。

### 4. 共享内存

我们的下一步是在远程任务和本地任务之间创建共享内存。这将使我们能够更轻松地在进程之间传输数据：有了共享内存区域，任意内存读写只需通过远程调用`memcpy()`即可完成。此外，拥有共享内存区域还可以轻松设置堆栈，以便我们可以调用具有超过8个参数的函数。

为了简化操作，我们可以重用libxpc的共享内存功能。Libxpc提供了一个XPC对象类型`OS_xpc_shmem`，允许在XPC上建立共享内存区域。通过反向工程libxpc，我们确定`OS_xpc_shmem`基于Mach内存条目，这些Mach内存条目是代表虚拟内存区域的Mach端口。由于我们已经展示了如何将Mach端口发送到远程任务，因此我们可以使用这个方法轻松地设置自己的共享内存。

首先，我们需要使用`mach_vm_allocate()`来分配我们将共享的内存。我们需要使用`mach_vm_allocate()`来使用`xpc_shmem_create()`为该区域创建一个`OS_xpc_shmem`对象。`xpc_shmem_create()`将负责为我们创建Mach内存条目，并将Mach发送权限存储在偏移量为`0x18`的不透明`OS_xpc_shmem`对象中。

一旦我们获得了内存条目端口，我们将在远程进程中创建一个表示相同内存区域的`OS_xpc_shmem`对象，从而允许我们调用`xpc_shmem_map()`来建立共享内存映射。首先，我们通过远程调用`malloc()`来为`OS_xpc_shmem`分配内存，并使用我们的基本写入原语将本地`OS_xpc_shmem`对象的内容复制到其中。不幸的是，结果对象并不完全正确：其偏移量为`0x18`的Mach内存条目字段包含的是本地任务对内存条目的名称，而不是远程任务的名称。为了解决这个问题，我们使用`thread_set_special_port()`技巧将Mach内存条目的发送权限插入到远程任务中，并将字段`0x18`覆盖为远程内存条目的名称。此时，远程的`OS_xpc_shmem`对象是有效的，并且可以通过远程调用`xpc_shmem_remote()`来建立内存映射。

### 5. 完全控制 <a href="#step-5-full-control" id="step-5-full-control"></a>

有了已知地址的共享内存和任意执行原语，我们基本上已经完成了。通过调用`memcpy()`来实现任意内存读写，通过按照调用约定在堆栈上布置超过8个参数的附加参数来执行具有超过8个参数的函数调用。通过在之前建立的端口上发送Mach消息，可以在任务之间传输任意Mach端口。我们甚至可以使用文件端口在进程之间传输文件描述符（特别感谢Ian Beer在triple_fetch中演示了这种技术！）。

简而言之，我们现在对受害进程拥有完全且轻松的控制。您可以在[threadexec](https://github.com/bazad/threadexec)库中查看完整的实现和公开的API。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在一家**网络安全公司**工作吗？您想在HackTricks中**为您的公司做广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
