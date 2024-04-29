# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

**Grand Central Dispatch (GCD)**，也称为**libdispatch**（`libdispatch.dyld`），在macOS和iOS中都可用。这是由Apple开发的技术，用于优化应用程序在多核硬件上的并发（多线程）执行支持。

**GCD**提供并管理**FIFO队列**，您的应用程序可以将**任务**以**块对象**的形式**提交**到这些队列中。提交到调度队列的块会在系统完全管理的线程池上执行。GCD会自动为在调度队列中执行任务创建线程，并安排这些任务在可用核心上运行。

{% hint style="success" %}
简而言之，为了在**并行**中执行代码，进程可以将**代码块发送到GCD**，GCD将负责执行这些代码。因此，进程不会创建新线程；**GCD使用自己的线程池执行给定的代码**（根据需要可能会增加或减少）。
{% endhint %}

这对成功管理并行执行非常有帮助，大大减少了进程创建的线程数量，并优化了并行执行。这对于需要**很高的并行性**（暴力破解？）或不应阻塞主线程的任务非常理想：例如，在iOS上，主线程处理UI交互，因此通过这种方式管理任何可能使应用程序挂起的其他功能（搜索、访问网页、读取文件等）。

### 代码块

代码块是一个**自包含的代码段**（类似于带参数返回值的函数），还可以指定绑定变量。\
但是，在编译器级别，代码块不存在，它们是`os_object`。每个这些对象由两个结构组成：

- **代码块文字**：&#x20;
  - 它以指向代码块类的**`isa`**字段开头：
    - `NSConcreteGlobalBlock`（来自`__DATA.__const`的代码块）
    - `NSConcreteMallocBlock`（堆中的代码块）
    - `NSConcreateStackBlock`（栈中的代码块）
  - 它具有**`flags`**（指示代码块描述符中存在的字段）和一些保留字节
  - 要调用的函数指针
  - 指向代码块描述符的指针
  - 导入的代码块变量（如果有）
- **代码块描述符**：其大小取决于存在的数据（如前面的标志所示）
  - 它有一些保留字节
  - 其大小
  - 通常会有一个指向Objective-C风格签名的指针，以了解参数所需的空间大小（标志`BLOCK_HAS_SIGNATURE`）
  - 如果引用了变量，此代码块还将具有指向复制助手（在开始时复制值）和处理助手（释放值）的指针。

### 队列

调度队列是提供代码块FIFO执行顺序的命名对象。

将代码块设置在队列中以执行，这些队列支持2种模式：`DISPATCH_QUEUE_SERIAL`和`DISPATCH_QUEUE_CONCURRENT`。当然，**串行**队列**不会有竞争条件**问题，因为代码块在前一个代码块完成之前不会执行。但是**另一种类型的队列可能会有**。

默认队列：

- `.main-thread`：来自`dispatch_get_main_queue()`
- `.libdispatch-manager`：GCD的队列管理器
- `.root.libdispatch-manager`：GCD的队列管理器
- `.root.maintenance-qos`：最低优先级任务
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`：可用作`DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`：可用作`DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`：可用作`DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`：可用作`DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`：最高优先级
- `.root.background-qos.overcommit`

请注意，系统将决定**哪些线程在每个时间处理哪些队列**（多个线程可能在同一队列中工作，或同一线程可能在不同队列中工作）。

#### 属性

使用**`dispatch_queue_create`**创建队列时，第三个参数是一个`dispatch_queue_attr_t`，通常是`DISPATCH_QUEUE_SERIAL`（实际上是NULL）或`DISPATCH_QUEUE_CONCURRENT`，它是一个指向`dispatch_queue_attr_t`结构的指针，允许控制队列的一些参数。

### 调度对象

libdispatch使用几种对象，队列和代码块只是其中的两种。可以使用`dispatch_object_create`创建这些对象：

- `block`
- `data`：数据块
- `group`：代码块组
- `io`：异步I/O请求
- `mach`：Mach端口
- `mach_msg`：Mach消息
- `pthread_root_queue`：具有pthread线程池而不是工作队列的队列
- `queue`
- `semaphore`
- `source`：事件源

## Objective-C

在Objective-C中，有不同的函数可用于发送代码块以并行执行：

- [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async)：提交一个代码块以在调度队列上异步执行，并立即返回。
- [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)：提交一个代码块以执行，并在该代码块执行完成后返回。
- [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once)：仅在应用程序的生命周期中执行一次代码块。
- [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait)：提交一个工作项以执行，并仅在其执行完成后返回。与[**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)不同，此函数在执行代码块时遵守队列的所有属性。

这些函数期望这些参数：[**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

这是**代码块的结构**：
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
以下是使用**`dispatch_async`**与**并行性**的示例：
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

**`libswiftDispatch`** 是一个库，为Grand Central Dispatch (GCD)框架提供了**Swift绑定**，该框架最初是用C编写的。\
**`libswiftDispatch`**库将C GCD API封装在一个更适合Swift的接口中，使Swift开发人员更容易更直观地使用GCD。

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**代码示例**：
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

以下Frida脚本可用于**钩入多个`dispatch`函数并提取队列名称、回溯和块：**[**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

目前 Ghidra 既不理解 ObjectiveC **`dispatch_block_t`** 结构，也不理解 **`swift_dispatch_block`** 结构。

因此，如果你希望它理解它们，你可以简单地**声明它们**：

<figure><img src="../../.gitbook/assets/image (1157).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1159).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

然后，在代码中找到它们被**使用**的地方：

{% hint style="success" %}
注意所有提到“block”的引用，以了解如何找出该结构体正在被使用的方式。
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1161).png" alt="" width="563"><figcaption></figcaption></figure>

右键点击变量 -> 重新定义变量，然后选择在这种情况下的 **`swift_dispatch_block`**：

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra 将自动重写所有内容：

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

## References

* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
