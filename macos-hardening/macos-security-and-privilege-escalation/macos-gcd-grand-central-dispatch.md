# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

**Grand Central Dispatch (GCD)**，也称为**libdispatch**，在macOS和iOS中都可用。这是由Apple开发的技术，用于优化应用程序在多核硬件上的并发（多线程）执行支持。

**GCD**提供并管理**FIFO队列**，您的应用程序可以将**任务**以**块对象**的形式**提交**到这些队列中。提交到调度队列的块会在系统完全管理的线程池上**执行**。GCD会自动为在调度队列中执行任务创建线程，并安排这些任务在可用核心上运行。

{% hint style="success" %}
简而言之，为了**并行执行**代码，进程可以将**代码块发送到GCD**，GCD将负责执行这些代码。因此，进程不会创建新线程；**GCD使用自己的线程池执行给定的代码**。
{% endhint %}

这对成功管理并行执行非常有帮助，大大减少了进程创建的线程数量，并优化了并行执行。这对于需要**大量并行性**（暴力破解？）的任务或不应阻塞主线程的任务非常有用：例如，在iOS上，主线程处理UI交互，因此通过这种方式管理任何可能使应用程序挂起的其他功能（搜索、访问网页、读取文件等）。

## Objective-C

在Objective-C中，有不同的函数可用于发送一个块以并行执行：

- [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async)：将一个块提交到调度队列以进行异步执行，并立即返回。
- [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)：提交一个块对象以执行，并在该块完成执行后返回。
- [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once)：仅在应用程序的生命周期中执行一次块对象。
- [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait)：提交一个工作项以执行，并仅在其完成执行后返回。与[**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)不同，此函数在执行块时尊重队列的所有属性。

这些函数期望这些参数：[**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

这是一个**块的结构**：
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
这是一个使用**并行处理**和**`dispatch_async`**的示例：
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

**`libswiftDispatch`** 是一个库，为 Grand Central Dispatch (GCD) 框架提供了 **Swift 绑定**，该框架最初是用 C 编写的。\
**`libswiftDispatch`** 库将 C GCD API 封装在一个更适合 Swift 的接口中，使得 Swift 开发人员更容易更直观地使用 GCD。

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

目前 Ghidra 无法理解 ObjectiveC **`dispatch_block_t`** 结构，也无法理解 **`swift_dispatch_block`** 结构。

因此，如果你希望它能够理解它们，你可以简单地 **声明它们**：

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

然后，在代码中找到它们被 **使用** 的地方：

{% hint style="success" %}
注意所有提到 "block" 的引用，以了解如何找出该结构体正在被使用的方式。
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

右键点击变量 -> 重新定义变量，然后选择这种情况下的 **`swift_dispatch_block`**：

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra 将自动重写所有内容：

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>
