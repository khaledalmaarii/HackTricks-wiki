# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>从零到英雄学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 基本信息

**Grand Central Dispatch (GCD),** 也称为 **libdispatch**, 在macOS和iOS上都可用。它是苹果开发的一项技术，旨在优化应用程序对多核硬件的并发（多线程）执行支持。

**GCD** 提供并管理 **FIFO队列**，您的应用程序可以向其 **提交任务**，以 **block对象** 的形式。提交到调度队列的blocks在系统完全管理的线程池上 **执行**。GCD自动为执行调度队列中的任务创建线程，并安排这些任务在可用的核心上运行。

{% hint style="success" %}
总结来说，为了并行执行代码，进程可以将 **代码块发送给GCD**，GCD将负责它们的执行。因此，进程不创建新线程；**GCD使用其自己的线程池执行给定的代码**。
{% endhint %}

这对于成功管理并行执行非常有帮助，大大减少了进程创建的线程数量，并优化了并行执行。这对于需要 **高度并行性**（暴力破解？）的任务或不应阻塞主线程的任务来说是理想的：例如，iOS上的主线程处理UI交互，因此任何可能使应用程序挂起的其他功能（搜索、访问网页、读取文件...）都是以这种方式管理的。

## Objective-C

在Objective-C中，有不同的函数可以发送一个block以并行执行：

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): 提交一个block以在调度队列上异步执行，并立即返回。
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): 提交一个block对象以执行，并在该block执行完毕后返回。
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): 在应用程序的生命周期内只执行一次block对象。
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): 提交一个工作项以执行，并且只有在它执行完毕后才返回。与 [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync) 不同，这个函数在执行block时尊重队列的所有属性。

这些函数期望以下参数：[**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

这是 **Block的结构**：
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
这是使用 **`dispatch_async`** 实现**并行性**的一个例子：
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

**`libswiftDispatch`** 是一个提供了对 Grand Central Dispatch (GCD) 框架的 **Swift 绑定** 的库，该框架最初是用 C 语言编写的。\
**`libswiftDispatch`** 库将 C 语言的 GCD API 封装成了更适合 Swift 的接口，使得 Swift 开发者使用 GCD 变得更加容易和直观。

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

以下 Frida 脚本可用于**挂钩多个 `dispatch`** 函数并提取队列名称、回溯和块： [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

目前Ghidra既不理解ObjectiveC中的**`dispatch_block_t`**结构，也不理解**`swift_dispatch_block`**结构。

因此，如果你想让它理解这些结构，你可以简单地**声明它们**：

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

然后，在代码中找到一个使用它们的地方：

{% hint style="success" %}
注意所有引用"block"的地方，以了解如何判断出结构体正在被使用。
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

右键点击变量 -> Retype Variable 并在这个例子中选择**`swift_dispatch_block`**：

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra会自动重写所有内容：

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

其他支持HackTricks的方式：

* 如果你想在HackTricks中看到你的**公司广告**或者**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享你的黑客技巧。

</details>
