# macOS xpc\_connection\_get\_audit\_token 攻击

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

**有关更多信息，请查看原始帖子：** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。这是一个摘要：

## Mach消息基本信息

如果您不知道什么是Mach消息，请查看此页面：

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

目前记住（[定义来自此处](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：

Mach消息通过一个_mach端口_发送，这是内置在mach内核中的**单接收器，多发送器通信**通道。**多个进程可以向mach端口发送消息**，但在任何时候**只有一个进程可以从中读取**。就像文件描述符和套接字一样，mach端口由内核分配和管理，进程只看到一个整数，它们可以用来指示内核它们想要使用哪个mach端口。

## XPC连接

如果您不知道如何建立XPC连接，请查看：

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## 漏洞摘要

您需要知道的有趣之处是**XPC的抽象是一对一连接**，但它是基于一个技术构建的，该技术**可以有多个发送器，因此**：

* Mach端口是单接收器，**多发送器**。
* XPC连接的审计令牌是从**最近接收的消息**中复制的审计令牌。
* 获取XPC连接的**审计令牌**对许多**安全检查**至关重要。

尽管前述情况听起来很有前途，但在某些情况下，这不会造成问题（[来自此处](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)）：

* 审计令牌通常用于授权检查，以决定是否接受连接。由于这是使用消息发送到服务端口进行的，**尚未建立连接**。在此端口上的更多消息将只被处理为附加的连接请求。因此，**在接受连接之前的任何检查都不会有漏洞**（这也意味着在`-listener:shouldAcceptNewConnection:`中审计令牌是安全的）。因此，我们**正在寻找验证特定操作的XPC连接**。
* XPC事件处理程序是同步处理的。这意味着一个消息的事件处理程序必须在调用下一个消息的事件处理程序之前完成，即使在并发调度队列上也是如此。因此，在**XPC事件处理程序内部，审计令牌不能被其他正常（非回复！）消息覆盖**。

这可能会利用的两种不同方法：

1. 变体1：
* **利用**连接到服务**A**和服务**B**
* 服务**B**可以调用服务**A**中用户无法执行的**特权功能**
* 服务**A**在**不在****事件处理程序**中调用**`xpc_connection_get_audit_token`**时。
* 因此，**不同的**消息可能会**覆盖审计令牌**，因为它是在事件处理程序之外异步调度的。
* 攻击利用**将SEND权限传递给服务A的服务B**。
* 因此，svc **B**实际上将**消息发送**到服务**A**。
* **利用**尝试**调用**特权操作。在RC svc **A** **检查**此**操作**的授权，而**svc B覆盖了审计令牌**（使攻击可以调用特权操作）。
2. 变体2：
* 服务**B**可以调用服务**A**中用户无法执行的**特权功能**
* 利用与**服务A**建立连接，**发送**期望响应的消息到特定**回复端口**。
* 利用向**服务**B发送消息，传递**该回复端口**。
* 当服务**B回复**时，它将**消息发送到服务A**，**同时**攻击向服务**A**发送不同的**消息**，尝试**访问特权功能**，并期望来自服务B的回复在完美时机覆盖审计令牌（竞争条件）。

## 变体1：在事件处理程序之外调用xpc\_connection\_get\_audit\_token <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

场景：

* 两个Mach服务**`A`**和**`B`**，我们都可以连接（基于沙箱配置文件和接受连接前的授权检查）。
* _**A**_必须对**`B`**可以通过的特定操作进行**授权检查**（但我们的应用程序不能）。
* 例如，如果B具有某些**授权**或以**root**身份运行，则可能允许其要求A执行特权操作。
* 对于此授权检查，**`A`**通过异步方式获取审计令牌，例如通过从**`dispatch_async`**调用`xpc_connection_get_audit_token`。

{% hint style="danger" %}
在这种情况下，攻击者可以触发**竞争条件**，制作一个**请求A执行操作**的**利用**，同时让**B向`A`发送消息**。当RC**成功**时，**B**的**审计令牌**将被复制到内存中，**而**我们**利用**的请求正在被**A处理**，使其可以访问只有B可以请求的特权操作。
{% endhint %}

这发生在**`A`**作为`smd`，**`B`**作为`diagnosticd`的情况下。从smb中的函数[`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc)可以用于安装新的特权助手工具（作为**root**）。如果以**root**身份运行的进程联系**smd**，则不会执行其他检查。

因此，服务**B**是**`diagnosticd`**，因为它以**root**身份运行，并可用于**监视**进程，因此一旦监视开始，它将**每秒发送多个消息。**

执行攻击的步骤：

1. 使用标准XPC协议**建立**到名为`smd`的服务的**连接**。
2. 与正常程序相反，形成到`diagnosticd`的**次要连接**。而不是创建并发送两个新的mach端口，客户端端口发送权限被替换为与`smd`连接关联的**发送权限**的副本。
3. 结果，XPC消息可以被分派到`diagnosticd`，但来自`diagnosticd`的响应被重新路由到`smd`。对于`smd`，似乎来自用户和`diagnosticd`的消息都是来自同一连接。

![描绘攻击过程的图像](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)
4. 下一步涉及指示`diagnosticd`启动对所选进程（可能是用户自己的进程）的监视。同时，向`smd`发送大量常规的1004消息。这里的意图是安装一个具有提升权限的工具。
5. 这个操作触发了`handle_bless`函数内的竞争条件。时机至关重要：`xpc_connection_get_pid`函数调用必须返回用户进程的PID（因为特权工具位于用户的应用程序包中）。然而，`xpc_connection_get_audit_token`函数，特别是在`connection_is_authorized`子例程内，必须引用属于`diagnosticd`的审计令牌。

## 变种2：回复转发

在XPC（跨进程通信）环境中，虽然事件处理程序不会并发执行，但回复消息的处理具有独特的行为。具体而言，存在两种不同的方法用于发送期望回复的消息：

1. **`xpc_connection_send_message_with_reply`**：在这里，XPC消息在指定队列上接收并处理。
2. **`xpc_connection_send_message_with_reply_sync`**：相反，在这种方法中，XPC消息在当前调度队列上接收并处理。

这种区别至关重要，因为它允许**在执行XPC事件处理程序的同时并发解析回复数据包**的可能性。值得注意的是，虽然`_xpc_connection_set_creds`实现了锁定以防止审计令牌的部分覆盖，但它没有将此保护扩展到整个连接对象。因此，这会产生一个漏洞，其中在解析数据包和执行其事件处理程序之间的时间间隔内，审计令牌可以被替换。

要利用这个漏洞，需要以下设置：

* 两个名为**`A`**和**`B`**的mach服务，两者都可以建立连接。
* 服务**`A`**应包含一个授权检查，用于执行只有**`B`**可以执行的特定操作（用户的应用程序无法执行）。
* 服务**`A`**应发送一条期望回复的消息。
* 用户可以向**`B`**发送一条它将回复的消息。

利用过程包括以下步骤：

1. 等待服务**`A`**发送一条期望回复的消息。
2. 不直接回复给**`A`**，而是劫持回复端口并用于向服务**`B`**发送消息。
3. 随后，发送涉及被禁止操作的消息，期望它将与**`B`**的回复同时处理。

下面是所描述的攻击场景的可视化表示：

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## 发现问题

* **定位实例的困难性**：在静态和动态方面搜索`xpc_connection_get_audit_token`的使用实例是具有挑战性的。
* **方法论**：使用Frida来挂钩`xpc_connection_get_audit_token`函数，过滤不是源自事件处理程序的调用。然而，这种方法仅限于被挂钩的进程，并且需要主动使用。
* **分析工具**：使用IDA/Ghidra来检查可达的mach服务，但这个过程耗时，复杂性增加了与dyld共享缓存相关的调用。
* **脚本限制**：尝试为从`dispatch_async`块到`xpc_connection_get_audit_token`的调用编写脚本受到解析块和与dyld共享缓存的交互复杂性的阻碍。

## 修复 <a href="#the-fix" id="the-fix"></a>

* **报告的问题**：向Apple提交了一份报告，详细说明了在`smd`中发现的一般和具体问题。
* **苹果的回应**：苹果通过用`xpc_dictionary_get_audit_token`替换`xpc_connection_get_audit_token`来解决了`smd`中的问题。
* **修复的性质**：`xpc_dictionary_get_audit_token`函数被认为是安全的，因为它直接从与接收到的XPC消息相关联的mach消息中检索审计令牌。然而，它不是公共API的一部分，类似于`xpc_connection_get_audit_token`。
* **缺乏更广泛的修复**：目前尚不清楚为什么苹果没有实施更全面的修复，例如丢弃与连接的保存的审计令牌不符的消息。在某些情况下（例如`setuid`使用），合法审计令牌更改的可能性可能是一个因素。
* **当前状态**：这个问题在iOS 17和macOS 14中仍然存在，对于那些试图识别和理解它的人来说是一个挑战。
