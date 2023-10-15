# macOS xpc\_connection\_get\_audit\_token攻击

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

**此技术摘自**[**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

## Mach消息基本信息

如果你不知道什么是Mach消息，请查看以下页面：

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

暂时记住以下内容：\
Mach消息通过_mach端口_发送，这是一个内置于mach内核中的**单接收器、多发送器通信**通道。**多个进程可以向mach端口发送消息**，但在任何时刻**只有一个进程可以从中读取**。就像文件描述符和套接字一样，mach端口由内核分配和管理，进程只看到一个整数，它们可以用来指示内核它们想要使用的mach端口。

## XPC连接

如果你不知道如何建立XPC连接，请查看：

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## 漏洞摘要

你需要知道的是，**XPC的抽象是一对一的连接**，但它是基于一种**可以有多个发送器的技术**构建的：

* Mach端口是单接收器，_**多发送器**_。
* XPC连接的审计令牌是从最近接收的消息中**复制**的审计令牌。
* 获得XPC连接的**审计令牌**对于许多**安全检查**至关重要。

尽管前面的情况听起来很有希望，但在某些情况下，这不会引起问题：

* 审计令牌通常用于授权检查，以决定是否接受连接。由于这是使用对服务端口的消息进行的，**尚未建立连接**。在此端口上的更多消息只会被处理为附加的连接请求。因此，**接受连接之前的检查不会受到漏洞的影响**（这也意味着在`-listener:shouldAcceptNewConnection:`中，审计令牌是安全的）。因此，我们正在**寻找验证特定操作的XPC连接**。
* XPC事件处理程序是同步处理的。这意味着一个消息的事件处理程序必须在调用下一个消息的事件处理程序之前完成，即使在并发调度队列上也是如此。因此，在**XPC事件处理程序中，审计令牌不能被其他正常（非回复！）消息覆盖**。

这给我们提供了两种可能的方法：

1. 变体1：
* **Exploit**连接到服务**A**和服务**B**。
* 服务**B**可以调用服务**A**中用户无法调用的**特权功能**。
* 服务**A**在**不在**`dispatch_async`的事件处理程序**内部**调用**`xpc_connection_get_audit_token`**。
* 因此，一个**不同的消息**可以**覆盖审计令牌**，因为它是在事件处理程序之外异步调度的。
* Exploit将**发送权**传递给服务**A**的**SEND right**。
* 因此，svc **B**实际上将**发送消息**到服务**A**。
* Exploit尝试**调用特权操作**。在一个RC svc **A**中，**检查**此**操作**的授权，而**svc B覆盖了审计令牌**（使得Exploit可以调用特权操作）。
2. 变体2：
* 服务**B**可以调用服务**A**中用户无法调用的**特权功能**。
* Exploit连接到**服务A**，**服务A**向Exploit发送一个**期望响应**的消息，使用特定的**回复端口**。
* Exploit向服务**B**发送一条消息，传递**该回复端口**。
* 当服务**B回复**时，它将消息**发送到服务A**，而**Exploit**发送一条不同的消息到服务**A**，试图**达到特权功能**，并期望服务**B的回复**在恰当的时刻覆盖审计令牌（竞争条件）。
## 变种1：在事件处理程序之外调用xpc_connection_get_audit_token <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

场景：

* 有两个我们都可以连接的mach服务**A**和**B**（基于沙盒配置文件和接受连接之前的授权检查）。
* **A**必须对**B**可以通过的特定操作进行**授权检查**（但我们的应用程序不能）。
* 例如，如果B具有某些**权限**或以**root**身份运行，它可能允许他要求A执行特权操作。
* 对于此授权检查，**A**通过异步方式获取审核令牌，例如通过从**`dispatch_async`**调用`xpc_connection_get_audit_token`。

{% hint style="danger" %}
在这种情况下，攻击者可以触发**竞争条件**，制作一个**利用程序**，在**B向A发送消息**的同时**多次要求A执行操作**。当RC（Race Condition）**成功**时，**B**的**审核令牌**将在**处理**我们的**利用程序**的A的同时被复制到内存中，使其能够访问只有B才能请求的特权操作。
{% endhint %}

这种情况发生在**A**作为`smd`，**B**作为`diagnosticd`的情况下。可以使用[`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc)函数从smb安装新的特权助手工具（作为**root**）。如果以**root**身份运行的进程联系**smd**，则不会执行其他检查。

因此，服务**B**是`diagnosticd`，因为它以**root**身份运行，并且可以用于**监视**进程，因此一旦监视开始，它将**每秒发送多个消息**。

进行攻击的步骤：

1. 我们按照正常的XPC协议与`smd`建立**连接**。
2. 然后，我们与`diagnosticd`建立**连接**，但我们不是生成两个新的mach端口并发送它们，而是用我们对与`smd`的连接的**发送权利的副本**替换客户端端口的发送权利。
3. 这意味着我们可以向`diagnosticd`发送XPC消息，但是`diagnosticd`发送的任何消息都会发送到`smd`。
* 对于`smd`，我们和`diagnosticd`的消息都出现在同一个连接上。

<figure><img src="../../../../../../.gitbook/assets/image.png" alt="" width="563"><figcaption></figcaption></figure>

4. 我们要求`diagnosticd`**开始监视**我们（或任何活动的）进程，并且我们向`smd`**垃圾邮件例程1004消息**（以安装特权工具）。
5. 这会创建一个需要在`handle_bless`中命中非常特定窗口的竞争条件。我们需要`xpc_connection_get_pid`的调用返回我们自己进程的PID，因为特权助手工具位于我们的应用程序包中。但是，`connection_is_authorized`函数内部的`xpc_connection_get_audit_token`调用必须使用`diganosticd`的审核令牌。

## 变种2：回复转发

如前所述，对XPC连接上的事件处理程序的处理永远不会同时执行多次。然而，**XPC回复**消息的处理方式不同。有两个用于发送期望回复的消息的函数：

* `void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler)`，在这种情况下，XPC消息在指定的队列上接收和解析。
* `xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message)`，在这种情况下，XPC消息在当前调度队列上接收和解析。

因此，**XPC回复数据包可能在执行XPC事件处理程序时被解析**。虽然`_xpc_connection_set_creds`使用了锁定，但这仅防止对审核令牌的部分覆盖，它不会锁定整个连接对象，因此有可能在解析数据包和执行其事件处理程序之间**替换审核令牌**。

对于这种情况，我们需要：

* 与之前一样，两个我们都可以连接的mach服务_A_和_B_。
* 再次，_A_必须对_B_可以通过的特定操作进行授权检查（但我们的应用程序不能）。
* _A_向我们发送一条期望回复的消息。
* 我们可以向_B_发送一条它将回复的消息。

我们等待_A_向我们发送一条期望回复的消息（1），而不是回复，我们获取回复端口并将其用于我们发送给_B_的消息（2）。然后，我们发送一条使用被禁止的操作的消息，并希望它与_B_的回复同时到达（3）。

<figure><img src="../../../../../../.gitbook/assets/image (1).png" alt="" width="563"><figcaption></figcaption></figure>

## 发现问题

我们花了很长时间来寻找其他实例，但由于条件的限制，无论是静态搜索还是动态搜索都很困难。为了搜索异步调用`xpc_connection_get_audit_token`，我们使用Frida来钩住此函数，以检查回溯是否包含`_xpc_connection_mach_event`（这意味着它不是从事件处理程序中调用的）。但是，这只能找到我们当前钩住的进程中的调用和活动使用的操作。在IDA/Ghidra中分析所有可达的mach服务非常耗时，特别是当调用涉及dyld共享缓存时。我们尝试编写脚本来查找从使用`dispatch_async`提交的块可达的调用`xpc_connection_get_audit_token`，但是解析块和传递到dyld共享缓存中的调用使得这变得困难。在花了一段时间后，我们决定最好提交我们已经有的内容。
## 修复方法 <a href="#the-fix" id="the-fix"></a>

最后，我们报告了`smd`中的一般问题和特定问题。苹果只在`smd`中进行了修复，将调用`xpc_connection_get_audit_token`替换为`xpc_dictionary_get_audit_token`。

函数`xpc_dictionary_get_audit_token`从接收到此XPC消息的mach消息中复制审核令牌，这意味着它不容易受到攻击。然而，就像`xpc_dictionary_get_audit_token`一样，这也不是公共API的一部分。对于更高级的`NSXPCConnection` API，没有明确的方法来获取当前消息的审核令牌，因为它将所有消息抽象为方法调用。

我们不清楚为什么苹果没有应用更一般的修复方法，例如丢弃与连接的保存的审核令牌不匹配的消息。可能存在某些情况下，进程的审核令牌合法地发生变化，但连接应该保持打开状态（例如，调用`setuid`会更改UID字段），但是PID或PID版本不同的更改不太可能是有意的。

无论如何，这个问题在iOS 17和macOS 14中仍然存在，所以如果你想去寻找它，祝你好运！

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
