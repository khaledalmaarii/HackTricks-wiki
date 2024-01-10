# macOS xpc\_connection\_get\_audit\_token 攻击

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

**此技术复制自** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

## Mach 消息基础信息

如果您不知道 Mach 消息是什么，请先查看此页面：

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

目前请记住：
Mach 消息是通过 _mach 端口_ 发送的，这是内置在 mach 内核中的**单一接收者、多个发送者通信**渠道。**多个进程可以向 mach 端口发送消息**，但在任何时候**只有一个进程可以从中读取**。就像文件描述符和套接字一样，mach 端口由内核分配和管理，进程只看到一个整数，它们可以用它来指示内核它们想要使用哪个 mach 端口。

## XPC 连接

如果您不知道如何建立 XPC 连接，请查看：

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## 漏洞摘要

您需要知道的有趣之处是，**XPC 的抽象是一对一连接**，但它基于可以**有多个发送者**的技术，所以：

* Mach 端口是单一接收者，_**多个发送者**_。
* XPC 连接的审计令牌是从_**最近收到的消息中复制的**_。
* 获取 XPC 连接的**审计令牌**对许多**安全检查**至关重要。

尽管之前的情况听起来很有希望，但在某些情况下这不会引起问题：

* 审计令牌通常用于授权检查以决定是否接受连接。由于这是使用消息发送到服务端口完成的，因此**尚未建立连接**。此端口上的更多消息将仅作为额外的连接请求处理。因此，在接受连接之前的**任何检查都不会受到影响**（这也意味着在 `-listener:shouldAcceptNewConnection:` 中的审计令牌是安全的）。因此，我们**正在寻找验证特定操作的 XPC 连接**。
* XPC 事件处理程序是同步处理的。这意味着在并发调度队列上，即使一个消息的事件处理程序必须完成后才能为下一个消息调用它。因此，在**XPC 事件处理程序内部，审计令牌不能被其他正常（非回复！）消息覆盖**。

这给了我们两种可能的方法：

1. 变体1：
   * **利用**连接到服务**A**和服务**B**
   * 服务**B**可以调用用户无法调用的服务**A**中的**特权功能**
   * 服务**A**在**`dispatch_async`** 中调用 **`xpc_connection_get_audit_token`** 时，_**不**_在事件处理程序内。
   * 因此，一个**不同的**消息可能会**覆盖审计令牌**，因为它在事件处理程序外异步分派。
   * 利用将**服务 B 的 SEND 权限传递给服务 A**。
   * 因此，服务**B**实际上将**发送**消息给服务**A**。
   * **利用**尝试**调用**特权操作。在 RC 中，服务**A**在**服务 B 覆盖了审计令牌**时**检查**此**操作**的授权（给予利用访问调用特权操作的权限）。
2. 变体 2：
   * 服务**B**可以调用用户无法调用的服务**A**中的**特权功能**
   * 利用与**服务 A**连接，后者**发送**期望在特定**回复**端口收到响应的消息给利用。
   * 利用向**服务 B**发送消息，传递**那个回复端口**。
   * 当服务**B 回复**时，它**发送消息给服务 A**，**同时**，**利用**发送不同的**消息给服务 A**，试图**达到特权功能**，并期望服务 B 的回复将在完美时刻覆盖审计令牌（竞态条件）。

## 变体 1：在事件处理程序外部调用 xpc\_connection\_get\_audit\_token <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

场景：

* 两个 mach **服务 A** 和 **B** 我们都可以连接到（基于沙箱配置文件和接受连接之前的授权检查）。
* **A** 必须对特定**操作有授权检查，B** 可以通过（但我们的应用程序不能）。
* 例如，如果 B 有一些**权限**或以**root**身份运行，它可能允许他要求 A 执行特权操作。
* 对于此授权检查，**A** 异步获取审计令牌，例如通过从 **`dispatch_async`** 调用 `xpc_connection_get_audit_token`。

{% hint style="danger" %}
在这种情况下，攻击者可以触发**竞态条件**，制作一个**利用**，要求 A 多次执行操作，同时让 B 向 A 发送消息。当 RC **成功**时，**B 的审计令牌**将在我们的**利用**请求被 A 处理时复制到内存中，使其**获得只有 B 才能请求的特权操作的访问权限**。
{% endhint %}

这发生在**A** 作为 `smd` 和 **B** 作为 `diagnosticd`。函数 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) 从 smb 可以用来安装一个新的特权帮助工具（作为 **root**）。如果一个**以 root 身份运行的进程联系** **smd**，不会执行其他检查。

因此，服务**B** 是 **`diagnosticd`**，因为它以 **root** 身份运行，可以用来**监控**进程，所以一旦监控开始，它将**每秒发送多条消息**。

执行攻击：

1. 我们通过遵循正常的 XPC 协议建立与 **`smd`** 的**连接**。
2. 然后，我们建立与 **`diagnosticd`** 的**连接**，但我们没有生成两个新的 mach 端口并发送它们，而是用我们与 `smd` 连接的**发送权限的副本**替换了客户端端口发送权限。
3. 这意味着我们可以向 `diagnosticd` 发送 XPC 消息，但任何 **`diagnosticd` 发送的消息都会发送给 `smd`**。
   * 对于 `smd` 来说，我们和 `diagnosticd` 的消息似乎都是在同一个连接上到达的。

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

4. 我们要求 **`diagnosticd`** **开始监控**我们的（或任何活跃的）进程，并且我们**向 `smd` 发送 1004 消息**（以安装特权工具）。
5. 这创建了一个需要在 `handle_bless` 中击中一个非常特定窗口的竞态条件。我们需要 `xpc_connection_get_pid` 的调用返回我们自己进程的 PID，因为特权帮助工具在我们的应用程序包中。然而，在 `connection_is_authorized` 函数内部的 `xpc_connection_get_audit_token` 调用必须使用 `diganosticd` 的审计令牌。

## 变体 2：回复转发

如前所述，XPC 连接上的事件处理程序从不同时执行多次。然而，**XPC 回复** 消息的处理方式不同。存在两个发送期望回复的消息的函数：

* `void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler)`，在这种情况下，XPC 消息在指定的队列上接收和解析。
* `xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message)`，在这种情况下，XPC 消息在当前调度队列上接收和解析。

因此，**XPC 回复包可能在 XPC 事件处理程序执行时被解析**。虽然 `_xpc_connection_set_creds` 使用锁定，这只能防止审计令牌的部分覆盖，它并没有锁定整个连接对象，使得可能在解析包和执行其事件处理程序之间**替换审计令牌**。

对于这个场景，我们需要：

* 如前所述，两个我们都可以连接的 mach 服务 _A_ 和 _B_。
* 同样，_A_ 必须对特定操作有授权检查，_B_ 可以通过（但我们的应用程序不能）。
* _A_ 发送给我们期望回复的消息。
* 我们可以向 _B_ 发送消息，它会回复。

我们等待 _A_ 发送给我们期望回复的消息（1），我们没有回复，而是取回复端口用于我们发送给 _B_ 的消息（2）。然后，我们发送一个使用禁止操作的消息，我们希望它与 _B_ 的回复同时到达（3）。

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## 发现问题

我们花了很长时间试图找到其他实例，但条件使得它难以静态或动态搜索。为了搜索对 `xpc_connection_get_audit_token` 的异步调用，我们使用 Frida 钩住这个函数，检查回溯是否包括 `_xpc_connection_mach_event`（这意味着它不是从事件处理程序中调用的）。但这只能找到我们当前挂钩的进程中的调用，以及主动使用的操作。在 IDA/Ghidra 中分析所有可达的 mach 服务非常耗时，特别是当调用涉及到 dyld 共享缓存时。我们尝试编写脚本来查找从使用 `dispatch_async` 提交的块中可达的对 `xpc_connection_get_audit_token` 的调用，但解析块和调用传递到 dyld 共享缓存也很困难。在此花费了一段时间后，我们决定最好提交我们所拥有的。

## 修复 <a href="#the-fix" id="the-fix"></a>

最终，我们报告了一般问题和 `smd` 中的特定问题。苹果只在 `smd` 中修复了它，通过用 `xpc_dictionary_get_audit_token` 替换对 `xpc_connection_get_audit_token` 的调用。

函数 `xpc_dictionary_get_audit_token` 从收到此 XPC 消息的 mach 消息中复制审计令牌，这意味着它不容易受到攻击。然而，就像 `xpc_dictionary_get_audit_token` 一样，这不是公共 API 的一部分。对于更高级别的 `NSXPCConnection` API，不存在清晰的方法来获取当前消息的审计令牌，因为这将所有消息抽象为方法调用。

我们不清楚为什么苹果没有应用更通用的修复，例如丢弃与连接保存的审计令牌不匹配的消息。可能存在进程的审计令牌合法更改但连接应保持打开的情况（例如，调用 `setuid` 更改了 UID 字段），但像不同的 PID 或 PID 版本的更改不太可能是预期的。

无论如何，这个问题仍然存在于 iOS 17 和 macOS 14 中，所以如果你想去寻找它，祝你好运！

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
