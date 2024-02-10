# macOS xpc\_connection\_get\_audit\_token Attack

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>tlhIngan Hol</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**For further information check the original post: [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)**. This is a summary:


## Mach Messages Basic Info

If you don't know what Mach Messages are start checking this page:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

For the moment remember that ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages are sent over a _mach port_, which is a **single receiver, multiple sender communication** channel built into the mach kernel. **Multiple processes can send messages** to a mach port, but at any point **only a single process can read from it**. Just like file descriptors and sockets, mach ports are allocated and managed by the kernel and processes only see an integer, which they can use to indicate to the kernel which of their mach ports they want to use.

## XPC Connection

If you don't know how a XPC connection is established check:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Vuln Summary

What is interesting for you to know is that **XPC’s abstraction is a one-to-one connection**, but it is based on top of a technology which **can have multiple senders, so:**

* Mach ports are single receiver, **multiple sender**.
* An XPC connection’s audit token is the audit token of **copied from the most recently received message**.
* Obtaining the **audit token** of an XPC connection is critical to many **security checks**.

Although the previous situation sounds promising there are some scenarios where this is not going to cause problems ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Audit tokens are often used for an authorization check to decide whether to accept a connection. As this happens using a message to the service port, there is **no connection established yet**. More messages on this port will just be handled as additional connection requests. So any **checks before accepting a connection are not vulnerable** (this also means that within `-listener:shouldAcceptNewConnection:` the audit token is safe). We are therefore **looking for XPC connections that verify specific actions**.
* XPC event handlers are handled synchronously. This means that the event handler for one message must be completed before calling it for the next one, even on concurrent dispatch queues. So inside an **XPC event handler the audit token can not be overwritten** by other normal (non-reply!) messages.

Two different methods this might be exploitable:

1. Variant1:
* **Exploit** **connects** to service **A** and service **B**
* Service **B** can call a **privileged functionality** in service A that the user cannot
* Service **A** calls **`xpc_connection_get_audit_token`** while _**not**_ inside the **event handler** for a connection in a **`dispatch_async`**.
* So a **different** message could **overwrite the Audit Token** because it's being dispatched asynchronously outside of the event handler.
* The exploit passes to **service B the SEND right to service A**.
* So svc **B** will be actually **sending** the **messages** to service **A**.
* The **exploit** tries to **call** the **privileged action.** In a RC svc **A** **checks** the authorization of this **action** while **svc B overwrote the Audit token** (giving the exploit access to call the privileged action).
2. Variant 2:
* Service **B** can call a **privileged functionality** in service A that the user cannot
* Exploit connects with **service A** which **sends** the exploit a **message expecting a response** in a specific **replay** **port**.
* Exploit sends **service** B a message passing **that reply port**.
* When service **B replies**, it s**ends the message to service A**, **while** the **exploit** sends a different **message to service A** trying to **reach a privileged functionality** and expecting that the reply from service B will overwrite the Audit token in the perfect moment (Race Condition).

## Variant 1: calling xpc\_connection\_get\_audit\_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

* Two mach services **`A`** and **`B`** that we can both connect to (based on the sandbox profile and the authorization checks before accepting the connection).
* _**A**_ must have an **authorization check** for a specific action that **`B`** can pass (but our app can’t).
* For example, if B has some **entitlements** or is running as **root**, it might allow him to ask A to perform a privileged action.
* For this authorization check, **`A`** obtains the audit token asynchronously, for example by calling `xpc_connection_get_audit_token` from **`dispatch_async`**.

{% hint style="danger" %}
In this case an attacker could trigger a **Race Condition** making a **exploit** that **asks A to perform an action** several times while making **B send messages to `A`**. When the RC is **successful**, the **audit token** of **B** will be copied in memory **while** the request of our **exploit** is being **handled** by A, giving it **access to the privilege action only B could request**.
{% endhint %}

This happened with **`A`** as `smd` and **`B`** as `diagnosticd`. The function [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) from smb an be used to install a new privileged helper toot (as **root**). If a **process running as root contact** **smd**, no other checks will be performed.

Therefore, the service **B** is **`diagnosticd`** because it runs as **root** and can be used to **monitor** a process, so once monitoring has started, it will **send multiple messages per second.**

To perform the attack:

1. Initiate a **connection** to the service named `smd` using the standard XPC protocol.
2. Form a secondary **connection** to `diagnosticd`. Contrary to normal procedure, rather than creating and sending two new mach ports, the client port send right is substituted with a duplicate of the **send right** associated with the `smd` connection.
3. As a result, XPC messages can be dispatched to `diagnosticd`, but responses from `diagnosticd` are rerouted to `smd`. To `smd`, it appears as though the messages from both the user and `diagnosticd` are originating from the same connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)
4. **Variant 2: reply forwarding**

**XPC (Cross-Process Communication)** jImejDaq 'e' vItlhutlh. 'ej reply messages handling vItlhutlh. vaj 'ej vItlhutlh reply messages vItlhutlh:

1. **`xpc_connection_send_message_with_reply`**: XPC message vItlhutlh 'ej designated queue vItlhutlh 'ej vItlhutlh.
2. **`xpc_connection_send_message_with_reply_sync`**: vaj, 'ej vItlhutlh XPC message vItlhutlh 'ej vItlhutlh current dispatch queue vItlhutlh.

vItlhutlh 'ej **reply packets parsed concurrently with the execution of an XPC event handler** vItlhutlh. 'ach, `_xpc_connection_set_creds` vItlhutlh locking implement vItlhutlh audit token partial overwrite protection vItlhutlh, connection object vItlhutlh vItlhutlh protection vItlhutlh. vaj, vItlhutlh vulnerability vItlhutlh audit token replacement vItlhutlh packet parsing 'ej vItlhutlh event handler execution interval vItlhutlh.

vItlhutlh vulnerability exploit, vItlhutlh setup vItlhutlh:

- mach services, **`A`** 'ej **`B`** vItlhutlh, vItlhutlh connection vItlhutlh.
- Service **`A`** vItlhutlh authorization check vItlhutlh vItlhutlh action vItlhutlh **`B`** vItlhutlh vItlhutlh (user's application vItlhutlh).
- Service **`A`** vItlhutlh vItlhutlh message vItlhutlh reply vItlhutlh.
- user vItlhutlh vItlhutlh message vItlhutlh **`B`** vItlhutlh vItlhutlh.

vItlhutlh exploitation process vItlhutlh:

1. Wait vItlhutlh service **`A`** vItlhutlh vItlhutlh message vItlhutlh reply vItlhutlh.
2. **`A`** vItlhutlh reply port hijacked vItlhutlh vItlhutlh message vItlhutlh **`B`** vItlhutlh vItlhutlh.
3. vItlhutlh message vItlhutlh forbidden action vItlhutlh vItlhutlh vItlhutlh, vItlhutlh vItlhutlh reply **`B`** vItlhutlh vItlhutlh concurrently processed.

visual representation vItlhutlh attack scenario:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)


<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Difficulties in Locating Instances**: `xpc_connection_get_audit_token` vItlhutlh usage vItlhutlh, both statically 'ej dynamically vItlhutlh challenging.
- **Methodology**: Frida vItlhutlh `xpc_connection_get_audit_token` function hook vItlhutlh, event handlers vItlhutlh originating calls filtering vItlhutlh. 'ach, vItlhutlh hooked process vItlhutlh vItlhutlh vItlhutlh active usage vItlhutlh.
- **Analysis Tooling**: IDA/Ghidra vItlhutlh reachable mach services vItlhutlh examining vItlhutlh, vItlhutlh time-consuming vItlhutlh, dyld shared cache vItlhutlh calls vItlhutlh complicated vItlhutlh.
- **Scripting Limitations**: `xpc_connection_get_audit_token` vItlhutlh `dispatch_async` blocks vItlhutlh calls analysis vItlhutlh scripting attempts vItlhutlh, blocks parsing vItlhutlh complexities vItlhutlh, dyld shared cache vItlhutlh interactions vItlhutlh hindered vItlhutlh.

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Apple vItlhutlh 'ej `smd` vItlhutlh general 'ej specific issues vItlhutlh report vItlhutlh submitted.
- **Apple's Response**: Apple vItlhutlh `smd` vItlhutlh `xpc_connection_get_audit_token` vItlhutlh `xpc_dictionary_get_audit_token` vItlhutlh substitution vItlhutlh.
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` function vItlhutlh secure vItlhutlh, directly mach message vItlhutlh audit token vItlhutlh retrieved vItlhutlh received XPC message vItlhutlh. 'ach, public API vItlhutlh vItlhutlh, 'ej `xpc_connection_get_audit_token` vItlhutlh vItlhutlh.
- **Absence of a Broader Fix**: 'ach, 'oH Apple vItlhutlh vItlhutlh comprehensive fix vItlhutlh implement vItlhutlh, connection vItlhutlh saved audit token vItlhutlh aligning messages vItlhutlh discarding vItlhutlh. legitimate audit token changes certain scenarios (e.g., `setuid` vItlhutlh) vItlhutlh factor vItlhutlh.
- **Current Status**: iOS 17 'ej macOS 14 vItlhutlh issue vItlhutlh, vItlhutlh identify 'ej understand vItlhutlh challenge vItlhutlh.

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
