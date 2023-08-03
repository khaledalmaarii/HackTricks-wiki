# macOS系统扩展

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家NFT收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 系统扩展 / 终端安全框架

与内核扩展不同，**系统扩展在用户空间运行**，而不是内核空间，从而降低了由于扩展故障导致系统崩溃的风险。

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

系统扩展有三种类型：**DriverKit**扩展、**Network**扩展和**Endpoint Security**扩展。

### **DriverKit扩展**

DriverKit是内核扩展的替代品，**提供硬件支持**。它允许设备驱动程序（如USB、串口、NIC和HID驱动程序）在用户空间而不是内核空间运行。DriverKit框架包括**某些I/O Kit类的用户空间版本**，内核将常规I/O Kit事件转发到用户空间，为这些驱动程序提供更安全的运行环境。

### **Network扩展**

Network扩展提供了自定义网络行为的能力。有几种类型的Network扩展：

* **App Proxy**：用于创建实现基于流而不是单个数据包处理网络流量的VPN客户端。
* **Packet Tunnel**：用于创建实现基于数据包而不是单个数据包处理网络流量的VPN客户端。
* **Filter Data**：用于过滤网络“流”。它可以监视或修改流级别的网络数据。
* **Filter Packet**：用于过滤单个网络数据包。它可以监视或修改数据包级别的网络数据。
* **DNS Proxy**：用于创建自定义DNS提供程序。它可以用于监视或修改DNS请求和响应。

## 终端安全框架

终端安全是苹果在macOS中提供的一个框架，用于提供一组用于系统安全的API。它旨在供**安全供应商和开发人员使用**，以构建可以监控和控制系统活动、识别和防止恶意活动的产品。

该框架提供了一组API来监控和控制系统活动，如进程执行、文件系统事件、网络和内核事件。

该框架的核心是在内核中实现的，作为一个位于**`/System/Library/Extensions/EndpointSecurity.kext`**的内核扩展（KEXT）。该KEXT由几个关键组件组成：

* **EndpointSecurityDriver**：它充当内核扩展的“入口点”。它是操作系统与终端安全框架之间的主要交互点。
* **EndpointSecurityEventManager**：该组件负责实现内核钩子。内核钩子允许框架通过拦截系统调用来监视系统事件。
* **EndpointSecurityClientManager**：它管理与用户空间客户端的通信，跟踪连接的客户端并需要接收事件通知。
* **EndpointSecurityMessageManager**：它向用户空间客户端发送消息和事件通知。

终端安全框架可以监视的事件分为以下几类：

* 文件事件
* 进程事件
* Socket事件
* 内核事件（如加载/卸载内核扩展或打开I/O Kit设备）

### 终端安全框架架构

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt=""><figcaption></figcaption></figure>

与终端安全框架的**用户空间通信**通过IOUserClient类进行。根据调用者的类型，使用了两个不同的子类：

* **EndpointSecurityDriverClient**：它需要`com.apple.private.endpoint-security.manager`权限，该权限仅由系统进程`endpointsecurityd`持有。
* **EndpointSecurityExternalClient**：它需要`com.apple.developer.endpoint-security.client`权限。这通常由第三方安全软件使用，需要与终端安全框架进行交互。

终端安全扩展使用的C库是**`libEndpointSecurity.dylib`**，该库使用I/O Kit（`IOKit`）与终端安全KEXT进行通信。

**`endpointsecurityd`**是一个关键的系统守护进程，负责管理和启动终端安全系统扩展，特别是在早期引导过程中。只有在其`Info.plist`文件中标有**`NSEndpointSecurityEarlyBoot`**的系统扩展才会接受这种早期引导处理。

另一个系统守护进程**`sysextd`**验证系统扩展并将其移动到适当的系统位置。然后，它会要求相关的守护进程加载扩展。**`SystemExtensions.framework`**负责激活和停用系统扩展。
## 绕过ESF

ESF被安全工具使用，这些工具会尝试检测红队人员，因此任何关于如何避免这种检测的信息都很有趣。

### CVE-2021-30965

问题在于安全应用程序需要具有**完全磁盘访问权限**。因此，如果攻击者能够删除该权限，他就可以阻止软件运行：
```bash
tccutil reset All
```
有关此绕过和相关绕过的**更多信息**，请查看演讲[#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

最后，通过将新的权限**`kTCCServiceEndpointSecurityClient`**授予由**`tccd`**管理的安全应用程序，以便`tccutil`不会清除其权限，从而防止其运行。

## 参考资料

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在HackTricks中**为您的公司做广告**吗？或者您想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
