# macOS系统扩展

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中被广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 系统扩展 / 端点安全框架

与内核扩展不同，**系统扩展在用户空间中运行**，而不是内核空间，降低了由于扩展故障导致系统崩溃的风险。

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

有三种类型的系统扩展：**DriverKit**扩展，**Network**扩展和**Endpoint Security**扩展。

### **DriverKit扩展**

DriverKit是内核扩展的替代品，**提供硬件支持**。它允许设备驱动程序（如USB、串行、NIC和HID驱动程序）在用户空间而不是内核空间中运行。DriverKit框架包括**某些I/O Kit类的用户空间版本**，内核将正常的I/O Kit事件转发到用户空间，为这些驱动程序提供了更安全的运行环境。

### **Network扩展**

网络扩展提供了自定义网络行为的能力。有几种类型的网络扩展：

* **应用代理**：用于创建实现基于流的自定义VPN协议的VPN客户端。这意味着它根据连接（或流）处理网络流量，而不是单个数据包。
* **数据包隧道**：用于创建实现基于数据包的自定义VPN协议的VPN客户端。这意味着它根据单个数据包处理网络流量。
* **过滤数据**：用于过滤网络“流”。它可以监视或修改流级别的网络数据。
* **过滤数据包**：用于过滤单个网络数据包。它可以监视或修改数据包级别的网络数据。
* **DNS代理**：用于创建自定义DNS提供程序。它可用于监视或修改DNS请求和响应。

## 端点安全框架

端点安全是苹果在macOS中提供的一个框架，提供了一组用于系统安全的API。它旨在供**安全供应商和开发人员使用，构建可以监视和控制系统活动**以识别和防范恶意活动的产品。

该框架提供了一组API来监视和控制系统活动，如进程执行、文件系统事件、网络和内核事件。

该框架的核心是在内核中实现的，作为一个位于**`/System/Library/Extensions/EndpointSecurity.kext`**的内核扩展（KEXT）。该KEXT由几个关键组件组成：

* **EndpointSecurityDriver**：充当内核扩展的“入口点”。它是操作系统与端点安全框架之间的主要交互点。
* **EndpointSecurityEventManager**：负责实现内核挂钩。内核挂钩允许框架通过拦截系统调用来监视系统事件。
* **EndpointSecurityClientManager**：管理与用户空间客户端的通信，跟踪连接的客户端并需要接收事件通知。
* **EndpointSecurityMessageManager**：向用户空间客户端发送消息和事件通知。

端点安全框架可以监视的事件分为以下类别：

* 文件事件
* 进程事件
* 套接字事件
* 内核事件（如加载/卸载内核扩展或打开I/O Kit设备）

### 端点安全框架架构

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

与端点安全框架的**用户空间通信**通过IOUserClient类进行。根据调用者的类型，使用两种不同的子类：

* **EndpointSecurityDriverClient**：需要`com.apple.private.endpoint-security.manager`权限，该权限仅由系统进程`endpointsecurityd`持有。
* **EndpointSecurityExternalClient**：需要`com.apple.developer.endpoint-security.client`权限。这通常由需要与端点安全框架交互的第三方安全软件使用。

端点安全扩展：**`libEndpointSecurity.dylib`**是系统扩展用于与内核通信的C库。该库使用I/O Kit（`IOKit`）与端点安全KEXT通信。

**`endpointsecurityd`**是一个关键的系统守护程序，负责管理和启动端点安全系统扩展，特别是在早期引导过程中。**只有**在其`Info.plist`文件中标记为**`NSEndpointSecurityEarlyBoot`**的**系统扩展**才会接收到这种早期引导处理。

另一个系统守护程序**`sysextd`**，**验证系统扩展**并将其移动到适当的系统位置。然后，它会要求相关的守护程序加载扩展。**`SystemExtensions.framework`**负责激活和停用系统扩展。

## 绕过ESF

ESF被安全工具使用，将尝试检测红队人员，因此任何关于如何避免这种情况的信息都很有趣。

### CVE-2021-30965

问题在于安全应用程序需要具有**完全磁盘访问权限**。因此，如果攻击者可以移除该权限，他可以阻止软件运行：
```bash
tccutil reset All
```
有关此绕过和相关内容的**更多信息**，请查看演讲[#OBTS v5.0: "终端安全的致命弱点" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

最后，通过向由**`tccd`**管理的安全应用程序授予新权限**`kTCCServiceEndpointSecurityClient`**来修复此问题，因此`tccutil`不会清除其权限，从而阻止其运行。

## 参考资料

* [**OBTS v3.0: "终端安全与不安全" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF版本的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)上**关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧**。

</details>
