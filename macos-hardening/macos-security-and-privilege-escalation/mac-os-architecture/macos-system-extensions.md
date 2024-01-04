# macOS 系统扩展

<details>

<summary><strong>从零到英雄学习 AWS 黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 系统扩展 / 端点安全框架

与内核扩展不同，**系统扩展在用户空间运行** 而不是内核空间，减少了由于扩展故障导致的系统崩溃风险。

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

系统扩展有三种类型：**DriverKit** 扩展、**网络** 扩展和 **端点安全** 扩展。

### **DriverKit 扩展**

DriverKit 是提供硬件支持的内核扩展的替代品。它允许设备驱动程序（如 USB、串行、NIC 和 HID 驱动程序）在用户空间而不是内核空间运行。DriverKit 框架包括 **某些 I/O Kit 类的用户空间版本**，内核将正常的 I/O Kit 事件转发到用户空间，为这些驱动程序提供了一个更安全的运行环境。

### **网络扩展**

网络扩展提供了自定义网络行为的能力。网络扩展有几种类型：

* **应用代理**：用于创建实现基于流的自定义 VPN 协议的 VPN 客户端。这意味着它根据连接（或流）而不是单个数据包处理网络流量。
* **数据包隧道**：用于创建实现基于数据包的自定义 VPN 协议的 VPN 客户端。这意味着它根据单个数据包处理网络流量。
* **过滤数据**：用于过滤网络“流”。它可以在流级别监控或修改网络数据。
* **过滤数据包**：用于过滤单个网络数据包。它可以在数据包级别监控或修改网络数据。
* **DNS 代理**：用于创建自定义 DNS 提供商。它可以用来监控或修改 DNS 请求和响应。

## 端点安全框架

端点安全是 Apple 在 macOS 中提供的一个框架，提供了一套系统安全 API。它旨在供**安全供应商和开发人员使用，以构建能够监控和控制系统活动**的产品，以识别和防护恶意活动。

该框架提供了一系列 API 来监控和控制系统活动，如进程执行、文件系统事件、网络和内核事件。

该框架的核心在内核中实现，作为位于 **`/System/Library/Extensions/EndpointSecurity.kext`** 的内核扩展（KEXT）。这个 KEXT 由几个关键组件组成：

* **EndpointSecurityDriver**：这充当内核扩展的“入口点”。它是操作系统和端点安全框架之间的主要交互点。
* **EndpointSecurityEventManager**：该组件负责实现内核钩子。内核钩子允许框架通过拦截系统调用来监控系统事件。
* **EndpointSecurityClientManager**：这管理与用户空间客户端的通信，跟踪哪些客户端已连接并需要接收事件通知。
* **EndpointSecurityMessageManager**：这向用户空间客户端发送消息和事件通知。

端点安全框架可以监控的事件分为以下几类：

* 文件事件
* 进程事件
* 套接字事件
* 内核事件（如加载/卸载内核扩展或打开 I/O Kit 设备）

### 端点安全框架架构

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt=""><figcaption></figcaption></figure>

与端点安全框架的**用户空间通信**通过 IOUserClient 类进行。根据调用者的类型，使用两个不同的子类：

* **EndpointSecurityDriverClient**：需要 `com.apple.private.endpoint-security.manager` 权限，该权限仅由系统进程 `endpointsecurityd` 持有。
* **EndpointSecurityExternalClient**：需要 `com.apple.developer.endpoint-security.client` 权限。这通常会被需要与端点安全框架交互的第三方安全软件使用。

端点安全扩展：**`libEndpointSecurity.dylib`** 是系统扩展用来与内核通信的 C 库。这个库使用 I/O Kit（`IOKit`）与端点安全 KEXT 通信。

**`endpointsecurityd`** 是一个关键的系统守护进程，涉及管理和启动端点安全系统扩展，特别是在早期引导过程中。**只有系统扩展** 在其 `Info.plist` 文件中标记了 **`NSEndpointSecurityEarlyBoot`** 才会接受这种早期引导处理。

另一个系统守护进程，**`sysextd`**，**验证系统扩展** 并将它们移动到适当的系统位置。然后它请求相关守护进程加载扩展。**`SystemExtensions.framework`** 负责激活和停用系统扩展。

## 绕过 ESF

ESF 被安全工具使用，旨在尝试检测红队成员，因此任何关于如何避免这种情况的信息听起来都很有趣。

### CVE-2021-30965

问题在于安全应用程序需要具有**完整磁盘访问权限**。因此，如果攻击者可以移除这个权限，他可以阻止软件运行：
```bash
tccutil reset All
```
有关此绕过及相关绕过的**更多信息**，请查看演讲[#OBTS v5.0：“EndpointSecurity的致命弱点” - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

最终，通过给安全应用程序授予新权限**`kTCCServiceEndpointSecurityClient`**并由**`tccd`**管理，从而修复了这个问题，这样`tccutil`就不会清除其权限，防止它运行。

## 参考资料

* [**OBTS v3.0：“端点安全与不安全” - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为英雄，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧。

</details>
