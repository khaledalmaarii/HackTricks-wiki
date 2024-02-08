# 将设备注册到其他组织

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 简介

如[**先前评论的**](./#what-is-mdm-mobile-device-management)**，为了尝试将设备注册到一个组织中，只需要一个属于该组织的序列号**。一旦设备注册成功，多个组织将在新设备上安装敏感数据：证书、应用程序、WiFi密码、VPN配置[等等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。\
因此，如果注册过程没有得到正确保护，这可能成为攻击者的危险入口。

**以下是对研究[https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)的总结。请查看以获取更多技术细节！**

## DEP和MDM二进制分析概述

该研究深入探讨了与设备注册计划（DEP）和移动设备管理（MDM）在macOS上相关的二进制文件。关键组件包括：

- **`mdmclient`**：与MDM服务器通信，并在macOS 10.13.4之前的版本上触发DEP签入。
- **`profiles`**：管理配置文件，并在macOS 10.13.4及更高版本上触发DEP签入。
- **`cloudconfigurationd`**：管理DEP API通信并检索设备注册配置文件。

DEP签入利用私有配置文件框架中的`CPFetchActivationRecord`和`CPGetActivationRecord`函数来获取激活记录，其中`CPFetchActivationRecord`通过XPC与`cloudconfigurationd`协调。

## Tesla协议和Absinthe方案的逆向工程

DEP签入涉及`cloudconfigurationd`向_iprofiles.apple.com/macProfile_发送加密、签名的JSON负载。负载包括设备的序列号和动作“RequestProfileConfiguration”。内部使用的加密方案称为“Absinthe”。解开这个方案很复杂，涉及多个步骤，因此探索了插入激活记录请求中任意序列号的替代方法。

## 代理DEP请求

使用Charles Proxy等工具拦截和修改DEP请求到_iprofiles.apple.com_的尝试受到负载加密和SSL/TLS安全措施的阻碍。然而，启用`MCCloudConfigAcceptAnyHTTPSCertificate`配置允许绕过服务器证书验证，尽管负载的加密性质仍然阻止了在没有解密密钥的情况下修改序列号。

## 仪器化与DEP交互的系统二进制文件

仪器化系统二进制文件如`cloudconfigurationd`需要在macOS上禁用系统完整性保护（SIP）。禁用SIP后，可以使用LLDB等工具附加到系统进程，并可能修改DEP API交互中使用的序列号。这种方法更可取，因为它避免了授权和代码签名的复杂性。

**利用二进制仪器化：**
在`cloudconfigurationd`中的JSON序列化之前修改DEP请求负载证明是有效的。该过程涉及：

1. 将LLDB附加到`cloudconfigurationd`。
2. 定位提取系统序列号的位置。
3. 在加密并发送负载之前向内存中注入任意序列号。

这种方法允许检索任意序列号的完整DEP配置文件，展示了潜在的漏洞。

### 使用Python自动化仪器化

使用LLDB API自动化利用过程，使得可以以编程方式注入任意序列号并检索相应的DEP配置文件。

### DEP和MDM漏洞的潜在影响

该研究突出了重要的安全问题：

1. **信息泄露**：通过提供DEP注册的序列号，可以检索包含在DEP配置文件中的敏感组织信息。
2. **恶意DEP注册**：在没有适当身份验证的情况下，具有DEP注册序列号的攻击者可以将恶意设备注册到组织的MDM服务器中，可能获取对敏感数据和网络资源的访问权限。

总之，虽然DEP和MDM为企业环境中管理苹果设备提供了强大工具，但它们也呈现出需要保护和监控的潜在攻击向量。
