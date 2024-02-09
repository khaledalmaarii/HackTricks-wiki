# AD 证书

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) 上 **关注**我们。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 简介

### 证书的组成部分

- 证书的**主体**表示其所有者。
- 与私钥配对的**公钥**将证书与其合法所有者关联起来。
- 由**NotBefore**和**NotAfter**日期定义的**有效期**标志着证书的有效持续时间。
- 由证书颁发机构（CA）提供的唯一**序列号**标识每个证书。
- **颁发者**指的是颁发证书的 CA。
- **SubjectAlternativeName** 允许为主体添加其他名称，增强识别灵活性。
- **基本约束**标识证书是用于 CA 还是终端实体，并定义使用限制。
- **扩展密钥用途（EKUs）**通过对象标识符（OIDs）详细说明证书的具体用途，如代码签名或电子邮件加密。
- **签名算法**指定签署证书的方法。
- 由颁发者的私钥创建的**签名**保证了证书的真实性。

### 特殊考虑事项

- **主体替代名称（SANs）**扩展了证书适用于多个身份，对于具有多个域的服务器至关重要。安全的颁发流程对于避免攻击者操纵 SAN 规范而造成的冒充风险至关重要。

### Active Directory（AD）中的证书颁发机构（CAs）

AD CS 通过指定的容器承认 AD 森林中的 CA 证书，每个容器提供独特的角色：

- **Certification Authorities** 容器保存受信任的根 CA 证书。
- **Enrolment Services** 容器详细说明企业 CA 及其证书模板。
- **NTAuthCertificates** 对象包括授权用于 AD 认证的 CA 证书。
- **AIA（Authority Information Access）** 容器通过中间和跨 CA 证书促进证书链验证。

### 证书获取：客户端证书请求流程

1. 请求过程始于客户端查找企业 CA。
2. 创建 CSR，包含公钥和其他详细信息，生成公私钥对后。
3. CA 根据可用的证书模板评估 CSR，根据模板的权限颁发证书。
4. 获得批准后，CA 使用其私钥签署证书并将其返回给客户端。

### 证书模板

在 AD 中定义的这些模板概述了用于颁发证书的设置和权限，包括允许的 EKUs 和注册或修改权限，对于管理证书服务的关键。

## 证书注册

证书的注册过程由管理员发起，管理员**创建证书模板**，然后由企业证书颁发机构（CA）**发布**。这使得模板可供客户端注册，通过将模板名称添加到 Active Directory 对象的 `certificatetemplates` 字段来实现。

要求客户端请求证书，必须授予**注册权限**。这些权限由证书模板和企业 CA 本身上的安全描述符定义。必须在两个位置授予权限才能成功请求。

### 模板注册权限

这些权限通过访问控制条目（ACEs）指定，详细说明权限，如：
- **Certificate-Enrollment** 和 **Certificate-AutoEnrollment** 权限，每个与特定 GUID 关联。
- **ExtendedRights**，允许所有扩展权限。
- **FullControl/GenericAll**，提供对模板的完全控制。

### 企业 CA 注册权限

CA 的权限在其安全描述符中概述，可通过证书颁发机构管理控制台访问。某些设置甚至允许低特权用户远程访问，这可能是一个安全问题。

### 附加颁发控制

可能适用某些控制，如：
- **管理者批准**：将请求置于待定状态，直到由证书管理员批准。
- **注册代理和授权签名**：指定 CSR 上所需签名的数量以及必要的应用程序策略 OID。

### 请求证书的方法

可以通过以下方式请求证书：
1. **Windows 客户端证书注册协议**（MS-WCCE），使用 DCOM 接口。
2. **ICertPassage 远程协议**（MS-ICPR），通过命名管道或 TCP/IP。
3. **证书注册 Web 界面**，安装了证书颁发机构 Web 注册角色。
4. **证书注册服务**（CES），与证书注册策略（CEP）服务一起使用。
5. **网络设备注册服务**（NDES）用于网络设备，使用简单证书注册协议（SCEP）。

Windows 用户还可以通过 GUI（`certmgr.msc` 或 `certlm.msc`）或命令行工具（`certreq.exe` 或 PowerShell 的 `Get-Certificate` 命令）请求证书。
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 证书认证

Active Directory（AD）支持证书认证，主要利用 **Kerberos** 和 **Secure Channel (Schannel)** 协议。

### Kerberos 认证过程

在 Kerberos 认证过程中，用户请求获取票据授予票据（TGT），使用用户证书的 **私钥** 进行签名。该请求经过域控制器进行多项验证，包括证书的 **有效性**、**路径** 和 **吊销状态**。验证还包括验证证书来自受信任的来源，并确认发行者在 **NTAUTH 证书存储** 中的存在。成功的验证会导致 TGT 的颁发。在 AD 中的 **`NTAuthCertificates`** 对象，位于：
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
### 安全信道（Schannel）认证

Schannel促进了安全的TLS/SSL连接，在握手过程中，客户端提供一个证书，如果成功验证，就会授权访问。证书与AD帐户的映射可能涉及Kerberos的**S4U2Self**功能或证书的**主体替代名称（SAN）**，以及其他方法。

### AD证书服务枚举

可以通过LDAP查询枚举AD的证书服务，揭示有关**企业证书颁发机构（CAs）**及其配置的信息。这可被任何具有域身份验证的用户访问，无需特殊权限。工具如**[Certify](https://github.com/GhostPack/Certify)**和**[Certipy](https://github.com/ly4k/Certipy)**用于在AD CS环境中进行枚举和漏洞评估。

使用这些工具的命令包括：
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## 参考资料

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF版本的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
