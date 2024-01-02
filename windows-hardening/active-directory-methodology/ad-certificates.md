# AD 证书

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 基本信息

### 证书的组成部分

* **主题** - 证书的所有者。
* **公钥** - 将主题与单独存储的私钥关联起来。
* **NotBefore 和 NotAfter 日期** - 定义证书有效的持续时间。
* **序列号** - 由 CA 分配的证书标识符。
* **颁发者** - 标识颁发证书的实体（通常是 CA）。
* **SubjectAlternativeName** - 定义主题可能使用的一个或多个备用名称。（_查看下面_）
* **基本约束** - 标识证书是 CA 还是终端实体，以及使用证书时是否有任何约束。
* **扩展密钥用途 (EKUs)** - 描述**证书将如何使用**的对象标识符（OID）。在 Microsoft 术语中也称为增强型密钥用途。常见的 EKU OID 包括：
* 代码签名 (OID 1.3.6.1.5.5.7.3.3) - 证书用于签署可执行代码。
* 加密文件系统 (OID 1.3.6.1.4.1.311.10.3.4) - 证书用于加密文件系统。
* 安全电子邮件 (1.3.6.1.5.5.7.3.4) - 证书用于加密电子邮件。
* 客户端认证 (OID 1.3.6.1.5.5.7.3.2) - 证书用于向另一服务器（例如，向 AD）进行认证。
* 智能卡登录 (OID 1.3.6.1.4.1.311.20.2.2) - 证书用于智能卡认证。
* 服务器认证 (OID 1.3.6.1.5.5.7.3.1) - 证书用于识别服务器（例如，HTTPS 证书）。
* **签名算法** - 指定用于签署证书的算法。
* **签名** - 使用颁发者（例如 CA）的私钥对证书正文进行的签名。

#### 备用主题名称

**备用主题名称**（SAN）是 X.509v3 扩展。它允许将**额外的身份**绑定到**证书**。例如，如果一个 web 服务器托管**多个域的内容**，**每个**适用的**域**都可以包含在**SAN**中，这样 web 服务器只需要一个 HTTPS 证书。

默认情况下，在基于证书的认证过程中，AD 会根据 SAN 中指定的 UPN 将证书映射到用户帐户。如果攻击者在请求具有**启用客户端认证的 EKU**的证书时可以**指定任意 SAN**，并且 CA 使用攻击者提供的 SAN 创建并签署证书，**攻击者可以成为域中的任何用户**。

### CAs

AD CS 在 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>` 容器下的四个位置定义了 AD 林信任的 CA 证书，每个位置的目的不同：

* **认证机构**容器定义了**受信任的根 CA 证书**。这些 CA 位于 PKI 树层次结构的**顶部**，是 AD CS 环境中信任的基础。每个 CA 都作为 AD 对象存在于容器内，其中**objectClass**设置为**`certificationAuthority`**，**`cACertificate`**属性包含**CA 证书的字节**。Windows 将这些 CA 证书传播到**每台 Windows 机器**上的受信任的根证书颁发机构证书存储中。对于 AD 来说，要考虑证书为**受信任**的，证书的信任**链**必须最终**以定义在此容器中的根 CA**结束。
* **注册服务**容器定义了每个**企业 CA**（即，在 AD CS 中创建并启用了企业 CA 角色的 CAs）。每个企业 CA 都有一个 AD 对象，具有以下属性：
* 一个**objectClass**属性设置为**`pKIEnrollmentService`**
* 一个**`cACertificate`**属性包含**CA 证书的字节**
* 一个**`dNSHostName`**属性设置了**CA 的 DNS 主机**
* 一个**certificateTemplates**字段定义了**启用的证书模板**。证书模板是 CA 在创建证书时使用的设置的“蓝图”，包括 EKUs、注册权限、证书的到期时间、发行要求和加密设置等。我们稍后将更详细地讨论证书模板。

{% hint style="info" %}
在 AD 环境中，**客户端与企业 CA 互动以根据证书模板中定义的设置请求证书**。企业 CA 证书被传播到每台 Windows 机器上的中间证书颁发机构证书存储中。
{% endhint %}

* **NTAuthCertificates** AD 对象定义了启用 AD 认证的 CA 证书。该对象具有**objectClass**为**`certificationAuthority`**，对象的**`cACertificate`**属性定义了**受信任的 CA 证书数组**。AD 加入的 Windows 机器将这些 CA 传播到每台机器上的中间证书颁发机构证书存储中。**客户端**应用程序只有在**由 NTAuthCertificates** 对象定义的**CAs 签署**了认证客户端的证书时，才能**认证**到 AD。
* **AIA**（授权信息访问）容器保存了中间和交叉 CAs 的 AD 对象。**中间 CAs 是根 CAs 的“子级”**，在 PKI 树层次结构中；因此，此容器存在是为了帮助**验证证书链**。与认证机构容器一样，每个**CA 都作为 AD 对象**存在于 AIA 容器中，其中 objectClass 属性设置为 certificationAuthority，**`cACertificate`**属性包含**CA 证书的字节**。这些 CAs 被传播到每台 Windows 机器上的中间证书颁发机构证书存储中。

### 客户端证书请求流程

<figure><img src="../../.gitbook/assets/image (5) (2) (2).png" alt=""><figcaption></figcaption></figure>

这是从 AD CS **获取证书**的过程。在高层次上，在注册期间，客户端首先根据上面讨论的**注册服务**容器中的**对象找到企业 CA**。

1. 客户端然后生成一个**公私钥对**，
2. 并将公钥放在一个**证书签名请求（CSR）**消息中，以及其他详细信息，如证书的主题和**证书模板名称**。然后客户端**用他们的私钥签署 CSR** 并将 CSR 发送到企业 CA 服务器。
3. **CA** 服务器检查客户端**是否可以请求证书**。如果可以，它通过查找 CSR 中指定的**证书模板** AD 对象来确定是否会发放证书。CA 将检查证书模板 AD 对象的**权限是否允许**认证帐户**获取证书**。
4. 如果可以，**CA 使用证书模板定义的“蓝图”设置生成证书**（例如 EKUs、加密设置和发行要求），并使用 CSR 中提供的其他信息（如果证书模板设置允许）。**CA 使用其私钥签署证书**，然后将其返回给客户端。

### 证书模板

AD CS 将可用的证书模板作为 AD 对象存储，其**objectClass**为**`pKICertificateTemplate`**，位于以下容器中：

`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`

AD 证书模板对象的属性**定义其设置，其安全描述符控制**哪些**主体可以注册**证书或**编辑**证书模板。

AD 证书模板对象的**`pKIExtendedKeyUsage`**属性包含模板中启用的**OID 数组**。这些 EKU OID 影响**证书可用于什么**。您可以在[这里找到可能的 OID 列表](https://www.pkisolutions.com/object-identifiers-oid-in-pki/)。

#### 认证 OID

* `1.3.6.1.5.5.7.3.2`：客户端认证
* `1.3.6.1.5.2.3.4`：PKINIT 客户端认证（需要手动添加）
* `1.3.6.1.4.1.311.20.2.2`：智能卡登录
* `2.5.29.37.0`：任何目的
* `(无 EKUs)`：SubCA
* 我们发现我们可以滥用的另一个 EKU OID 是证书请求代理 OID（`1.3.6.1.4.1.311.20.2.1`）。除非实施特定限制，否则具有此 OID 的证书可用于**代表另一用户请求证书**。

## 证书注册

管理员需要**创建证书**模板，然后企业 CA **“发布”**模板，使其可供客户端注册。AD CS 指定证书模板在企业 CA 上启用，方法是**将模板的名称添加到 AD 对象的 `certificatetemplates` 字段**。

<figure><img src="../../.gitbook/assets/image (11) (2) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
AD CS 定义了注册权限 - 哪些**主体可以请求**证书 - 使用两个安全描述符：一个在**证书模板** AD 对象上，另一个在**企业 CA 本身**上。\
客户端需要在两个安全描述符中被授予才能请求证书。
{% endhint %}

### 证书模板注册权限

* **ACE 授予主体 Certificate-Enrollment 扩展权限**。原始 ACE 授予主体 `RIGHT_DS_CONTROL_ACCESS45` 访问权限，其中**ObjectType**设置为 `0e10c968-78fb-11d2-90d4-00c04f79dc5547`。此 GUID 对应于**证书注册**扩展权限。
* **ACE 授予主体 Certificate-AutoEnrollment 扩展权限**。原始 ACE 授予主体 `RIGHT_DS_CONTROL_ACCESS48` 访问权限，其中**ObjectType**设置为 `a05b8cc2-17bc-4802-a710-e7c15ab866a249`。此 GUID 对应于**证书自动注册**扩展权限。
* **ACE 授予主体所有 ExtendedRights**。原始 ACE 启用 `RIGHT_DS_CONTROL_ACCESS` 访问权限，其中**ObjectType**设置为 `00000000-0000-0000-0000-000000000000`。此 GUID 对应于**所有扩展权限**。
* **ACE 授予主体 FullControl/GenericAll**。原始 ACE 启用 FullControl/GenericAll 访问权限。

### 企业 CA 注册权限

**企业 CA**上配置的**安全描述符**定义了这些权限，并且可以在证书颁发机构 MMC 管理单元 `certsrv.msc` 中查看，方法是右键单击 CA → 属性 → 安全。

<figure><img src="../../.gitbook/assets/image (7) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

这最终会在 CA 服务器上的键 **`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration<CA NAME>`** 中设置安全注册表值。我们遇到了几个 AD CS 服务器，它们通过远程注册表授予低权限用户对此键的远程访问权限：

<figure><img src="../../.gitbook/assets/image (6) (2) (1).png" alt=""><figcaption></figcaption></figure>

低权限用户还可以使用 `ICertAdminD2` COM 接口的 `GetCASecurity` 方法通过 DCOM **枚举**此信息。然而，正常的 Windows 客户端需要安装远程服务器管理工具 (RSAT) 才能使用它，因为 COM 接口和任何实现它的 COM 对象默认情况下不在 Windows 上。

### 发行要求

其他要求可能到位以控制谁可以获得证书。

#### 经理批准

**CA 证书经理批准**导致证书模板在 AD 对象的 `msPKI-EnrollmentFlag` 属性上设置 `CT_FLAG_PEND_ALL_REQUESTS`（0x2）位。这将所有基于模板的**证书请求**置于**待处理状态**（在 `certsrv.msc` 的“待处理请求”部分可见），这需要证书经理**批准或拒绝**请求才能发放证书：

<figure><img src="../../.gitbook/assets/image (13) (2).png" alt=""><figcaption></figcaption></figure>

#### 注册代理、授权签名和应用策略

**授权签名数量**和**应用策略**。前者控制 CSR 中需要的**签名数量**以便 CA 接受它。后者定义了 CSR 签名证书必须具有的**EKU OID**。

这些设置的常见用途是**注册代理**。注册代理是 AD CS 术语，指可以**代表另一用户请求证书**的实体。要做到这一点，CA 必须向注册代理帐户颁发至少包含**证书请求代理 EKU**（OID 1.3.6.1.4.1.311.20.2.1）的证书。一旦颁发，注册代理就可以**签署 CSR 并代表其他用户请求证书**。CA 将在以下非全面的**条件集**下**向注册代理颁发**作为**另一用户**的**证书**（主要在默认策略模块 `cert
```bash
# https://github.com/GhostPack/Certify
Certify.exe cas #enumerate trusted root CA certificates, certificates defined by the NTAuthCertificates object, and various information about Enterprise CAs
Certify.exe find #enumerate certificate templates
Certify.exe find /vulnerable #Enumerate vulenrable certificate templater

# https://github.com/ly4k/Certipy
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
certipy find -vulnerable [-hide-admins] -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128 #Search vulnerable templates

certutil.exe -TCAInfo #enumerate Enterprise CAs
certutil -v -dstemplate #enumerate certificate templates
```
## 参考资料

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击技巧！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
