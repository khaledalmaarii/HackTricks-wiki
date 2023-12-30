# 证书

<details>

<summary><strong>从零到英雄学习AWS黑客攻击，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter**上**关注**我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 什么是证书

在密码学中，**公钥证书**，也称为**数字证书**或**身份证书**，是用来证明公钥所有权的电子文件。证书包含关于密钥的信息、其所有者（称为主题）的身份信息，以及已验证证书内容的实体（称为发行者）的数字签名。如果签名有效，并且检查证书的软件信任发行者，那么它可以使用该密钥与证书的主题安全通信。

在典型的[公钥基础设施](https://en.wikipedia.org/wiki/Public-key_infrastructure)（PKI）方案中，证书发行者是[证书机构](https://en.wikipedia.org/wiki/Certificate_authority)（CA），通常是向客户收费以为他们发行证书的公司。相比之下，在[信任网络](https://en.wikipedia.org/wiki/Web_of_trust)方案中，个人直接签署彼此的密钥，以一种执行与公钥证书类似功能的格式。

公钥证书最常见的格式由[X.509](https://en.wikipedia.org/wiki/X.509)定义。因为X.509非常通用，所以格式进一步受到某些用例定义的配置文件的限制，例如[RFC 5280](https://en.wikipedia.org/wiki/PKIX)中定义的[公钥基础设施（X.509）]。

## x509常见字段

* **版本号**：x509格式的版本。
* **序列号**：用于在CA系统内唯一识别证书。特别是用于跟踪撤销信息。
* **主题**：证书所属的实体：机器、个人或组织。
* **通用名称**：受证书影响的域。可以是1个或多个，可以包含通配符。
* **国家（C）**：国家
* **可分辨名称（DN）**：完整的主题：`C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
* **地点（L）**：本地地点
* **组织（O）**：组织名称
* **组织单位（OU）**：组织的部门（如“人力资源”）。
* **州或省（ST, S或P）**：州或省名称列表
* **发行者**：验证信息并签署证书的实体。
* **通用名称（CN）**：证书机构的名称
* **国家（C）**：证书机构的国家
* **可分辨名称（DN）**：证书机构的可分辨名称
* **地点（L）**：可以找到组织的本地地点。
* **组织（O）**：组织名称
* **组织单位（OU）**：组织的部门（如“人力资源”）。
* **生效前**：证书有效的最早时间和日期。通常设置在证书发行时刻的几小时或几天前，以避免[时钟偏差](https://en.wikipedia.org/wiki/Clock_skew#On_a_network)问题。
* **生效后**：证书不再有效的时间和日期。
* **公钥**：属于证书主题的公钥。（这是主要部分之一，因为这是由CA签名的）
* **公钥算法**：用于生成公钥的算法。如RSA。
* **公钥曲线**：椭圆曲线公钥算法使用的曲线（如果适用）。如nistp521。
* **公钥指数**：用于推导公钥的指数（如果适用）。如65537。
* **公钥大小**：公钥空间的位大小。如2048。
* **签名算法**：用于签署公钥证书的算法。
* **签名**：由发行者的私钥对证书正文的签名。
* **x509v3扩展**
* **密钥用途**：证书公钥的有效加密用途。常见值包括数字签名验证、密钥加密和证书签名。
* 在Web证书中，这将显示为_X509v3扩展_，值为`数字签名`
* **扩展密钥用途**：证书可能使用的应用程序。常见值包括TLS服务器认证、电子邮件保护和代码签名。
* 在Web证书中，这将显示为_X509v3扩展_，值为`TLS Web服务器认证`
* **主题备用名称**：允许用户为单个SSL**证书**指定额外的主机**名称**。使用SAN扩展是SSL证书的标准做法，它正在取代通用**名称**的使用。
* **基本约束**：此扩展描述证书是CA证书还是终端实体证书。CA证书是签署其他证书的证书，终端实体证书是例如在网页中使用的证书（链的最后部分）。
* **主题密钥标识符**（SKI）：此扩展声明证书中公钥的唯一**标识符**。所有CA证书都需要此扩展。CA将自己的SKI传播到所发行证书的发行者**密钥标识符**（AKI）扩展上。它是主题公钥的哈希。
* **权威密钥标识符**：它包含从发行者证书中的公钥派生的密钥标识符。它是发行者公钥的哈希。
* **权威信息访问**（AIA）：此扩展最多包含两种类型的信息：
  * 有关**如何获取此证书的发行者**（CA发行者访问方法）的信息
  * 可以检查此证书撤销情况的**OCSP响应者的地址**（OCSP访问方法）。
* **CRL分发点**：此扩展标识了可以检查此证书撤销情况的CRL的位置。处理证书的应用程序可以从此扩展获取CRL的位置，下载CRL，然后检查此证书的撤销情况。
* **CT预证书SCTs**：关于证书的证书透明度日志

### OCSP与CRL分发点之间的区别

**OCSP**（RFC 2560）是一个标准协议，由**OCSP客户端和OCSP响应者**组成。该协议**确定给定数字公钥证书的撤销状态**，**无需**下载**整个CRL**。\
**CRL**是检查证书有效性的**传统方法**。**CRL提供了已被撤销或不再有效的证书序列号的列表**。CRL允许验证者在验证证书时检查所呈现证书的撤销状态。CRL的条目限制为512个。\
来自[这里](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm)。

### 什么是证书透明度

证书透明度旨在通过**使SSL证书的发行和存在对域名所有者、CA和域名用户开放审查**来解决基于证书的威胁。具体来说，证书透明度有三个主要目标：

* 使CA**发行域名的SSL证书而不被该域名的所有者看到变得不可能（或至少非常困难）**。
* 提供一个**开放的审计和监控系统，任何域名所有者或CA都可以确定是否有证书被错误地或恶意地**发行。
* **尽可能保护用户**不受错误或恶意发行的证书的欺骗。

#### **证书日志**

证书日志是简单的网络服务，维护**加密保证的、公开可审计的、仅附加记录的证书**。**任何人都可以向日志提交证书**，尽管证书机构可能是最主要的提交者。同样，任何人都可以查询日志以获取加密证明，该证明可用于验证日志是否正常运行或验证特定证书是否已记录。日志服务器的数量不必很多（比如，全球不到一千个），每个服务器可以由CA、ISP或任何其他感兴趣的方独立运营。

#### 查询

您可以在[https://crt.sh/](https://crt.sh)查询任何域名的证书透明度日志。

## 格式

有不同的格式可用于存储证书。

#### **PEM格式**

* 它是用于证书的最常见格式
* 大多数服务器（例如：Apache）期望证书和私钥在单独的文件中\
\- 通常它们是Base64编码的ASCII文件\
\- PEM证书使用的扩展名有.cer、.crt、.pem、.key文件\
\- Apache和类似服务器使用PEM格式证书

#### **DER格式**

* DER格式是证书的二进制形式
* 所有类型的证书和私钥都可以编码为DER格式
* DER格式的证书不包含“BEGIN CERTIFICATE/END CERTIFICATE”语句
* DER格式的证书最常使用‘.cer’和'.der'扩展名
* DER通常用于Java平台

#### **P7B/PKCS#7格式**

* PKCS#7或P7B格式存储在Base64 ASCII格式中，文件扩展名为.p7b或.p7c
* P7B文件只包含证书和链证书（中间CA），不包含私钥
* 支持P7B文件的最常见平台是Microsoft Windows和Java Tomcat

#### **PFX/P12/PKCS#12格式**

* PKCS#12或PFX/P12格式是一种二进制格式，用于在一个可加密文件中存储服务器证书、中间证书和私钥
* 这些文件通常具有.pfx和.p12等扩展名
* 它们通常用于Windows机器上导入和导出证书和私钥

### 格式转换

**将x509转换为PEM**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **将 PEM 转换为 DER**
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
**将DER转换为PEM**
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**将 PEM 转换为 P7B**

**注意：** PKCS#7 或 P7B 格式以 Base64 ASCII 格式存储，文件扩展名为 .p7b 或 .p7c。P7B 文件仅包含证书和链证书（中间 CA），不包含私钥。最常支持 P7B 文件的平台是 Microsoft Windows 和 Java Tomcat。
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**将PKCS7转换为PEM**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**将 pfx 转换为 PEM**

**注意：** PKCS#12 或 PFX 格式是一种二进制格式，用于在一个可加密文件中存储服务器证书、中间证书和私钥。PFX 文件通常具有 .pfx 和 .p12 等扩展名。PFX 文件通常用于 Windows 机器上导入和导出证书和私钥。
```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
**转换 PFX 至 PKCS#8**\
**注意：** 这需要2条命令

**1- 将 PFX 转换为 PEM**
```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
**2- 将 PEM 转换为 PKCS8**
```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
**将 P7B 转换为 PFX**\
**注意：** 这需要2个命令

1- **将 P7B 转换为 CER**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
**2- 将 CER 和私钥转换为 PFX**
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

其他支持HackTricks的方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧。

</details>
