# 证书

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)的GitHub仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，并由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 什么是证书

在密码学中，**公钥证书**，也称为**数字证书**或**身份证书**，是用于证明公钥所有权的电子文档。证书包括有关密钥的信息，其所有者的身份信息（称为主体），以及已验证证书内容的实体的数字签名（称为颁发者）。如果签名有效，并且检查证书的软件信任颁发者，则可以使用该密钥与证书的主体安全通信。

在典型的[公钥基础设施](https://en.wikipedia.org/wiki/Public-key\_infrastructure)（PKI）方案中，证书颁发者是[证书颁发机构](https://en.wikipedia.org/wiki/Certificate\_authority)（CA），通常是一家为客户收费以为其颁发证书的公司。相比之下，在[信任网络](https://en.wikipedia.org/wiki/Web\_of\_trust)方案中，个人直接签署彼此的密钥，以一种类似于公钥证书的格式执行功能。

公钥证书的最常见格式由[X.509](https://en.wikipedia.org/wiki/X.509)定义。由于X.509非常通用，因此格式受到为某些用例定义的配置文件的进一步限制，例如[RFC 5280](https://en.wikipedia.org/wiki/PKIX)中定义的[公钥基础设施（X.509）](https://en.wikipedia.org/wiki/PKIX)。

## x509常见字段

- **版本号：** x509格式的版本。
- **序列号：** 用于在CA系统内唯一标识证书。特别是用于跟踪吊销信息。
- **主体：** 证书所属的实体：机器、个人或组织。
- **通用名称：** 受证书影响的域。可以是1个或多个，并且可以包含通配符。
- **国家（C）：** 国家
- **显著名称（DN）：** 整个主体：`C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
- **地点（L）：** 地点
- **组织（O）：** 组织名称
- **组织单位（OU）：** 组织的部门（如“人力资源”）。
- **州或省（ST，S或P）：** 州或省名称列表
- **颁发者：** 验证信息并签署证书的实体。
- **通用名称（CN）：** 证书颁发机构的名称
- **国家（C）：** 证书颁发机构的国家
- **显著名称（DN）：** 证书颁发机构的显著名称
- **地点（L）：** 组织所在地的地点。
- **组织（O）：** 组织名称
- **组织单位（OU）：** 组织的部门（如“人力资源”）。
- **生效日期：** 证书有效的最早时间和日期。通常设置为证书签发前几小时或几天，以避免[时钟偏移](https://en.wikipedia.org/wiki/Clock\_skew#On\_a\_network)问题。
- **过期日期：** 证书不再有效的时间和日期。
- **公钥：** 属于证书主体的公钥。（这是主要部分之一，因为这是CA签名的内容）
- **公钥算法：** 用于生成公钥的算法。如RSA。
- **公钥曲线：** 椭圆曲线公钥算法使用的曲线（如果适用）。如nistp521。
- **公钥指数：** 用于生成公钥的指数（如果适用）。如65537。
- **公钥大小：** 以位为单位的公钥空间大小。如2048。
- **签名算法：** 用于签署公钥证书的算法。
- **签名：** 颁发者的私钥对证书正文的签名。
- **x509v3扩展**
- **密钥用途：** 证书公钥的有效加密用途。常见值包括数字签名验证、密钥加密和证书签名。
  - 在Web证书中，这将显示为_X509v3扩展_，并将具有值`数字签名`
- **扩展密钥用途：** 证书可用于的应用程序。常见值包括TLS服务器身份验证、电子邮件保护和代码签名。
  - 在Web证书中，这将显示为_X509v3扩展_，并将具有值`TLS Web服务器身份验证`
- **主体替代名称：** 允许用户为单个SSL **证书**指定其他主机**名称**。SAN扩展的使用是SSL证书的标准做法，它正在取代常见**名称**的使用。
- **基本约束：** 此扩展描述证书是CA证书还是终端实体证书。CA证书是签署其他证书的实体，终端实体证书是用于网页的证书，例如（链的最后一部分）。
- **主体密钥标识符**（SKI）：此扩展声明证书中公钥的唯一**标识符**。所有CA证书都需要此扩展。CA将其自己的SKI传播到已签发证书的颁发者**密钥标识符**（AKI）扩展中。它是主体公钥的哈希值。
- **颁发者密钥标识符**：它包含从颁发者证书中的公钥派生的密钥标识符。它是颁发者公钥的哈希值。
- **颁发者信息访问**（AIA）：此扩展包含最多两种类型的信息：
  - 关于**如何获取此证书的颁发者**的信息（CA颁发者访问方法）
  - 可以检查此证书吊销的OCSP响应器地址（OCSP访问方法）。
- **CRL分发点**：此扩展标识可以检查此证书吊销的CRL的位置。处理证书的应用程序可以从此扩展中获取CRL的位置，下载CRL，然后检查此证书的吊销。
- **CT预证书SCTs**：关于证书的证书透明度日志

### OCSP和CRL分发点的区别

**OCSP**（RFC 2560）是一个标准协议，由**OCSP客户端和OCSP响应器**组成。该协议**确定给定数字公钥证书的吊销状态**，而**无需下载**整个CRL。\
**CRL**是检查证书有效性的传统方法。**CRL提供已吊销或不再有效的证书序列号列表**。CRL允许验证者在验证证书时检查所呈现证书的吊销状态。CRL限制为512个条目。\
来源：[这里](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm)。

### 什么是证书透明度

证书透明度旨在通过使SSL证书的颁发和存在对域所有者、CA和域用户公开审查来解决基于证书的威胁。具体而言，证书透明度有三个主要目标：

- 使CA**无法为域颁发SSL证书**，而不让该域的所有者看到该证书，或者至少非常困难。
- 提供一个**开放的审计和监控系统**，让任何域所有者或CA确定证书是否被错误或恶意颁发。
- **尽可能**保护用户免受被错误或恶意颁发的证书欺骗。

#### **证书日志**

证书日志是简单的网络服务，用于维护**具有密码保证、公开可审计、仅追加记录的证书**。**任何人都可以向日志提交证书**，尽管证书颁发机构可能是最主要的提交者。同样，任何人都可以查询日志以获取加密证明，该证明可用于验证日志是否正常运行或验证特定证书是否已记录。日志服务器的数量不必很大（例如，全球范围内远远少于一千个），每个服务器可以由CA、ISP或任何其他感兴趣的方运营。

#### 查询

您可以查询任何域的证书透明度日志在[https://crt.sh/](https://crt.sh)。

## 格式

有不同的格式可用于存储证书。

#### **PEM格式**

- 这是用于证书的最常见格式
- 大多数服务器（例如：Apache）期望证书和私钥在单独的文件中\
  - 通常它们是Base64编码的ASCII文件\
  - 用于PEM证书的扩展名为.cer、.crt、.pem、.key文件\
  - Apache和类似的服务器使用PEM格式证书

#### **DER格式**

- DER格式是证书的二进制形式
- 所有类型的证书和私钥都可以以DER格式编码
- DER格式的证书不包含“BEGIN CERTIFICATE/END CERTIFICATE”语句
- DER格式的证书通常使用“.cer”和“.der”扩展名
- DER通常用于Java平台

#### **P7B/PKCS#7格式**

- PKCS#7或P7B格式以Base64 ASCII格式存储，并具有.p7b或.p7c文件扩展名
- P7B文件仅包含证书和链证书（中间CA），不包含私钥
- 支持P7B文件的最常见平台是Microsoft Windows和Java Tomcat

#### **PFX/P12/PKCS#12格式**

- PKCS#12或PFX/P12格式是一种用于在一个可加密文件中存储服务器证书、中间证书和私钥的二进制格式
- 这些文件通常具有.pfx和.p12等扩展名
- 它们通常用于Windows机器导入和导出证书和私钥

### 格式转换

**将x509转换为PEM**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **将PEM转换为DER**
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
**将 DER 转换为 PEM**
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**将PEM转换为P7B**

**注意：** PKCS#7或P7B格式以Base64 ASCII格式存储，并具有.p7b或.p7c文件扩展名。 P7B文件仅包含证书和链证书（中间CA），而不包含私钥。 支持P7B文件的最常见平台是Microsoft Windows和Java Tomcat。
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**将PKCS7转换为PEM**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**将 pfx 转换为 PEM**

**注意：** PKCS#12 或 PFX 格式是一种用于存储服务器证书、中间证书和私钥的二进制格式，存储在一个可加密文件中。PFX 文件通常具有 .pfx 和 .p12 等扩展名。PFX 文件通常用于在 Windows 计算机上导入和导出证书和私钥。
```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
**将PFX转换为PKCS#8**\
**注意：** 这需要2个命令

**1- 将PFX转换为PEM**
```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
**2- 将PEM转换为PKCS8**
```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
**将 P7B 转换为 PFX**\
**注意：** 这需要 2 条命令

1- **将 P7B 转换为 CER**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
**2- 将CER证书和私钥转换为PFX格式**
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 可轻松构建并通过世界上**最先进**的社区工具**自动化工作流程**。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
