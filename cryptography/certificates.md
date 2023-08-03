# 证书

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.io/)可以轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 什么是证书

在密码学中，**公钥证书**，也称为**数字证书**或**身份证书**，是用于证明公钥所有权的电子文档。证书包括有关密钥的信息，其所有者的身份信息（称为主体），以及验证证书内容的实体的数字签名（称为颁发者）。如果签名有效，并且检查证书的软件信任颁发者，则可以使用该密钥与证书的主体进行安全通信。

在典型的[公钥基础设施](https://en.wikipedia.org/wiki/Public-key\_infrastructure)（PKI）方案中，证书颁发者是一个[证书颁发机构](https://en.wikipedia.org/wiki/Certificate\_authority)（CA），通常是一家向客户收费以为其颁发证书的公司。相比之下，在[信任网络](https://en.wikipedia.org/wiki/Web\_of\_trust)方案中，个人直接签署彼此的密钥，以一种类似于公钥证书的格式执行类似功能。

公钥证书的最常见格式由[X.509](https://en.wikipedia.org/wiki/X.509)定义。由于X.509非常通用，因此该格式受到为某些用例定义的配置文件的进一步限制，例如[RFC 5280](https://en.wikipedia.org/wiki/PKIX)中定义的[公钥基础设施（X.509）](https://en.wikipedia.org/wiki/PKIX)。

## x509 常见字段

* **版本号**：x509 格式的版本。
* **序列号**：用于在 CA 的系统中唯一标识证书。特别是用于跟踪吊销信息。
* **主体**：证书所属的实体：机器、个人或组织。
* **通用名称**：受证书影响的域。可以是一个或多个，并且可以包含通配符。
* **国家（C）**：国家
* **可分辨名称（DN）**：完整的主体：`C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
* **地点（L）**：地点
* **组织（O）**：组织名称
* **组织单位（OU）**：组织的部门（如“人力资源”）。
* **州或省（ST、S 或 P）**：州或省名称列表
* **颁发者**：验证信息并签署证书的实体。
* **通用名称（CN）**：证书颁发机构的名称
* **国家（C）**：证书颁发机构的国家
* **可分辨名称（DN）**：证书颁发机构的可分辨名称
* **地点（L）**：组织所在的地点。
* **组织（O）**：组织名称
* **组织单位（OU）**：组织的部门（如“人力资源”）。
* **起始日期**：证书有效的最早时间和日期。通常设置为证书签发的几个小时或几天之前的时刻，以避免[时钟偏差](https://en.wikipedia.org/wiki/Clock\_skew#On\_a\_network)问题。
* **截止日期**：证书不再有效的时间和日期。
* **公钥**：属于证书主体的公钥。（这是主要部分之一，因为这是由 CA 签名的内容）
* **公钥算法**：用于生成公钥的算法。如 RSA。
* **公钥曲线**：椭圆曲线公钥算法使用的曲线（如果适用）。如 nistp521。
* **公钥指数**：用于推导公钥的指数（如果适用）。如 65537。
* **公钥大小**：公钥空间的位数大小。如 2048。
* **签名算法**：用于签署公钥证书的算法。
* **签名**：颁发者的私钥对证书主体进行的签名。
* **x509v3 扩展**
* **密钥用途**：证书公钥的有效加密用途。常见值包括数字签名验证、密钥加密和证书签名。
* 在 Web 证书中，它将显示为 _X509v3 扩展_，并具有值 `Digital Signature`
* **扩展密钥用途**：证书可用于的应用程序。常见值包括 TLS 服务器身份验证、电子邮件保护和代码签名。
* 在 Web 证书中，它将显示为 _X509v3 扩展_，并具有值 `TLS Web Server Authentication`
* **主体备用名称**：允许用户为单个 SSL 证书指定其他主机**名称**。使用 SAN 扩展是 SSL 证书的标准做法，它正在取代常见**名称**的使用。
* **基本约束**：此扩展描述证书是 CA 证书还是终端实体证书。CA 证书是签署其他证书的证书，终端实体证书是例如在网页中使用的证书（链的最后一部分）。
* **主体密钥标识符**（SKI）：此扩展声明证书中公钥的唯一**标识符**。所有 CA 证书都需要它。CA 将自己的 SKI 传播到已颁发证书的颁发者**密钥标识符**（AKI）扩展中。它是主体公钥的哈希值。
* **Authority Key Identifier**（AKI）：它包含一个从颁发者证书中的公钥派生出的密钥标识符。它是颁发者公钥的哈希值。
* **Authority Information Access**（AIA）：该扩展最多包含两种类型的信息：
* 关于**如何获取此证书的颁发者**的信息（CA颁发者访问方法）
* 可以检查此证书吊销的**OCSP响应者的地址**（OCSP访问方法）。
* **CRL分发点**：此扩展标识了可以检查此证书吊销的CRL的位置。处理证书的应用程序可以从此扩展中获取CRL的位置，下载CRL，然后检查此证书的吊销情况。
* **CT预证书SCT**：关于证书的证书透明性日志

### OCSP和CRL分发点的区别

**OCSP**（RFC 2560）是一个标准协议，由**OCSP客户端和OCSP响应者**组成。该协议**确定给定数字公钥证书的吊销状态**，而无需**下载**整个CRL。\
**CRL**是检查证书有效性的**传统方法**。**CRL提供了已吊销或不再有效的证书序列号列表**。CRL允许验证者在验证证书时检查所呈现证书的吊销状态。CRL的条目数限制为512个。\
来源：[这里](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm)。

### 什么是证书透明性

证书透明性旨在通过使SSL证书的颁发和存在对域所有者、CA和域用户进行公开审查来解决基于证书的威胁。具体而言，证书透明性有三个主要目标：

* 使CA**无法在未被该域的所有者**看到的情况下**为该域颁发SSL证书**，或者至少非常困难。
* 提供一个**开放的审计和监控系统**，让任何域所有者或CA确定证书是否被错误或恶意颁发。
* **尽可能地保护用户**免受错误或恶意颁发的证书的欺骗。

#### **证书日志**

证书日志是简单的网络服务，用于维护**具有密码学保证、可公开审计、仅追加记录的证书**。**任何人都可以向日志提交证书**，尽管证书颁发机构可能是最主要的提交者。同样，任何人都可以查询日志以获取密码学证明，用于验证日志的行为是否正确或验证特定证书是否已被记录。日志服务器的数量不必很大（比如全球不到一千个），每个服务器可以由CA、ISP或任何其他感兴趣的方运营。

#### 查询

您可以查询[https://crt.sh/](https://crt.sh)上任何域的证书透明性日志。

## 格式

有不同的格式可用于存储证书。

#### **PEM格式**

* 这是最常用的证书格式
* 大多数服务器（例如：Apache）期望证书和私钥分别存储在不同的文件中\
\- 通常它们是Base64编码的ASCII文件\
\- 用于PEM证书的扩展名为.cer、.crt、.pem、.key文件\
\- Apache和类似的服务器使用PEM格式证书

#### **DER格式**

* DER格式是证书的二进制形式
* 所有类型的证书和私钥都可以编码为DER格式
* DER格式的证书不包含“BEGIN CERTIFICATE/END CERTIFICATE”语句
* DER格式的证书通常使用“.cer”和“.der”扩展名
* DER通常用于Java平台

#### **P7B/PKCS#7格式**

* PKCS#7或P7B格式以Base64 ASCII格式存储，并具有.p7b或.p7c文件扩展名
* P7B文件仅包含证书和链证书（中间CA），不包含私钥
* 支持P7B文件的最常见平台是Microsoft Windows和Java Tomcat

#### **PFX/P12/PKCS#12格式**

* PKCS#12或PFX/P12格式是一种二进制格式，用于将服务器证书、中间证书和私钥存储在一个可加密文件中
* 这些文件通常具有.pfx和.p12等扩展名
* 它们通常用于Windows机器上导入和导出证书和私钥

### 格式转换

**将x509转换为PEM**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **将PEM转换为DER**

To convert a PEM (Privacy-Enhanced Mail) certificate file to DER (Distinguished Encoding Rules) format, you can use the OpenSSL command-line tool. The DER format is a binary representation of the certificate, while the PEM format is a base64-encoded ASCII representation.

To perform the conversion, use the following command:

```plaintext
openssl x509 -in certificate.pem -outform der -out certificate.der
```

Replace `certificate.pem` with the path to your PEM certificate file, and `certificate.der` with the desired output file name for the DER format.

After executing the command, you will have a DER format certificate file that can be used in various cryptographic applications.
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
**将DER转换为PEM**

要将DER格式的证书转换为PEM格式，可以使用以下命令：

```bash
openssl x509 -inform der -in certificate.der -out certificate.pem
```

这将把名为`certificate.der`的DER证书转换为PEM格式，并将其保存为`certificate.pem`文件。
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**将PEM转换为P7B**

**注意：** PKCS#7或P7B格式以Base64 ASCII格式存储，并具有.p7b或.p7c的文件扩展名。P7B文件仅包含证书和链证书（中间CA），而不包含私钥。支持P7B文件的最常见平台是Microsoft Windows和Java Tomcat。
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**将PKCS7转换为PEM格式**

To convert a PKCS7 file to PEM format, you can use the OpenSSL command-line tool. Here's the command you can use:

```plaintext
openssl pkcs7 -print_certs -in input.p7b -out output.pem
```

Replace `input.p7b` with the path to your PKCS7 file and `output.pem` with the desired name and path for the PEM file.

使用OpenSSL命令行工具可以将PKCS7文件转换为PEM格式。以下是您可以使用的命令：

```plaintext
openssl pkcs7 -print_certs -in input.p7b -out output.pem
```

将`input.p7b`替换为您的PKCS7文件的路径，将`output.pem`替换为PEM文件的所需名称和路径。
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**将pfx转换为PEM**

**注意：** PKCS#12或PFX格式是一种二进制格式，用于将服务器证书、中间证书和私钥存储在一个可加密的文件中。PFX文件通常具有.pfx和.p12等扩展名。PFX文件通常用于Windows机器上导入和导出证书和私钥。
```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
**将PFX转换为PKCS#8**\
**注意：**这需要2个命令

**1- 将PFX转换为PEM**
```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
**2- 将PEM转换为PKCS8**

To convert a PEM (Privacy-Enhanced Mail) formatted file to PKCS8 (Public-Key Cryptography Standards #8) format, you can use the OpenSSL command-line tool.

使用OpenSSL命令行工具可以将PEM（Privacy-Enhanced Mail）格式的文件转换为PKCS8（Public-Key Cryptography Standards #8）格式。

```plaintext
openssl pkcs8 -topk8 -inform PEM -outform PEM -in private_key.pem -out private_key_pkcs8.pem
```

Replace `private_key.pem` with the path to your PEM file, and `private_key_pkcs8.pem` with the desired output file name for the PKCS8 formatted key.

将`private_key.pem`替换为您的PEM文件的路径，将`private_key_pkcs8.pem`替换为PKCS8格式密钥的所需输出文件名。

This command will convert the private key in the PEM file to PKCS8 format and save it in the specified output file.

该命令将把PEM文件中的私钥转换为PKCS8格式，并将其保存在指定的输出文件中。
```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
**将P7B转换为PFX**\
**注意：**这需要2个命令

1- **将P7B转换为CER**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
**2- 将CER证书和私钥转换为PFX格式**

To convert a CER certificate and its corresponding private key to PFX format, you can use the OpenSSL tool. The PFX format is commonly used for storing both the certificate and private key in a single file.

Here is the command to perform the conversion:

```plaintext
openssl pkcs12 -export -out certificate.pfx -inkey privatekey.key -in certificate.cer
```

Replace `privatekey.key` with the path to your private key file and `certificate.cer` with the path to your CER certificate file. The resulting PFX file will be named `certificate.pfx`.

During the conversion process, you will be prompted to set a password for the PFX file. Make sure to choose a strong password and keep it secure.

After the conversion is complete, you can use the PFX file for various purposes, such as importing it into a web server or using it for client authentication.
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
![](<../.gitbook/assets/image (9) (1) (2).png>)

使用[**Trickest**](https://trickest.io/)轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
