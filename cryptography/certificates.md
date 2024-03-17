# 证书

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，并由全球**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 什么是证书

**公钥证书**是密码学中使用的数字身份证，用于证明某人拥有公钥。它包括密钥的详细信息、所有者的身份（主体）以及来自受信任机构（签发者）的数字签名。如果软件信任签发者并且签名有效，则可以与密钥所有者进行安全通信。

证书通常由[证书颁发机构](https://en.wikipedia.org/wiki/Certificate\_authority)（CAs）在[公钥基础设施](https://en.wikipedia.org/wiki/Public-key\_infrastructure)（PKI）设置中颁发。另一种方法是[信任网络](https://en.wikipedia.org/wiki/Web\_of\_trust)，用户直接验证彼此的密钥。证书的常见格式是[X.509](https://en.wikipedia.org/wiki/X.509)，可以根据RFC 5280中概述的特定需求进行调整。

## x509常见字段

### **x509证书中的常见字段**

在x509证书中，几个**字段**在确保证书的有效性和安全性方面起着关键作用。以下是这些字段的详细信息：

* **版本号**表示x509格式的版本。
* **序列号**在证书颁发机构（CA）系统中唯一标识证书，主要用于吊销跟踪。
* **主体**字段代表证书的所有者，可以是机器、个人或组织。它包括详细的标识，如：
* **通用名称（CN）**：证书涵盖的域。
* **国家（C）**、**地点（L）**、**州或省（ST、S或P）**、**组织（O）**和**组织单位（OU）**提供地理和组织详细信息。
* **可分辨名称（DN）**封装了完整的主体标识。
* **签发者**详细说明了谁验证并签署了证书，包括与CA的主体类似的子字段。
* **有效期**由**Not Before**和**Not After**时间戳标记，确保证书在特定日期之前或之后不被使用。
* **公钥**部分对证书的安全性至关重要，指定了公钥的算法、大小和其他技术细节。
* **x509v3扩展**增强了证书的功能，指定了**密钥用途**、**扩展密钥用途**、**主体替代名称**和其他属性，以微调证书的应用。

#### **密钥用途和扩展**

* **密钥用途**标识公钥的加密应用，如数字签名或密钥加密。
* **扩展密钥用途**进一步缩小了证书的用途范围，例如用于TLS服务器身份验证。
* **主体替代名称**和**基本约束**定义了证书涵盖的附加主机名以及它是CA还是终端实体证书。
* **主体密钥标识符**和**颁发者密钥标识符**确保密钥的唯一性和可追溯性。
* **颁发者信息访问**和**CRL分发点**提供了验证颁发CA和检查证书吊销状态的路径。
* **CT预证书SCTs**提供透明日志，对证书的公共信任至关重要。
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **OCSP和CRL分发点的区别**

**OCSP**（**RFC 2560**）涉及客户端和响应者共同工作，检查数字公钥证书是否已被吊销，无需下载完整的**CRL**。这种方法比传统的**CRL**更高效，后者提供了吊销证书序列号列表，但需要下载一个可能很大的文件。CRL可以包含多达512个条目。更多详细信息请参阅[此处](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm)。

### **什么是证书透明度**

证书透明度通过确保SSL证书的签发和存在对域所有者、CA和用户可见，有助于防范与证书相关的威胁。其目标包括：

* 防止CA未经域所有者知情为域签发SSL证书。
* 建立一个用于跟踪错误或恶意签发证书的开放审计系统。
* 保护用户免受欺诈证书的侵害。

#### **证书日志**

证书日志是由网络服务维护的公开可审计的、仅追加记录证书的记录。这些日志为审计目的提供了加密证据。签发机构和公众都可以向这些日志提交证书或查询以进行验证。虽然日志服务器的确切数量不固定，但全球预计不会超过一千个。这些服务器可以由CA、ISP或任何感兴趣的实体独立管理。

#### **查询**

要查看任何域的证书透明度日志，请访问[https://crt.sh/](https://crt.sh)。

存在不同格式用于存储证书，每种格式都有其自己的用例和兼容性。本摘要涵盖了主要格式并提供了在它们之间转换的指导。

## **格式**

### **PEM格式**

* 证书最广泛使用的格式。
* 需要单独的文件用于证书和私钥，编码为Base64 ASCII。
* 常见扩展名：.cer、.crt、.pem、.key。
* 主要由Apache和类似服务器使用。

### **DER格式**

* 证书的二进制格式。
* 不包含在PEM文件中找到的“BEGIN/END CERTIFICATE”语句。
* 常见扩展名：.cer、.der。
* 通常与Java平台一起使用。

### **P7B/PKCS#7格式**

* 以Base64 ASCII存储，扩展名为.p7b或.p7c。
* 仅包含证书和链证书，不包括私钥。
* 受Microsoft Windows和Java Tomcat支持。

### **PFX/P12/PKCS#12格式**

* 将服务器证书、中间证书和私钥封装在一个文件中的二进制格式。
* 扩展名：.pfx、.p12。
* 主要用于Windows上的证书导入和导出。

### **格式转换**

**PEM转换**对于兼容性至关重要：

* **x509转为PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM to DER**  
  * **PEM转DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER转PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM to P7B**  
  * **PEM转P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **将PKCS7转换为PEM格式**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX 转换**对于在 Windows 上管理证书至关重要：

- **PFX 到 PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX to PKCS#8** 包括两个步骤：
1. 将 PFX 转换为 PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. 将PEM转换为PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B转PFX**也需要两个命令：
1. 将P7B转换为CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. 将CER证书和私钥转换为PFX格式

```bash
openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.cer
```
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建并由全球**最先进**的社区工具驱动的**自动化工作流程**。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
