# AD CS 域持久性

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)** 上**关注我。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

**这是在 [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf) 中分享的域持久性技术摘要**。查看以获取更多详细信息。

## 使用窃取的 CA 证书伪造证书 - DPERSIST1

如何判断证书是否为 CA 证书？

可以通过以下几个条件来确定证书是否为 CA 证书：

- 证书存储在 CA 服务器上，其私钥由机器的 DPAPI 或硬件（如 TPM/HSM，如果操作系统支持）保护。
- 证书的颁发者和主题字段与 CA 的专有名称匹配。
- CA 证书中独占地存在“CA 版本”扩展。
- 证书缺少扩展密钥用途（EKU）字段。

要提取此证书的私钥，CA 服务器上的 `certsrv.msc` 工具是通过内置 GUI 支持的方法。然而，此证书与系统中存储的其他证书无异；因此，可以应用诸如[THEFT2 技术](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)以进行提取。

还可以使用 Certipy 获取证书和私钥，命令如下：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
在获取了以 `.pfx` 格式保存的 CA 证书及其私钥后，可以利用 [ForgeCert](https://github.com/GhostPack/ForgeCert) 等工具生成有效的证书：
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
针对证书伪造的用户必须是活跃的并且能够在Active Directory中进行身份验证，才能成功进行该过程。对于像krbtgt这样的特殊帐户伪造证书是无效的。
{% endhint %}

这个伪造的证书将**有效**直到指定的结束日期，并且只要根CA证书有效（通常为5到**10年以上**）。它也适用于**机器**，因此结合**S4U2Self**，攻击者可以在CA证书有效的情况下在任何域机器上**保持持久性**。\
此外，使用此方法生成的**证书**是**无法吊销**的，因为CA不知道它们的存在。

## 信任恶意CA证书 - DPERSIST2

`NTAuthCertificates`对象被定义为包含一个或多个**CA证书**的对象，Active Directory（AD）使用其中的`cacertificate`属性。域控制器的验证过程涉及检查`NTAuthCertificates`对象，以查找与认证**证书**的Issuer字段中指定的**CA**匹配的条目。如果找到匹配项，则进行身份验证。

攻击者可以将自签名的CA证书添加到`NTAuthCertificates`对象中，前提是他们控制了这个AD对象。通常，只有**企业管理员**组的成员，以及**域管理员**或**林根域的管理员**被授予权限修改此对象。他们可以使用`certutil.exe`命令`certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`编辑`NTAuthCertificates`对象，或者使用[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)。

当与先前概述的使用ForgeCert动态生成证书的方法结合使用时，这种能力尤为重要。

## 恶意配置错误 - DPERSIST3

通过对AD CS组件的安全描述符进行修改，攻击者有很多机会实现**持久性**。在"[域提升](domain-escalation.md)"部分描述的修改可以被具有提升访问权限的攻击者恶意实施。这包括向敏感组件（例如**CA服务器的AD计算机**对象、**CA服务器的RPC/DCOM服务器**、**`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`**中的任何后代AD对象或容器（例如证书模板容器、证书颁发机构容器、NTAuthCertificates对象等）、默认或组织授予控制AD CS权限的**AD组**（例如内置的Cert Publishers组及其任何成员））添加“控制权限”（例如WriteOwner/WriteDACL等）的权限。

恶意实施的一个例子可能涉及在域中具有**提升权限**的攻击者向默认的**`User`**证书模板添加**`WriteOwner`**权限，攻击者成为权限的主体。为了利用这一点，攻击者首先会将**`User`**模板的所有权更改为自己。随后，将模板上的**`mspki-certificate-name-flag`**设置为**1**，以启用**`ENROLLEE_SUPPLIES_SUBJECT`**，允许用户在请求中提供主题备用名称。随后，攻击者可以使用**模板**进行**注册**，选择一个**域管理员**名称作为备用名称，并利用获得的证书进行DA身份验证。
