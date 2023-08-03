# AD CS域持久性

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## 使用窃取的CA证书伪造证书 - DPERSIST1

如何判断证书是否为CA证书？

* CA证书存在于**CA服务器本身**上，其**私钥由机器DPAPI保护**（除非操作系统使用TPM/HSM/其他硬件进行保护）。
* 证书的**颁发者**和**主题**都设置为**CA的可分辨名称**。
* CA证书（仅限CA证书）**具有“CA版本”扩展**。
* 没有**扩展密钥用途（EKUs）**。

内置的GUI支持的方法来**提取此证书的私钥**是在CA服务器上使用`certsrv.msc`。\
然而，这个证书与系统中存储的其他证书**没有区别**，所以例如可以查看[**THEFT2技术**](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)来了解如何**提取**它们。

您还可以使用[**certipy**](https://github.com/ly4k/Certipy)获取证书和私钥：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
一旦你拥有了以 `.pfx` 格式保存的 **CA 证书**和私钥，你可以使用 [**ForgeCert**](https://github.com/GhostPack/ForgeCert) 来创建有效的证书：
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
**注意**：在伪造证书时，目标**用户**需要在AD中处于**活动/启用**状态并且能够进行身份验证，因为身份验证交换仍将以该用户的身份进行。例如，试图伪造krbtgt帐户的证书将不起作用。
{% endhint %}

这个伪造的证书将在指定的结束日期之前**有效**，并且只要根CA证书有效（通常为5到**10+年**）。它也适用于**机器**，因此结合**S4U2Self**，攻击者可以在CA证书有效的情况下**在任何域机器上保持持久性**。\
此外，使用此方法生成的**证书无法撤销**，因为CA不知道它们的存在。

## 信任恶意CA证书 - DPERSIST2

对象`NTAuthCertificates`在其`cacertificate`**属性**中定义了一个或多个**CA证书**，AD在使用它时：在身份验证期间，**域控制器**会检查**`NTAuthCertificates`**对象是否包含用于认证**证书**的发行者字段中指定的**CA**的条目。如果**是的，身份验证将继续进行**。

攻击者可以生成一个**自签名的CA证书**并将其添加到**`NTAuthCertificates`**对象中。如果攻击者对**`NTAuthCertificates`**AD对象具有**控制权**（在默认配置中，只有**企业管理员**组成员和**域管理员**或**管理员**在**森林根域**中的成员具有这些权限），则可以执行此操作。通过提升的访问权限，可以使用`certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`从任何系统编辑**`NTAuthCertificates`**对象，或使用[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)。

指定的证书应该与之前详细介绍的伪造方法**ForgeCert**一起使用，以便根据需要生成证书。

## 恶意配置错误 - DPERSIST3

通过对AD CS组件的**安全描述符修改**，可以利用各种机会进行**持久性**。在“[域升级](domain-escalation.md)”部分中描述的任何场景都可以由具有提升访问权限的攻击者恶意实施，以及向敏感组件添加“控制权限”（即WriteOwner/WriteDACL等）。这包括：

* **CA服务器的AD计算机**对象
* **CA服务器的RPC/DCOM服务器**
* 容器**`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`**中的任何**后代AD对象或容器**（例如，证书模板容器、证书颁发机构容器、NTAuthCertificates对象等）
* **默认情况下或当前组织**授予控制AD CS权限的**AD组**（例如，内置的Cert Publishers组及其任何成员）

例如，具有域中的**提升权限**的攻击者可以将**`WriteOwner`**权限添加到默认的**`User`**证书模板中，其中攻击者是该权限的主体。为了在以后滥用此权限，攻击者首先会将**`User`**模板的所有权修改为自己，然后将模板上的**`mspki-certificate-name-flag`**设置为**1**，以启用**`ENROLLEE_SUPPLIES_SUBJECT`**（即允许用户在请求中提供替代名称）。然后，攻击者可以在模板中**注册**，指定一个**域管理员**名称作为替代名称，并使用生成的证书进行身份验证。

## 参考资料

* 此页面的所有信息均来自[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
