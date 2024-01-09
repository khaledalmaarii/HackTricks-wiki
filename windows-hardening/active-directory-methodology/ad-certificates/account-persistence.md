# AD CS 账户持久性

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零到英雄学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 通过证书实现活跃用户凭证盗窃 – PERSIST1

如果用户被允许请求允许域认证的证书，攻击者可以**请求**并**窃取**它以**维持** **持久性**。

**`User`** 模板默认允许这样做。然而，它可能被禁用。因此，[**Certify**](https://github.com/GhostPack/Certify) 可以帮助您找到有效的证书来保持持久性：
```
Certify.exe find /clientauth
```
请注意，只要证书**有效**，即使用户**更改**了他们的**密码**，也可以使用**证书进行身份验证**。

从**图形用户界面**，可以使用 `certmgr.msc` 请求证书，或者通过命令行使用 `certreq.exe`。

使用 [**Certify**](https://github.com/GhostPack/Certify) 你可以运行：
```
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
结果将是一个**证书** + **私钥** `.pem` 格式的文本块
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
要**使用该证书**，可以将 `.pfx` **上传**到目标上，并使用 [**Rubeus**](https://github.com/GhostPack/Rubeus) 来**请求**已注册用户的 TGT，只要证书有效（默认有效期为1年）：
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
{% hint style="warning" %}
结合在[**THEFT5**](certificate-theft.md#ntlm-credential-theft-via-pkinit-theft5)部分概述的技术，攻击者还可以持久地**获取账户的NTLM哈希值**，攻击者可以使用该哈希值通过**pass-the-hash**或**破解**来获取**明文** **密码**。\
这是一种**长期凭证盗窃**的替代方法，它**不接触LSASS**，并且可以在**非提升的上下文中**实现。
{% endhint %}

## 通过证书实现机器持久性 - PERSIST2

如果证书模板允许**域计算机**作为注册主体，攻击者可以**注册被攻陷系统的机器账户**。默认的**`Machine`**模板符合所有这些特征。

如果**攻击者在被攻陷的系统上提升权限**，攻击者可以使用**SYSTEM**账户注册授予机器账户注册权限的证书模板（更多信息见[**THEFT3**](certificate-theft.md#machine-certificate-theft-via-dpapi-theft3)）。

你可以使用[**Certify**](https://github.com/GhostPack/Certify)来自动提升到SYSTEM，为机器账户收集证书：
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
请注意，一旦攻击者获取了机器账户证书，他们就可以**以机器账户的身份对 Kerberos 进行认证**。使用 **S4U2Self**，攻击者接着可以获取**对主机上任何服务的 Kerberos 服务票据**（例如 CIFS、HTTP、RPCSS 等），并且可以作为任何用户。

最终，这为攻击者提供了一种机器持久性方法。

## 通过证书续期实现账户持久性 - PERSIST3

证书模板有一个**有效期**，用于确定已发行证书的使用时长，以及一个**续期期限**（通常为6周）。这是一个**在证书**到期**之前**，**账户可以从颁发证书的权威机构续期的时间窗口**。

如果攻击者通过盗窃或恶意注册，攻破了能够进行域认证的证书，攻击者可以**在证书的有效期内对 AD 进行认证**。然而，攻击者可以**在证书到期前续期**。这可以作为一种**延长持久性**的方法，**防止请求额外的票据**注册，这**可能会在 CA 服务器本身留下痕迹**。

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方的 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
