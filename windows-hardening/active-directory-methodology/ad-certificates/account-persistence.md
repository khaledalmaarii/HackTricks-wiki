# AD CS 账户持久性

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** 上**关注我们。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

**这是来自[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)出色研究中机器持久性章节的简要总结**


## **使用证书理解活动用户凭据窃取 - PERSIST1**

在一个场景中，用户可以请求一个允许域认证的证书，攻击者有机会**请求**和**窃取**这个证书以在网络上**保持持久性**。默认情况下，Active Directory 中的 `User` 模板允许这样的请求，尽管有时可能会被禁用。

使用名为 [**Certify**](https://github.com/GhostPack/Certify) 的工具，可以搜索有效的证书，从而实现持久访问：
```bash
Certify.exe find /clientauth
```
强调证书的力量在于其能够**作为所属用户**进行身份验证，而不受任何密码更改的影响，只要证书保持**有效**。

可以通过图形界面使用`certmgr.msc`或通过命令行使用`certreq.exe`来请求证书。使用**Certify**，请求证书的过程简化如下：
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
成功请求后，将生成一个带有私钥的证书，格式为`.pem`。要将其转换为可在Windows系统上使用的`.pfx`文件，使用以下命令：
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
`.pfx` 文件随后可以上传到目标系统，并与名为 [**Rubeus**](https://github.com/GhostPack/Rubeus) 的工具一起使用，以请求用户的票据授予票据 (TGT)，从而延长攻击者的访问权限，直到证书失效（通常为一年）:
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
## **使用证书获得机器持久性 - PERSIST2**

另一种方法涉及为受损系统的机器账户注册证书，利用默认的`Machine`模板允许此类操作。如果攻击者在系统上获得了提升的特权，他们可以使用**SYSTEM**账户请求证书，提供一种**持久性**的形式：
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
这种访问权限使攻击者能够作为机器帐户进行Kerberos身份验证，并利用S4U2Self获取主机上任何服务的Kerberos服务票据，有效地授予攻击者对机器的持久访问。

## 通过证书更新延长持久性 - PERSIST3

讨论的最后一种方法涉及利用证书模板的**有效性**和**更新周期**。通过在证书到期之前对证书进行**更新**，攻击者可以在不需要额外票据注册的情况下保持对Active Directory的身份验证，这可能会在证书颁发机构（CA）服务器上留下痕迹。

这种方法允许一种**延长的持久性**方法，通过与CA服务器的互动减少，避免生成可能提醒管理员入侵的工件。
