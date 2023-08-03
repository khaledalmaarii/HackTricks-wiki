# AD CS 账户持久性

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想要**获取 PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享你的黑客技巧**。

</details>

## 通过证书窃取活动用户凭据 - PERSIST1

如果用户被允许请求一个允许域身份验证的证书，攻击者可以**请求**并**窃取**它以**保持****持久性**。

**`User`** 模板允许这样做，并且默认情况下存在。然而，它可能被禁用。因此，[**Certify**](https://github.com/GhostPack/Certify) 允许你找到有效的证书以实现持久性：
```
Certify.exe find /clientauth
```
请注意，只要证书有效，即使用户更改了密码，证书仍可用于对该用户进行身份验证。

可以使用`certmgr.msc`在**GUI**中请求证书，也可以使用`certreq.exe`通过命令行请求证书。

使用[**Certify**](https://github.com/GhostPack/Certify)，您可以运行：
```
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
结果将是一个以`.pem`格式的文本块，其中包含**证书**和**私钥**。
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
要**使用该证书**，可以将`.pfx`上传到目标主机，并使用[Rubeus](https://github.com/GhostPack/Rubeus)来为已注册用户**请求TGT**，只要证书有效（默认有效期为1年）：
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
{% hint style="warning" %}
结合[**THEFT5**](certificate-theft.md#ntlm-credential-theft-via-pkinit-theft5)部分中概述的技术，攻击者还可以持久地**获取账户的NTLM哈希**，攻击者可以使用该哈希通过**传递哈希**或**破解**来获取**明文密码**。\
这是一种**长期凭证窃取**的替代方法，不会触及LSASS，并且可以在**非提升的上下文**中实现。
{% endhint %}

## 通过证书实现机器持久性 - PERSIST2

如果证书模板允许**域计算机**作为注册主体，攻击者可以**注册一个受损系统的机器账户**。默认的**`Machine`**模板符合所有这些特征。

如果攻击者在受损系统上提升了权限，攻击者可以使用**SYSTEM**账户来注册授予机器账户注册权限的证书模板（更多信息请参见[**THEFT3**](certificate-theft.md#machine-certificate-theft-via-dpapi-theft3)）。

您可以使用[**Certify**](https://github.com/GhostPack/Certify)自动将机器账户提升为SYSTEM来收集证书：
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
请注意，通过获取机器账户证书，攻击者可以作为机器账户进行**Kerberos身份验证**。使用**S4U2Self**，攻击者可以获取主机上任何服务（如CIFS、HTTP、RPCSS等）的**Kerberos服务票据**，并冒充任何用户。

最终，这为攻击者提供了一种机器持久性方法。

## 通过证书续订实现账户持久性 - PERSIST3

证书模板具有**有效期**，确定已发行证书的使用期限，以及**续订期**（通常为6周）。这是在证书**到期之前**的一段时间内，账户可以从颁发证书机构**续订证书**的窗口。

如果攻击者通过盗窃或恶意注册获得了能够进行域身份验证的证书，攻击者可以在证书的有效期内**对AD进行身份验证**。然而，攻击者可以在证书到期之前**续订证书**。这可以作为一种**延长的持久性**方法，**防止请求额外票据**，从而**可能在CA服务器本身上留下痕迹**。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
