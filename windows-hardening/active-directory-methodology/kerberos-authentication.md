# Kerberos身份验证

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

**此信息摘自文章：**[**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Kerberos（I）：Kerberos是如何工作的？- 理论

2019年3月20日 - ELOY PÉREZ

这一系列文章的目标是澄清Kerberos的工作原理，而不仅仅是介绍攻击技术。这是因为在许多情况下，为什么某些技术有效或无效并不清楚。了解这些知识可以让我们知道何时在渗透测试中使用这些攻击之一。

因此，在长时间的文档研究和关于该主题的几篇文章之后，我们试图在本文中写出所有重要细节，以便审计人员能够理解如何利用Kerberos协议。

在本文中，只讨论基本功能。在以后的文章中，将介绍如何执行攻击以及更复杂的方面，如委派。

如果对未解释清楚的主题有任何疑问，请随时留下评论或提问。现在，进入主题。

### 什么是Kerberos？

首先，Kerberos是一种身份验证协议，而不是授权协议。换句话说，它允许识别每个用户，用户提供一个秘密密码，但它不验证该用户可以访问哪些资源或服务。

Kerberos在Active Directory中使用。在这个平台上，Kerberos提供有关每个用户特权的信息，但确定用户是否可以访问其资源是每个服务的责任。

### Kerberos组件

本节将研究Kerberos环境的几个组件。

**传输层**

Kerberos使用UDP或TCP作为传输协议，以明文发送数据。因此，Kerberos负责提供加密。

Kerberos使用的端口是UDP/88和TCP/88，这些端口应该在KDC（下一节中解释）上监听。

**代理**

多个代理共同工作以提供Kerberos中的身份验证。它们是：

* **客户端或用户**，希望访问服务的用户。
* **AP**（应用程序服务器），提供用户所需的服务。
* **KDC**（密钥分发中心），Kerberos的主要服务，负责发行票证，安装在DC（域控制器）上。它由**AS**（认证服务）支持，AS发行TGT。

**加密密钥**

Kerberos处理多个结构，如票证。这些结构中的许多是加密或签名的，以防止被第三方篡改。这些密钥包括：

* **KDC或krbtgt密钥**，派生自krbtgt帐户的NTLM哈希。
* **用户密钥**，派生自用户的NTLM哈希。
* **服务密钥**，派生自服务所有者的NTLM哈希，可以是用户或计算机帐户。
* **会话密钥**，在用户和KDC之间协商。
* **服务会话密钥**，在用户和服务之间使用。

**票证**

Kerberos处理的主要结构是票证。这些票证交付给用户，以便用户在Kerberos领域中执行多个操作。有两种类型：

* **TGS**（票证授予服务）是用户可以用来对服务进行身份验证的票证。它使用服务密钥进行加密。
* **TGT**（票证授予票证）是提交给KDC以请求TGS的票证。它使用KDC密钥进行加密。

**PAC**

**PAC**（特权属性证书）是几乎每个票证中包含的结构。此结构包含用户的特权，并使用KDC密钥进行签名。

服务可以通过与KDC通信来验证PAC，尽管这种情况并不经常发生。然而，PAC验证仅包括检查其签名，而不检查PAC内部的特权是否正确。

此外，客户端可以通过在票证请求的_KERB-PA-PAC-REQUEST_字段中指定来避免将PAC包含在票证中。

**消息**

Kerberos使用不同类型的消息。最有趣的是以下几种：

* **KRB\_AS\_REQ**：用于向KDC请求TGT。
* **KRB\_AS\_REP**：由KDC交付TGT使用。
* **KRB\_TGS\_REQ**：使用TGT向KDC请求TGS。
* **KRB\_TGS\_REP**：由KDC交付TGS使用。
* **KRB\_AP\_REQ**：使用TGS对用户进行身份验证。
* **KRB\_AP\_REP**：（可选）由服务用于对用户进行身份验证。
* **KRB\_ERROR**：用于通信错误条件的消息。

此外，即使它不是Kerberos的一部分，但是NRPC，AP还可以使用**KERB\_VERIFY\_PAC\_REQUEST**消息向KDC发送PAC的签名，并验证其是否正确。

下面是执行身份验证的消息序列的摘要

![Kerberos消息摘要](<../../.gitbook/assets/image (174) (1).png>)
### 认证过程

在本节中，将研究执行认证所需的消息序列，从没有票证的用户开始，直到对所需服务进行身份验证。

**KRB\_AS\_REQ**

首先，用户必须从KDC获取TGT。为此，必须发送一个KRB\_AS\_REQ：

![KRB\_AS\_REQ消息结构图](<../../.gitbook/assets/image (175) (1).png>)

_KRB\_AS\_REQ_包含以下字段之一：

* 使用客户端密钥加密的**时间戳**，用于验证用户身份并防止重放攻击
* 已验证用户的**用户名**
* 与**krbtgt**帐户关联的服务**SPN**
* 用户生成的**Nonce**

注意：只有在用户需要预身份验证时，才需要加密时间戳，这是常见情况，除非在用户帐户中设置了[_DONT\_REQ\_PREAUTH_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro)标志。

**KRB\_AS\_REP**

收到请求后，KDC通过解密时间戳来验证用户身份。如果消息正确，则必须用_KRB\_AS\_REP_进行响应：

![KRB\_AS\_REP消息结构图](<../../.gitbook/assets/image (176) (1).png>)

_KRB\_AS\_REP_包括以下信息：

* **用户名**
* **TGT**，其中包括：
* **用户名**
* **会话密钥**
* **TGT的过期日期**
* 由KDC签名的具有用户特权的**PAC**
* 使用用户密钥加密的一些**加密数据**，其中包括：
* **会话密钥**
* **TGT的过期日期**
* 用于防止重放攻击的用户**Nonce**

完成后，用户已经拥有了TGT，可以用它来请求TGS，然后访问服务。

**KRB\_TGS\_REQ**

为了请求TGS，必须向KDC发送一个_KRB\_TGS\_REQ_消息：

![KRB\_TGS\_REQ消息结构图](<../../.gitbook/assets/image (177).png>)

_KRB\_TGS\_REQ_包括：

* 使用会话密钥的**加密数据**：
* **用户名**
* **时间戳**
* **TGT**
* 所请求服务的**SPN**
* 用户生成的**Nonce**

**KRB\_TGS\_REP**

收到_KRB\_TGS\_REQ_消息后，KDC返回一个包含TGS的_KRB\_TGS\_REP_：

![KRB\_TGS\_REP消息结构图](<../../.gitbook/assets/image (178) (1).png>)

_KRB\_TGS\_REP_包括：

* **用户名**
* **TGS**，其中包含：
* **服务会话密钥**
* **用户名**
* **TGS的过期日期**
* 由KDC签名的具有用户特权的**PAC**
* 使用会话密钥的**加密数据**：
* **服务会话密钥**
* **TGS的过期日期**
* 用于防止重放攻击的用户**Nonce**

**KRB\_AP\_REQ**

最后，如果一切顺利，用户已经拥有有效的TGS以与服务进行交互。为了使用它，用户必须向AP发送一个_KRB\_AP\_REQ_消息：

![KRB\_AP\_REQ消息结构图](<../../.gitbook/assets/image (179) (1).png>)

_KRB\_AP\_REQ_包括：

* **TGS**
* 使用服务会话密钥的**加密数据**：
* **用户名**
* **时间戳**，以避免重放攻击

之后，如果用户权限正确，就可以访问服务。如果是这种情况（通常不会发生），AP将根据KDC验证PAC，并在需要相互认证时向用户响应一个_KRB\_AP\_REP_消息。

### 参考资料

* Kerberos v5 RFC: [https://tools.ietf.org/html/rfc4120](https://tools.ietf.org/html/rfc4120)
* \[MS-KILE\] – Kerberos扩展: [https://msdn.microsoft.com/en-us/library/cc233855.aspx](https://msdn.microsoft.com/en-us/library/cc233855.aspx)
* \[MS-APDS\] – 认证协议域支持: [https://msdn.microsoft.com/en-us/library/cc223948.aspx](https://msdn.microsoft.com/en-us/library/cc223948.aspx)
* Mimikatz和Active Directory Kerberos攻击: [https://adsecurity.org/?p=556](https://adsecurity.org/?p=556)
* 用5岁孩子的语言解释Kerberos: [https://www.roguelynn.com/words/explain-like-im-5-kerberos/](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
* Kerberos和KRBTGT: [https://adsecurity.org/?p=483](https://adsecurity.org/?p=483)
* 掌握Windows网络取证和调查，第2版。作者：S. Anson，S. Bunting，R. Johnson和S. Pearson。出版社Sibex。
* Active Directory，第5版。作者：B. Desmond，J. Richards，R. Allen和A.G. Lowe-Norris
* 服务主体名称：[https://msdn.microsoft.com/en-us/library/ms677949(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/ms677949\(v=vs.85\).aspx)
* Active Directory的功能级别：[https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0](https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0)
* OverPass The Hash – Gentilkiwi博客: [https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash](https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash)
* Pass The Ticket – Gentilkiwi博客: [https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos](https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos)
* Golden Ticket – Gentilkiwi博客: [https://blog.gentilkiwi.com/securite/mimikatz/golden-ticket-kerberos](https://blog.gentilkiwi.com/securite/mimikatz/golden-ticket-kerberos)
* Mimikatz Golden Ticket Walkthrough: [https://www.beneaththewaves.net/Projects/Mimikatz\_20\_-\_Golden\_Ticket\_Walkthrough.html](https://www.beneaththewaves.net/Projects/Mimikatz\_20\_-\_Golden\_Ticket\_Walkthrough.html)
* 攻击Kerberos: 踢开冥界的守卫犬: [https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf](https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin\(1\).pdf)
* Kerberoasting – Part 1: [https://room362.com/post/2016/kerberoast-pt1/](https://room362.com/post/2016/kerberoast-pt1/)
* Kerberoasting – Part 2: [https://room362.com/post/2016/kerberoast-pt2/](https://room362.com/post/2016/kerberoast-pt2/)
* 烤AS-REPs：[https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
* PAC验证：[https://passing-the-hash.blogspot.com.es/2014/09/pac-validation-20-minute-rule-and.html](https://passing-the-hash.blogspot.com.es/2014/09/pac-validation-20-minute-rule-and.html)
* 理解PAC验证：[https://blogs.msdn.microsoft.com/openspecification/2009/04/24/understanding-microsoft-kerberos-pac-validation/](https://blogs.msdn.microsoft.com/openspecification/2009/04/24/understanding-microsoft-kerberos-pac-validation/)
* 重置krbtgt账户密码/密钥：[https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51)
* 缓解Pass-the-Hash (PtH)攻击和其他凭证盗窃：[https://www.microsoft.com/en-us/download/details.aspx?id=36036](https://www.microsoft.com/en-us/download/details.aspx?id=36036)
* 在AD环境中使用LDAP、Kerberos (和MSRPC)的有趣玩法：[https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments?slide=58](https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments?slide=58)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
