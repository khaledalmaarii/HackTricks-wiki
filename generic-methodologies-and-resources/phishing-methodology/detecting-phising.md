# 检测钓鱼

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 介绍

要检测钓鱼尝试，重要的是**了解当前使用的钓鱼技术**。在本帖子的父页面上，您可以找到这些信息，因此如果您不了解今天使用的技术，请建议您转到父页面并至少阅读该部分。

本帖子基于这样一个想法，即**攻击者将尝试模仿或使用受害者的域名**。如果您的域名为`example.com`，并且由于某种原因如`youwonthelottery.com`而被钓鱼，这些技术不会揭示它。

## 域名变体

发现那些将在电子邮件中使用**类似域名**的**钓鱼**尝试是**相当容易**的。\
只需**生成攻击者可能使用的最有可能的钓鱼名称列表**，并**检查**它是否**已注册**或只是检查是否有任何**IP**在使用它。

### 查找可疑域名

为此，您可以使用以下任何工具。请注意，这些工具还将自动执行DNS请求，以检查域名是否分配了任何IP：

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### 位翻转

**您可以在父页面中找到此技术的简要解释。或阅读原始研究** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

例如，对微软的域名进行1位修改，可以将其转换为_windnws.com._\
**攻击者可能注册尽可能多与受害者相关的位翻转域，以将合法用户重定向到他们的基础设施**。

**所有可能的位翻转域名也应该受到监控。**

### 基本检查

一旦您有潜在可疑域名列表，您应该**检查**它们（主要是HTTP和HTTPS端口），以查看它们是否使用与受害者域名相似的登录表单。\
您还可以检查端口3333，看看是否打开并运行了`gophish`实例。\
了解每个发现的可疑域名的**年龄**也很有趣，年龄越小，风险越大。\
您还可以获取HTTP和/或HTTPS可疑网页的**屏幕截图**，以查看是否可疑，如果是这种情况，则**访问以进行更深入的查看**。

### 高级检查

如果您想再进一步，我建议您**定期监控这些可疑域名并搜索更多**（每天？只需几秒钟/几分钟）。您还应该**检查**相关IP的**开放端口**，并**搜索`gophish`或类似工具的实例**（是的，攻击者也会犯错误），并**监控可疑域名和子域的HTTP和HTTPS网页**，以查看它们是否复制了受害者网页的任何登录表单。\
为了**自动化**这一过程，我建议您拥有受害者域的登录表单列表，爬取可疑网页，并使用类似`ssdeep`的工具比较在可疑域内找到的每个登录表单与受害者域的每个登录表单。\
如果您已经找到了可疑域的登录表单，您可以尝试**发送垃圾凭据**并**检查是否将您重定向到受害者域**。

## 使用关键字的域名

父页面还提到了一种域名变体技术，即将**受害者的域名放在更大的域名中**（例如paypal.com的paypal-financial.com）。

### 证书透明度

无法采用先前的“暴力”方法，但实际上也**可以通过证书透明度揭示此类钓鱼尝试**。每当CA发出证书时，详细信息都会公开。这意味着通过阅读证书透明度甚至监控它，**可以找到在其名称中使用关键字的域名**。例如，如果攻击者生成了一个[https://paypal-financial.com](https://paypal-financial.com)的证书，通过查看证书，可以找到关键字“paypal”，并知道正在使用可疑的电子邮件。

帖子[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)建议您可以使用Censys搜索受特定关键字影响的证书，并按日期（仅“新”证书）和CA发行者“Let's Encrypt”进行过滤：

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1115).png>)

但是，您也可以使用免费的网络[**crt.sh**](https://crt.sh)来“做同样的事”。您可以**搜索关键字**，如果愿意，还可以**按日期和CA**过滤结果。

![](<../../.gitbook/assets/image (519).png>)

使用最后一种选项，您甚至可以使用匹配身份字段，查看真实域的任何身份是否与任何可疑域中的身份匹配（请注意，可疑域可能是误报）。

**另一种选择**是名为[**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)的出色项目。CertStream提供新生成证书的实时流，您可以使用它来实时检测指定关键字。实际上，有一个名为[**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher)的项目就是这样做的。
### **新域名**

**最后一个选择** 是收集一些顶级域名（TLDs）的**新注册域名列表**（[Whoxy](https://www.whoxy.com/newly-registered-domains/)提供此类服务），并**检查这些域名中的关键词**。然而，长域名通常使用一个或多个子域，因此关键词不会出现在FLD内，您将无法找到钓鱼子域。
