# 检测钓鱼网站

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## 简介

要检测钓鱼尝试，重要的是**了解当前使用的钓鱼技术**。在本文的父页面上，您可以找到这些信息，因此如果您不知道当前使用的技术，请去父页面至少阅读该部分。

本文基于这样一个想法，即**攻击者将尝试模仿或使用受害者的域名**。如果您的域名为`example.com`，而您被钓鱼使用完全不同的域名，例如`youwonthelottery.com`，这些技术将无法发现。

## 域名变体

发现在电子邮件中使用**类似域名**的**钓鱼**尝试是相当**容易**的。\
只需**生成一个最可能的钓鱼名称列表**，攻击者可能会使用这些名称，并**检查**它是否已**注册**，或者只需检查是否有任何**IP**在使用它。

### 查找可疑域名

为此，您可以使用以下任何工具。请注意，这些工具还将自动执行DNS请求，以检查该域名是否有任何分配给它的IP：

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### 位翻转

在计算世界中，所有内容都以位（零和一）存储在内存中。\
域名也是如此。例如，_windows.com_在计算设备的易失性内存中变为_01110111..._。\
然而，如果其中一个位由于太阳耀斑、宇宙射线或硬件错误而自动翻转会怎样呢？也就是说，其中的一个0变为1，反之亦然。\
将这个概念应用到DNS请求中，可能发生的情况是**到达DNS服务器的请求域名与最初请求的域名不同**。

例如，对域名microsoft.com进行1位修改，可以将其转换为_windnws.com_。\
**攻击者可能会注册尽可能多的与受害者相关的位翻转域名，以将合法用户重定向到他们的基础设施**。

有关更多信息，请阅读[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

**还应监视所有可能的位翻转域名。**

### 基本检查

一旦您有了潜在可疑域名列表，您应该**检查**它们（主要是HTTP和HTTPS端口），以**查看它们是否使用与受害者域名相似的登录表单**。\
您还可以检查端口3333，看看是否打开并运行了一个`gophish`实例。\
了解每个发现的可疑域名的**年龄**也很有趣，年龄越小，风险越大。\
您还可以获取HTTP和/或HTTPS可疑网页的**屏幕截图**，以查看是否可疑，并在这种情况下**访问它以进行更深入的查看**。

### 高级检查

如果您想更进一步，我建议您**定期监视这些可疑域名并搜索更多**（每天一次？只需要几秒钟/几分钟）。您还应该**检查**相关IP的**开放端口**，并**搜索`gophish`或类似工具的实例**（是的，攻击者也会犯错误），并**监视可疑域名和子域名的HTTP和HTTPS网页**，以查看它们是否复制了受害者网页的任何登录表单。\
为了**自动化**这个过程，我建议您拥有受害者域名的登录表单列表，爬取可疑网页，并使用类似`ssdeep`的工具将每个可疑域名中找到的每个登录表单与受害者域名的每个登录表单进行比较。\
如果找到了可疑域名的登录表单，您可以尝试**发送垃圾凭据**并**检查是否将您重定向到受害者域名**。
## 使用关键词的域名

父页面还提到了一种域名变体技术，即将**受害者的域名放在更大的域名中**（例如，paypal.com的paypal-financial.com）。

### 证书透明度

虽然无法采用之前的“暴力破解”方法，但实际上可以通过证书透明度揭示此类钓鱼企图。每当CA发出证书时，详细信息都会公开。这意味着通过阅读证书透明度或监视它，**可以找到使用关键词的域名**。例如，如果攻击者生成了一个[https://paypal-financial.com](https://paypal-financial.com)的证书，通过查看证书，可以找到关键词“paypal”，并知道正在使用可疑的电子邮件。

文章[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)建议您可以使用Censys搜索影响特定关键词的证书，并按日期（仅“新”证书）和CA发行者“Let's Encrypt”进行过滤：

![](<../../.gitbook/assets/image (390).png>)

但是，您也可以使用免费的网站[**crt.sh**](https://crt.sh)来做“相同的事情”。您可以**搜索关键词**，并根据需要**按日期和CA进行筛选**结果。

![](<../../.gitbook/assets/image (391).png>)

使用最后一种选项，您甚至可以使用匹配身份字段查看真实域与任何可疑域是否匹配（请注意，可疑域可能是误报）。

**另一种选择**是名为[**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)的出色项目。CertStream提供了新生成的证书的实时流，您可以使用它来实时检测指定关键词。实际上，有一个名为[**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher)的项目就是这样做的。

### **新域名**

**最后一种选择**是收集一些TLD的**新注册域名列表**（[Whoxy](https://www.whoxy.com/newly-registered-domains/)提供此类服务），并**检查这些域名中的关键词**。但是，长域名通常使用一个或多个子域，因此关键词不会出现在FLD中，您将无法找到钓鱼子域。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
