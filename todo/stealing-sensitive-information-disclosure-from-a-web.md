# Stealing Sensitive Information Disclosure from a Web

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。\*\*

</details>

如果你在某个时刻发现一个**基于你的会话向你展示敏感信息的网页**：可能它在反映cookies，或打印信用卡细节或任何其他敏感信息，你可能会尝试窃取它。\
这里我向你介绍主要的方法来尝试实现它：

* [**CORS绕过**](../pentesting-web/cors-bypass.md)：如果你能绕过CORS头，你将能够通过恶意页面执行Ajax请求来窃取信息。
* [**XSS**](../pentesting-web/xss-cross-site-scripting/)：如果你在页面上发现了XSS漏洞，你可能能够利用它来窃取信息。
* [**悬空标记**](../pentesting-web/dangling-markup-html-scriptless-injection/)：如果你不能注入XSS标签，你仍然可能使用其他常规HTML标签来窃取信息。
* [**点击劫持**](../pentesting-web/clickjacking.md)：如果没有防护措施，你可能能够诱导用户向你发送敏感数据（一个例子[这里](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)）。

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。\*\*

</details>
