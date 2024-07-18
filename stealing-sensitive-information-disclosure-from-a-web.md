# 从网络中窃取敏感信息泄露

{% hint style="success" %}
学习并实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

如果你在某个时刻发现一个**网页根据你的会话呈现敏感信息**：也许它反射了 cookie，或打印了信用卡详细信息或其他敏感信息，你可以尝试窃取它。\
这里我向你介绍了主要的尝试方法：

* [**CORS 绕过**](pentesting-web/cors-bypass.md)：如果你可以绕过 CORS 头，你将能够通过对恶意页面执行 Ajax 请求来窃取信息。
* [**XSS**](pentesting-web/xss-cross-site-scripting/)：如果你在页面上发现了 XSS 漏洞，你可能可以滥用它来窃取信息。
* [**悬挂标记**](pentesting-web/dangling-markup-html-scriptless-injection/)：如果你无法注入 XSS 标签，你仍然可以使用其他常规 HTML 标签来窃取信息。
* [**Clickjaking**](pentesting-web/clickjacking.md)：如果没有防护措施防止这种攻击，你可能可以欺骗用户发送给你敏感数据（一个示例[在这里](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)）。

{% hint style="success" %}
学习并实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
