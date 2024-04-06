# 其他网络技巧

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFT收藏品The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter上** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧**。

</details>

### Host头

有时后端会信任**Host头**来执行某些操作。例如，它可以将其值用作发送密码重置的**域名**。因此，当您收到一封带有重置密码链接的电子邮件时，使用的域名就是您在Host头中输入的域名。然后，您可以请求其他用户的密码重置并将域名更改为您控制的域名，以窃取他们的密码重置代码。[WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)。

{% hint style="warning" %}
请注意，您甚至可能无需等待用户单击重置密码链接即可获取令牌，因为**垃圾邮件过滤器或其他中间设备/机器人可能会单击链接以进行分析**。
{% endhint %}

### 会话布尔值

有时，当您正确完成某些验证时，后端会**将一个布尔值（True）添加到会话的安全属性中**。然后，不同的端点将知道您是否成功通过了该检查。\
然而，如果您**通过了检查**并且您的会话在安全属性中被授予了该"True"值，您可以尝试访问其他依赖于相同属性的资源，但您**不应该有权限**访问这些资源。[WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)。

### 注册功能

尝试以已存在的用户注册。还可以尝试使用等效字符（点、大量空格和Unicode）。

### 接管电子邮件

注册一个电子邮件，在确认之前更改电子邮件，然后，如果新的确认电子邮件发送到第一个注册的电子邮件，您可以接管任何电子邮件。或者，如果您可以启用第二个电子邮件来确认第一个电子邮件，您也可以接管任何帐户。

### 访问使用Atlassian的公司的内部服务台

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE方法

开发人员可能会忘记在生产环境中禁用各种调试选项。例如，HTTP `TRACE` 方法是为了诊断目的而设计的。如果启用，Web服务器将通过在响应中回显确切接收到的请求来响应使用`TRACE`方法的请求。这种行为通常是无害的，但有时会导致信息泄露，例如可能由反向代理附加到请求中的内部身份验证标头的名称。![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFT收藏品The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter上** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧**。

</details>
