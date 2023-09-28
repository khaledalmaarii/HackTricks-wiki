# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## DCSync

**DCSync**权限意味着对域本身具有以下权限：**DS-Replication-Get-Changes**、**Replicating Directory Changes All**和**Replicating Directory Changes In Filtered Set**。

**关于DCSync的重要说明：**

* **DCSync攻击模拟了域控制器的行为，并要求其他域控制器使用目录复制服务远程协议（MS-DRSR）复制信息**。由于MS-DRSR是Active Directory的一个有效且必要的功能，因此无法关闭或禁用它。
* 默认情况下，只有**域管理员、企业管理员、管理员和域控制器**组具有所需的特权。
* 如果任何帐户密码使用可逆加密存储，Mimikatz中有一个选项可以返回明文密码。

### 枚举

使用`powerview`检查具有这些权限的用户：
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### 本地利用

Exploit Locally（本地利用）是一种攻击方法，利用本地访问权限来获取目标系统的敏感信息。在Active Directory环境中，一种常见的本地利用方法是使用DCSync攻击。

#### DCSync攻击

DCSync攻击是一种利用Active Directory域控制器（DC）的特权来提取目标用户凭据的攻击方法。通过模拟域控制器的行为，攻击者可以获取目标用户的NTLM哈希值，从而进一步获取其明文密码。

以下是DCSync攻击的步骤：

1. 获取域控制器的访问权限：攻击者需要获得域控制器的本地访问权限，通常通过提升本地权限或者利用已知的漏洞来实现。

2. 使用Mimikatz工具：攻击者使用Mimikatz工具来执行DCSync攻击。Mimikatz是一款强大的密码提取工具，可以从域控制器中提取目标用户的凭据。

3. 提取目标用户凭据：攻击者使用Mimikatz的DCSync模块来模拟域控制器的行为，并提取目标用户的NTLM哈希值。

4. 破解NTLM哈希值：攻击者可以使用各种破解工具来破解目标用户的NTLM哈希值，从而获取其明文密码。

DCSync攻击是一种隐蔽且有效的攻击方法，因此在保护Active Directory环境时，需要采取相应的防御措施，如限制域控制器的本地访问权限、定期更新凭据、监控异常活动等。
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### 远程利用

DCSync is a technique that allows an attacker to impersonate a domain controller and request the replication of password data from the targeted domain controller. This technique can be used remotely to extract password hashes from the Active Directory database without the need for administrative privileges.

To exploit DCSync remotely, the attacker needs to have network access to the targeted domain controller. The attacker can use tools like Mimikatz or Impacket to perform the DCSync attack.

The steps to exploit DCSync remotely are as follows:

1. Identify the targeted domain controller: The attacker needs to identify the domain controller that they want to impersonate and extract password data from.

2. Obtain the domain controller's NTLM hash: The attacker needs to obtain the NTLM hash of the domain controller's computer account. This can be done by dumping the LSASS process memory or by using other techniques like Pass-the-Hash.

3. Generate a fake domain controller: The attacker needs to generate a fake domain controller using tools like Mimikatz or Impacket. This involves creating a fake domain controller object in memory and configuring it to respond to DCSync requests.

4. Impersonate the domain controller: The attacker needs to impersonate the targeted domain controller by injecting the fake domain controller object into the LSASS process memory. This can be done using techniques like process injection or by exploiting vulnerabilities in the LSASS process.

5. Request password data replication: Once the attacker has successfully impersonated the domain controller, they can use the DCSync command to request the replication of password data from the targeted domain controller. This command can be executed using tools like Mimikatz or Impacket.

6. Extract password hashes: After the replication request is made, the targeted domain controller will send the password hashes to the attacker's fake domain controller. The attacker can then extract the password hashes from the fake domain controller and use them for further attacks like password cracking or pass-the-hash.

It is important to note that exploiting DCSync remotely requires advanced knowledge of Active Directory and network security. It is also considered an unauthorized activity and should only be performed in controlled environments with proper authorization.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` 生成3个文件：

* 一个包含 **NTLM 哈希值** 的文件
* 一个包含 **Kerberos 密钥** 的文件
* 一个包含启用了[**可逆加密**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)的 NTDS 中明文密码的文件。你可以使用以下命令获取启用了可逆加密的用户：

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 持久性

如果你是域管理员，你可以使用 `powerview` 将这些权限授予任何用户：
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
然后，您可以通过查找输出中的特权名称（应该能够在"ObjectType"字段中看到特权名称）来**检查用户是否正确分配了这3个特权**：
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 缓解措施

* 安全事件ID 4662（必须启用对象的审核策略）- 对对象执行了操作
* 安全事件ID 5136（必须启用对象的审核策略）- 修改了目录服务对象
* 安全事件ID 4670（必须启用对象的审核策略）- 更改了对象的权限
* AD ACL Scanner - 创建和比较ACL的创建报告。[https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## 参考资料

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
