# Windows凭证保护

## 凭证保护

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396)协议在Windows XP中引入，旨在与HTTP协议一起用于身份验证。微软在多个版本的Windows中**默认启用了此协议**（Windows XP - Windows 8.0和Windows Server 2003 - Windows Server 2012），这意味着**明文密码存储在LSASS**（本地安全性子系统服务）中。**Mimikatz**可以与LSASS进行交互，使攻击者能够通过以下命令**检索这些凭证**：
```
sekurlsa::wdigest
```
这个行为可以通过将 _**UseLogonCredential**_ 和 _**Negotiate**_ 的值设置为1来**启用/禁用**，这些值位于 _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_。\
如果这些注册表键**不存在**或值为**"0"**，那么WDigest将被**禁用**。
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA 保护

微软在 **Windows 8.1 及更高版本**中为 LSA 提供了额外的保护，以防止不受信任的进程能够读取其内存或注入代码。这将阻止常规的 `mimikatz.exe sekurlsa:logonpasswords` 正常工作。\
要**激活此保护**，您需要将值 _**RunAsPPL**_ 设置为 1，位于 _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_。
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### 绕过

可以使用Mimikatz驱动程序mimidrv.sys绕过此保护：

![](../../.gitbook/assets/mimidrv.png)

## 凭据保护

**凭据保护**是Windows 10（企业版和教育版）中的一项新功能，可帮助保护机器上的凭据免受哈希传递等威胁。这通过一种称为虚拟安全模式（VSM）的技术实现，该技术利用CPU的虚拟化扩展（但不是实际的虚拟机）来为内存的某些区域提供保护（您可能会听到这被称为基于虚拟化的安全或VBS）。VSM为关键的**进程**创建了一个与常规**操作系统**进程隔离的独立的“气泡”，即使是内核和**只有特定的受信任进程才能与VSM中的进程**（称为**trustlets**）通信。这意味着主操作系统中的进程无法读取来自VSM的内存，即使是内核进程也不行。**本地安全局（LSA）是VSM中的一个trustlet**，除了仍在主操作系统中运行以确保与现有进程的兼容性的标准**LSASS**进程外，它实际上只是充当代理或存根，用于与VSM中的版本通信，确保实际的凭据在VSM中运行，因此受到保护。必须在组织中启用和部署凭据保护，因为它**默认情况下未启用**。\
来自[https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard)\
有关更多信息和启用凭据保护的PS1脚本，请[点击此处](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。

在这种情况下，**Mimikatz无法绕过**此保护并从LSASS中提取哈希。但是，您始终可以添加您的**自定义SSP**并在用户尝试以**明文**登录时**捕获凭据**。\
有关[**SSP以及如何执行此操作的更多信息，请点击此处**](../active-directory-methodology/custom-ssp.md)。

可以通过不同的方式**启用凭据保护**。要检查是否使用注册表启用了凭据保护，可以检查_HKLM\System\CurrentControlSet\Control\LSA_中键_**LsaCfgFlags**_的值。如果值为**"1"**，则启用了带有UEFI锁定的凭据保护，如果值为**"2"**，则启用了不带锁定的凭据保护，如果值为**"0"**，则未启用。\
这**不足以启用凭据保护**（但是这是一个强有力的指标）。\
有关更多信息和启用凭据保护的PS1脚本，请[点击此处](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
## RDP RestrictedAdmin 模式

在 Windows 8.1 和 Windows Server 2012 R2 中引入了一些新的安全功能。其中之一是用于 RDP 的 _Restricted Admin 模式_。这个新的安全功能旨在减轻 [传递哈希](https://blog.ahasayen.com/pass-the-hash/) 攻击的风险。

当你使用 RDP 连接到远程计算机时，你的凭据会存储在你所连接的远程计算机上。通常情况下，你会使用一个强大的账户来连接远程服务器，而在所有这些计算机上存储你的凭据确实是一个安全威胁。

使用 _Restricted Admin 模式_ 进行 RDP 连接时，通过命令 **mstsc.exe /RestrictedAdmin**，你将被认证到远程计算机，但是**你的凭据将不会存储在该远程计算机上**，就像过去那样。这意味着，如果恶意软件甚至是恶意用户在远程服务器上活动，你的凭据将不会在远程桌面服务器上可用于恶意软件攻击。

请注意，由于你的凭据不会保存在 RDP 会话中，如果**尝试访问网络资源**，你的凭据将不会被使用。**机器标识将被使用**。

![](../../.gitbook/assets/ram.png)

来源：[这里](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)。

## 缓存凭据

**域凭据**由操作系统组件使用，并由**本地安全机构**（LSA）进行**认证**。通常情况下，当注册的安全包验证用户的登录数据时，会为用户建立域凭据。这个注册的安全包可以是**Kerberos**协议或**NTLM**。

**Windows 在域控制器离线时会存储最近的十个域登录凭据**。如果域控制器离线，用户仍然能够登录到他们的计算机。这个功能主要是为那些不经常登录公司域的笔记本用户设计的。计算机存储的凭据数量可以通过以下**注册表键或通过组策略**进行控制：
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
凭据对普通用户和管理员账户都是隐藏的。**SYSTEM**用户是唯一具有**查看**这些**凭据**权限的用户。为了以管理员身份在注册表中查看这些凭据，必须以SYSTEM用户的身份访问注册表。\
缓存凭据存储在注册表的以下位置：
```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```
**从Mimikatz中提取**: `lsadump::cache`\
从[这里](http://juggernaut.wikidot.com/cached-credentials)。

## 受保护的用户

当登录用户是受保护用户组的成员时，将应用以下保护措施：

* 即使启用了“允许委派默认凭据”组策略设置，凭据委派（CredSSP）也不会缓存用户的明文凭据。
* 从Windows 8.1和Windows Server 2012 R2开始，即使启用了Windows Digest，Windows Digest也不会缓存用户的明文凭据。
* NTLM不会缓存用户的明文凭据或NT单向函数（NTOWF）。
* Kerberos将不再创建DES或RC4密钥。此外，在获取初始TGT后，Kerberos也不会缓存用户的明文凭据或长期密钥。
* 在登录或解锁时不会创建缓存的验证器，因此不再支持离线登录。

将用户帐户添加到受保护的用户组后，保护将在用户登录设备时开始。来自[这里](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)。

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

来自[这里](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)的表格。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
