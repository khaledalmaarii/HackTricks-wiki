# Windows 凭证保护

## 凭证保护

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库**提交 PR 来分享您的黑客技巧**。

</details>

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) 协议在 Windows XP 中引入，旨在与 HTTP 协议一起用于认证。Microsoft 在多个版本的 Windows 中**默认启用了此协议**（Windows XP — Windows 8.0 和 Windows Server 2003 — Windows Server 2012），这意味着**明文密码存储在 LSASS**（本地安全权限子系统服务）中。**Mimikatz** 可以与 LSASS 交互，允许攻击者通过以下命令**检索这些凭证**：
```
sekurlsa::wdigest
```
此行为可以通过将 _**UseLogonCredential**_ 和 _**Negotiate**_ 在 _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 中的值**设置为 1** 来**激活/停用**。\
如果这些注册表键**不存在**或值为**"0"**，则 WDigest 将被**停用**。
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA 保护

Microsoft 在 **Windows 8.1 及以后的版本**中为 LSA 提供了额外的保护，以**防止**不受信任的进程能够**读取其内存**或注入代码。这将阻止常规的 `mimikatz.exe sekurlsa:logonpasswords` 正常工作。\
要**激活这项保护**，您需要将 _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ 下的 _**RunAsPPL**_ 值设置为 1。
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### 绕过

可以使用 Mimikatz 驱动程序 mimidrv.sys 绕过此保护：

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard** 是 Windows 10（企业版和教育版）中的一项新功能，它有助于保护机器上的凭据不受如 pass the hash 此类威胁的影响。这通过一项名为虚拟安全模式（VSM）的技术实现，该技术利用 CPU 的虚拟化扩展（但不是实际的虚拟机）来**保护内存区域**（您可能听说过这被称为基于虚拟化的安全性或 VBS）。VSM 为关键**进程**创建了一个与常规**操作系统**进程隔离的单独“泡沫”，甚至包括内核，**只有特定的受信任进程可以与 VSM 中的进程**（称为**trustlets**）通信。这意味着主 OS 中的进程无法读取 VSM 的内存，即使是内核进程。**本地安全权限 (LSA) 是 VSM 中的 trustlets 之一**，除了在主 OS 中仍在运行的标准**LSASS**进程，以确保与现有进程的兼容性，但实际上它只是充当代理或存根与 VSM 中的版本通信，确保实际凭据在 VSM 版本上运行，因此受到保护免受攻击。对于 Windows 10，必须在您的组织中启用并部署 Credential Guard，因为它**默认不启用。**
来自 [https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard)。更多信息和启用 Credential Guard 的 PS1 脚本[可以在这里找到](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。然而，从 Windows 11 企业版，版本 22H2 和 Windows 11 教育版，版本 22H2 开始，兼容系统已将 Windows Defender Credential Guard [默认打开](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#Default%20Enablement)。

在这种情况下，**Mimikatz 无法做太多绕过**这一点并从 LSASS 提取哈希值。但是，您始终可以添加您的**自定义 SSP**并在用户尝试以**明文**登录时**捕获凭据**。\
有关[**SSP 以及如何执行此操作的更多信息在这里**](../active-directory-methodology/custom-ssp.md)。

可以通过**不同方式启用 Credentials Guard**。要使用注册表检查是否启用了它，您可以检查 _**HKLM\System\CurrentControlSet\Control\LSA**_ 下的 _**LsaCfgFlags**_ 键的值。如果值是 **"1"** 则它是带 UEFI 锁的活动状态，如果是 **"2"** 则是无锁的活动状态，如果是 **"0"** 则未启用。\
这**不足以启用 Credentials Guard**（但它是一个强有力的指标）。\
更多信息和启用 Credential Guard 的 PS1 脚本[可以在这里找到](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
## RDP RestrictedAdmin 模式

在 Windows 8.1 和 Windows Server 2012 R2 中，引入了新的安全功能。其中一个安全功能是 _RDP 的 Restricted Admin 模式_。这个新的安全功能是为了减轻 [pass the hash](https://blog.ahasayen.com/pass-the-hash/) 攻击的风险。

当您使用 RDP 连接到远程计算机时，您的凭据会被存储在您 RDP 进入的远程计算机上。通常您使用一个强大的账户连接到远程服务器，而在所有这些计算机上存储您的凭据确实是一个安全威胁。

使用 _RDP 的 Restricted Admin 模式_，当您使用命令 **mstsc.exe /RestrictedAdmin** 连接到远程计算机时，您将被远程计算机认证，但 **您的凭据不会被存储在那台远程计算机上**，就像过去那样。这意味着，如果远程服务器上有恶意软件或恶意用户活动，您的凭据将不会在远程桌面服务器上可用，供恶意软件攻击。

请注意，由于您的凭据没有被保存在 RDP 会话中，如果 **尝试访问网络资源**，您的凭据将不会被使用。**将使用机器身份代替**。

![](../../.gitbook/assets/ram.png)

来自 [这里](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## 缓存的凭据

**域凭据** 由操作系统组件使用，并由 **本地** **安全权限** (LSA) **认证**。通常，当注册的安全包验证用户的登录数据时，会为用户建立域凭据。这个注册的安全包可能是 **Kerberos** 协议或 **NTLM**。

**Windows 在域控制器离线的情况下存储最后十次的域登录凭据**。如果域控制器离线，用户将 **仍然能够登录到他们的计算机**。这个功能主要是为了不经常登录到公司域的笔记本电脑用户。计算机存储的凭据数量可以通过以下 **注册表键值，或通过组策略** 控制：
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
凭据对普通用户隐藏，即使是管理员账户也是如此。**SYSTEM** 用户是唯一有**权限**去**查看**这些**凭据**的用户。为了让管理员在注册表中查看这些凭据，他们必须以 SYSTEM 用户的身份访问注册表。
缓存的凭据存储在注册表的以下位置：
```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```
**从Mimikatz提取**: `lsadump::cache`\
从[这里](http://juggernaut.wikidot.com/cached-credentials)获取。

## 受保护的用户

当登录用户是受保护用户组的成员时，将应用以下保护措施：

* 即使启用了**允许委派默认凭据**的组策略设置，凭据委派（CredSSP）也不会缓存用户的明文凭据。
* 从Windows 8.1和Windows Server 2012 R2开始，即使启用了Windows Digest，Windows Digest也不会缓存用户的明文凭据。
* **NTLM** 将**不会缓存**用户的**明文凭据**或NT**单向函数**（NTOWF）。
* **Kerberos** 将不再创建**DES**或**RC4密钥**。它也**不会在获取初始TGT后缓存用户的明文**凭据或长期密钥。
* **在登录或解锁时不会创建缓存的验证器**，因此不再支持离线登录。

在用户账户被添加到受保护用户组后，用户登录设备时将开始保护。**从** [**这里**](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)**获取。**

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

**表格来自** [**这里**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**。**

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧**。

</details>
