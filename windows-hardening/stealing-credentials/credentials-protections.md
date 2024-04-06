# Windows Credentials Protections

## 凭证保护

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396)协议是在Windows XP中引入的，旨在通过HTTP协议进行身份验证，**在Windows XP到Windows 8.0和Windows Server 2003到Windows Server 2012上默认启用**。这个默认设置导致**LSASS中存储明文密码**。攻击者可以使用Mimikatz来**提取这些凭证**，执行以下操作：

```bash
sekurlsa::wdigest
```

要**关闭或打开此功能**，必须将\_HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest\_中的\_**UseLogonCredential**_和_**Negotiate**\_注册表键设置为"1"。如果这些键**不存在或设置为"0"**，则WDigest被**禁用**：

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```

## 凭证保护

从 **Windows 8.1** 开始，微软增强了对 LSA 的安全性，以**阻止不受信任进程的未经授权的内存读取或代码注入**。这种增强阻碍了像 `mimikatz.exe sekurlsa:logonpasswords` 这样的命令的典型功能。要**启用这种增强保护**，需要将 _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ 中的 _**RunAsPPL**_ 值调整为 1：

```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```

### 绕过

可以使用 Mimikatz 驱动程序 mimidrv.sys 绕过此保护：

![](../../.gitbook/assets/mimidrv.png)

## 凭据保护

**凭据保护** 是 **Windows 10（企业和教育版本）** 专属的功能，通过 **虚拟安全模式（VSM）** 和 **基于虚拟化的安全（VBS）** 增强了机器凭据的安全性。它利用 CPU 虚拟化扩展来将关键进程隔离在受保护的内存空间中，远离主操作系统的访问范围。这种隔离确保即使内核也无法访问 VSM 中的内存，有效保护凭据免受 **传递哈希** 等攻击。**本地安全机构（LSA）** 在这个安全环境中作为一个信任模块运行，而主操作系统中的 **LSASS** 进程仅作为与 VSM 的 LSA 进行通信的工具。

默认情况下，**凭据保护** 处于非活动状态，需要在组织内手动激活。这对增强安全性非常关键，可以防止像 **Mimikatz** 这样的工具提取凭据。然而，仍然可以通过添加自定义 **安全支持提供程序（SSP）** 来利用漏洞，在登录尝试期间捕获明文凭据。

要验证 **凭据保护** 的激活状态，可以检查注册表键 _**HKLM\System\CurrentControlSet\Control\LSA**_ 下的 _**LsaCfgFlags**_。数值为 "**1**" 表示激活并带有 **UEFI 锁**，"**2**" 表示未锁定，"**0**" 表示未启用。尽管这种注册表检查是一个强有力的指标，但并非启用凭据保护的唯一步骤。在线提供了详细指南和用于启用此功能的 PowerShell 脚本。

```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```

要全面了解并了解在Windows 10中启用**凭据保护**以及在\*\*Windows 11企业和教育版（版本22H2）\*\*兼容系统中自动激活的详细说明，请访问[Microsoft的文档](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。

有关为凭据捕获实施自定义SSP的详细信息，请参阅[此指南](../active-directory-methodology/custom-ssp.md)。

## RDP RestrictedAdmin 模式

**Windows 8.1和Windows Server 2012 R2**引入了几项新的安全功能，包括_**RDP的受限管理员模式**_。该模式旨在通过减轻与\*\*[传递哈希](https://blog.ahasayen.com/pass-the-hash/)\*\*攻击相关的风险来增强安全性。

传统上，通过RDP连接到远程计算机时，您的凭据会存储在目标计算机上。这会带来重大的安全风险，特别是在使用具有提升权限的帐户时。然而，引入_**受限管理员模式**_后，这种风险大大降低。

使用命令**mstsc.exe /RestrictedAdmin**启动RDP连接时，对远程计算机的身份验证是在不将您的凭据存储在其上的情况下执行的。这种方法确保在恶意软件感染或恶意用户访问远程服务器时，您的凭据不会泄露，因为它们未存储在服务器上。

需要注意的是，在**受限管理员模式**下，从RDP会话尝试访问网络资源时不会使用您的个人凭据；而是使用**计算机的身份**。

这一功能在确保远程桌面连接安全性和在安全漏洞发生时保护敏感信息不被暴露方面迈出了重要的一步。

![](../../.gitbook/assets/ram.png)

有关更详细的信息，请访问[此资源](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)。

## 缓存凭据

Windows通过**本地安全机构（LSA）来保护域凭据**，支持使用安全协议如**Kerberos**和**NTLM**的登录过程。Windows的一个关键功能是其能够缓存**最后十个域登录**，以确保用户即使**域控制器脱机**时仍然可以访问其计算机——这对经常远离公司网络的笔记本电脑用户来说是一个福音。

缓存登录次数可通过特定的**注册表键或组策略**进行调整。要查看或更改此设置，使用以下命令：

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

访问这些缓存凭据受到严格控制，只有 **SYSTEM** 帐户具有查看它们所需的权限。需要访问这些信息的管理员必须以 SYSTEM 用户权限进行访问。这些凭据存储在：`HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** 可以用来提取这些缓存凭据，使用命令 `lsadump::cache`。

有关更多详细信息，请参阅原始 [来源](http://juggernaut.wikidot.com/cached-credentials) 提供的全面信息。

## 受保护用户

加入 **受保护用户组** 会为用户引入几项安全增强功能，确保更高级别的保护，防止凭据被窃取和滥用：

* **凭据委派 (CredSSP)**：即使启用了 **允许委派默认凭据** 的组策略设置，受保护用户的明文凭据也不会被缓存。
* **Windows Digest**：从 **Windows 8.1 和 Windows Server 2012 R2** 开始，系统不会缓存受保护用户的明文凭据，无论 Windows Digest 状态如何。
* **NTLM**：系统不会缓存受保护用户的明文凭据或 NT 单向函数 (NTOWF)。
* **Kerberos**：对于受保护用户，Kerberos 认证不会生成 **DES** 或 **RC4 密钥**，也不会缓存明文凭据或长期密钥超出初始票据授予票证 (TGT) 获取。
* **离线登录**：受保护用户在登录或解锁时不会创建缓存的验证器，这意味着不支持这些帐户的离线登录。

这些保护措施在属于 **受保护用户组** 的用户登录设备时立即激活。这确保了关键的安全措施已经就位，以防范各种凭据泄露方法。

有关更详细信息，请参阅官方 [文档](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)。

**来自** [**文档**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)\*\* 的表格\*\*。

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
