# 检查清单 - 本地Windows权限提升

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧。**

</details>

### **查找Windows本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [系统信息](windows-local-privilege-escalation/#system-info)

* [ ] 获取[**系统信息**](windows-local-privilege-escalation/#system-info)
* [ ] 使用脚本搜索**内核**[**漏洞**](windows-local-privilege-escalation/#version-exploits)
* [ ] 使用**Google搜索**内核**漏洞**
* [ ] 使用**searchsploit搜索**内核**漏洞**
* [ ] [**环境变量**](windows-local-privilege-escalation/#environment)中的有趣信息？
* [ ] [**PowerShell历史记录**](windows-local-privilege-escalation/#powershell-history)中的密码？
* [ ] [**Internet设置**](windows-local-privilege-escalation/#internet-settings)中的有趣信息？
* [ ] [**驱动器**](windows-local-privilege-escalation/#drives)？
* [ ] [**WSUS漏洞**](windows-local-privilege-escalation/#wsus)？
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)？

### [日志/AV枚举](windows-local-privilege-escalation/#enumeration)

* [ ] 检查[**审计**](windows-local-privilege-escalation/#audit-settings)和[**WEF**](windows-local-privilege-escalation/#wef)设置
* [ ] 检查[**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] 检查是否启用了[**WDigest**](windows-local-privilege-escalation/#wdigest)
* [ ] [**LSA保护**](windows-local-privilege-escalation/#lsa-protection)？
* [ ] [**凭据保护**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**缓存凭据**](windows-local-privilege-escalation/#cached-credentials)？
* [ ] 检查是否有任何[**AV**](windows-av-bypass)
* [ ] [**AppLocker策略**](authentication-credentials-uac-and-efs#applocker-policy)？
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)？
* [ ] [**用户特权**](windows-local-privilege-escalation/#users-and-groups)？
* [ ] 检查[**当前**用户**特权**](windows-local-privilege-escalation/#users-and-groups)
* [ ] 你是[**任何特权组的成员**](windows-local-privilege-escalation/#privileged-groups)吗？
* [ ] 检查是否启用了以下任何一个令牌：**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**？[**令牌操作**](windows-local-privilege-escalation/#token-manipulation)
* [ ] [**用户会话**](windows-local-privilege-escalation/#logged-users-sessions)？
* [ ] 检查[**用户主目录**](windows-local-privilege-escalation/#home-folders)（访问权限？）
* [ ] 检查[**密码策略**](windows-local-privilege-escalation/#password-policy)
* [ ] [**剪贴板**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)中有什么？

### [网络](windows-local-privilege-escalation/#network)

* [ ] 检查**当前**[**网络信息**](windows-local-privilege-escalation/#network)
* [ ] 检查**限制对外部的隐藏本地服务**

### [运行中的进程](windows-local-privilege-escalation/#running-processes)

* [ ] 进程二进制文件和文件夹权限[**权限**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**内存密码挖掘**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**不安全的GUI应用程序**](windows-local-privilege-escalation/#insecure-gui-apps)
### [服务](windows-local-privilege-escalation/#services)

* [ ] [你能修改任何服务吗？](windows-local-privilege-escalation#permissions)
* [ ] [你能修改任何服务执行的二进制文件吗？](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [你能修改任何服务的注册表吗？](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [你能利用任何未引用的服务二进制路径吗？](windows-local-privilege-escalation/#unquoted-service-paths)

### [应用程序](windows-local-privilege-escalation/#applications)

* [ ] 安装应用程序的写权限
* [ ] 启动应用程序
* [ ] 可能存在的漏洞驱动程序

### [DLL劫持](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] 你能在PATH中的任何文件夹中写入吗？
* [ ] 是否有已知的服务二进制文件尝试加载任何不存在的DLL？
* [ ] 你能在任何二进制文件夹中写入吗？

### [网络](windows-local-privilege-escalation/#network)

* [ ] 枚举网络（共享、接口、路由、邻居等）
* [ ] 特别关注在本地主机（127.0.0.1）上监听的网络服务

### [Windows凭据](windows-local-privilege-escalation/#windows-credentials)

* [ ] Winlogon凭据
* [ ] Windows Vault凭据
* [ ] 有趣的DPAPI凭据
* [ ] 已保存的Wifi网络密码
* [ ] 已保存的RDP连接中的有趣信息
* [ ] 最近运行的命令中的密码
* [ ] Remote Desktop Credentials Manager密码
* [ ] 是否存在AppCmd.exe？凭据？
* [ ] SCClient.exe？DLL Side Loading？

### [文件和注册表（凭据）](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] Putty：凭据和SSH主机密钥
* [ ] 注册表中的SSH密钥？
* [ ] 未经人工干预的文件中的密码？
* [ ] 任何SAM和SYSTEM备份？
* [ ] 云凭据？
* [ ] McAfee SiteList.xml文件？
* [ ] 缓存的GPP密码？
* [ ] IIS Web配置文件中的密码？
* [ ] 日志中的有趣信息？
* [ ] 是否要求用户提供凭据？
* [ ] 回收站中的有趣文件？
* [ ] 包含凭据的其他注册表？
* [ ] 浏览器数据（数据库、历史记录、书签等）中的有趣信息？
* [ ] 在文件和注册表中进行通用密码搜索的工具
* [ ] 自动搜索密码的工具

### [泄漏的处理程序](windows-local-privilege-escalation/#leaked-handlers)

* [ ] 你能访问任何由管理员运行的进程的处理程序吗？

### [管道客户端模拟](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] 检查是否可以滥用它

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家网络安全公司工作吗？你想在HackTricks中宣传你的公司吗？或者你想获得PEASS的最新版本或下载PDF格式的HackTricks吗？请查看[订阅计划](https://github.com/sponsors/carlospolop)！

- 发现我们的独家NFT收藏品[The PEASS Family](https://opensea.io/collection/the-peass-family)

- 获取[官方PEASS和HackTricks周边产品](https://peass.creator-spring.com)

- 加入[💬](https://emojipedia.org/speech-balloon/) [Discord群](https://discord.gg/hRep4RUj7f)或[电报群](https://t.me/peass)，或在Twitter上关注我[🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[@carlospolopm](https://twitter.com/hacktricks_live)。

- 通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧。

</details>
