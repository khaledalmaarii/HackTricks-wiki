# 检查表 - 本地Windows权限提升

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

### **查找Windows本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [系统信息](windows-local-privilege-escalation/#system-info)

* [ ] 获取[**系统信息**](windows-local-privilege-escalation/#system-info)
* [ ] 使用脚本搜索**内核**[**漏洞**](windows-local-privilege-escalation/#version-exploits)
* [ ] 使用**Google搜索**内核**漏洞**
* [ ] 使用**searchsploit搜索**内核**漏洞**
* [ ] [**环境变量**](windows-local-privilege-escalation/#environment)中有趣的信息？
* [ ] [**PowerShell历史记录**](windows-local-privilege-escalation/#powershell-history)中的密码？
* [ ] [**Internet设置**](windows-local-privilege-escalation/#internet-settings)中有趣的信息？
* [ ] [**驱动器**](windows-local-privilege-escalation/#drives)？
* [ ] [**WSUS漏洞**](windows-local-privilege-escalation/#wsus)？
* [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)？

### [日志/AV枚举](windows-local-privilege-escalation/#enumeration)

* [ ] 检查[**审计**](windows-local-privilege-escalation/#audit-settings)和[**WEF**](windows-local-privilege-escalation/#wef)设置
* [ ] 检查[**LAPS**](windows-local-privilege-escalation/#laps)
* 检查[**WDigest**](windows-local-privilege-escalation/#wdigest)是否激活
* [**LSA保护**](windows-local-privilege-escalation/#lsa-protection)?
* [**凭据保护**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [**缓存凭据**](windows-local-privilege-escalation/#cached-credentials)？
* 检查是否有任何[**AV**](windows-av-bypass)
* [**AppLocker策略**](authentication-credentials-uac-and-efs#applocker-policy)？
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)？
* [**用户权限**](windows-local-privilege-escalation/#users-and-groups)？
* 检查[**当前用户的**权限](windows-local-privilege-escalation/#users-and-groups)？
* 您是否是[**任何特权组的成员**](windows-local-privilege-escalation/#privileged-groups)？
* 检查是否启用了以下任何令牌](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [**用户会话**](windows-local-privilege-escalation/#logged-users-sessions)？
* 检查[**用户主目录**](windows-local-privilege-escalation/#home-folders)（访问？）
* 检查[**密码策略**](windows-local-privilege-escalation/#password-policy)？
* [**剪贴板**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)中有什么？

### [网络](windows-local-privilege-escalation/#network)

* 检查**当前**[**网络信息**](windows-local-privilege-escalation/#network)
* 检查**隐藏的本地服务**是否受限于外部

### [运行进程](windows-local-privilege-escalation/#running-processes)

* 进程二进制文件和文件夹权限](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**内存密码挖掘**](windows-local-privilege-escalation/#memory-password-mining)
* [**不安全的GUI应用程序**](windows-local-privilege-escalation/#insecure-gui-apps)
* 通过`ProcDump.exe`窃取**有趣进程**的凭据？（firefox，chrome等...）

### [服务](windows-local-privilege-escalation/#services)

* [您能否**修改任何服务**？](windows-local-privilege-escalation#permissions)
* [您能否**修改**任何**服务**执行的**二进制文件**？](windows-local-privilege-escalation/#modify-service-binary-path)
* [您能否**修改**任何**服务**的**注册表**？](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [您能否利用任何**未加引号的服务**二进制**路径**？](windows-local-privilege-escalation/#unquoted-service-paths)

### [**应用程序**](windows-local-privilege-escalation/#applications)

* **写入**[**已安装应用程序的权限**](windows-local-privilege-escalation/#write-permissions)
* [**启动应用程序**](windows-local-privilege-escalation/#run-at-startup)
* **易受攻击的**[**驱动程序**](windows-local-privilege-escalation/#drivers)

### [DLL劫持](windows-local-privilege-escalation/#path-dll-hijacking)

* 您能否**写入PATH中的任何文件夹**？
* 是否有任何已知的服务二进制文件**尝试加载任何不存在的DLL**？
* 您能否在任何**二进制文件夹**中**写入**？
### [网络](windows-local-privilege-escalation/#network)

* [ ] 枚举网络（共享、接口、路由、邻居，...）
* [ ] 特别关注监听在本地主机（127.0.0.1）上的网络服务

### [Windows凭证](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)凭证
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) 可以使用的凭证？
* [ ] 有趣的[**DPAPI凭证**](windows-local-privilege-escalation/#dpapi)？
* [ ] 已保存的[**Wifi网络**](windows-local-privilege-escalation/#wifi)密码？
* [ ] 已保存的RDP连接中的有趣信息[**saved RDP Connections**](windows-local-privilege-escalation/#saved-rdp-connections)？
* [ ] 最近运行命令中的密码[**recently run commands**](windows-local-privilege-escalation/#recently-run-commands)？
* [ ] [**远程桌面凭据管理器**](windows-local-privilege-escalation/#remote-desktop-credential-manager)密码？
* [ ] [**AppCmd.exe** 是否存在](windows-local-privilege-escalation/#appcmd-exe)？凭证？
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)？DLL侧加载？

### [文件和注册表（凭证）](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**凭证**](windows-local-privilege-escalation/#putty-creds) **和** [**SSH主机密钥**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] 注册表中的[**SSH密钥**](windows-local-privilege-escalation/#ssh-keys-in-registry)？
* [ ] 无人值守文件中的密码[**unattended files**](windows-local-privilege-escalation/#unattended-files)？
* [ ] 任何[**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)备份？
* [ ] [**云凭证**](windows-local-privilege-escalation/#cloud-credentials)？
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) 文件？
* [ ] [**缓存的GPP密码**](windows-local-privilege-escalation/#cached-gpp-pasword)？
* [ ] [**IIS Web配置文件**](windows-local-privilege-escalation/#iis-web-config)中的密码？
* [ ] 日志中的有趣信息[**web** **logs**](windows-local-privilege-escalation/#logs)？
* [ ] 想要向用户[**请求凭证**](windows-local-privilege-escalation/#ask-for-credentials)吗？
* [ ] 回收站中的有趣[**文件**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)？
* [ ] 其他包含凭证的[**注册表**](windows-local-privilege-escalation/#inside-the-registry)？
* [ ] 浏览器数据中的[**内容**](windows-local-privilege-escalation/#browsers-history)（数据库、历史记录、书签，...）？
* [**在文件和注册表中进行通用密码搜索**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)？
* [**工具**](windows-local-privilege-escalation/#tools-that-search-for-passwords)自动搜索密码

### [泄漏的处理程序](windows-local-privilege-escalation/#leaked-handlers)

* [ ] 是否可以访问由管理员运行的进程的任何处理程序？

### [管道客户端冒充](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] 检查是否可以滥用它
