# 清单 - 本地Windows权限提升

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

### **寻找Windows本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [系统信息](windows-local-privilege-escalation/#system-info)

* [ ] 获取[**系统信息**](windows-local-privilege-escalation/#system-info)
* [ ] 使用脚本搜索**内核** [**漏洞**](windows-local-privilege-escalation/#version-exploits)
* [ ] 使用**Google搜索**内核**漏洞**
* [ ] 使用**searchsploit搜索**内核**漏洞**
* [ ] [**环境变量**](windows-local-privilege-escalation/#environment)中的有趣信息？
* [ ] [**PowerShell历史记录**](windows-local-privilege-escalation/#powershell-history)中的密码？
* [ ] [**互联网设置**](windows-local-privilege-escalation/#internet-settings)中的有趣信息？
* [ ] [**驱动器**](windows-local-privilege-escalation/#drives)？
* [ ] [**WSUS漏洞**](windows-local-privilege-escalation/#wsus)？
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)？

### [日志/防病毒枚举](windows-local-privilege-escalation/#enumeration)

* [ ] 检查[**审计**](windows-local-privilege-escalation/#audit-settings)和[**WEF**](windows-local-privilege-escalation/#wef)设置
* [ ] 检查[**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] 检查是否激活了[**WDigest**](windows-local-privilege-escalation/#wdigest)
* [ ] [**LSA保护**](windows-local-privilege-escalation/#lsa-protection)？
* [ ] [**凭据保护**](windows-local-privilege-escalation/#credentials-guard)[？](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**缓存的凭据**](windows-local-privilege-escalation/#cached-credentials)？
* [ ] 检查是否有任何[**防病毒软件**](windows-av-bypass)
* [ ] [**AppLocker策略**](authentication-credentials-uac-and-efs#applocker-policy)？
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**用户权限**](windows-local-privilege-escalation/#users-and-groups)
* [ ] 检查[**当前**用户**权限**](windows-local-privilege-escalation/#users-and-groups)
* [ ] 您是[**任何特权组的成员**](windows-local-privilege-escalation/#privileged-groups)吗？
* [ ] 检查您是否拥有以下任何[**令牌**](windows-local-privilege-escalation/#token-manipulation)：**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**？
* [ ] [**用户会话**](windows-local-privilege-escalation/#logged-users-sessions)？
* [ ] 检查[**用户主目录**](windows-local-privilege-escalation/#home-folders)（访问权限？）
* [ ] 检查[**密码策略**](windows-local-privilege-escalation/#password-policy)
* [ ] [**剪贴板**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)里面有什么？

### [网络](windows-local-privilege-escalation/#network)

* [ ] 检查**当前**[**网络** **信息**](windows-local-privilege-escalation/#network)
* [ ] 检查对外部限制的**隐藏本地服务**

### [运行中的进程](windows-local-privilege-escalation/#running-processes)

* [ ] 进程二进制文件[**文件和文件夹权限**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**内存密码挖掘**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**不安全的GUI应用程序**](windows-local-privilege-escalation/#insecure-gui-apps)

### [服务](windows-local-privilege-escalation/#services)

* [ ] [**您可以修改任何服务吗**？](windows-local-privilege-escalation#permissions)
* [ ] [**您可以修改**由任何**服务执行**的**二进制文件**吗？](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [**您可以修改**任何**服务的注册表**吗？](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [**您可以利用任何未加引号的服务二进制**路径吗？](windows-local-privilege-escalation/#unquoted-service-paths)

### [**应用程序**](windows-local-privilege-escalation/#applications)

* [ ] 对已安装应用程序的[**写入权限**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**启动应用程序**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **存在漏洞的** [**驱动程序**](windows-local-privilege-escalation/#drivers)

### [DLL劫持](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] 您可以**在PATH中的任何文件夹内写入**吗？
* [ ] 是否有任何已知的服务二进制文件**尝试加载任何不存在的DLL**？
* [ ] 您可以**在任何二进制文件夹中写入**吗？

### [网络](windows-local-privilege-escalation/#network)

* [ ] 枚举网络（共享、接口、路由、邻居等）
* [ ] 特别注意监听localhost (127.0.0.1)的网络服务

### [Windows凭据](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)凭据
* [ ] 您可以使用的[**Windows保险箱**](windows-local-privilege-escalation/#credentials-manager-windows-vault)凭据？
* [ ] 有趣的[**DPAPI凭据**](windows-local-privilege-escalation/#dpapi)？
* [ ] 已保存[**Wifi网络**](windows-local-privilege-escalation/#wifi)的密码？
* [ ] [**已保存的RDP连接**](windows-local-privilege-escalation/#saved-rdp-connections)中的有趣信息？
* [ ] [**最近运行的命令**](windows-local-privilege-escalation/#recently-run-commands)中的密码？
* [ ] [**远程桌面凭据管理器**](windows-local-privilege-escalation/#remote-desktop-credential-manager)密码？
* [ ] [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)存在吗？凭据？
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)？DLL侧加载？

### [文件和注册表（凭据）](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty：** [**凭据**](windows-local-privilege-escalation/#putty-creds) **和** [**SSH主机密钥**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**注册表中的SSH密钥**](windows-local-privilege-escalation/#ssh-keys-in-registry)？
* [ ] [**无人值守文件**](windows-local-privilege-escalation/#unattended-files)中的密码？
* [ ] 任何[**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)备份？
* [ ] [**云凭据**](windows-local-privilege-escalation/#cloud-credentials)？
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)文件？
* [ ] [**缓存的GPP密码**](windows-local-privilege-escalation/#cached-gpp-pasword)？
* [ ] [**IIS Web配置文件**](windows-local-privilege-escalation/#iis-web-config)中的密码？
* [ ] [**网络** **日志**](windows-local-privilege-escalation/#logs)中的有趣信息？
* [ ] 您想[**向用户请求凭据**](windows-local-privilege-escalation/#ask-for-credentials)吗？
* [ ] [**回收站内的有趣文件**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)？
* [ ] [**注册表中包含凭据的其他地方**](windows-local-privilege-escalation/#inside-the-registry)？
* [ ] [**浏览器数据内**](windows-local-privilege-escalation/#browsers-history)（数据库、历史记录、书签等）？
* [ ] [**文件和注册表中的通用密码搜索**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)
* [ ] [**自动搜索密码的工具**](windows-local-privilege-escalation/#tools-that-search-for-passwords)

### [泄露的处理程序](windows-local-privilege-escalation/#leaked-handlers)

* [ ] 您是否可以访问由管理员运行的进程的任何处理程序？

### [管道客户端模拟](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] 检查是否可以滥用它

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
