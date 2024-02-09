# 骨架密钥

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 骨架密钥攻击

**骨架密钥攻击**是一种复杂的技术，允许攻击者通过向域控制器**注入主密码**来**绕过Active Directory身份验证**。这使得攻击者可以**以任何用户的身份进行身份验证**，而无需其密码，有效地**授予他们对域的无限制访问权限**。

可以使用[Mimikatz](https://github.com/gentilkiwi/mimikatz)执行此攻击。要执行此攻击，**需要域管理员权限**，攻击者必须针对每个域控制器以确保全面入侵。然而，由于**重新启动域控制器会清除恶意软件**，因此攻击的效果是暂时的，需要重新实施以获得持续访问权限。

**执行攻击**只需一个命令：`misc::skeleton`。

## 缓解措施

针对此类攻击的缓解策略包括监视指示安装服务或使用敏感权限的特定事件ID。具体来说，查找System事件ID 7045或Security事件ID 4673可以揭示可疑活动。此外，将`lsass.exe`作为受保护进程运行可以显著阻碍攻击者的努力，因为这要求他们使用内核模式驱动程序，增加了攻击的复杂性。

以下是增强安全措施的PowerShell命令：

- 要检测可疑服务的安装，请使用：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
  
- 具体来说，要检测Mimikatz的驱动程序，可以使用以下命令：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
  
- 为加固`lsass.exe`，建议将其作为受保护进程启用：`New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

重启系统后进行验证至关重要，以确保保护措施已成功应用。可以通过以下方式实现：`Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## 参考资料
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
