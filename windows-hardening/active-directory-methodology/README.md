# Active Directory 方法论

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在**HackTricks**上看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载HackTricks的PDF**？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **提交PR来分享你的黑客技巧**和[**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud)。

</details>

## 基本概述

Active Directory 允许网络管理员在网络中创建和管理域、用户和对象。例如，管理员可以创建一个用户组，并给予他们对服务器上某些目录的特定访问权限。随着网络的增长，Active Directory 提供了一种组织大量用户到逻辑组和子组的方法，同时在每个级别提供访问控制。

Active Directory 结构包括三个主要层次：1) 域，2) 树，和 3) 森林。几个对象（用户或设备）可能被分组到一个单一的域中，它们都使用相同的数据库。多个域可以组合成一个称为树的单一组。多个树可以组合成一个称为森林的集合。这些级别中的每一个都可以被分配特定的访问权和通信权限。

Active Directory 的主要概念：

1. **目录** – 包含 Active Directory 对象的所有信息
2. **对象** – 对象几乎指目录内的任何东西（用户、组、共享文件夹...）
3. **域** – 目录的对象被包含在域内。在一个“森林”中可以存在多个域，每个域都有自己的对象集合。
4. **树** – 具有相同根的域组。例如：_dom.local, email.dom.local, www.dom.local_
5. **森林** – 森林是组织层次结构的最高级别，由一组树组成。这些树通过信任关系连接。

Active Directory 提供了几种不同的服务，这些服务统称为“Active Directory 域服务”或 AD DS。这些服务包括：

1. **域服务** – 存储集中数据并管理用户和域之间的通信；包括登录认证和搜索功能
2. **证书服务** – 创建、分发和管理安全证书
3. **轻量级目录服务** – 使用开放的（LDAP）协议支持目录启用的应用程序
4. **目录联合服务** – 提供单点登录（SSO），在单个会话中认证用户访问多个网络应用程序
5. **权利管理** – 通过防止未经授权的使用和分发数字内容来保护版权信息
6. **DNS服务** – 用于解析域名。

AD DS 包含在 Windows Server（包括 Windows Server 10）中，旨在管理客户端系统。虽然运行常规版本的 Windows 的系统没有 AD DS 的管理功能，但它们确实支持 Active Directory。这意味着任何 Windows 计算机都可以连接到 Windows 工作组，前提是用户具有正确的登录凭据。\
**来源：** [**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active\_directory)

### **Kerberos 认证**

要学习如何**攻击 AD**，你需要非常好地**理解 Kerberos 认证过程**。\
[**如果你还不知道它是如何工作的，请阅读此页面。**](kerberos-authentication.md)

## 速查表

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io) 快速查看你可以运行哪些命令来枚举/利用 AD。

## Recon Active Directory（无凭证/会话）

如果你只是能够访问 AD 环境，但没有任何凭证/会话，你可以：

* **渗透测试网络：**
* 扫描网络，找到机器和开放端口，并尝试**利用漏洞**或**提取凭证**（例如，[打印机可能是非常有趣的目标](ad-information-in-printers.md)。
* 枚举 DNS 可以获得域中关键服务器的信息，如网页、打印机、共享、VPN、媒体等。
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* 查看通用[**渗透测试方法论**](../../generic-methodologies-and-resources/pentesting-methodology.md)以获取更多关于如何做到这一点的信息。
* **检查 smb 服务上的 null 和 Guest 访问**（这在现代 Windows 版本上不起作用）：
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* 关于如何枚举 SMB 服务器的更详细指南可以在这里找到：

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **枚举 Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* 关于如何枚举 LDAP 的更详细指南可以在这里找到（**特别注意匿名访问**）：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **网络投毒**
* 通过[**冒充服务与 Responder 收集凭证**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* 通过[**滥用中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)访问主机
* 通过[**暴露**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) [**假的 UPnP 服务与 evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 收集凭证
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology)：
* 从内部文件、社交媒体、服务（主要是网页）中提取用户名/姓名，在域环境内以及公开可用的信息中。
* 如果你找到公司员工的全名，你可以尝试不同的 AD **用户名约定**（[**阅读这个**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的约定是：_NameSurname_, _Name.Surname_, _NamSur_（每个3个字母），_Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3个_随机字母和3个随机数字_（abc123）。
* 工具：
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

* **匿名 SMB/LDAP 枚举：** 查看[**渗透测试 SMB**](../../network-services-pentesting/pentesting-smb.md) 和 [**渗透测试 LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
* **Kerbrute 枚举**：当**请求无效用户名**时，服务器将使用**Kerberos 错误**代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 响应，允许我们确定用户名无效。**有效的用户名**将引发**TGT 在 AS-REP**响应中或错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表明用户需要执行预认证。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA (Outlook Web Access) 服务器**

如果你在网络中发现了这样的服务器，你也可以对其执行**用户枚举**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper)：
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
您可以在[**这个github仓库**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)中找到用户名单，还有这个仓库（[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)）。

不过，您应该已经从之前的侦察步骤中获得了**公司员工的姓名**。有了名字和姓氏，您可以使用脚本[**namemash.py**](https://gist.github.com/superkojiman/11076951)来生成潜在有效的用户名。
{% endhint %}

### 知道一个或多个用户名

好的，所以你现在已经有了一个有效的用户名，但没有密码... 那么尝试：

* [**ASREPRoast**](asreproast.md)：如果用户**没有**属性 _DONT\_REQ\_PREAUTH_，您可以**请求该用户的AS\_REP消息**，其中将包含一些由用户密码派生加密的数据。
* [**Password Spraying**](password-spraying.md)：让我们尝试使用每个发现的用户的最**常见密码**，也许有些用户使用了弱密码（记住密码策略！）。
* 注意，您还可以**喷涂OWA服务器**，尝试获取用户邮件服务器的访问权限。

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS投毒

您可能能够通过**投毒**某些**网络**协议来**获取**一些挑战**哈希值**以供破解：

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML中继

如果您已经枚举了活动目录，您将拥有**更多的电子邮件和对网络更深入的了解**。您可能能够强制NTML [**中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)以获取AD环境的访问权限。

### 盗取NTLM凭证

如果您可以使用**null或guest用户**访问其他PC或共享，您可以**放置文件**（如SCF文件），如果以某种方式访问，将**触发对您的NTML认证**，这样您就可以**盗取**用于破解的**NTLM挑战**：

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## 使用凭证/会话枚举活动目录

在这个阶段，您需要**危及有效域帐户的凭证或会话**。如果您拥有一些有效的凭证或作为域用户的shell，**您应该记住之前给出的选项仍然是危及其他用户的选项**。

在开始认证枚举之前，您应该了解什么是**Kerberos双跳问题**。

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### 枚举

危及一个帐户是**开始危及整个域的大步骤**，因为您将能够开始**活动目录枚举：**

关于[**ASREPRoast**](asreproast.md)，您现在可以找到每个可能的脆弱用户，关于[**Password Spraying**](password-spraying.md)，您可以获取**所有用户名的列表**，并尝试已危及帐户的密码、空密码和新的有希望的密码。

* 您可以使用[**CMD进行基本侦察**](../basic-cmd-for-pentesters.md#domain-info)
* 您也可以使用[**powershell进行侦察**](../basic-powershell-for-pentesters/)，这将更隐蔽
* 您还可以[**使用powerview**](../basic-powershell-for-pentesters/powerview.md)提取更详细的信息
* 另一个在活动目录中进行侦察的惊人工具是[**BloodHound**](bloodhound.md)。它**不是很隐蔽**（取决于您使用的收集方法），但**如果您不在乎**，您应该完全尝试一下。找到用户可以RDP的地方，找到通往其他组的路径等。
* **其他自动化AD枚举工具包括：**[**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**。**
* [**AD的DNS记录**](ad-dns-records.md)，因为它们可能包含有趣的信息。
* 您可以使用的一个**带GUI的工具**来枚举目录是**SysInternal**套件中的**AdExplorer.exe**。
* 您还可以使用**ldapsearch**在LDAP数据库中搜索，寻找_userPassword_和_unixUserPassword_字段中的凭证，甚至是_Description_。参见[PayloadsAllTheThings上的AD用户评论中的密码](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)了解其他方法。
* 如果您使用的是**Linux**，您还可以使用[**pywerview**](https://github.com/the-useless-one/pywerview)来枚举域。
* 您还可以尝试自动化工具，如：
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **提取所有域用户**

从Windows获取所有域用户名非常容易（`net user /domain`，`Get-DomainUser`或`wmic useraccount get name,sid`）。在Linux中，您可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username`或`enum4linux -a -u "user" -p "password" <DC IP>`

> 即使这个枚举部分看起来很小，这是所有部分中最重要的部分。访问链接（主要是cmd、powershell、powerview和BloodHound的链接），学习如何枚举域，并练习直到您感到舒适。在评估期间，这将是找到通往DA的方法或决定无法做任何事情的关键时刻。

### Kerberoast

Kerberoasting的目标是收集代表域用户帐户运行的**服务的TGS票据**。这些TGS票据的一部分是用从用户密码派生的密钥**加密的**。因此，它们的凭证可以**离线破解**。\
更多关于这个：

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### 远程连接（RDP、SSH、FTP、Win-RM等）

一旦您获得了一些凭证，您可以检查是否可以访问任何**机器**。为此，您可以使用**CrackMapExec**尝试使用不同的协议连接到几个服务器，根据您的端口扫描。

### 本地权限提升

如果您已经危及了作为普通域用户的凭证或会话，并且您可以使用此用户访问**域中的任何机器**，您应该尝试找到方法来**在本地提升权限并寻找凭证**。这是因为只有具有本地管理员权限，您才能**转储内存中的其他用户的哈希值**（LSASS）和本地（SAM）。

本书中有一个完整的页面关于[**Windows中的本地权限提升**](../windows-local-privilege-escalation/)和一个[**检查清单**](../checklist-windows-privilege-escalation.md)。另外，不要忘记使用[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### 当前会话票据

您很**不可能**在当前用户中找到**授予您访问**意外资源的**票据**，但您可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML 中继

如果您已经成功枚举了活动目录，您将拥有**更多的电子邮件和对网络更好的了解**。您可能能够强制执行NTML [**中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)。

### **在计算机共享中寻找凭据**

现在您已经拥有一些基本凭据，您应该检查是否可以**在AD内找到**任何**有趣的共享文件**。您可以手动执行此操作，但这是一项非常枯燥重复的任务（如果您发现需要检查的文档有数百个，那就更加枯燥了）。

[**点击此链接了解您可以使用的工具。**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### 偷取 NTLM 凭据

如果您可以**访问其他PC或共享**，您可以**放置文件**（如SCF文件），如果以某种方式访问，将**触发对您的NTML认证**，这样您就可以**窃取**用于破解的**NTLM挑战**：

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

这个漏洞允许任何经过身份验证的用户**危害域控制器**。

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## 在具有特权凭据/会话的活动目录上的权限提升

**对于以下技术，普通域用户是不够的，您需要一些特殊权限/凭据来执行这些攻击。**

### 哈希提取

希望您已经成功**危害了一些本地管理员**账户，使用[AsRepRoast](asreproast.md)、[密码喷洒](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)包括中继、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[本地权限提升](../windows-local-privilege-escalation/)。\
然后，是时候转储内存中和本地的所有哈希了。\
[**阅读此页面了解获取哈希的不同方法。**](broken-reference/)

### 传递哈希

**一旦您拥有用户的哈希**，您可以使用它来**冒充**它。\
您需要使用一些**工具**来**执行**使用该**哈希**的**NTLM认证**，**或者**您可以创建一个新的**sessionlogon**并**注入**该**哈希**到**LSASS**中，所以当任何**NTLM认证执行时**，将使用该**哈希**。mimikatz所做的就是最后一个选项。\
[**阅读此页面了解更多信息。**](../ntlm/#pass-the-hash)

### 超越传递哈希/传递密钥

这种攻击旨在**使用用户NTLM哈希请求Kerberos票据**，作为常见的NTLM协议上的传递哈希的替代方法。因此，这在只允许**Kerberos作为认证协议**并禁用NTLM协议的网络中尤其**有用**。

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### 传递票据

这种攻击与传递密钥类似，但不是使用哈希请求票据，而是**窃取票据本身**并使用它作为其所有者进行认证。

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### 凭据重用

如果您拥有**本地管理员**的**哈希**或**密码**，您应该尝试使用它**本地登录**到其他**PC**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
请注意，这是相当**嘈杂**的，而**LAPS**将会**减轻**这种情况。
{% endhint %}

### MSSQL 滥用和可信链接

如果用户有权限**访问 MSSQL 实例**，他可能能够使用它在 MSSQL 主机上**执行命令**（如果以 SA 身份运行），**窃取** NetNTLM **哈希**，甚至进行**中继** **攻击**。\
此外，如果一个 MSSQL 实例被另一个 MSSQL 实例信任（数据库链接）。如果用户对受信任的数据库有权限，他将能够**使用信任关系在另一个实例中执行查询**。这些信任可以被串联，用户可能最终能够找到一个配置不当的数据库，在那里他可以执行命令。\
**数据库之间的链接甚至可以跨越森林信任工作。**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### 无限制委派

如果您发现任何具有属性 [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) 的计算机对象，并且您在计算机上拥有域权限，您将能够从内存中转储每个登录到计算机的用户的 TGT。\
因此，如果**域管理员登录到计算机**，您将能够转储他的 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 伪装他。\
通过受限委派，您甚至可以**自动攻击打印服务器**（希望它是一个 DC）。

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### 受限委派

如果允许用户或计算机进行“受限委派”，它将能够**冒充任何用户访问计算机中的某些服务**。\
然后，如果您**攻破了**这个用户/计算机的**哈希**，您将能够**冒充任何用户**（甚至是域管理员）来访问某些服务。

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### 基于资源的受限委派

如果您对计算机的 AD 对象拥有写权限，您可以在远程计算机上获得具有**提升权限的代码执行**。

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACL 滥用

受损用户可能对某些域对象拥有一些**有趣的权限**，这些权限可以让您**横向移动**/**提升**权限。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 打印机假脱机服务滥用

如果您能在域内找到任何**监听的假脱机服务**，您可能能够**滥用**它来**获取新的凭据**和**提升权限**。\
[**关于如何滥用假脱机服务的更多信息在这里。**](printers-spooler-service-abuse.md)

### 第三方会话滥用

如果**其他用户** **访问** **受损**的机器，可以从内存中**收集凭据**，甚至**在他们的进程中注入信标**来冒充他们。\
通常用户会通过 RDP 访问系统，所以这里有如何对第三方 RDP 会话执行一对攻击的方法：

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** 允许您**管理本地管理员密码**（这是**随机化**的，唯一的，并且**定期更改**）在域加入的计算机上。这些密码在 Active Directory 中集中存储，并使用 ACL 限制授权用户。如果您有**足够的权限读取这些密码，您可以移动到其他计算机**。

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### 证书盗窃

从受损机器收集证书可能是提升环境内权限的一种方式：

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### 证书模板滥用

如果配置了易受攻击的模板，可以滥用它们来提升权限：

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## 拥有高权限账户的后期开发

### 转储域凭据

一旦您获得**域管理员**或更好的**企业管理员**权限，您可以**转储** **域数据库**：_ntds.dit_。

[**关于 DCSync 攻击的更多信息可以在这里找到**](dcsync.md)。

[**关于如何窃取 NTDS.dit 的更多信息可以在这里找到**](broken-reference/)

### Privesc 作为持久性

之前讨论的一些技术可以用于持久性。\
例如，您可以：

*   使用户易受 [**Kerberoast**](kerberoast.md) 攻击

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   使用户易受 [**ASREPRoast**](asreproast.md) 攻击

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   授予用户 [**DCSync**](./#dcsync) 权限

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### 银票

银票攻击基于**制作一个有效的 TGS 为服务一旦拥有服务的 NTLM 哈希**（如**PC 账户哈希**）。因此，通过伪造一个自定义 TGS **作为任何用户**（如获得对计算机的特权访问），可以**访问该服务**。

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### 金票

可以使用 krbtgt AD 账户的 NTLM 哈希**创建一个有效的 TGT 作为任何用户**。伪造 TGT 而不是 TGS 的优势是能够**访问域中的任何服务**（或机器）作为冒充的用户。

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### 钻石票

这些像金票一样被伪造，以**绕过常见的金票检测机制**。

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **证书账户持久性**

**拥有账户的证书或能够请求它们**是能够在用户账户中持久化的非常好的方式（即使他更改了密码）：

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **证书域持久性**

**使用证书也可以在域内持久化高权限：**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder 组

**AdminSDHolder** 对象的访问控制列表（ACL）用作模板，以**复制** **权限** 到 Active Directory 中的**所有“受保护组”**及其成员。受保护的组包括 Domain Admins、Administrators、Enterprise Admins 和 Schema Admins、Backup Operators 和 krbtgt 等特权组。\
默认情况下，该组的 ACL 被复制到所有“受保护的组”中。这样做是为了避免对这些关键组的故意或意外更改。然而，如果攻击者**修改**了组**AdminSDHolder**的 ACL，例如，给予普通用户完全权限，这个用户将在受保护组内的所有组中拥有完全权限（在一个小时内）。\
如果有人试图从 Domain Admins（例如）中删除这个用户，在一个小时或更短的时间内，用户将回到该组。\
[**关于 AdminDSHolder 组的更多信息在这里。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM 凭据

每个**DC**内部都有一个**本地管理员**账户。拥有这台机器的管理员权限，您可以使用 mimikatz **转储本地管理员哈希**。然后，修改注册表以**激活这个密码**，这样您就可以远程访问这个本地管理员用户。

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL 持久性

您可以**给予**某个**用户**对某些特定域对象的**特殊权限**，这将让用户**在未来提升权限**。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 安全描述符

**安全描述符**用于**存储**一个**对象**对**另一个对象**的**权限**。如果您只是在对象的**安全描述符**中**做出一点改变**，您可以在不需要成为特权组成员的情况下获得对该对象的非常有趣的权限。

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### 骷髅钥匙

**修改内存中的 LSASS** 创建一个**主密码**，适用于域中的任何账户。

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### 自定义 SSP

[了解什么是 SSP（安全支持提供者）在这里。](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
您可以创建您**自己的 SSP** 来**捕获**以**明文**形式使用的**凭据**来访问机器。\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

它在 AD 中注册一个**新的域控制器**并使用它来**推送属性**（SIDHistory、SPNs...）到指定对象**而不**留下任何关于**修改**的**日志**。您**需要 DA** 权限并位于**根域**内。\
请注意，如果您使用错误的数据，将会出现非常丑陋的日志。

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS 持久性

之前我们已经讨论了如何在您有**足够的权限读取 LAPS 密码**的情况下提升权限。然而，这些密码也可以用来**维持持久性**。\
检查：

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## 森林权限提升 - 域信任

Microsoft 认为**域不是安全边界**，**森林是安全边界**。这意味着**如果您攻破了森林内的一个域，您可能能够攻破整个森林**。

### 基本信息

从高层次上看，[**域信任**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx)建立了**一个域中的用户对另一个域的资源进行身份验证**的能力，或者作为[安全主体](https://technet.microsoft.com/en-us/library/cc780957\(v=ws.10\).aspx) **在另一个域中**的能力。

本质上，信任所做的就是**连接两个域的身份验证系统**，并允许身份验证流量通过一个推荐系统在它们之间流动。\
当**两个域相互信任时，它们会交换密钥**，这些**密钥**将被**保存**在**每个域的 DC** 中（**每个信任方向 2 个密钥，最新和之前的**），并且密钥将是信任的基础。

当**用户**尝试**访问** **信任域**中的**服务**时，它将向其域的 DC 请求一个**跨领域 TGT**。DC 将为客户端提供这个**TGT**，它将用**跨领域** **密钥**（两个域**交换**的密钥）**加密/签名**。然后，**客户端**将**访问** **另一个域的 DC** 并将使用**跨领域 TGT** **请求** 服务的**TGS**。信任域的**DC**将**检查**使用的**密钥**，如果没问题，它将**信任该票证中的所有内容**，并将 TGS 提供给客户端。

![](<../../.gitbook/assets/image (166) (1).png>)

### 不同的信任

重要的是要注意**信任可以是单向的或双向的**。在双向选项中，两个域将相互信任，但在**单向**信任关系中，一个域将是**受信任的**，另一个将是**信任的**域。在后一种情况下，**您只能从受信任的域访问信任域内的资源**。

如果域 A 信任域 B，A 是信任域，B 是受信任的。此外，在**域 A**中，这将是一个**出站信任**；并且在**域 B**中，这将是一个**入站信任**。

**不同的信任关系**

* **父子** - 属于同一个森林 - 子域与其父域保留隐式的双向传递信任。这可能是您最常遇到的信任类型。
* **交叉链接** - 子域之间的“快捷信任”，以改善推荐时间。通常在复杂的森林中的推荐必须先过滤到森林根，然后再回到目标域，所以对于地理分布广泛的情况，交叉链接可以减少身份验证时间。
* **外部** - 在不同域之
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
存在**2个受信任的密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
您可以使用当前域的密钥：
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
#### SID-History 注入

以企业管理员身份升级到子域/父域，通过 SID-History 注入滥用信任关系：

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### 利用可写的 Configuration NC

Configuration NC 是森林配置信息的主要存储库，并复制到森林中的每个 DC。此外，森林中的每个可写 DC（非只读 DC）都持有 Configuration NC 的可写副本。利用这一点需要在（子）DC 上以 SYSTEM 身份运行。

有多种方法可以危及根域，下面将详细介绍。

**将 GPO 链接到根 DC 站点**

Configuration NC 中的 Sites 容器包含 AD 森林中加入域的计算机的所有站点。当以任何森林中的 DC 的 SYSTEM 身份运行时，可以将 GPO 链接到站点，包括森林根 DC 的站点，从而危及这些站点。

更多细节可以在这里阅读 [Bypass SID filtering research](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)。

**在森林中危及任何 gMSA**

攻击依赖于目标域中的具有特权的 gMSA。

用于计算森林中 gMSA 密码的 KDS 根密钥存储在 Configuration NC 中。当在森林中的任何 DC 上以 SYSTEM 身份运行时，可以读出 KDS 根密钥并计算森林中任何 gMSA 的密码。

更多细节可以在这里阅读：[Golden gMSA trust attack from child to parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**架构更改攻击**

攻击要求攻击者等待新的具有特权的 AD 对象被创建。

当在森林中的任何 DC 上以 SYSTEM 身份运行时，可以授予任何用户对 AD 架构中所有类的完全控制。可以滥用该控制权，在任何 AD 对象的默认安全描述符中创建一个 ACE，该 ACE 授予对受损主体的完全控制。修改后的 AD 对象类型的所有新实例都将具有此 ACE。

更多细节可以在这里阅读：[Schema change trust attack from child to parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

**通过 ADCS ESC5 从 DA 到 EA**

ADCS ESC5（易受攻击的 PKI 对象访问控制）攻击滥用对 PKI 对象的控制，创建一个易受攻击的证书模板，可以用来作为森林中任何用户进行认证。由于所有 PKI 对象都存储在 Configuration NC 中，如果有人危及了森林中的任何可写（子）DC，就可以执行 ESC5。

更多细节可以在这里阅读：[From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)

如果 AD 森林没有 ADCS，攻击者可以按照这里描述的创建必要组件：[Escalating from child domain’s admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

### 外部森林域 - 单向（入站）或双向
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
在这种情况下，**你的域被一个外部域信任**，给予你对它的**不确定的权限**。你需要找出**你的域中哪些主体对外部域有哪些访问权限**，然后尝试利用它：

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### 外部森林域 - 单向（出站）
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
在这种情况下，**你的域**正在信任来自**不同域**的主体的一些**权限**。

然而，当一个**域被信任域信任**时，被信任的域会**创建一个用户**，这个用户有一个**可预测的名称**，并使用**被信任的密码**作为密码。这意味着有可能**访问信任域的用户以进入被信任的域**，对其进行枚举并尝试提升更多权限：

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

另一种侵入被信任域的方法是找到一个在域信任的**相反方向**创建的[**SQL信任链接**](abusing-ad-mssql.md#mssql-trusted-links)（这不是很常见）。

另一种侵入被信任域的方法是在一个**被信任域的用户可以访问**的机器上等待，通过**RDP**登录。然后，攻击者可以在RDP会话进程中注入代码，并**从那里访问受害者的原始域**。\
此外，如果**受害者挂载了他的硬盘驱动器**，从**RDP会话**进程中，攻击者可以在**硬盘启动文件夹**中存储**后门**。这种技术被称为**RDPInception**。

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### 域信任滥用缓解

**SID过滤：**

* 避免滥用跨森林信任的SID历史属性的攻击。
* 默认在所有跨森林信任上启用。默认情况下，假设森林内信任是安全的（微软认为森林而不是域是安全边界）。
* 但是，由于SID过滤可能会破坏应用程序和用户访问，因此它经常被禁用。
* 选择性认证
* 在跨森林信任中，如果配置了选择性认证，信任之间的用户将不会自动被认证。应该给予信任域/森林中的域和服务器的个别访问权限。
* 不能防止可写配置NC利用和信任账户攻击。

[**在ired.team上了解更多关于域信任的信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> 云 & 云 -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## 一些通用防御措施

[**在这里了解更多关于如何保护凭证的信息。**](../stealing-credentials/credentials-protections.md)\
**请在技术描述中找到针对每种技术的一些迁移措施。**

* 不允许域管理员在域控制器之外的任何其他主机上登录
* 永远不要以DA权限运行服务
* 如果你需要域管理员权限，限制时间：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### 欺骗

* 密码不过期
* 受信任的委派
* 拥有SPN的用户
* 描述中的密码
* 是高权限组成员的用户
* 对其他用户、组或容器拥有ACL权限的用户
* 计算机对象
* ...
* [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
* `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

## 如何识别欺骗

**对于用户对象：**

* ObjectSID（与域不同）
* lastLogon, lastlogontimestamp
* Logoncount（非常低的数字是可疑的）
* whenCreated
* Badpwdcount（非常低的数字是可疑的）

**通用：**

* 有些解决方案会在所有可能的属性中填充信息。例如，将计算机对象的属性与DC这样的100%真实计算机对象的属性进行比较。或者将用户与RID 500（默认管理员）进行比较。
* 检查是否有些东西好得难以置信
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### 绕过Microsoft ATA检测

#### 用户枚举

ATA只在你尝试在DC中枚举会话时抱怨，所以如果你不在DC中寻找会话而是在其他主机中寻找，你可能不会被检测到。

#### 票据冒充创建（Over pass the hash, golden ticket...）

始终使用**aes**密钥创建票据，因为ATA识别为恶意的是降级到NTLM。

#### DCSync

如果你不是从域控制器执行此操作，ATA会抓到你，抱歉。

## 更多工具

* [Powershell脚本进行域审计自动化](https://github.com/phillips321/adaudit)
* [Python脚本枚举活动目录](https://github.com/ropnop/windapsearch)
* [Python脚本枚举活动目录](https://github.com/CroweCybersecurity/ad-ldap-enum)

## 参考

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**hacktricks repo**](https://github.com/carlospolop/hacktricks) 和 [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)提交PR来**分享你的黑客技巧**。

</details>
