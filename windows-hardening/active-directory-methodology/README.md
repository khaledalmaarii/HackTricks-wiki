# Active Directory 方法论

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告** 吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 基本概述

Active Directory 允许网络管理员在网络中创建和管理域、用户和对象。例如，管理员可以创建一个用户组，并为他们在服务器上的特定目录提供特定的访问权限。随着网络的增长，Active Directory 提供了一种将大量用户组织成逻辑组和子组的方式，并在每个级别提供访问控制。

Active Directory 结构包括三个主要层次：1) 域，2) 树，和 3) 林。多个使用相同数据库的对象（用户或设备）可以分组到一个单独的域中。多个域可以组合成一个称为树的单个组。多个树可以组合成一个称为林的集合。每个级别都可以分配特定的访问权限和通信特权。

Active Directory 提供了几种不同的服务，这些服务属于 "Active Directory 域服务" 或 AD DS 的范畴。这些服务包括：

1. **域服务** - 存储集中化数据并管理用户和域之间的通信；包括登录认证和搜索功能
2. **证书服务** - 创建、分发和管理安全证书
3. **轻量级目录服务** - 使用开放的 (LDAP) 协议支持目录启用的应用程序
4. **目录联合服务** - 提供单点登录 (SSO)，以在单个会话中对多个 Web 应用程序进行用户身份验证
5. **权限管理** - 通过防止未经授权的使用和分发数字内容来保护版权信息
6. **DNS 服务** - 用于解析域名。

AD DS 包含在 Windows Server 中（包括 Windows Server 10）并设计用于管理客户端系统。虽然运行常规版本的 Windows 的系统没有 AD DS 的管理功能，但它们支持 Active Directory。这意味着任何 Windows 计算机都可以连接到 Windows 工作组，只要用户具有正确的登录凭据。\
**来源：**[**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active\_directory)

### **Kerberos 认证**

要学习如何**攻击 AD**，你需要**深入了解** Kerberos 认证过程。\
[**如果你还不知道它是如何工作的，请阅读此页面。**](kerberos-authentication.md)

## 速查表

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io) 查看可以运行以枚举/利用 AD 的命令。

## 侦察 Active Directory（无凭证/会话）

如果你只能访问 AD 环境，但没有任何凭证/会话，你可以：

* **渗透测试网络：**
* 扫描网络，查找机器和打开的端口，并尝试从中**利用漏洞**或**提取凭证**（例如，[打印机可能是非常有趣的目标](ad-information-in-printers.md)）。
* 枚举 DNS 可以提供关于域中的关键服务器（如 Web、打印机、共享、VPN、媒体等）的信息。
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* 查看通用的[**渗透测试方法论**](../../generic-methodologies-and-resources/pentesting-methodology.md)以获取更多关于如何执行此操作的信息。
* **检查 smb 服务上的空和 Guest 访问**（这在现代 Windows 版本上不起作用）：
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* 关于如何枚举 SMB 服务器的更详细指南可以在这里找到：

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **枚举 Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* 关于如何枚举 LDAP 的更详细指南可以在这里找到（特别注意匿名访问）：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **中毒网络**
* 收集凭证[**模拟 Responder 服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* 通过[滥用中继攻击](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)访问主机
* 使用[evil-S**SDP](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)暴露虚假UPnP服务来收集凭据
* [OSINT](https://book.hacktricks.xyz/external-recon-methodology):
* 从内部文档、社交媒体、域环境内的服务（主要是Web）以及公开可用的地方提取用户名/姓名
* 如果找到公司员工的完整姓名，可以尝试不同的AD用户名约定（[阅读此处](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的约定有：_NameSurname_，_Name.Surname_，_NamSur_（每个字母的前3个字母），_Nam.Sur_，_NSurname_，_N.Surname_，_SurnameName_，_Surname.Name_，_SurnameN_，_Surname.N_，3个_随机字母和3个随机数字_（abc123）。
* 工具：
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

* **匿名SMB/LDAP枚举：**请查看[**渗透测试SMB**](../../network-services-pentesting/pentesting-smb.md)和[**渗透测试LDAP**](../../network-services-pentesting/pentesting-ldap.md)页面。
* **Kerbrute枚举：**当请求一个**无效的用户名**时，服务器将使用Kerberos错误代码_KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_进行响应，从而使我们能够确定用户名无效。**有效的用户名**将引发AS-REP响应中的TGT或错误_KRB5KDC\_ERR\_PREAUTH\_REQUIRED_，表示用户需要执行预身份验证。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA（Outlook Web Access）服务器**

如果在网络中发现了其中一个服务器，您还可以对其执行**用户枚举**。例如，您可以使用工具[**MailSniper**](https://github.com/dafthack/MailSniper)：
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
您可以在[**此 GitHub 仓库**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)和[**此仓库**](https://github.com/insidetrust/statistically-likely-usernames)中找到用户名列表。

然而，您应该从之前的侦察步骤中获得的公司员工的姓名。有了名字和姓氏，您可以使用脚本[**namemash.py**](https://gist.github.com/superkojiman/11076951)生成潜在的有效用户名。
{% endhint %}

### 已知一个或多个用户名

好的，所以您知道已经有一个有效的用户名，但没有密码...然后尝试：

* [**ASREPRoast**](asreproast.md)：如果用户**没有**属性_DONT\_REQ\_PREAUTH_，您可以为该用户**请求一个 AS\_REP 消息**，该消息将包含由用户密码的派生加密的一些数据。
* [**密码喷洒**](password-spraying.md)：尝试使用已发现的每个用户的**常见密码**，也许某个用户正在使用弱密码（请记住密码策略！）。
* 请注意，您还可以**喷洒 OWA 服务器**，以尝试访问用户的邮件服务器。

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS 毒化

您可以通过**毒化**网络的一些协议来**获取**一些挑战**哈希**以破解：

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML 中继

如果您已经枚举了活动目录，您将拥有**更多的电子邮件和对网络的更好了解**。您可以尝试强制进行 NTML [**中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)以访问 AD 环境。

### 窃取 NTML 凭证

如果您可以使用**空用户或访客用户**访问其他计算机或共享资源，您可以**放置文件**（如 SCF 文件），如果以某种方式访问，将**触发针对您的 NTML 认证**，以便您可以**窃取** NTML 挑战并破解它：

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## 使用凭证/会话枚举 Active Directory

在此阶段，您需要**获取有效域帐户的凭证或会话**。如果您拥有一些有效凭证或作为域用户的 shell，**您应该记住之前给出的选项仍然是获取其他用户凭证的选项**。

在开始经过身份验证的枚举之前，您应该了解**Kerberos 双跳问题**。

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### 枚举

获得一个帐户是开始入侵整个域的**重要一步**，因为您将能够开始**枚举 Active Directory**：

关于[**ASREPRoast**](asreproast.md)，您现在可以找到每个可能的易受攻击的用户，关于[**密码喷洒**](password-spraying.md)，您可以获得**所有用户名的列表**并尝试使用被入侵帐户的密码、空密码和新的有希望的密码。

* 您可以使用[**CMD 进行基本侦察**](../basic-cmd-for-pentesters.md#domain-info)
* 您还可以使用[**用于侦察的 PowerShell**](../basic-powershell-for-pentesters/)，这将更隐蔽
* 您还可以使用[**powerview**](../basic-powershell-for-pentesters/powerview.md)提取更详细的信息
* 在活动目录中进行侦察的另一个很棒的工具是[**BloodHound**](bloodhound.md)。它**不太隐蔽**（取决于您使用的收集方法），但**如果您不在意**，您应该完全尝试一下。找到用户可以进行 RDP 的位置，找到到其他组的路径等。
* **其他自动化的 AD 枚举工具有：**[**AD Explorer**](bloodhound.md#ad-explorer)**、**[**ADRecon**](bloodhound.md#adrecon)**、**[**Group3r**](bloodhound.md#group3r)**、**[**PingCastle**](bloodhound.md#pingcastle)**。**
* [**AD 的 DNS 记录**](ad-dns-records.md)可能包含有趣的信息。
* 一个可以用于枚举目录的**带有图形界面的工具**是来自**SysInternal**套件的**AdExplorer.exe**。
* 您还可以使用**ldapsearch**在 LDAP 数据库中搜索以查找字段_userPassword_和_unixUserPassword_中的凭据，甚至可以搜索_Description_字段。参见[PayloadsAllTheThings 上的 AD 用户注释中的密码](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)以获取其他方法。
* 如果您使用的是**Linux**，您还可以使用[**pywerview**](https://github.com/the-useless-one/pywerview)枚举域。
* 您还可以尝试自动化工具，如：
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **提取所有域用户**

从 Windows（`net user /domain`、`Get-DomainUser`或`wmic useraccount get name,sid`）中获取所有域用户名非常容易。在 Linux 中，您可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username`或`enum4linux -a -u "user" -p "password" <DC IP>`

> 即使此枚举部分看起来很小，但这是最重要的部分。访问链接（主要是 cmd、powershell、powerview 和 BloodHound），学习如何枚举域并进行实践，直到您感到舒适。在评估过程中，这将是找到 DA 的关键时刻，或者决定无法做任何事情的时刻。
### Kerberoast

Kerberoast的目标是收集代表域用户帐户运行的服务的TGS票据。这些TGS票据的一部分使用从用户密码派生的密钥进行加密。因此，它们的凭据可以在离线环境中被破解。
了解更多信息：

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### 远程连接（RDP，SSH，FTP，Win-RM等）

一旦您获得了一些凭据，您可以检查是否可以访问任何机器。为此，您可以使用CrackMapExec尝试使用不同协议连接到多个服务器，根据您的端口扫描结果。

### 本地权限提升

如果您拥有被入侵的凭据或作为常规域用户的会话，并且您可以使用此用户访问域中的任何机器，您应该尝试找到提升本地权限和窃取凭据的方法。这是因为只有具有本地管理员权限，您才能在内存（LSASS）和本地（SAM）中转储其他用户的哈希。

本书中有一整页关于[Windows中的本地权限提升](../windows-local-privilege-escalation/)和一个[检查清单](../checklist-windows-privilege-escalation.md)。此外，不要忘记使用[WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### 当前会话票据

很不可能在当前用户中找到授予您访问意外资源的票据，但您可以进行检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

如果你已经成功枚举了活动目录，你将会有更多的电子邮件和对网络的更好理解。你可能能够强制进行NTML中继攻击。

### 在计算机共享中查找凭据

现在你已经获得了一些基本凭据，你应该检查是否可以在AD内找到任何有趣的共享文件。你可以手动进行，但这是一项非常乏味重复的任务（如果你找到了数百个需要检查的文档，那就更加乏味了）。

[**点击此链接了解你可以使用的工具。**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### 窃取NTLM凭据

如果你可以访问其他计算机或共享，你可以放置一些文件（如SCF文件），如果以某种方式访问，将会对你发起NTML身份验证，以便你可以窃取NTLM挑战并破解它：

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何经过身份验证的用户**危害域控制器**。

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## 使用特权凭据/会话提升Active Directory

**对于以下技术，普通域用户是不够的，你需要一些特殊的权限/凭据来执行这些攻击。**

### 提取哈希

希望你已经成功**破解了一些本地管理员**账户，使用[AsRepRoast](asreproast.md)，[Password Spraying](password-spraying.md)，[Kerberoast](kerberoast.md)，[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)包括中继，[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)，[提升本地权限](../windows-local-privilege-escalation/)。\
然后，是时候将所有哈希值转储到内存和本地了。\
[**阅读此页面了解不同获取哈希值的方法。**](broken-reference)

### 传递哈希

**一旦你获得了用户的哈希值**，你可以使用它来**冒充**该用户。\
你需要使用一些**工具**来**使用**该**哈希值**执行**NTLM身份验证**，或者你可以创建一个新的**sessionlogon**并将该**哈希值**注入**LSASS**，这样当执行任何**NTLM身份验证**时，将使用该**哈希值**。这是mimikatz所做的最后选择。\
[**阅读此页面获取更多信息。**](../ntlm/#pass-the-hash)

### 超越传递哈希/传递密钥

这种攻击旨在使用用户NTLM哈希请求Kerberos票据，作为常规Pass The Hash over NTLM协议的替代方法。因此，在禁用NTLM协议并只允许Kerberos作为认证协议的网络中，这可能特别有用。

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### 传递票据

这种攻击类似于传递密钥，但不是使用哈希值请求票据，而是窃取票据并用其所有者的身份进行身份验证。

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### 凭据重用

如果你有一个**本地管理员的哈希值**或**密码**，你应该尝试使用它在其他计算机上进行本地登录。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
请注意，这可能会产生很多**噪音**，而且**LAPS**可以**减轻**这种情况。
{% endhint %}

### MSSQL滥用和可信链接

如果用户具有**访问MSSQL实例的权限**，他可能能够使用它在MSSQL主机中**执行命令**（如果作为SA运行），**窃取**NetNTLM **哈希**，甚至执行**中继** **攻击**。\
此外，如果一个MSSQL实例被另一个MSSQL实例信任（数据库链接）。如果用户对受信任的数据库具有权限，他将能够**使用信任关系在其他实例中执行查询**。这些信任可以链接在一起，用户可能能够找到一个配置错误的数据库，从而可以在其中执行命令。\
**数据库之间的链接甚至可以跨域信任工作。**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### 无限制委派

如果您找到任何具有属性[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)的计算机对象，并且您在计算机上具有域权限，则可以从每个登录到计算机的用户的内存中转储TGT。\
因此，如果**域管理员登录到计算机**，您将能够转储他的TGT并使用[传递票证](pass-the-ticket.md)冒充他。\
通过受限委派，您甚至可以**自动攻击打印服务器**（希望它是一个DC）。

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### 受限委派

如果允许用户或计算机进行“受限委派”，它将能够**冒充任何用户以访问计算机中的某些服务**。\
然后，如果您**破解**了此用户/计算机的哈希，您将能够**冒充任何用户**（甚至是域管理员）以访问某些服务。

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### 基于资源的受限委派

如果您对远程计算机的AD对象具有**写入权限**，则可以在该计算机上以**提升的权限执行代码**。

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACL滥用

被入侵的用户可能对某些域对象具有一些**有趣的权限**，这可能使您能够**横向移动**/**提升**权限。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 打印机打印池服务滥用

如果您可以找到域内的任何**打印池服务监听**，您可能能够**滥用**它以**获取新的凭据**和**提升权限**。\
[**在此处了解有关如何滥用打印池服务的更多信息。**](printers-spooler-service-abuse.md)

### 第三方会话滥用

如果**其他用户**访问**被入侵的**计算机，您可以从内存中**获取凭据**，甚至**在其进程中注入信标**以冒充他们。\
通常，用户将通过RDP访问系统，因此您可以了解如何对第三方RDP会话执行一些攻击：

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS**允许您**管理域加入计算机上的本地管理员密码**（该密码是**随机**、**唯一**且**定期更改**的）。这些密码以集中方式存储在Active Directory中，并使用ACLs限制授权用户。如果您有**足够的权限读取这些密码，您可以转移到其他计算机**。

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### 证书窃取

从被入侵的计算机收集证书可能是升级环境中的权限的一种方式：

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### 证书模板滥用

如果配置了易受攻击的模板，则可以滥用它们以提升权限：

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## 具有高权限帐户的后渗透

### 转储域凭据

一旦获得**域管理员**甚至更好的**企业管理员**权限，您可以**转储**域数据库：_ntds.dit_。

[**在此处了解有关DCSync攻击的更多信息**](dcsync.md)。

[**在此处了解有关如何窃取NTDS.dit的更多信息**](broken-reference)

### 权限提升作为持久性

之前讨论的一些技术可以用于持久性。\
例如，您可以：

*   使用户容易受到[**Kerberoast**](kerberoast.md)的攻击

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   使用户容易受到[**ASREPRoast**](asreproast.md)的攻击

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   授予用户[**DCSync**](./#dcsync)权限

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### 银票证

银票证攻击是基于**拥有服务的NTLM哈希**（如**PC帐户哈希**）来**构造有效的TGS**。因此，可以通过伪造自定义TGS**作为任何用户**（如对计算机的特权访问）来**访问该服务**。

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}
### 黄金票据

可以使用krbtgt AD账户的NTLM哈希值创建一个有效的TGT，而不管是哪个用户。与伪造TGS相比，伪造TGT的优势在于能够以冒名顶替的用户身份访问域中的任何服务（或机器）。

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### 钻石票据

这些票据就像以一种绕过常见黄金票据检测机制的方式伪造的黄金票据。

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### 证书账户持久性

拥有一个账户的证书或能够请求这些证书是一种非常好的方式，可以在用户账户中持久存在（即使用户更改了密码）：

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### 证书域持久性

使用证书也可以在域中以高权限持久存在：

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder组

“AdminSDHolder”对象的访问控制列表（ACL）被用作将权限复制到Active Directory中的所有“受保护组”及其成员的模板。受保护组包括特权组，如域管理员、管理员、企业管理员和模式管理员、备份操作员和krbtgt。

默认情况下，此组的ACL会被复制到所有“受保护组”中。这样做是为了防止对这些关键组的故意或意外更改。然而，如果攻击者修改了“AdminSDHolder”组的ACL，例如，给一个普通用户完全权限，那么这个用户将在受保护组中的所有组上拥有完全权限（在一个小时内）。

如果有人在一个小时内或更短的时间内尝试从域管理员中删除此用户，那么该用户将重新加入该组。

[有关AdminSDHolder组的更多信息，请点击此处。](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM凭据

每个DC中都有一个本地管理员账户。如果在该机器上拥有管理员权限，可以使用mimikatz来转储本地管理员哈希值。然后，修改注册表以激活此密码，以便可以远程访问此本地管理员用户。

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL持久性

您可以为某些特定的域对象授予某个用户一些特殊权限，以便用户将来可以提升权限。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 安全描述符

安全描述符用于存储对象对对象的权限。如果您只是对对象的安全描述符进行一点点的更改，就可以在不需要成为特权组成员的情况下获得对该对象的非常有趣的权限。

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### 骷髅钥匙

在内存中修改LSASS以创建一个适用于域中任何账户的主密码。

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### 自定义SSP

[在这里了解什么是SSP（安全支持提供程序）。](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)

您可以创建自己的SSP，以明文方式捕获用于访问机器的凭据。

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

它在AD中注册一个新的域控制器，并使用它来在指定的对象上推送属性（SIDHistory、SPN等），而不会留下任何关于修改的日志。您需要DA权限并位于根域中。

请注意，如果使用错误的数据，将会出现相当丑陋的日志。

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS持久性

之前我们已经讨论过如果有足够的权限来读取LAPS密码，如何升级权限。然而，这些密码也可以用于保持持久性。

请查看：

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## 森林权限提升 - 域信任

微软认为域不是安全边界，而是森林是安全边界。这意味着如果您入侵了森林中的一个域，您可能能够入侵整个森林。

### 基本信息

在高层次上，[域信任](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx)建立了一个能够使一个域中的用户对资源进行身份验证或充当另一个域中的安全主体的能力。

基本上，信任所做的就是将两个域的身份验证系统连接起来，并通过引荐系统允许身份验证流量在它们之间流动。

当两个域相互信任时，它们会交换密钥，这些密钥将保存在每个域的DC中（每个信任方向有2个密钥，最新的和之前的），这些密钥将成为信任的基础。

当用户尝试访问受信任域上的服务时，它将向其域的DC请求一个域间TGT。DC将为客户端提供此TGT，该TGT将使用域间密钥（两个域交换的密钥）进行加密/签名。然后，客户端将访问另一个域的DC，并使用域间TGT请求该服务的TGS。受信任域的DC将检查所使用的密钥，如果正确，它将信任该票据中的所有内容，并向客户端提供TGS。

![](<../../.gitbook/assets/image (166) (1).png>)
### 不同的信任关系

需要注意的是，**信任可以是单向的或双向的**。在双向选项中，两个域都会相互信任，但在**单向**信任关系中，一个域将成为**被信任**域，另一个域将成为**信任**域。在后一种情况下，**您只能从被信任的域中访问信任的域内的资源**。

如果域A信任域B，则A是信任域，B是被信任域。此外，在**域A**中，这将是一个**出站信任**；在**域B**中，这将是一个**入站信任**。

**不同的信任关系**

* **父子关系** - 属于同一森林 - 子域与其父域保持隐式的双向可传递信任关系。这可能是您遇到的最常见的信任类型。
* **交叉链接** - 即子域之间的“快捷信任”，用于改善引用时间。通常，在复杂的森林中，引用必须上溯到森林根，然后再返回到目标域，因此在地理分散的场景中，交叉链接可以减少认证时间。
* **外部** - 在不同的域之间创建的隐式非传递性信任。"[外部信任提供对森林之外的域中资源的访问，该域尚未通过森林信任加入。](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx)" 外部信任强制执行SID过滤，这是本文稍后介绍的一种安全保护措施。
* **树根** - 森林根域与您正在添加的新树根之间的隐式双向可传递信任。我并不经常遇到树根信任，但根据[Microsoft文档](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx)所述，当您在森林中创建一个新的域树时，它们会被创建。这些是森林内的信任关系，它们[保持双向传递性](https://technet.microsoft.com/en-us/library/cc757352\(v=ws.10\).aspx)，同时允许树具有单独的域名（而不是child.parent.com）。
* **森林** - 两个森林根域之间的传递性信任。森林信任还强制执行SID过滤。
* **MIT** - 与非Windows [RFC4120兼容](https://tools.ietf.org/html/rfc4120) 的Kerberos域的信任。我希望将来能更深入地研究MIT信任。

#### **信任关系**中的其他差异

* 信任关系也可以是**可传递的**（A信任B，B信任C，那么A信任C）或**不可传递的**。
* 信任关系可以设置为**双向信任**（两者互相信任）或**单向信任**（只有其中一个信任另一个）。

### 攻击路径

1. **枚举**信任关系
2. 检查任何**安全主体**（用户/组/计算机）是否可以访问**其他域**的资源，可能是通过ACE条目或在其他域的组中。寻找**跨域关系**（信任可能是为此创建的）。
1. 在这种情况下，kerberoast可能是另一个选择。
3. **入侵**可以通过域进行**枢轴**的**帐户**。

有三种**主要**方式，使来自一个域的安全主体（用户/组/计算机）可以访问另一个外部/信任域中的资源：

* 他们可以被添加到个别计算机上的**本地组**中，例如服务器上的本地“Administrators”组。
* 他们可以被添加到**外部域中的组**中。根据信任类型和组范围，可能会有一些注意事项，稍后会进行描述。
* 他们可以作为主体添加到**访问控制列表**中，对我们来说最有趣的是作为**DACL**中的**ACE**的主体。有关ACLs/DACLs/ACEs的更多背景信息，请查看“[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)”白皮书。

### 子域到父域的提权
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
有**2个受信任的密钥**，一个用于_子级 --> 父级_，另一个用于_父级_ --> _子级_。\
您可以使用以下命令找到当前域使用的密钥：
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

利用SID-History注入，将企业管理员权限提升到子/父域，滥用与SID-History注入相关的信任关系：

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### 利用可写的配置NC进行攻击

配置NC是一个森林中用于存储配置信息的主要存储库，并且会被复制到森林中的每个DC。此外，森林中的每个可写DC（而不是只读DC）都持有配置NC的可写副本。利用此漏洞需要在（子）DC上以SYSTEM权限运行。

可以通过以下多种方式来攻击根域。

##### 将GPO链接到根DC站点
配置NC中的Sites容器包含AD森林中加入域计算机的所有站点。在以任何DC的SYSTEM权限运行时，可以将GPO链接到站点，包括森林根DC的站点，从而对其进行攻击。

可以在此处阅读更多详细信息：[绕过SID过滤的研究](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)。

##### 攻击森林中的任何gMSA
该攻击依赖于目标域中的特权gMSA。

KDS根密钥用于计算森林中gMSA的密码，并存储在配置NC中。在森林中的任何DC上以SYSTEM权限运行时，可以读取KDS根密钥并计算森林中任何gMSA的密码。

可以在此处阅读更多详细信息：[从子域到父域的Golden gMSA信任攻击](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

##### 模式更改攻击
该攻击要求攻击者等待创建新的特权AD对象。

在森林中的任何DC上以SYSTEM权限运行时，可以授予任何用户对AD模式中的所有类的完全控制。可以滥用该控制来在任何AD对象的默认安全描述符中创建一个ACE，该ACE授予被攻陷的主体完全控制权限。修改后的AD对象类型的所有新实例都将具有此ACE。

可以在此处阅读更多详细信息：[从子域到父域的模式更改信任攻击](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

##### 通过ADCS ESC5从DA提升到EA
ADCS ESC5（易受攻击的PKI对象访问控制）攻击滥用对PKI对象的控制，创建一个易受攻击的证书模板，可以滥用该模板以任何用户的身份进行身份验证。由于所有PKI对象都存储在配置NC中，因此如果攻击者已经攻陷了森林中的任何可写（子）DC，则可以执行ESC5攻击。

可以在此处阅读更多详细信息：[从DA到EA的ESC5攻击](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)

如果AD森林没有ADCS，则攻击者可以按照此处描述的方式创建必要的组件：[通过滥用AD CS在5分钟内从子域管理员提升到企业管理员](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

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
在这种情况下，**您的域受到外部域的信任**，使您对其具有**未确定的权限**。您需要找出**您的域中的哪些主体对外部域具有哪些访问权限**，然后尝试利用它：

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
在这种情况下，**你的域**正在将一些**特权**委派给来自**不同域**的主体。

然而，当一个**域被信任**时，被信任的域会**创建一个用户**，使用信任密码作为**密码**。这意味着可以通过访问来自信任域的用户来进入被信任域，对其进行枚举并尝试提升更多的特权：

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

入侵被信任域的另一种方法是找到在域信任的**相反方向**上创建的[**SQL信任链接**](abusing-ad-mssql.md#mssql-trusted-links)（这种情况并不常见）。

入侵被信任域的另一种方法是在一个**被信任域的用户可以访问的机器上等待**，然后攻击者可以在RDP会话进程中注入代码，并从那里访问受害者的原始域。此外，如果**受害者挂载了他的硬盘**，攻击者可以在**硬盘的启动文件夹**中存储**后门**。这种技术被称为**RDPInception**。

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### 防止域信任滥用

**SID过滤：**

* 避免滥用跨域信任中的SID历史属性的攻击。
* 所有域间信任默认启用。域内信任默认被视为安全（微软认为森林而不是域是安全边界）。
* 但是，由于SID过滤可能破坏应用程序和用户访问，它经常被禁用。
* 选择性身份验证
* 在域间信任中，如果配置了选择性身份验证，则不会自动对信任域之间的用户进行身份验证。应该给予信任域/森林中的域和服务器个别访问权限。
* 无法防止可写配置NC的利用和信任账户攻击。

[**在ired.team上了解有关域信任的更多信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> 云 & 云 -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## 一些常规防御措施

[**在这里了解如何保护凭据。**](../stealing-credentials/credentials-protections.md)\
**请在每种技术的描述中找到一些对抗措施。**

* 不允许域管理员登录除域控制器之外的任何其他主机
* 永远不要以DA权限运行服务
* 如果需要域管理员权限，请限制时间：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### 诱骗

* 密码不过期
* 可信任的委派
* 具有SPN的用户
* 描述中的密码
* 高特权组的成员用户
* 具有其他用户、组或容器的ACL权限的用户
* 计算机对象
* ...
* [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
* `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

## 如何识别诱骗

**对于用户对象：**

* ObjectSID（与域不同）
* lastLogon、lastlogontimestamp
* Logoncount（非常低的数字是可疑的）
* whenCreated
* Badpwdcount（非常低的数字是可疑的）

**常规：**

* 一些解决方案会在所有可能的属性中填充信息。例如，将计算机对象的属性与100%真实的计算机对象（如DC）的属性进行比较。或者将用户与RID 500（默认管理员）进行比较。
* 检查是否有太好以至于难以置信的东西
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### 绕过Microsoft ATA检测

#### 用户枚举

ATA只在尝试枚举DC中的会话时才会报警，因此如果你不在DC中寻找会话而是在其他主机中寻找，你可能不会被检测到。

#### 伪造票据创建（通过哈希传递、黄金票据等）

始终使用**aes**密钥创建票据，因为ATA识别为恶意的是降级为NTLM的过程。

#### DCSync

如果你不是从域控制器上执行此操作，ATA将会捕捉到你，抱歉。

## 更多工具

* [用于域审计自动化的PowerShell脚本](https://github.com/phillips321/adaudit)
* [用于枚举Active Directory的Python脚本](https://github.com/ropnop/windapsearch)
* [用于枚举Active Directory的Python脚本](https://github.com/CroweCybersecurity/ad-ldap-enum)

## 参考资料

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
