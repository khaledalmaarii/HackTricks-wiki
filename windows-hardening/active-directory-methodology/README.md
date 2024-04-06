# Active Directory Methodology

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本概述

**Active Directory**作为一项基础技术，使**网络管理员**能够高效地在网络中创建和管理**域**、**用户**和**对象**。它被设计为可扩展的，便于将大量用户组织成可管理的**组**和**子组**，同时在不同层级上控制**访问权限**。

**Active Directory**的结构由三个主要层级组成：**域**、**树**和**森林**。**域**包含一组对象，如**用户**或**设备**，共享一个数据库。**树**是由这些域组成的群组，通过共享结构连接在一起，**森林**代表多个树的集合，通过**信任关系**相互连接，形成组织结构的最高层。在每个层级上可以指定特定的**访问**和**通信权限**。

**Active Directory**中的关键概念包括：

1. **目录** – 存储有关Active Directory对象的所有信息。
2. **对象** – 表示目录中的实体，包括**用户**、**组**或**共享文件夹**。
3. **域** – 作为目录对象的容器，多个域可以共存于一个**森林**中，每个域维护自己的对象集合。
4. **树** – 共享一个公共根域的域的分组。
5. **森林** – Active Directory组织结构的最高层，由多个通过**信任关系**相互连接的树组成。

\*\*Active Directory域服务（AD DS）\*\*涵盖了网络中的集中管理和通信所必需的一系列服务。这些服务包括：

1. **域服务** – 集中存储数据并管理**用户**和**域**之间的交互，包括**认证**和**搜索**功能。
2. **证书服务** – 管理安全**数字证书**的创建、分发和管理。
3. **轻量级目录服务** – 通过**LDAP协议**支持启用目录的应用程序。
4. **目录联合服务** – 提供**单点登录**功能，以在单个会话中对多个Web应用程序的用户进行身份验证。
5. **权限管理** – 通过监管未经授权的分发和使用来帮助保护版权材料。
6. **DNS服务** – 对于**域名**的解析至关重要。

有关更详细的解释，请查看：[**TechTerms - Active Directory定义**](https://techterms.com/definition/active\_directory)

### **Kerberos认证**

要学习如何**攻击AD**，您需要非常了解**Kerberos认证过程**。\
[**如果您仍不了解其工作原理，请阅读此页面。**](kerberos-authentication.md)

## 备忘单

您可以访问[https://wadcoms.github.io/](https://wadcoms.github.io)快速查看可以运行以枚举/利用AD的命令。

## 侦察Active Directory（无凭证/会话）

如果您只能访问AD环境但没有任何凭证/会话，您可以：

* **对网络进行渗透测试：**
* 扫描网络，查找机器和打开端口，尝试从中**利用漏洞**或**提取凭证**（例如，[打印机可能是非常有趣的目标](ad-information-in-printers.md)）。
* 枚举DNS可能会提供关于域中关键服务器（如Web、打印机、共享、VPN、媒体等）的信息。
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* 查看通用[**渗透测试方法论**](../../generic-methodologies-and-resources/pentesting-methodology.md)以获取更多关于如何执行此操作的信息。
* **检查SMB服务上的空和Guest访问权限**（这在现代Windows版本上不起作用）：
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* 可以在此找到有关如何枚举SMB服务器的更详细指南：

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **枚举LDAP**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* 可以在此找到有关如何枚举LDAP的更详细指南（特别注意匿名访问）：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **毒害网络**
* 收集凭证[**模拟使用Responder的服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* 通过[**滥用中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)访问主机
* 通过[**暴露带有evil-S的虚假UPnP服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)收集凭证
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology)：
* 从内部文档、社交媒体、域环境内的服务（主要是Web）以及公开可用的地方提取公司员工的用户名/姓名。
* 如果找到公司员工的完整姓名，可以尝试不同的AD**用户名约定（**[**阅读此内容**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的约定有：_NameSurname_、_Name.Surname_、_NamSur_（每个字母3个）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3个\_随机字母和3个随机数字\_（abc123）。
* 工具：
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

* **匿名SMB/LDAP枚举：** 查看[**渗透测试SMB**](../../network-services-pentesting/pentesting-smb/)和[**渗透测试LDAP**](../../network-services-pentesting/pentesting-ldap.md)页面。
* **Kerbrute枚举**：当请求一个**无效的用户名**时，服务器将使用\_Kerberos错误\_代码\_KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN\_进行响应，从而使我们能够确定用户名无效。**有效的用户名**将在\_AS-REP\_响应中产生\_TGT\_，或者产生错误\_KRB5KDC\_ERR\_PREAUTH\_REQUIRED\_，表明用户需要执行预身份验证。

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```

* **OWA (Outlook Web Access) 服务器**

如果在网络中找到了这些服务器，您还可以对其执行**用户枚举**。例如，您可以使用工具[**MailSniper**](https://github.com/dafthack/MailSniper)：

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
您可以在[**此 GitHub 存储库**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)和这个([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))中找到用户名列表。

但是，您应该在执行此步骤之前进行的侦察步骤中获得了**公司员工的姓名**。有了名字和姓氏，您可以使用脚本[**namemash.py**](https://gist.github.com/superkojiman/11076951)生成潜在的有效用户名。
{% endhint %}

### 知道一个或多个用户名

好的，所以您知道已经有一个有效的用户名，但没有密码... 然后尝试：

* [**ASREPRoast**](asreproast.md)：如果用户**没有**属性 _DONT\_REQ\_PREAUTH_，您可以为该用户**请求 AS\_REP 消息**，该消息将包含由用户密码的派生加密的一些数据。
* [**密码喷洒**](password-spraying.md)：尝试使用发现的每个用户的**常见密码**，也许某些用户正在使用弱密码（请记住密码策略！）。
* 请注意，您还可以**喷洒 OWA 服务器**，尝试访问用户的邮件服务器。

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS 毒化

您可能能够通过**毒化**网络的一些协议来**获得**一些挑战**哈希**以破解：

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML 中继

如果您已枚举出活动目录，您将获得**更多的电子邮件和对网络的更好理解**。您可能能够强制进行 NTML [**中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)以访问 AD 环境。

### 窃取 NTLM 凭证

如果您可以使用**空用户或访客用户**访问其他计算机或共享，您可以**放置文件**（如 SCF 文件），如果某种方式访问了这些文件，将会**触发对您的 NTML 认证**，以便您可以**窃取\*\*\*\*NTLM 挑战**以破解它：

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## 使用凭证/会话枚举活动目录

在此阶段，您需要**破解有效域帐户的凭证或会话**。如果您有一些有效凭证或作为域用户的 shell，**请记住之前提供的选项仍然是妥协其他用户的选项**。

在开始经过身份验证的枚举之前，您应该了解**Kerberos 双跳问题**。

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### 枚举

获得一个帐户的控制权是**开始妥协整个域的重要一步**，因为您将能够开始**活动目录枚举：**

关于[**ASREPRoast**](asreproast.md)，您现在可以找到每个可能易受攻击的用户，关于[**密码喷洒**](password-spraying.md)，您可以获取**所有用户名的列表**，并尝试使用被妥协帐户的密码、空密码和新的有希望的密码。

* 您可以使用[**CMD 执行基本侦察**](../basic-cmd-for-pentesters.md#domain-info)
* 您还可以使用[**用于侦察的 PowerShell**](../basic-powershell-for-pentesters/)，这将更隐蔽
* 您还可以使用[**powerview**](../basic-powershell-for-pentesters/powerview.md)提取更详细的信息
* 在活动目录中进行侦察的另一个神奇工具是[**BloodHound**](bloodhound.md)。它**不太隐蔽**（取决于您使用的收集方法），但**如果您不在乎**，绝对值得一试。找到用户可以 RDP 的位置，找到其他组的路径等。
* **其他自动化的 AD 枚举工具有：**[**AD Explorer**](bloodhound.md#ad-explorer)**、**[**ADRecon**](bloodhound.md#adrecon)**、**[**Group3r**](bloodhound.md#group3r)**、**[**PingCastle**](bloodhound.md#pingcastle)**。**
* [**AD 的 DNS 记录**](ad-dns-records.md)可能包含有趣的信息。
* 一个您可以使用的具有 GUI 的**工具**来枚举目录是来自**SysInternal** Suite 的**AdExplorer.exe**。
* 您还可以使用**ldapsearch**在 LDAP 数据库中搜索以查找字段\_userPassword\_和\_unixUserPassword\_中的凭证，甚至是\_Description\_。参见[PayloadsAllTheThings 上的 AD 用户评论中的密码](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)以获取其他方法。
* 如果您使用**Linux**，您还可以使用[**pywerview**](https://github.com/the-useless-one/pywerview)枚举域。
* 您还可以尝试自动化工具，如：
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
* **提取所有域用户**

从 Windows（`net user /domain`，`Get-DomainUser`或`wmic useraccount get name,sid`）很容易获取所有域用户名。在 Linux 中，您可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username`或`enum4linux -a -u "user" -p "password" <DC IP>`

> 即使此枚举部分看起来很小，这是最重要的部分。访问链接（主要是 cmd、powershell、powerview 和 BloodHound 的链接），学习如何枚举域并练习直到您感到自在。在评估期间，这将是找到通往 DA 的关键时刻，或者决定无法做任何事情的关键时刻。

### Kerberoast

Kerberoasting 包括获取与用户帐户绑定的服务使用的**TGS 票证**并**离线**破解其基于用户密码的加密。

有关更多信息，请参阅：

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### 远程连接（RDP、SSH、FTP、Win-RM 等）

一旦您获得了一些凭证，您可以检查是否可以访问任何**计算机**。为此，您可以使用**CrackMapExec**尝试使用不同协议连接到多台服务器，根据您的端口扫描。

### 本地权限提升

如果您作为常规域用户获得了凭证或会话，并且可以使用此用户访问域中的任何计算机，您应该尝试找到提升本地权限和窃取凭证的方法。这是因为只有具有本地管理员权限，您才能在内存（LSASS）和本地（SAM）中**转储其他用户的哈希**。

本书中有一整页关于[**Windows 中的本地权限提升**](../windows-local-privilege-escalation/)和一个[**清单**](../checklist-windows-privilege-escalation.md)。此外，不要忘记使用[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### 当前会话票证

当前用户的**票证**中很**不可能**会发现**允许访问**意外资源的权限，但您可以检查：

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTML Relay

如果你已经枚举了活动目录，你将拥有更多的电子邮件和对网络的更好理解。你可能能够强制进行 NTML 中继攻击。

### 在计算机共享中查找凭证

现在你已经有了一些基本凭证，你应该检查是否可以在活动目录中找到任何共享的有趣文件。你可以手动执行此操作，但这是一项非常乏味重复的任务（尤其是如果你发现需要检查数百个文档）。

[**点击此链接了解可使用的工具。**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### 窃取 NTLM 凭证

如果你可以访问其他计算机或共享，你可以放置文件（如一个 SCF 文件），如果某种方式被访问，将会触发一个针对你的 NTML 认证，这样你就可以窃取 NTLM 挑战以破解它：

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何经过身份验证的用户妥协域控制器。

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## 在具有特权凭证/会话的活动目录上提升权限

**对于以下技术，普通域用户是不够的，你需要一些特殊的特权/凭证来执行这些攻击。**

### 提取哈希

希望你已经成功妥协了一些本地管理员帐户，使用 AsRepRoast、Password Spraying、Kerberoast、Responder 包括中继、EvilSSDP、本地权限提升等方法。\
然后，是时候在内存和本地转储所有哈希了。\
[**阅读此页面了解获取哈希的不同方法。**](https://github.com/carlospolop/hacktricks/blob/cn/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 传递哈希

**一旦你有了用户的哈希，你可以使用它来冒充该用户。**\
你需要使用一些工具，它将使用该哈希执行 NTLM 认证，或者你可以创建一个新的 sessionlogon 并将该哈希注入 LSASS，因此当执行任何 NTLM 认证时，将使用该哈希。最后一种选择是 mimikatz 所做的。\
[**阅读此页面获取更多信息。**](../ntlm/#pass-the-hash)

### 超越传递哈希/传递密钥

这种攻击旨在使用用户的 NTLM 哈希请求 Kerberos 门票，作为常见的通过 NTLM 协议传递哈希的替代方法。因此，在禁用 NTLM 协议且仅允许 Kerberos 作为认证协议的网络中，这可能特别有用。

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### 传递门票

在“传递门票（PTT）”攻击方法中，攻击者窃取用户的认证票据，而不是其密码或哈希值。然后使用这个被窃取的票据冒充用户，获取对网络中资源和服务的未授权访问。

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### 凭证重用

如果你有本地管理员的哈希或密码，你应该尝试使用它在其他计算机上进行本地登录。

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

{% hint style="warning" %}
请注意，这可能会**嘈杂**，而**LAPS**可以**减轻**这种情况。
{% endhint %}

### MSSQL 滥用 & 受信任的链接

如果用户具有**访问 MSSQL 实例的权限**，他可能能够使用它在 MSSQL 主机中（如果作为 SA 运行）**执行命令**，**窃取** NetNTLM **哈希**，甚至执行**中继** **攻击**。\
此外，如果一个 MSSQL 实例被另一个 MSSQL 实例信任（数据库链接）。如果用户对受信任的数据库具有权限，他将能够**使用信任关系在另一个实例中执行查询**。这些信任可以链接在一起，用户最终可能能够找到一个配置错误的数据库，从而可以执行命令。\
**数据库之间的链接甚至可以跨森林信任工作。**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### 无限制委派

如果发现任何具有属性 [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) 的计算机对象，并且您在计算机中具有域权限，您将能够从每个登录到计算机的用户的内存中转储 TGT。\
因此，如果**域管理员登录到计算机**，您将能够转储他的 TGT 并使用 [传递票据](pass-the-ticket.md) 模拟他。\
借助有限制的委派，您甚至可以**自动妥协打印服务器**（希望它将是 DC）。

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### 有限制的委派

如果允许用户或计算机进行“有限制的委派”，它将能够**模拟任何用户以访问计算机中的某些服务**。\
然后，如果您**妥协了此用户/计算机的哈希**，您将能够**模拟任何用户**（甚至域管理员）以访问某些服务。

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### 基于资源的有限制委派

在远程计算机的 Active Directory 对象上具有**写入**权限可以实现以**提升权限**执行代码：

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACL 滥用

受损的用户可能对一些**域对象**具有一些**有趣的特权**，这可能让您**横向移动**/**提升**特权。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 打印池服务滥用

发现域中有一个**监听 Spool 服务**的服务可能会被**滥用**以**获取新凭证**和**提升权限**。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 第三方会话滥用

如果**其他用户访问受损**的计算机，可以**从内存中收集凭证**，甚至**在其进程中注入信标**以冒充他们。\
通常用户将通过 RDP 访问系统，因此您可以在这里执行一些关于第三方 RDP 会话的攻击：

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** 提供了一个管理域加入计算机上的**本地管理员密码**的系统，确保其是**随机的**、唯一的，并经常**更改**。这些密码存储在 Active Directory 中，并且通过 ACLs 仅控制授权用户的访问。有足够权限访问这些密码，就可以进行到其他计算机的转移。

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### 证书窃取

从受损计算机中**收集证书**可能是升级环境中的权限的一种方式：

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### 证书模板滥用

如果**配置了易受攻击的模板**，可以滥用它们以提升权限：

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## 具有高权限帐户的后期利用

### 转储域凭据

一旦获得**域管理员**甚至更好的**企业管理员**权限，您可以**转储**域数据库：_ntds.dit_。

[**有关 DCSync 攻击的更多信息，请参阅此处**](dcsync.md)。

[**有关如何窃取 NTDS.dit 的更多信息，请参阅此处**](https://github.com/carlospolop/hacktricks/blob/cn/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 特权升级作为持久性

之前讨论过的一些技术可以用于持久性。\
例如，您可以：

* 使用户容易受到 [**Kerberoast**](kerberoast.md) 的攻击

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

* 使用户容易受到 [**ASREPRoast**](asreproast.md) 的攻击

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

* 授予用户 [**DCSync**](./#dcsync) 权限

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### 银票据

**银票据攻击**通过使用（例如，PC 帐户的**哈希**）创建特定服务的**合法票据授予服务 (TGS) 票据**。此方法用于**访问服务权限**。

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### 金票据

**金票据攻击**涉及攻击者获取 Active Directory（AD）环境中 **krbtgt 帐户的 NTLM 哈希**。此帐户特殊之处在于它用于签署所有**票据授予票据 (TGTs)**，这对于在 AD 网络内进行身份验证至关重要。

一旦攻击者获得此哈希，他们可以为他们选择的任何帐户创建**TGTs**（银票据攻击）。

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### 钻石票据

这些类似于以一种方式伪造的金票据，**绕过常见的金票据检测机制**。

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **证书帐户持久性**

**拥有帐户的证书或能够请求它们**是一种非常好的方式，可以在用户帐户中**持久存在**（即使他更改密码）：

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **证书域持久性**

**使用证书也可以在域内以高权限持久存在**：

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder 组

Active Directory 中的 **AdminSDHolder** 对象通过在这些组上应用标准的 **访问控制列表 (ACL)** 来确保**特权组**（如域管理员和企业管理员）的安全，以防止未经授权的更改。但是，这个功能可以被利用；如果攻击者修改 AdminSDHolder 的 ACL 以授予常规用户完全访问权限，那么该用户将对所有特权组拥有广泛的控制权。这个旨在保护的安全措施可能会逆火，除非受到密切监视，否则会导致未经授权的访问。

[**有关 AdminDSHolder 组的更多信息，请点击此处。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM 凭据

在每个**域控制器 (DC)** 中都存在一个**本地管理员**帐户。通过在这样的计算机上获得管理员权限，可以使用 **mimikatz** 提取本地管理员哈希。随后，需要进行注册表修改以**启用使用此密码**，从而实现远程访问本地管理员帐户。

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL 持久性

您可以对某些特定域对象的**用户**授予**特殊权限**，这将使用户能够在将来**提升权限**。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 安全描述符

**安全描述符** 用于**存储**对象对**对象**的**权限**。如果您可以**对对象的安全描述符进行小小更改**，则可以在不需要成为特权组成员的情况下获得对该对象的非常有趣的权限。

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### 骨架密钥

在内存中更改 **LSASS** 以建立**通用密码**，从而授予对所有域帐户的访问权限。

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### 自定义 SSP

[了解什么是 SSP（安全支持提供程序）请点击此处。](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
您可以创建**自己的 SSP** 以**以明文**捕获用于访问计算机的**凭据**。

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

它在 AD 中注册一个**新的域控制器**，并使用它来在指定对象上**推送属性**（SIDHistory、SPN...），而不会留下任何关于**修改**的**日志**。您需要 DA 权限并位于**根域**内。\
请注意，如果使用错误的数据，将会出现非常丑陋的日志。

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS 持久性

之前我们已经讨论了如果您有**足够的权限读取 LAPS 密码**如何升级权限。但是，这些密码也可以用于**保持持久性**。\
查看：

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## 森林特权升级 - 域信任

微软将**森林**视为安全边界。这意味着**入侵单个域可能导致整个森林被入侵**。

### 基本信息

[**域信任**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) 是一种安全机制，使一个**域**的用户能够访问另一个**域**中的资源。它实质上在两个域的认证系统之间创建了一个链接，允许认证验证无缝流动。当域建立信任时，它们在它们的**域控制器 (DCs)** 中交换并保留特定的**密钥**，这对信任的完整性至关重要。

在典型情况下，如果用户打算访问**受信任域**中的服务，他们必须首先从自己域的 DC 请求一个称为**领域间 TGT** 的特殊票据。这个 TGT 使用两个域已经同意的共享**密钥**进行加密。然后用户将此 TGT 提交给**受信任域的 DC** 以获取一个服务票据 (**TGS**)。在受信任域的 DC 成功验证领域间 TGT 后，它会发放一个 TGS，授予用户访问服务的权限。

**步骤**：

1. **域 1** 中的**客户计算机**通过使用其**NTLM 哈希**从其**域控制器 (DC1)** 请求一个**票据授予票据 (TGT)** 来启动该过程。
2. 如果客户成功验证，DC1将发放一个新的 TGT。
3. 然后客户从 DC1 请求一个**领域间 TGT**，这是访问**域 2** 中资源所需的。
4. 领域间 TGT 使用 DC1 和 DC2 之间共享的**信任密钥**进行加密，这是双向域信任的一部分。
5. 客户将领域间 TGT 带到**域 2 的域控制器 (DC2)**。
6. DC2使用其共享的信任密钥验证领域间 TGT，并在有效时发放一个用于访问客户想要访问的域 2 中的服务器的**票据授予服务 (TGS)**。
7. 最后，客户将此 TGS 提交给服务器，该服务器使用其帐户哈希进行加密，以获取对域 2 中服务的访问权限。

### 不同的信任

重要的是要注意**信任可以是单向的或双向的**。在双向选项中，两个域将相互信任，但在**单向**信任关系中，其中一个域将是**受信任**域，另一个是**信任**域。在最后一种情况下，**您只能从受信任域访问信任域内的资源**。

如果域 A 信任域 B，则 A 是信任域，B 是受信任域。此外，在**域 A** 中，这将是**出站信任**；在**域 B** 中，这将是**入站信任**。

**不同的信任关系**

* **父子信任**：这是同一森林中常见的设置，其中子域自动与其父域建立双向传递信任。基本上，这意味着认证

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
有**2个受信任的密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
您可以使用以下命令查看当前域使用的密钥：

```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

利用SID-History注入来升级为企业管理员，滥用与SID-History注入相关的子/父域之间的信任：

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### 利用可写的配置NC

了解如何利用配置命名上下文（NC）是至关重要的。配置NC在Active Directory（AD）环境中充当跨森林的配置数据的中央存储库。这些数据会被复制到森林中的每个域控制器（DC），可写DC会维护配置NC的可写副本。要利用这一点，必须在DC上具有**SYSTEM特权**，最好是子DC。

**将GPO链接到根DC站点**

配置NC的站点容器包含有关AD森林中所有域加入计算机站点的信息。通过在任何DC上以SYSTEM特权运行，攻击者可以将GPO链接到根DC站点。这一操作可能通过操纵应用于这些站点的策略来危害根域。

要深入了解信息，可以研究有关[绕过SID过滤](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)的研究。

**危害森林中的任何gMSA**

一种攻击向量涉及针对域内特权gMSA。KDS根密钥，用于计算gMSA密码，存储在配置NC中。通过在任何DC上具有SYSTEM特权，可以访问KDS根密钥并计算森林中任何gMSA的密码。

有关详细分析，请参阅[Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)中的讨论。

**模式更改攻击**

此方法需要耐心等待新特权AD对象的创建。具有SYSTEM特权的攻击者可以修改AD模式以授予任何用户对所有类的完全控制。这可能导致对新创建的AD对象的未经授权访问和控制。

可在[Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)中找到更多阅读材料。

**从DA到EA使用ADCS ESC5**

ADCS ESC5漏洞旨在控制公钥基础设施（PKI）对象，以创建一个证书模板，使得可以作为森林中的任何用户进行身份验证。由于PKI对象驻留在配置NC中，因此攻击者可以通过妥善利用可写子DC来执行ESC5攻击。

有关更多详细信息，请阅读[From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在缺乏ADCS的情况下，攻击者有能力设置必要的组件，如[从子域管理员升级为企业管理员](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)中所讨论的。

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

在这种情况下，**您的域受到外部域的信任**，使您对其拥有**未确定的权限**。您需要找出**您的域的哪些主体对外部域具有哪些访问权限**，然后尝试利用它：

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

在这种情况下，**您的域**正在向来自**不同域**的主体授予一些**特权**。

然而，当受信任的域信任信任域时，受信任的域会创建一个使用**受信任密码**作为密码的**可预测名称**的用户。这意味着可以**访问信任域中的用户**以进入受信任域进行枚举并尝试提升更多特权：

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

另一种妥协受信任域的方法是找到在域信任的**相反方向**上创建的[**SQL受信任链接**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种妥协受信任域的方法是等待在受信任域用户可以访问的计算机上登录，然后通过**RDP**登录。然后，攻击者可以在RDP会话过程中注入代码并从那里**访问受害者的原始域**。\
此外，如果**受害者挂载了他的硬盘**，攻击者可以在**硬盘的启动文件夹**中存储**后门**。这种技术称为**RDPInception**。

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### 域信任滥用缓解

### **SID 过滤:**

* 通过SID过滤来减轻跨森林信任中利用SID历史属性的攻击风险，SID过滤在所有森林信任上默认激活。这是基于一个假设，即考虑到森林而不是域，将森林视为安全边界，符合微软的立场。
* 然而，有一个问题：SID过滤可能会干扰应用程序和用户访问，导致偶尔禁用。

### **选择性身份验证:**

* 对于森林间的信任，使用选择性身份验证确保来自两个森林的用户不会自动验证。相反，需要为用户访问信任域或森林内的域和服务器授予明确权限。
* 需要注意的是，这些措施并不能防止对可写配置命名上下文（NC）的利用或对信任帐户的攻击。

[**有关域信任的更多信息，请访问ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## 一些常规防御措施

[**了解如何保护凭据的更多信息。**](../stealing-credentials/credentials-protections.md)\\

### **保护凭据的防御措施**

* **域管理员限制**: 建议只允许域管理员登录域控制器，避免在其他主机上使用他们。
* **服务帐户特权**: 服务不应以域管理员（DA）特权运行，以保持安全性。
* **临时特权限制**: 对于需要DA特权的任务，其持续时间应受限制。可以通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **实施欺骗技术**

* 实施欺骗技术涉及设置陷阱，如虚假用户或计算机，具有诸如不过期或标记为可委派的密码等功能。详细方法包括创建具有特定权限的用户或将其添加到高特权组中。
* 一个实际的例子涉及使用工具：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* 有关部署欺骗技术的更多信息，请访问[GitHub上的Deploy-Deception](https://github.com/samratashok/Deploy-Deception)。

### **识别欺骗**

* **对于用户对象**: 可疑指标包括非典型的ObjectSID、不经常的登录、创建日期和低错误密码计数。
* **一般指标**: 将潜在的虚假对象的属性与真实对象的属性进行比较，可以揭示不一致之处。像[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)这样的工具可以帮助识别这种欺骗。

### **绕过检测系统**

* **Microsoft ATA检测绕过**:
* **用户枚举**: 避免在域控制器上进行会话枚举以防止ATA检测。
* **票据冒充**: 利用**aes**密钥进行票据创建有助于通过不降级为NTLM来避免检测。
* **DCSync攻击**: 建议从非域控制器执行以避免ATA检测，因为直接从域控制器执行会触发警报。

## 参考资料

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF版HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
