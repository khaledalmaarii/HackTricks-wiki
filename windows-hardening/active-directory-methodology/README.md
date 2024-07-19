# Active Directory Methodology

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

## 基本概述

**Active Directory** 作为基础技术，使 **网络管理员** 能够高效地创建和管理网络中的 **域**、**用户** 和 **对象**。它被设计为可扩展，便于将大量用户组织成可管理的 **组** 和 **子组**，同时在不同级别上控制 **访问权限**。

**Active Directory** 的结构由三个主要层次组成：**域**、**树** 和 **森林**。一个 **域** 包含一组对象，如 **用户** 或 **设备**，共享一个公共数据库。**树** 是这些域的组，按共享结构连接，而 **森林** 代表多个树的集合，通过 **信任关系** 互联，形成组织结构的最上层。可以在每个级别指定特定的 **访问** 和 **通信权限**。

**Active Directory** 中的关键概念包括：

1. **目录** – 存储与 Active Directory 对象相关的所有信息。
2. **对象** – 指目录中的实体，包括 **用户**、**组** 或 **共享文件夹**。
3. **域** – 作为目录对象的容器，多个域可以在一个 **森林** 中共存，每个域维护自己的对象集合。
4. **树** – 一组共享公共根域的域。
5. **森林** – Active Directory 中组织结构的顶点，由多个树组成，彼此之间有 **信任关系**。

**Active Directory 域服务 (AD DS)** 包含一系列对网络内集中管理和通信至关重要的服务。这些服务包括：

1. **域服务** – 集中数据存储并管理 **用户** 和 **域** 之间的交互，包括 **身份验证** 和 **搜索** 功能。
2. **证书服务** – 负责安全 **数字证书** 的创建、分发和管理。
3. **轻量级目录服务** – 通过 **LDAP 协议** 支持目录启用的应用程序。
4. **目录联合服务** – 提供 **单点登录** 功能，以在单个会话中对多个 Web 应用程序进行用户身份验证。
5. **权限管理** – 通过规范其未经授权的分发和使用来帮助保护版权材料。
6. **DNS 服务** – 对 **域名** 的解析至关重要。

有关更详细的解释，请查看：[**TechTerms - Active Directory 定义**](https://techterms.com/definition/active\_directory)

### **Kerberos 认证**

要学习如何 **攻击 AD**，您需要非常好地 **理解** **Kerberos 认证过程**。\
[**如果您还不知道它是如何工作的，请阅读此页面。**](kerberos-authentication.md)

## 备忘单

您可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io) 快速查看可以运行的命令，以枚举/利用 AD。

## 侦察 Active Directory (无凭据/会话)

如果您仅访问 AD 环境，但没有任何凭据/会话，您可以：

* **渗透测试网络：**
* 扫描网络，查找机器和开放端口，并尝试 **利用漏洞** 或 **提取凭据**（例如，[打印机可能是非常有趣的目标](ad-information-in-printers.md)）。
* 枚举 DNS 可能会提供有关域中关键服务器的信息，如 Web、打印机、共享、VPN、媒体等。
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* 查看一般的 [**渗透测试方法论**](../../generic-methodologies-and-resources/pentesting-methodology.md)，以获取有关如何执行此操作的更多信息。
* **检查 SMB 服务上的空和访客访问**（这在现代 Windows 版本上不起作用）：
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* 有关如何枚举 SMB 服务器的更详细指南，请参见：

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **枚举 LDAP**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* 有关如何枚举 LDAP 的更详细指南，请参见此处（请 **特别注意匿名访问**）：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **毒化网络**
* 收集凭据 [**通过 Responder 冒充服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* 通过 [**滥用中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机
* 收集凭据 **暴露** [**假 UPnP 服务与 evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology)：
* 从内部文档、社交媒体、服务（主要是 Web）中提取用户名/姓名，以及从公开可用的信息中提取。
* 如果您找到公司员工的完整姓名，您可以尝试不同的 AD **用户名约定**（[**阅读此文**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的约定是：_NameSurname_、_Name.Surname_、_NamSur_（每个 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个 _随机字母和 3 个随机数字_（abc123）。
* 工具：
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

* **匿名 SMB/LDAP 枚举：** 查看 [**渗透测试 SMB**](../../network-services-pentesting/pentesting-smb/) 和 [**渗透测试 LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
* **Kerbrute 枚举**：当请求 **无效用户名** 时，服务器将使用 **Kerberos 错误** 代码 _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_ 响应，从而使我们能够确定用户名无效。 **有效用户名** 将引发 **AS-REP** 响应中的 **TGT** 或错误 _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_，指示用户需要执行预身份验证。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA (Outlook Web Access) 服务器**

如果您在网络中发现了这些服务器，您也可以对其执行 **用户枚举**。例如，您可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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
您可以在[**这个github仓库**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\*和这个([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))中找到用户名列表。

然而，您应该从之前执行的侦查步骤中获得**公司员工的姓名**。有了名字和姓氏，您可以使用脚本[**namemash.py**](https://gist.github.com/superkojiman/11076951)生成潜在的有效用户名。
{% endhint %}

### 知道一个或多个用户名

好的，您已经知道有一个有效的用户名，但没有密码……那么尝试：

* [**ASREPRoast**](asreproast.md)：如果用户**没有**属性_DONT\_REQ\_PREAUTH_，您可以**请求该用户的AS\_REP消息**，该消息将包含一些由用户密码的派生加密的数据。
* [**密码喷洒**](password-spraying.md)：让我们尝试对每个发现的用户使用最**常见的密码**，也许某个用户使用了一个糟糕的密码（请记住密码策略！）。
* 请注意，您还可以**喷洒OWA服务器**以尝试访问用户的邮件服务器。

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS 中毒

您可能能够**获取**一些挑战**哈希**以破解**中毒**某些网络协议：

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML 中继

如果您成功枚举了活动目录，您将拥有**更多的电子邮件和对网络的更好理解**。您可能能够强制进行NTML [**中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\*以获取对AD环境的访问。

### 窃取 NTLM 凭据

如果您可以使用**空或访客用户**访问其他PC或共享，您可以**放置文件**（如SCF文件），如果以某种方式访问，将**触发对您的NTML身份验证**，以便您可以**窃取** **NTLM挑战**进行破解：

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## 使用凭据/会话枚举活动目录

在此阶段，您需要**破坏有效域帐户的凭据或会话**。如果您有一些有效的凭据或作为域用户的shell，**您应该记住之前给出的选项仍然是破坏其他用户的选项**。

在开始经过身份验证的枚举之前，您应该了解**Kerberos双跳问题**。

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### 枚举

成功破坏一个帐户是**开始破坏整个域的重大步骤**，因为您将能够开始**活动目录枚举：**

关于[**ASREPRoast**](asreproast.md)，您现在可以找到每个可能的易受攻击用户，关于[**密码喷洒**](password-spraying.md)，您可以获取**所有用户名的列表**并尝试被破坏帐户的密码、空密码和新的有前景的密码。

* 您可以使用[**CMD进行基本侦查**](../basic-cmd-for-pentesters.md#domain-info)
* 您还可以使用[**powershell进行侦查**](../basic-powershell-for-pentesters/)，这将更加隐蔽
* 您还可以[**使用powerview**](../basic-powershell-for-pentesters/powerview.md)提取更详细的信息
* 另一个在活动目录中进行侦查的惊人工具是[**BloodHound**](bloodhound.md)。它**不是很隐蔽**（取决于您使用的收集方法），但**如果您不在乎**这一点，您绝对应该尝试一下。查找用户可以RDP的地方，查找其他组的路径等。
* **其他自动化AD枚举工具包括：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**AD的DNS记录**](ad-dns-records.md)，因为它们可能包含有趣的信息。
* 您可以使用**SysInternal** Suite中的**AdExplorer.exe**进行目录枚举的**GUI工具**。
* 您还可以使用**ldapsearch**在LDAP数据库中搜索以查找字段_userPassword_和_unixUserPassword_中的凭据，甚至查找_Description_。请参阅[PayloadsAllTheThings上的AD用户注释中的密码](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)以获取其他方法。
* 如果您使用**Linux**，您还可以使用[**pywerview**](https://github.com/the-useless-one/pywerview)枚举域。
* 您还可以尝试自动化工具，如：
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **提取所有域用户**

从Windows中获取所有域用户名非常简单（`net user /domain`，`Get-DomainUser`或`wmic useraccount get name,sid`）。在Linux中，您可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username`或`enum4linux -a -u "user" -p "password" <DC IP>`

> 即使这个枚举部分看起来很小，这也是最重要的部分。访问链接（主要是cmd、powershell、powerview和BloodHound的链接），学习如何枚举域并练习，直到您感到舒适。在评估期间，这将是找到通往DA的关键时刻，或者决定没有任何事情可以做。

### Kerberoast

Kerberoasting涉及获取**TGS票证**，这些票证由与用户帐户相关的服务使用，并破解其加密——这基于用户密码——**离线**。

更多信息请参见：

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### 远程连接（RDP、SSH、FTP、Win-RM等）

一旦您获得了一些凭据，您可以检查是否可以访问任何**机器**。为此，您可以使用**CrackMapExec**尝试通过不同协议连接到多个服务器，具体取决于您的端口扫描结果。

### 本地权限提升

如果您已经破坏了凭据或作为常规域用户的会话，并且您可以使用此用户**访问域中的任何机器**，您应该尝试找到**本地提升权限和寻找凭据的方法**。这是因为只有在本地管理员权限下，您才能**在内存中（LSASS）和本地（SAM）转储其他用户的哈希**。

本书中有一整页关于[**Windows中的本地权限提升**](../windows-local-privilege-escalation/)和一个[**检查表**](../checklist-windows-privilege-escalation.md)。此外，不要忘记使用[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### 当前会话票证

您很**不可能**在当前用户中找到**票证**，使您能够访问意外资源，但您可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

如果你已经成功枚举了活动目录，你将会有**更多的电子邮件和对网络的更好理解**。你可能能够强制进行 NTML [**中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**。**

### **在计算机共享中查找凭据**

现在你有了一些基本凭据，你应该检查是否可以**找到**任何**在 AD 中共享的有趣文件**。你可以手动进行，但这是一项非常无聊的重复任务（如果你发现数百个需要检查的文档，更是如此）。

[**点击此链接了解你可以使用的工具。**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### 偷取 NTLM 凭据

如果你可以**访问其他 PC 或共享**，你可以**放置文件**（如 SCF 文件），如果以某种方式被访问，将**触发对你的 NTML 认证**，这样你就可以**窃取** **NTLM 挑战**以破解它：

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何经过身份验证的用户**破坏域控制器**。

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## 在具有特权凭据/会话的活动目录上进行特权提升

**对于以下技术，普通域用户是不够的，你需要一些特殊的特权/凭据来执行这些攻击。**

### 哈希提取

希望你已经成功**破坏了一些本地管理员**账户，使用 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 包括中继、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[本地提升特权](../windows-local-privilege-escalation/)。\
然后，是时候转储内存和本地的所有哈希。\
[**阅读此页面以了解获取哈希的不同方法。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 传递哈希

**一旦你拥有用户的哈希**，你可以用它来**冒充**该用户。\
你需要使用某些**工具**来**执行**使用该**哈希**的**NTLM 认证**，**或者**你可以创建一个新的**sessionlogon**并**注入**该**哈希**到**LSASS**中，这样当任何**NTLM 认证被执行**时，该**哈希将被使用。**最后一个选项就是 mimikatz 所做的。\
[**阅读此页面以获取更多信息。**](../ntlm/#pass-the-hash)

### 超越哈希/传递密钥

此攻击旨在**使用用户的 NTLM 哈希请求 Kerberos 票证**，作为常见的 NTLM 协议下的传递哈希的替代方案。因此，这在**禁用 NTLM 协议**且仅允许**Kerberos**作为认证协议的网络中尤其**有用**。

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### 传递票证

在**传递票证 (PTT)** 攻击方法中，攻击者**窃取用户的认证票证**而不是他们的密码或哈希值。然后使用这个被窃取的票证来**冒充用户**，获得对网络中资源和服务的未授权访问。

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### 凭据重用

如果你拥有**本地管理员**的**哈希**或**密码**，你应该尝试使用它**本地登录**到其他**PC**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
注意，这非常**嘈杂**，而且**LAPS**会**减轻**这种情况。
{% endhint %}

### MSSQL 滥用与受信任链接

如果用户有权限**访问 MSSQL 实例**，他可能能够利用它在 MSSQL 主机上**执行命令**（如果以 SA 身份运行），**窃取** NetNTLM **哈希**，甚至执行**中继****攻击**。\
此外，如果一个 MSSQL 实例被另一个 MSSQL 实例信任（数据库链接）。如果用户对受信任的数据库有权限，他将能够**利用信任关系在另一个实例中执行查询**。这些信任可以链式连接，在某些情况下，用户可能能够找到一个配置错误的数据库，在那里他可以执行命令。\
**数据库之间的链接甚至可以跨森林信任工作。**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### 不受限制的委派

如果你发现任何具有属性 [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) 的计算机对象，并且你在该计算机上拥有域权限，你将能够从登录到该计算机的每个用户的内存中转储 TGT。\
因此，如果**域管理员登录到该计算机**，你将能够转储他的 TGT，并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
得益于受限委派，你甚至可以**自动妥协打印服务器**（希望它是 DC）。

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### 受限委派

如果用户或计算机被允许进行“受限委派”，它将能够**冒充任何用户以访问计算机中的某些服务**。\
然后，如果你**妥协**该用户/计算机的哈希，你将能够**冒充任何用户**（甚至是域管理员）以访问某些服务。

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### 基于资源的受限委派

在远程计算机的 Active Directory 对象上拥有**写入**权限可以实现**提升权限**的代码执行：

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACL 滥用

被妥协的用户可能对某些域对象拥有一些**有趣的权限**，这可能让你**横向移动**/**提升**权限。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 打印机后台处理程序服务滥用

发现域内**后台处理程序服务**的**监听**可以被**滥用**以**获取新凭据**并**提升权限**。

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### 第三方会话滥用

如果**其他用户****访问**被**妥协**的机器，可能会**从内存中收集凭据**，甚至**在他们的进程中注入信标**以冒充他们。\
通常用户会通过 RDP 访问系统，因此这里有如何对第三方 RDP 会话执行几种攻击的方法：

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** 提供了一种管理域加入计算机上的**本地管理员密码**的系统，确保其**随机化**、唯一且频繁**更改**。这些密码存储在 Active Directory 中，访问通过 ACL 控制，仅限授权用户。拥有足够权限访问这些密码后，转向其他计算机变得可能。

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### 证书盗窃

**从被妥协的机器收集证书**可能是提升环境内权限的一种方式：

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### 证书模板滥用

如果**易受攻击的模板**被配置，可以利用它们来提升权限：

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## 高权限账户的后期利用

### 转储域凭据

一旦你获得**域管理员**或更好的**企业管理员**权限，你可以**转储**域数据库：_ntds.dit_。

[**有关 DCSync 攻击的更多信息可以在这里找到**](dcsync.md)。

[**有关如何窃取 NTDS.dit 的更多信息可以在这里找到**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 权限提升作为持久性

之前讨论的一些技术可以用于持久性。\
例如，你可以：

*   使用户易受[**Kerberoast**](kerberoast.md)攻击

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   使用户易受[**ASREPRoast**](asreproast.md)攻击

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   授予用户[**DCSync**](./#dcsync)权限

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### 银票

**银票攻击**为特定服务创建一个**合法的票据授予服务（TGS）票据**，通过使用**NTLM 哈希**（例如，**PC 账户的哈希**）。此方法用于**访问服务权限**。

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### 金票

**金票攻击**涉及攻击者在 Active Directory (AD) 环境中获取**krbtgt 账户的 NTLM 哈希**。该账户是特殊的，因为它用于签署所有**票据授予票据（TGTs）**，这些票据对于在 AD 网络中进行身份验证至关重要。

一旦攻击者获得此哈希，他们可以为他们选择的任何账户创建**TGTs**（银票攻击）。

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### 钻石票

这些票据类似于金票，但以**绕过常见金票检测机制**的方式伪造。

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **证书账户持久性**

**拥有账户的证书或能够请求它们**是能够在用户账户中持久存在的非常好方法（即使他更改密码）：

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **证书域持久性**

**使用证书也可以在域内以高权限持久存在：**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder 组

Active Directory 中的**AdminSDHolder**对象通过在这些组中应用标准的**访问控制列表（ACL）**来确保**特权组**（如域管理员和企业管理员）的安全，以防止未经授权的更改。然而，这一功能可以被利用；如果攻击者修改 AdminSDHolder 的 ACL 以授予普通用户完全访问权限，该用户将获得对所有特权组的广泛控制。这个本应保护的安全措施因此可能适得其反，允许不当访问，除非进行严格监控。

[**有关 AdminDSHolder 组的更多信息在这里。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM 凭据

在每个**域控制器（DC）**内部，存在一个**本地管理员**账户。通过在这样的机器上获得管理员权限，可以使用**mimikatz**提取本地管理员哈希。随后，需要进行注册表修改以**启用使用此密码**，从而允许远程访问本地管理员账户。

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL 持久性

你可以**给予**某个**用户**对某些特定域对象的**特殊权限**，这将使该用户**在未来提升权限**。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### 安全描述符

**安全描述符**用于**存储**对象对另一个对象的**权限**。如果你能在对象的**安全描述符**中**做一点小改动**，你可以在不需要成为特权组成员的情况下获得对该对象的非常有趣的权限。

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### 骨架钥匙

在内存中更改**LSASS**以建立一个**通用密码**，授予对所有域账户的访问权限。

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### 自定义 SSP

[在这里了解什么是 SSP（安全支持提供者）。](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
你可以创建自己的**SSP**以**捕获**用于访问机器的**凭据**的**明文**。\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

它在 AD 中注册一个**新的域控制器**，并使用它在指定对象上**推送属性**（SIDHistory、SPNs...）**而不**留下任何关于**修改**的**日志**。你**需要 DA** 权限并在**根域**内。\
注意，如果你使用错误的数据，会出现相当丑陋的日志。

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS 持久性

之前我们讨论了如果你有**足够的权限读取 LAPS 密码**，如何提升权限。然而，这些密码也可以用于**维持持久性**。\
检查：

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## 森林权限提升 - 域信任

微软将**森林**视为安全边界。这意味着**妥协一个域可能会导致整个森林被妥协**。

### 基本信息

[**域信任**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx)是一种安全机制，使一个**域**中的用户能够访问另一个**域**中的资源。它本质上在两个域的身份验证系统之间创建了一个链接，允许身份验证验证无缝流动。当域设置信任时，它们在其**域控制器（DCs）**中交换并保留特定的**密钥**，这些密钥对信任的完整性至关重要。

在典型场景中，如果用户打算访问**受信任域**中的服务，他们必须首先从自己域的 DC 请求一个称为**跨领域 TGT**的特殊票据。此 TGT 使用两个域已达成一致的共享**密钥**进行加密。然后，用户将此 TGT 提交给**受信任域的 DC**以获取服务票据（**TGS**）。在受信任域的 DC 成功验证跨领域 TGT 后，它会发出 TGS，授予用户访问该服务的权限。

**步骤**：

1. **域 1**中的**客户端计算机**开始该过程，使用其**NTLM 哈希**向其**域控制器（DC1）**请求**票据授予票据（TGT）**。
2. 如果客户端成功通过身份验证，DC1 会发出新的 TGT。
3. 客户端然后向 DC1 请求一个**跨领域 TGT**，该 TGT 是访问**域 2**中的资源所需的。
4. 跨领域 TGT 使用作为双向域信任的一部分在 DC1 和 DC2 之间共享的**信任密钥**进行加密。
5. 客户端将跨领域 TGT 带到**域 2 的域控制器（DC2）**。
6. DC2 使用其共享的信任密钥验证跨领域 TGT，如果有效，则为客户端想要访问的域 2 中的服务器发出**票据授予服务（TGS）**。
7. 最后，客户端将此 TGS 提交给服务器，该 TGS 使用服务器的账户哈希进行加密，以获取对域 2 中服务的访问权限。

### 不同的信任

重要的是要注意，**信任可以是单向或双向**。在双向选项中，两个域将相互信任，但在**单向**信任关系中，一个域将是**受信任**的，另一个是**信任**的。在最后一种情况下，**你只能从受信任的域访问信任域内的资源**。

如果域 A 信任域 B，A 是信任域，B 是受信任域。此外，在**域 A**中，这将是**出站信任**；而在**域 B**中，这将是**入站信任**。

**不同的信任关系**

* **父子信任**：这是同一森林内的常见设置，子域自动与其父域建立双向传递信任。这意味着身份验证请求可以在父域和子域之间无缝流动。
* **交叉链接信任**：被称为“快捷信任”，这些信任在子域之间建立，以加快引用过程。在复杂的森林中，身份验证引用通常必须向森林根节点上行，然后再向目标域下行。通过创建交叉链接，旅程缩短，这在地理分散的环境中特别有利。
* **外部信任**：这些信任在不同的、不相关的域之间建立，通常是非传递的。根据[微软的文档](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx)，外部信任对于访问当前森林外的域中的资源非常有用，该域未通过森林信任连接。通过 SID 过滤增强安全性。
* **树根信任**：这些信任在森林根域和新添加的树根之间自动建立。虽然不常见，但树根信任对于将新域树添加到森林中非常重要，使它们能够保持唯一的域名并确保双向传递性。有关更多信息，请参见[微软的指南](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx)。
* **森林信任**：这种类型的信任是两个森林根域之间的双向传递信任，也强制执行 SID 过滤以增强安全措施。
* **MIT 信任**：这些信任与非 Windows 的[RFC4120 兼容](https://tools.ietf.org/html/rfc4120) Kerberos 域建立。MIT 信任更为专业，适用于需要与 Windows 生态系统外的基于 Kerberos 的系统集成的环境。

#### **信任关系中的其他差异**

* 信任关系也可以是**传递的**（A 信任 B，B 信任 C，则 A 信任 C）或**非传递的**。
* 信任关系可以设置为**双向信任**（双方相互信任）或**单向信任**（只有一个信任另一个）。

### 攻击路径

1. **枚举**信任关系
2. 检查是否有任何**安全主体**（用户/组/计算机）对**另一个域**的资源有**访问**权限，可能通过 ACE 条目或在另一个域的组中。寻找**跨域关系**（信任可能是为此创建的）。
3. 在这种情况下，kerberoast 可能是另一个选项。
4. **妥协**可以**跨域**的**账户**。

攻击者可以通过三种主要机制访问另一个域中的资源：

* **本地组成员资格**：主体可能被添加到机器上的本地组中，例如服务器上的“管理员”组，从而授予他们对该机器的重大控制。
* **外部域组成员资格**：主体也可以是外部域中组的成员。然而，这种方法的有效性取决于信任的性质和组的范围。
* **访问控制列表（ACLs）**：主体可能在**ACL**中被指定，特别是在**DACL**中的**ACE**内，提供对特定资源的访问权限。对于那些希望深入了解 ACL、DACL 和 ACE 机制的人，名为“[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)”的白皮书是一个宝贵的资源。

### 子到父森林权限提升
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
有 **2 个受信任的密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_.\
您可以使用当前域使用的密钥：
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History 注入

通过利用与 SID-History 注入的信任关系，提升为企业管理员到子域/父域：

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### 利用可写配置 NC

理解如何利用配置命名上下文 (NC) 是至关重要的。配置 NC 作为 Active Directory (AD) 环境中跨森林的配置数据的中央存储库。这些数据会复制到森林内的每个域控制器 (DC)，可写的 DC 维护配置 NC 的可写副本。要利用这一点，必须在 DC 上拥有 **SYSTEM 权限**，最好是子 DC。

**将 GPO 链接到根 DC 站点**

配置 NC 的站点容器包含有关 AD 森林中所有域加入计算机的站点的信息。通过在任何 DC 上以 SYSTEM 权限操作，攻击者可以将 GPO 链接到根 DC 站点。此操作可能通过操纵应用于这些站点的策略来危害根域。

有关深入信息，可以探索关于 [绕过 SID 过滤](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) 的研究。

**危害森林中的任何 gMSA**

一个攻击向量涉及针对域内特权 gMSA。KDS 根密钥是计算 gMSA 密码所必需的，存储在配置 NC 中。通过在任何 DC 上拥有 SYSTEM 权限，可以访问 KDS 根密钥并计算森林中任何 gMSA 的密码。

详细分析可以在关于 [黄金 gMSA 信任攻击](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent) 的讨论中找到。

**架构变更攻击**

此方法需要耐心，等待新特权 AD 对象的创建。拥有 SYSTEM 权限的攻击者可以修改 AD 架构，以授予任何用户对所有类的完全控制。这可能导致对新创建的 AD 对象的未经授权的访问和控制。

进一步阅读可在 [架构变更信任攻击](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) 中找到。

**从 DA 到 EA 的 ADCS ESC5**

ADCS ESC5 漏洞针对对公钥基础设施 (PKI) 对象的控制，以创建一个证书模板，使其能够作为森林中的任何用户进行身份验证。由于 PKI 对象位于配置 NC 中，危害可写的子 DC 使得执行 ESC5 攻击成为可能。

有关此内容的更多细节可以在 [从 DA 到 EA 的 ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) 中阅读。在缺乏 ADCS 的情况下，攻击者有能力设置必要的组件，如 [从子域管理员提升到企业管理员](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) 中所讨论的。

### 外部森林域 - 单向 (入站) 或双向
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
在这种情况下，**您的域受到外部域的信任**，这使您对其拥有**不确定的权限**。您需要找出**您的域中的哪些主体对外部域具有哪些访问权限**，然后尝试利用它：

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
在这种情况下，**您的域**正在**信任**来自**不同域**的主体的一些**权限**。

然而，当一个**域被信任**时，受信任的域**创建一个用户**，其**名称是可预测的**，并使用**受信任的密码**作为**密码**。这意味着可以**访问来自信任域的用户以进入受信任域**，以枚举它并尝试提升更多权限：

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

另一种妥协受信任域的方法是查找在域信任的**相反方向**创建的[**SQL受信任链接**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种妥协受信任域的方法是在一台**受信任域用户可以访问的**机器上等待，通过**RDP**登录。然后，攻击者可以在RDP会话进程中注入代码，并从那里**访问受害者的源域**。\
此外，如果**受害者挂载了他的硬盘**，攻击者可以在**RDP会话**进程中将**后门**存储在**硬盘的启动文件夹**中。这种技术称为**RDPInception**。

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### 域信任滥用缓解

### **SID过滤：**

* 通过SID过滤来减轻利用SID历史属性进行攻击的风险，SID过滤在所有跨森林信任中默认启用。这是基于假设，考虑到森林而不是域作为安全边界，认为内部森林信任是安全的，这是微软的立场。
* 然而，有一个问题：SID过滤可能会干扰应用程序和用户访问，导致其偶尔被禁用。

### **选择性身份验证：**

* 对于跨森林信任，采用选择性身份验证确保两个森林的用户不会自动进行身份验证。相反，用户需要明确的权限才能访问信任域或森林中的域和服务器。
* 重要的是要注意，这些措施并不能保护免受可写配置命名上下文（NC）的利用或对信任帐户的攻击。

[**有关域信任的更多信息，请访问ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## 一些一般防御

[**在这里了解更多关于如何保护凭据的信息。**](../stealing-credentials/credentials-protections.md)\\

### **凭据保护的防御措施**

* **域管理员限制**：建议仅允许域管理员登录到域控制器，避免在其他主机上使用。
* **服务帐户权限**：服务不应以域管理员（DA）权限运行，以保持安全。
* **临时权限限制**：对于需要DA权限的任务，应限制其持续时间。这可以通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **实施欺骗技术**

* 实施欺骗涉及设置陷阱，如诱饵用户或计算机，具有如密码不过期或标记为受信任的委托等特征。详细的方法包括创建具有特定权限的用户或将其添加到高权限组。
* 一个实际的例子涉及使用工具：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* 有关部署欺骗技术的更多信息，请访问[Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **识别欺骗**

* **对于用户对象**：可疑指标包括不典型的ObjectSID、频率较低的登录、创建日期和低错误密码计数。
* **一般指标**：比较潜在诱饵对象的属性与真实对象的属性可以揭示不一致性。像[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)这样的工具可以帮助识别这种欺骗。

### **绕过检测系统**

* **Microsoft ATA检测绕过**：
* **用户枚举**：避免在域控制器上进行会话枚举，以防止ATA检测。
* **票据冒充**：利用**aes**密钥创建票据有助于避免检测，因为不降级到NTLM。
* **DCSync攻击**：建议从非域控制器执行，以避免ATA检测，因为直接从域控制器执行将触发警报。

## 参考文献

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{% hint style="success" %}
学习和实践AWS黑客攻击：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客攻击：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord小组**](https://discord.gg/hRep4RUj7f)或[**电报小组**](https://t.me/peass)或**在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR分享黑客技巧。

</details>
{% endhint %}
